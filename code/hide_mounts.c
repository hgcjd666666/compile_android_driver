// hide_mounts.c
//
// 内核模块：隐藏 /proc/self/mounts 中以 "KSU " 开头的挂载行
// 方法：kretprobe 劫持 seq_read_iter，在读挂载文件前临时替换 show 函数，
//       在数据生成点逐行过滤，首读即隐藏，无需修改 seq_read_iter 状态机。
//
// 作者：hgcjd666666（划掉）DeepSeek

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide KSU mounts from /proc/self/mounts by on-the-fly show replacement");
// MODULE_AUTHOR("hgcjd666666");
MODULE_AUTHOR("deepseek-v4-pro");

/* ---------- 过滤层：替换后的 show 函数 ---------- */

/* 保存挂载文件原始 show 函数指针，由钩子入口处动态获取 */
static int (*original_mounts_show)(struct seq_file *seq, void *v) = NULL;

/**
 * filtered_mounts_show - 自定义 show 函数，用于替换原 seq_operations->show
 * @seq: 序列文件指针
 * @v:   传递给 show 的迭代器参数（实际未使用）
 *
 * 工作原理：
 * 1. 分配临时缓冲区，将 m->buf 临时替换为临时缓冲区，保留原缓冲区指针和大小。
 * 2. 调用原始 show 函数，让它把一行数据输出到临时缓冲区。
 * 3. 检查输出内容是否以 "KSU " 开头：
 *    - 若是，直接丢弃该行（不写入原缓冲区）。
 *    - 否则将这一行拷贝到原缓冲区的已有内容之后。
 * 4. 恢复原 m->buf，释放临时缓冲区。
 *
 * 注意：每次调用只处理一行（show 每行调用一次），因此不需要遍历换行符。
 */
static int filtered_mounts_show(struct seq_file *seq, void *v)
{
    char *temp_buf;           // 临时缓冲区，用于承载原始 show 的输出
    size_t bytes_written;     // 原始 show 实际写入临时缓冲区的字节数
    char *saved_buf;          // 保存原 m->buf
    size_t saved_size;        // 保存原 m->size
    size_t saved_count;       // 保存原 m->count
    int ret;

    if (!original_mounts_show)
        return 0;

    /* 分配临时缓冲区，大小与原缓冲区一致，确保不会溢出 */
    temp_buf = kmalloc(seq->size, GFP_KERNEL);
    if (!temp_buf) {
        /* 内存不足时退化：直接调用原始 show 不进行过滤 */
        return original_mounts_show(seq, v);
    }

    /* 保存 seq_file 缓冲区原始状态，并替换为临时缓冲区 */
    saved_buf   = seq->buf;
    saved_size  = seq->size;
    saved_count = seq->count;

    seq->buf   = temp_buf;
    seq->count = 0;           // 从临时缓冲区起始位置开始写入

    /* 调用原始 show，让其将一行数据输出到 temp_buf */
    ret = original_mounts_show(seq, v);
    bytes_written = seq->count;

    /* 恢复原缓冲区 */
    seq->buf  = saved_buf;
    seq->size = saved_size;

    if (ret == 0 && bytes_written > 0) {
        /* 检查是否是我们需要隐藏的 KSU 行 */
        if (bytes_written >= 4 && memcmp(temp_buf, "KSU ", 4) == 0) {
            /* 匹配 KSU 行，丢弃：直接恢复原 count，相当于没写入任何数据 */
            seq->count = saved_count;
        } else {
            /* 非 KSU 行，追加到原缓冲区末尾 */
            if (saved_count + bytes_written <= saved_size) {
                memcpy(saved_buf + saved_count, temp_buf, bytes_written);
                seq->count = saved_count + bytes_written;
            } else {
                /* 溢出保护：清空缓冲区并返回空间不足错误 */
                seq->count = 0;
                ret = -ENOSPC;
            }
        }
    } else {
        /* 原始 show 失败，恢复原 count */
        seq->count = saved_count;
    }

    kfree(temp_buf);
    return ret;
}

/* ---------- seq_read_iter 钩子：临时替换 show ---------- */

/**
 * struct read_iter_hook_data - 每次 seq_read_iter 钩子的上下文
 * @file:        当前被读取的文件结构体
 * @seq:         文件的 seq_file 私有数据
 * @old_ops:     原始的 seq_operations，需要在读完后恢复
 * @new_ops:     新分配的 seq_operations，其 show 指向 filtered_mounts_show
 * @show_replaced: 标记本次调用中是否已替换 show，用于决定 ret 中是否恢复
 */
struct read_iter_hook_data {
    struct file *file;
    struct seq_file *seq;
    const struct seq_operations *old_ops;
    struct seq_operations *new_ops;
    bool show_replaced;
};

/**
 * hook_seq_read_iter_entry - kretprobe 入口处理函数
 * @ri:   kretprobe 实例
 * @regs: 函数调用时的寄存器快照
 *
 * 在 seq_read_iter 执行前被调用。
 * 检查本次读取是否为 /proc/self/mounts，若是则：
 * 1. 备份当前的 seq_operations。
 * 2. 分配新的 seq_operations，将 show 替换为 filtered_mounts_show。
 * 3. 让 seq_file 的 op 指向新 ops。
 * 这样后续调用 show 时将直接执行我们的过滤版本。
 */
static int hook_seq_read_iter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_hook_data *data = (struct read_iter_hook_data *)ri->data;
    /* ARM64 调用约定：x0 = kiocb, x1 = iov_iter */
    struct kiocb *iocb = (struct kiocb *)regs->regs[0];
    struct file *file   = iocb->ki_filp;
    struct seq_file *seq;

    data->file          = file;
    data->show_replaced = false;

    if (!file)
        return 0;

    seq = file->private_data;
    data->seq = seq;
    if (!seq || !seq->op || !file->f_path.dentry)
        return 0;

    /* 只拦截名为 "mounts" 的文件，通常是 /proc/self/mounts 或 /proc/xxx/mounts */
    if (strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    /* 如果已经被替换（例如并发读取，理论上不会发生，但做防御检查） */
    if (seq->op->show == filtered_mounts_show)
        return 0;

    /* 备份当前 ops，创建新 ops 并替换 show */
    data->old_ops = seq->op;
    data->new_ops = kmalloc(sizeof(*(data->new_ops)), GFP_KERNEL);
    if (!data->new_ops)
        return 0;

    /* 拷贝整个 ops 结构，仅修改 show 字段 */
    memcpy(data->new_ops, data->old_ops, sizeof(*(data->new_ops)));
    original_mounts_show = data->old_ops->show;   // 记录原始 show，供过滤函数调用
    data->new_ops->show  = filtered_mounts_show;
    seq->op = data->new_ops;

    data->show_replaced = true;

    /* 调试日志：使用 KERN_INFO 确保在普通日志级别可见 */
    printk(KERN_INFO "hm: replaced show for mounts (seq=%p)\n", seq);

    return 0;
}

/**
 * hook_seq_read_iter_ret - kretprobe 返回处理函数
 * @ri:   kretprobe 实例
 * @regs: 函数返回时的寄存器快照（此处未使用）
 *
 * 在 seq_read_iter 返回后调用，用于恢复原始的 seq_operations，
 * 并释放我们临时分配的新 ops 结构。
 * 无论本次读取是否成功，都应恢复原状，避免留下悬挂指针。
 */
static int hook_seq_read_iter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_hook_data *data = (struct read_iter_hook_data *)ri->data;

    if (!data->show_replaced || !data->seq)
        return 0;

    /* 恢复原始 ops 并释放我们分配的结构 */
    data->seq->op = data->old_ops;
    kfree(data->new_ops);
    data->show_replaced = false;

    return 0;
}

/* 定义 kretprobe 结构，挂载到导出函数 seq_read_iter */
static struct kretprobe kretp_seq_read_iter = {
    .entry_handler = hook_seq_read_iter_entry,
    .handler       = hook_seq_read_iter_ret,
    .data_size     = sizeof(struct read_iter_hook_data),
    .maxactive     = 64,                  // 最大并发探测实例数，足够使用
    .kp            = {
        .symbol_name = "seq_read_iter",
    },
};

/* ---------- 模块生命周期 ---------- */

/**
 * hide_mounts_init - 模块加载入口
 *
 * 注册 seq_read_iter 的 kretprobe，成功后会在 dmesg 中看到提示。
 */
static int __init hide_mounts_init(void)
{
    int ret;

    ret = register_kretprobe(&kretp_seq_read_iter);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: failed to register seq_read_iter kretprobe, error %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "hide_mounts: successfully loaded (seq_read_iter hook active)\n");
    return 0;
}

/**
 * hide_mounts_exit - 模块卸载入口
 *
 * 注销 kretprobe。由于该钩子在每次读取后都会恢复 ops，没有残留状态，
 * 因此卸载时不需要额外清理悬挂指针。
 */
static void __exit hide_mounts_exit(void)
{
    unregister_kretprobe(&kretp_seq_read_iter);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);