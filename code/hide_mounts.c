// hide_mounts.c
//
// 内核模块：隐藏 debugfs 在以下三个文件中的挂载痕迹
//   /proc/self/mounts     - 隐藏以 "debugfs " 开头的行
//   /proc/self/mountinfo  - 隐藏包含 " - debugfs debugfs rw,seclabel,mode=755" 的行
//   /proc/self/mountstats - 隐藏以 "device debugfs mounted on " 开头的行
// 方法：kretprobe 劫持 seq_read_iter，在读文件前临时替换 show 函数，
//       在数据生成点逐行过滤，首读即隐藏，无需修改 seq_read_iter 状态机。
//
// 历史：旧版用于隐藏 KSU 挂载行（mounts 以 "KSU " 开头、mountinfo 含 " KSU "），
//       现已改为隐藏 debugfs 痕迹，原 KSU 过滤逻辑被注释保留，不再生效。
//
// 作者：hgcjd666666

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide debugfs mount traces from mounts/mountinfo/mountstats by on-the-fly show replacement");
MODULE_AUTHOR("hgcjd666666");

/* ---------- 文件类型枚举 ---------- */

enum mount_file_type {
    FILE_MOUNTS = 0,   /* /proc/self/mounts */
    FILE_MOUNTINFO,    /* /proc/self/mountinfo */
    FILE_MOUNTSTATS,   /* /proc/self/mountstats */
    FILE_COUNT,
};

/* ---------- 隐藏规则 ---------- */

/*
 * ============================================================================
 * 旧版 KSU 隐藏逻辑（已废弃，仅注释保留，不再生效）
 *
 * mounts 的过滤 show：丢弃以 "KSU " 开头的行
 *     if (bytes_written >= 4 && memcmp(temp_buf, "KSU ", 4) == 0)
 *         seq->count = saved_count;   // 命中则丢弃
 *
 * mountinfo 的过滤 show：丢弃包含 " KSU " 的行
 *     if (strstr(temp_buf, " KSU ") != NULL)
 *         seq->count = saved_count;   // 命中则丢弃
 *
 * 现在改为隐藏 debugfs 挂载痕迹（见下方 mounts_is_hidden /
 * mountinfo_is_hidden / mountstats_is_hidden），KSU 相关行不再被过滤。
 * ============================================================================
 */

/**
 * mounts 隐藏规则：行以 "debugfs " 开头（mounts 行的首字段是文件系统类型）
 */
static bool mounts_is_hidden(const char *line)
{
    static const char prefix[] = "debugfs ";
    return strncmp(line, prefix, sizeof(prefix) - 1) == 0;
}

/**
 * mountinfo 隐藏规则：行中包含 " - debugfs debugfs rw,seclabel,mode=755"
 * （mountinfo 行以 " - <fstype> <source> <options>" 结尾，debugfs 特征在行尾段）
 */
static bool mountinfo_is_hidden(const char *line)
{
    static const char marker[] = " - debugfs debugfs rw,seclabel,mode=755";
    return strstr(line, marker) != NULL;
}

/**
 * mountstats 隐藏规则：行以 "device debugfs mounted on " 开头
 */
static bool mountstats_is_hidden(const char *line)
{
    static const char prefix[] = "device debugfs mounted on ";
    return strncmp(line, prefix, sizeof(prefix) - 1) == 0;
}

/**
 * 各文件类型对应的隐藏判定函数
 */
static bool (*const hide_predicates[FILE_COUNT])(const char *) = {
    [FILE_MOUNTS]     = mounts_is_hidden,
    [FILE_MOUNTINFO]  = mountinfo_is_hidden,
    [FILE_MOUNTSTATS] = mountstats_is_hidden,
};

/* ---------- 过滤层：替换后的 show 函数 ---------- */

/* 保存三个文件各自的原始 show 函数指针，由钩子入口处动态获取 */
static int (*original_show[FILE_COUNT])(struct seq_file *seq, void *v);

/**
 * filtered_show_common - 通用过滤 show：把原始 show 输出到临时缓冲区，
 *                       命中隐藏规则则丢弃整行，否则追加到真实缓冲区
 *
 * @seq:   seq_file
 * @v:     遍历到的位置对象
 * @type:  文件类型，决定使用哪条隐藏规则和哪个原始 show
 */
static int filtered_show_common(struct seq_file *seq, void *v, int type)
{
    char *temp_buf;           // 临时缓冲区，用于承载原始 show 的输出
    size_t bytes_written;     // 原始 show 实际写入临时缓冲区的字节数
    char *saved_buf;          // 保存原 m->buf
    size_t saved_size;        // 保存原 m->size
    size_t saved_count;       // 保存原 m->count
    bool hidden;
    int ret;

    if (!original_show[type])
        return 0;

    /* 分配临时缓冲区，大小与原缓冲区一致，确保不会溢出 */
    temp_buf = kmalloc(seq->size, GFP_KERNEL);
    if (!temp_buf) {
        /* 内存不足时退化：直接调用原始 show 不进行过滤 */
        return original_show[type](seq, v);
    }

    /* 保存 seq_file 缓冲区原始状态，并替换为临时缓冲区 */
    saved_buf   = seq->buf;
    saved_size  = seq->size;
    saved_count = seq->count;

    seq->buf   = temp_buf;
    seq->count = 0;           // 从临时缓冲区起始位置开始写入

    /* 调用原始 show，让其将一行数据输出到 temp_buf */
    ret = original_show[type](seq, v);
    bytes_written = seq->count;

    /* 恢复原缓冲区 */
    seq->buf  = saved_buf;
    seq->size = saved_size;

    if (ret == 0 && bytes_written > 0) {
        /* 判定是否命中本文件的隐藏规则 */
        hidden = hide_predicates[type](temp_buf);
        if (hidden) {
            /* 命中隐藏规则，丢弃：直接恢复原 count，相当于没写入任何数据 */
            seq->count = saved_count;
        } else {
            /* 未命中，追加到原缓冲区末尾 */
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

/* 各文件类型对应的过滤 show 包装 */
static int filtered_mounts_show(struct seq_file *seq, void *v)
{
    return filtered_show_common(seq, v, FILE_MOUNTS);
}
static int filtered_mountinfo_show(struct seq_file *seq, void *v)
{
    return filtered_show_common(seq, v, FILE_MOUNTINFO);
}
static int filtered_mountstats_show(struct seq_file *seq, void *v)
{
    return filtered_show_common(seq, v, FILE_MOUNTSTATS);
}

/* 各文件类型对应的过滤 show 函数表 */
static int (*const filtered_show[FILE_COUNT])(struct seq_file *, void *) = {
    [FILE_MOUNTS]     = filtered_mounts_show,
    [FILE_MOUNTINFO]  = filtered_mountinfo_show,
    [FILE_MOUNTSTATS] = filtered_mountstats_show,
};

/* 判断某个过滤 show 是否已经被安装到 seq->op 上（防御性检查） */
static bool is_filtered_show(int (*show)(struct seq_file *, void *))
{
    int i;
    for (i = 0; i < FILE_COUNT; i++) {
        if (filtered_show[i] == show)
            return true;
    }
    return false;
}

/* ---------- seq_read_iter 钩子：临时替换 show ---------- */
/**
 * struct read_iter_hook_data - 每次 seq_read_iter 钩子的上下文
 * @file:        当前被读取的文件结构体
 * @seq:         文件的 seq_file 私有数据
 * @old_ops:     原始的 seq_operations，需要在读完后恢复
 * @new_ops:     新分配的 seq_operations，替换后的 show 函数
 * @type:        识别出的文件类型（FILE_MOUNTS / FILE_MOUNTINFO / FILE_MOUNTSTATS）
 * @show_replaced: 标记本次调用中是否已替换 show，用于决定 ret 中是否恢复
 */
struct read_iter_hook_data {
    struct file *file;
    struct seq_file *seq;
    const struct seq_operations *old_ops;
    struct seq_operations *new_ops;
    int type;
    bool show_replaced;
};
/**
 * hook_seq_read_iter_entry - kretprobe 入口处理函数
 * @ri:   kretprobe 实例
 * @regs: 函数调用时的寄存器快照
 *
 * 在 seq_read_iter 执行前被调用。
 * 检查本次读取是否为 mounts / mountinfo / mountstats，若是则：
 * 1. 备份当前的 seq_operations。
 * 2. 分配新的 seq_operations，根据文件类型替换 show 为对应的过滤版本。
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
    const char *fname;
    int type = -1;

    data->file          = file;
    data->show_replaced = false;
    data->type          = -1;

    if (!file)
        return 0;

    seq = file->private_data;
    data->seq = seq;
    if (!seq || !seq->op || !file->f_path.dentry)
        return 0;

    /* 只拦截 mounts / mountinfo / mountstats 文件 */
    fname = file->f_path.dentry->d_name.name;
    if (strcmp(fname, "mounts") == 0) {
        type = FILE_MOUNTS;
    } else if (strcmp(fname, "mountinfo") == 0) {
        type = FILE_MOUNTINFO;
    } else if (strcmp(fname, "mountstats") == 0) {
        type = FILE_MOUNTSTATS;
    } else {
        return 0;
    }
    data->type = type;

    /* 如果已经被替换，做防御检查 */
    if (is_filtered_show(seq->op->show))
        return 0;

    /* 备份当前 ops，创建新 ops 并替换 show */
    data->old_ops = seq->op;
    data->new_ops = kmalloc(sizeof(*(data->new_ops)), GFP_KERNEL);
    if (!data->new_ops)
        return 0;

    /* 拷贝整个 ops 结构，替换为该文件类型的过滤 show */
    memcpy(data->new_ops, data->old_ops, sizeof(*(data->new_ops)));
    original_show[type] = data->old_ops->show;
    data->new_ops->show = filtered_show[type];
    seq->op = data->new_ops;

    data->show_replaced = true;

    printk(KERN_INFO "hm: replaced show for type=%d (seq=%p)\n", type, seq);

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
    .maxactive     = 0,                   // 0=内核自动选择，通常为 NR_CPUS 的倍数
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
