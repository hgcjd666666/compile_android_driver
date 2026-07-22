// hide_mounts.c
//
// 内核模块：隐藏 /proc/self/mounts 及 /proc/self/mountinfo 中的一些特征
// 方法：kretprobe 劫持 seq_read_iter，在读文件前临时替换 show 函数，
//       在数据生成点逐行过滤，首读即隐藏，无需修改 seq_read_iter 状态机。
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
#include <linux/sysfs.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide KSU mount lines from mounts and mountinfo by on-the-fly show replacement");
MODULE_AUTHOR("hgcjd666666");

/* ---------- insmod 参数：mounts/mountinfo 额外匹配串（逗号分隔） ---------- */
static char mounts_extra[256] = "";
module_param_string(mounts_extra, mounts_extra, sizeof(mounts_extra), 0);
static char minfo_extra[256] = "";
module_param_string(minfo_extra, minfo_extra, sizeof(minfo_extra), 0);

/* 模式串数组：pats[0] 为内置默认，后续由 *_extra 解析而来 */
#define MAX_PATTERNS 16
#define PATTERN_LEN_MAX 64
static char *mounts_pats[MAX_PATTERNS];
static int mounts_nr_pats;
static char *minfo_pats[MAX_PATTERNS];
static int minfo_nr_pats;
/* ---------- 过滤层：替换后的 show 函数 ---------- */

/* 保存 mounts 和 mountinfo 各自的原始 show 函数指针，由钩子入口处动态获取 */
static int (*original_mounts_show)(struct seq_file *seq, void *v) = NULL;
static int (*original_mountinfo_show)(struct seq_file *seq, void *v) = NULL;

/* ---------- 去重辅助函数 ---------- */

/**
 * skip_field - 跳过当前字段，指向下一个字段的第一个字符
 * @p: 指向字段开头的指针
 * 返回下一个字段的首字符，或 NULL（已到行尾）
 */
static const char *skip_field(const char *p)
{
    if (!p || !*p)
        return NULL;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n')
        p++;
    if (!*p || *p == '\n')
        return NULL;
    while (*p == ' ' || *p == '\t')
        p++;
    if (!*p || *p == '\n')
        return NULL;
    return p;
}

/**
 * paths_equal - 比较两个挂载点路径是否相同
 * @a: 指向路径开头的指针（在行文本中）
 * @b: 指向路径开头的指针（在行文本中）
 * 返回 true 当路径内容完全一致（遇到空格/\t/\n/\0 结束比较）
 */
static bool paths_equal(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    while (*a && *b && *a != ' ' && *a != '\t' && *a != '\n' &&
           *b != ' ' && *b != '\t' && *b != '\n' && *a == *b) {
        a++;
        b++;
    }
    return (!*a || *a == ' ' || *a == '\t' || *a == '\n') &&
           (!*b || *b == ' ' || *b == '\t' || *b == '\n');
}

/**
 * is_dup_mount_path - 检查当前行挂载点是否在 saved_buf 中已出现过
 * @line:        当前行文本
 * @saved_buf:   已输出的缓冲区
 * @saved_count: 已输出的字节数
 * @is_mountinfo: true=mountinfo格式，false=mounts格式
 *
 * 遍历 saved_buf 中每一行，提取挂载点路径与当前行比较。
 * saved_count == 0（尚无已输出行）时返回 false。
 * mounts格式挂载点是第2列，mountinfo是第5列。
 */
static bool is_dup_mount_path(const char *line, const char *saved_buf,
                                size_t saved_count, bool is_mountinfo)
{
    const char *curr_path, *prev_path;
    const char *p, *line_end;
    int i, skip_cnt;

    if (saved_count == 0)
        return false;

    /* 提取当前行的挂载点路径 */
    skip_cnt = is_mountinfo ? 4 : 1;
    curr_path = line;
    for (i = 0; i < skip_cnt; i++) {
        curr_path = skip_field(curr_path);
        if (!curr_path)
            return false;
    }

    /* 遍历 saved_buf 中每一行，逐一比较挂载点 */
    p = saved_buf;
    while (p < saved_buf + saved_count) {
        /* 找到本行结尾（\\n） */
        line_end = memchr(p, '\n', saved_buf + saved_count - p);
        if (!line_end)
            break;

        /* 提取该行的挂载点（只在行范围内搜索） */
        prev_path = p;
        for (i = 0; i < skip_cnt; i++) {
            prev_path = skip_field(prev_path);
            if (!prev_path || prev_path > line_end)
                goto next_line;
        }

        if (paths_equal(curr_path, prev_path))
            return true;

next_line:
        p = line_end + 1;
    }

    return false;
}/**
 * filtered_mounts_show - mounts 的过滤 show：丢弃以 "KSU " 开头的行
 *
 * 优化思路（懒得改）：
 * 当前方案是写入临时缓冲区再 memcpy，可以改为直接写入原始缓冲区，
 * 然后检查 saved_count 处是否为 'K'→'S'→'U'→' '，是则回退 count 丢弃。
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
        int i;
        bool hide = false;

        /* 先去重：检查当前行挂载点是否与上一行相同 */
        if (is_dup_mount_path(temp_buf, saved_buf, saved_count, false)) {
            hide = true;
        }
        /* 再检查是否匹配需隐藏的模式串 */
        if (!hide) {
            for (i = 0; i < mounts_nr_pats; i++) {
                if (strstr(temp_buf, mounts_pats[i]) != NULL) {
                    hide = true;
                    break;
                }
            }
        }
        if (hide) {
            seq->count = saved_count;
        } else {
            /* 非重复非匹配行，追加到原缓冲区末尾 */
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
/**
 * filtered_mountinfo_show - mountinfo 的过滤 show：丢弃包含 " KSU " 的行
 *
 * 优化思路（懒得改）：
 * mounts 的优化同样适用于此，但 mountinfo 的特征 " KSU " 在行中间，
 * 需要在新增内容中逐字节匹配，比行首判断略复杂，且临时缓冲区方案
 * 在实际测试中性能足够，暂时保持当前实现。
 */
static int filtered_mountinfo_show(struct seq_file *seq, void *v)
{
    char *temp_buf;    size_t bytes_written;
    char *saved_buf;
    size_t saved_size;
    size_t saved_count;
    int ret;

    if (!original_mountinfo_show)
        return 0;

    temp_buf = kmalloc(seq->size, GFP_KERNEL);
    if (!temp_buf)
        return original_mountinfo_show(seq, v);

    saved_buf   = seq->buf;
    saved_size  = seq->size;
    saved_count = seq->count;

    seq->buf   = temp_buf;
    seq->count = 0;

    ret = original_mountinfo_show(seq, v);
    bytes_written = seq->count;

    seq->buf  = saved_buf;
    seq->size = saved_size;

    if (ret == 0 && bytes_written > 0) {
        /* 先去重：检查当前行挂载点是否与上一行相同 */
        if (is_dup_mount_path(temp_buf, saved_buf, saved_count, true)) {
            seq->count = saved_count;
            kfree(temp_buf);
            return ret;
        }
        bool hide = false;
        int i;
        for (i = 0; i < minfo_nr_pats; i++) {
            if (strstr(temp_buf, minfo_pats[i]) != NULL) {
                hide = true;
                break;
            }
        }
        if (hide) {
            seq->count = saved_count;
        } else {
            if (saved_count + bytes_written <= saved_size) {
                memcpy(saved_buf + saved_count, temp_buf, bytes_written);
                seq->count = saved_count + bytes_written;
            } else {
                seq->count = 0;
                ret = -ENOSPC;
            }
        }
    } else {
        seq->count = saved_count;
    }

    kfree(temp_buf);
    return ret;
}/* ---------- seq_read_iter 钩子：临时替换 show ---------- */
/**
 * struct read_iter_hook_data - 每次 seq_read_iter 钩子的上下文
 * @file:        当前被读取的文件结构体
 * @seq:         文件的 seq_file 私有数据
 * @old_ops:     原始的 seq_operations，需要在读完后恢复
 * @new_ops:     新分配的 seq_operations，替换后的 show 函数
 * @is_mountinfo: true=mountinfo 文件，false=mounts 文件
 * @show_replaced: 标记本次调用中是否已替换 show，用于决定 ret 中是否恢复
 */
struct read_iter_hook_data {
    struct file *file;
    struct seq_file *seq;
    const struct seq_operations *old_ops;
    struct seq_operations *new_ops;
    bool is_mountinfo;
    bool show_replaced;
};
/**
 * hook_seq_read_iter_entry - kretprobe 入口处理函数
 * @ri:   kretprobe 实例
 * @regs: 函数调用时的寄存器快照
 *
 * 在 seq_read_iter 执行前被调用。
 * 检查本次读取是否为 mounts 或 mountinfo，若是则：
 * 1. 备份当前的 seq_operations。
 * 2. 分配新的 seq_operations，根据文件类型替换 show 为对应的过滤版本。
 * 3. 让 seq_file 的 op 指向新 ops。
 * 这样后续调用 show 时将直接执行我们的过滤版本。
 */
static int hook_seq_read_iter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_hook_data *data = (struct read_iter_hook_data *)ri->data;
    struct kiocb *iocb = (struct kiocb *)regs_get_kernel_argument(regs, 0);
    struct file *file   = iocb->ki_filp;
    struct seq_file *seq;
    const char *fname;

    data->file          = file;
    data->is_mountinfo  = false;
    data->show_replaced = false;

    if (!file)
        return 0;

    seq = file->private_data;
    data->seq = seq;
    if (!seq || !seq->op || !file->f_path.dentry)
        return 0;

    /* 只拦截 mounts 或 mountinfo 文件 */
    fname = file->f_path.dentry->d_name.name;
    if (strcmp(fname, "mounts") == 0) {
        data->is_mountinfo = false;
    } else if (strcmp(fname, "mountinfo") == 0) {
        data->is_mountinfo = true;
    } else {
        return 0;
    }

    /* 如果已经被替换，做防御检查 */
    if (seq->op->show == filtered_mounts_show ||
        seq->op->show == filtered_mountinfo_show)
        return 0;

    /* 备份当前 ops，创建新 ops 并替换 show */
    data->old_ops = seq->op;
    data->new_ops = kmalloc(sizeof(*(data->new_ops)), GFP_KERNEL);
    if (!data->new_ops)
        return 0;

    /* 拷贝整个 ops 结构，根据文件类型替换对应的 show */
    memcpy(data->new_ops, data->old_ops, sizeof(*(data->new_ops)));
    if (data->is_mountinfo) {
        original_mountinfo_show = data->old_ops->show;
        data->new_ops->show = filtered_mountinfo_show;
        printk(KERN_INFO "hm: replaced show for mountinfo (seq=%p)\n", seq);
    } else {
        original_mounts_show = data->old_ops->show;
        data->new_ops->show = filtered_mounts_show;
        printk(KERN_INFO "hm: replaced show for mounts (seq=%p)\n", seq);
    }
    seq->op = data->new_ops;

    data->show_replaced = true;

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
static int __init hide_mounts_init(void)
{
    int ret;
    char *p, *buf = NULL;
/* ---- 解析 mounts 模式串 ---- */
    mounts_pats[0] = "KSU ";
    mounts_nr_pats = 1;

    if (mounts_extra[0] != '\0') {
        buf = kstrndup(mounts_extra, sizeof(mounts_extra) - 1, GFP_KERNEL);
        if (buf) {
            while ((p = strsep(&buf, ",")) != NULL && mounts_nr_pats < MAX_PATTERNS) {
                if (*p == '\0')
                    continue;
                if (strlen(p) > PATTERN_LEN_MAX)
                    continue;
                mounts_pats[mounts_nr_pats] = kstrdup(p, GFP_KERNEL);
                if (mounts_pats[mounts_nr_pats])
                    mounts_nr_pats++;
            }
            kfree(buf);
        }
    }

    /* ---- 解析 mountinfo 模式串 ---- */
    minfo_pats[0] = " KSU ";
    minfo_nr_pats = 1;

    if (minfo_extra[0] != '\0') {
        buf = kstrndup(minfo_extra, sizeof(minfo_extra) - 1, GFP_KERNEL);
        if (buf) {
            while ((p = strsep(&buf, ",")) != NULL && minfo_nr_pats < MAX_PATTERNS) {
                if (*p == '\0')
                    continue;
                if (strlen(p) > PATTERN_LEN_MAX)
                    continue;
                minfo_pats[minfo_nr_pats] = kstrdup(p, GFP_KERNEL);
                if (minfo_pats[minfo_nr_pats])
                    minfo_nr_pats++;
            }
            kfree(buf);
        }
    }

    /* ---- 注册 kretprobe ---- */
    ret = register_kretprobe(&kretp_seq_read_iter);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: failed to register seq_read_iter kretprobe, error %d\n", ret);
        goto err_free_pats;
    }

    printk(KERN_INFO "hide_mounts: loaded (%d mounts, %d mountinfo patterns)\n",
           mounts_nr_pats, minfo_nr_pats);
    return 0;

err_free_pats: {
        int __i;
        for (__i = 1; __i < mounts_nr_pats; __i++)
            kfree(mounts_pats[__i]);
        for (__i = 1; __i < minfo_nr_pats; __i++)
            kfree(minfo_pats[__i]);
        mounts_nr_pats = 0;
        minfo_nr_pats = 0;
        return ret;
    }
}

static void __exit hide_mounts_exit(void)
{
    int i;

    unregister_kretprobe(&kretp_seq_read_iter);

    for (i = 1; i < mounts_nr_pats; i++)
        kfree(mounts_pats[i]);
    mounts_nr_pats = 0;

    for (i = 1; i < minfo_nr_pats; i++)
        kfree(minfo_pats[i]);
    minfo_nr_pats = 0;

    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);