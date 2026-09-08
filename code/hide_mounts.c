// hide_mounts.c
//
// 内核模块：隐藏 /proc/self/mounts、/proc/self/mountinfo、/proc/self/mountstats
//           中用户指定的行。完全由 insmod 参数决定隐藏内容，不内置任何默认模式。
// 方法：kretprobe 劫持 seq_read_iter，读文件前临时替换 show 函数，逐行过滤。
//
// 参数语法（每个文件一个参数，互不干扰）：
//   - 参数内用 '|' 分隔多个匹配模式，命中任意一个即隐藏该行
//   - 模式以 '?' 开头：子串匹配（可出现在行中间，等价 strstr）
//   - 模式不以 '?' 开头：前缀匹配（须在行开头，等价 strncmp）
//   - 空模式、'?' 后无内容的模式会被忽略
//   未传对应参数（或全为空）则该文件不做任何过滤。
//
// 示例：
//   insmod hide_mounts.ko \
//       mounts="debugfs " \
//       mountinfo="? - debugfs debugfs rw,seclabel,mode=755" \
//       mountstats="device debugfs mounted on "
//
// 作者：hgcjd666666

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide user-specified mount lines from mounts/mountinfo/mountstats");
MODULE_AUTHOR("hgcjd666666");

/* ---------- 参数与模式解析 ---------- */

#define HIDE_PARAM_LEN   4096   /* 单个参数总长度上限 */
#define HIDE_MAX_PATTERNS 32    /* 每个文件允许的模式数量上限 */
#define HIDE_PATTERN_LEN 256    /* 单个模式长度上限 */

struct hide_pattern {
    char text[HIDE_PATTERN_LEN];
    bool substring;             /* true=子串匹配, false=前缀匹配 */
};

struct hide_file_rules {
    int count;
    struct hide_pattern pat[HIDE_MAX_PATTERNS];
};

/* 每个文件的模式串参数（不预设默认值，全靠 insmod 传入） */
static char param_mounts[HIDE_PARAM_LEN] __read_mostly;
static char param_mountinfo[HIDE_PARAM_LEN] __read_mostly;
static char param_mountstats[HIDE_PARAM_LEN] __read_mostly;
module_param_string(mounts, param_mounts, sizeof(param_mounts), 0);
module_param_string(mountinfo, param_mountinfo, sizeof(param_mountinfo), 0);
module_param_string(mountstats, param_mountstats, sizeof(param_mountstats), 0);

/* ---------- 文件类型枚举 ---------- */

enum mount_file_type {
    FILE_MOUNTS = 0,   /* /proc/self/mounts */
    FILE_MOUNTINFO,    /* /proc/self/mountinfo */
    FILE_MOUNTSTATS,   /* /proc/self/mountstats */
    FILE_COUNT,
};

/* 解析 '|' 分隔、'?' 前缀的模式串到结构化规则。不信任输入：逐项限长限数。 */
static void parse_rules(struct hide_file_rules *out, char *src)
{
    char *tok, *rest;
    struct hide_pattern *p;

    out->count = 0;
    if (!src || !src[0])
        return;

    rest = src;
    while ((tok = strsep(&rest, "|")) != NULL) {
        if (out->count >= HIDE_MAX_PATTERNS)
            break;                 /* 数量超限：忽略剩余 */
        if (tok[0] == '\0')
            continue;              /* 空项忽略 */

        p = &out->pat[out->count];
        p->substring = false;
        if (tok[0] == '?') {
            p->substring = true;
            tok++;
        }
        if (tok[0] == '\0')
            continue;              /* "?" 单独无意义 */

        strscpy(p->text, tok, sizeof(p->text));  /* 限长拷贝，天然加 NUL */
        out->count++;
    }
}

static struct hide_file_rules hide_rules[FILE_COUNT];
static char *const param_src[FILE_COUNT] = {
    [FILE_MOUNTS]     = param_mounts,
    [FILE_MOUNTINFO]  = param_mountinfo,
    [FILE_MOUNTSTATS] = param_mountstats,
};

/* 判定一行是否命中某文件的规则。line 必须以 NUL 结尾（由调用方保证）。 */
static bool line_is_hidden(int type, const char *line)
{
    struct hide_file_rules *rules = &hide_rules[type];
    struct hide_pattern *p;
    size_t len;
    int i;

    for (i = 0; i < rules->count; i++) {
        p = &rules->pat[i];
        len = strlen(p->text);
        if (p->substring) {
            if (strstr(line, p->text))
                return true;
        } else {
            if (strncmp(line, p->text, len) == 0)
                return true;
        }
    }
    return false;
}

/* ---------- 过滤层：替换后的 show 函数 ---------- */

/* 保存三个文件各自的原始 show 函数指针，由钩子入口处动态获取 */
static int (*original_show[FILE_COUNT])(struct seq_file *seq, void *v);

/**
 * filtered_show_common - 把原始 show 输出到临时缓冲区（多留 1 字节置 NUL），
 *                       命中规则则丢弃整行，否则追加到真实缓冲区
 */
static int filtered_show_common(struct seq_file *seq, void *v, int type)
{
    char *temp_buf;           // 临时缓冲区，额外 1 字节用于 NUL 结尾
    size_t bytes_written;
    char *saved_buf;
    size_t saved_size;
    size_t saved_count;
    int ret;

    if (!original_show[type])
        return 0;

    temp_buf = kmalloc(seq->size + 1, GFP_KERNEL);
    if (!temp_buf)
        return original_show[type](seq, v);

    saved_buf   = seq->buf;
    saved_size  = seq->size;
    saved_count = seq->count;

    seq->buf   = temp_buf;
    seq->size  = saved_size;      /* 保持原 size，避免 show 越过安全写入范围 */
    seq->count = 0;

    ret = original_show[type](seq, v);
    bytes_written = seq->count;

    /* 恢复原缓冲区 */
    seq->buf  = saved_buf;
    seq->size = saved_size;

    if (bytes_written <= seq->size)
        temp_buf[bytes_written] = '\0';   /* NUL 结尾，供规则匹配安全使用 */

    if (ret == 0 && bytes_written > 0 && line_is_hidden(type, temp_buf)) {
        seq->count = saved_count;         /* 命中：丢弃 */
    } else if (ret == 0 && bytes_written > 0) {
        if (saved_count + bytes_written <= saved_size) {
            memcpy(saved_buf + saved_count, temp_buf, bytes_written);
            seq->count = saved_count + bytes_written;
        } else {
            seq->count = 0;
            ret = -ENOSPC;
        }
    } else {
        seq->count = saved_count;
    }

    kfree(temp_buf);
    return ret;
}

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

static int (*const filtered_show[FILE_COUNT])(struct seq_file *, void *) = {
    [FILE_MOUNTS]     = filtered_mounts_show,
    [FILE_MOUNTINFO]  = filtered_mountinfo_show,
    [FILE_MOUNTSTATS] = filtered_mountstats_show,
};

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

struct read_iter_hook_data {
    struct file *file;
    struct seq_file *seq;
    const struct seq_operations *old_ops;
    struct seq_operations *new_ops;
    bool show_replaced;
};

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

    if (!file)
        return 0;

    seq = file->private_data;
    data->seq = seq;
    if (!seq || !seq->op || !file->f_path.dentry)
        return 0;

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

    /* 该文件没有任何规则：不替换 show */
    if (hide_rules[type].count == 0)
        return 0;
    if (is_filtered_show(seq->op->show))
        return 0;

    data->old_ops = seq->op;
    data->new_ops = kmalloc(sizeof(*(data->new_ops)), GFP_KERNEL);
    if (!data->new_ops)
        return 0;

    memcpy(data->new_ops, data->old_ops, sizeof(*(data->new_ops)));
    original_show[type] = data->old_ops->show;
    data->new_ops->show = filtered_show[type];
    seq->op = data->new_ops;
    data->show_replaced = true;

    return 0;
}

static int hook_seq_read_iter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_hook_data *data = (struct read_iter_hook_data *)ri->data;

    if (!data->show_replaced || !data->seq)
        return 0;

    data->seq->op = data->old_ops;
    kfree(data->new_ops);
    data->show_replaced = false;

    return 0;
}

static struct kretprobe kretp_seq_read_iter = {
    .entry_handler = hook_seq_read_iter_entry,
    .handler       = hook_seq_read_iter_ret,
    .data_size     = sizeof(struct read_iter_hook_data),
    .maxactive     = 0,
    .kp            = {
        .symbol_name = "seq_read_iter",
    },
};

/* ---------- 模块生命周期 ---------- */

/* 记录被摘除的模块节点，便于卸载前恢复，避免 rmmod 时内核 sysfs 清理 panic */
static struct kobject *saved_module_parent;
static const char *saved_module_name;
static bool module_node_hidden;

static int __init hide_mounts_init(void)
{
    int type, ret;

    for (type = 0; type < FILE_COUNT; type++)
        parse_rules(&hide_rules[type], param_src[type]);

    ret = register_kretprobe(&kretp_seq_read_iter);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: failed to register seq_read_iter kretprobe, error %d\n", ret);
        return ret;
    }

#ifdef MODULE
    /* 摘掉 /sys/module/hide_mounts 节点；记录父节点与名字，供卸载前恢复 */
    saved_module_parent = THIS_MODULE->mkobj.kobj.parent;
    saved_module_name   = THIS_MODULE->mkobj.kobj.name;
    kobject_del(&THIS_MODULE->mkobj.kobj);
    module_node_hidden = true;
#endif

    printk(KERN_INFO "hide_mounts: loaded (mounts=%d mountinfo=%d mountstats=%d rules)\n",
           hide_rules[FILE_MOUNTS].count, hide_rules[FILE_MOUNTINFO].count,
           hide_rules[FILE_MOUNTSTATS].count);
    return 0;
}

static void __exit hide_mounts_exit(void)
{
#ifdef MODULE
    if (module_node_hidden) {
        /* 恢复节点，让内核能正常清理该模块的 sysfs 状态（防止 rmmod panic） */
        if (kobject_add(&THIS_MODULE->mkobj.kobj, saved_module_parent,
                        saved_module_name) == 0)
            module_node_hidden = false;
        else
            printk(KERN_ERR "hide_mounts: failed to restore /sys/module node\n");
    }
#endif

    unregister_kretprobe(&kretp_seq_read_iter);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);
