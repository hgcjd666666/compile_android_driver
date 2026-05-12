// hide_mounts.c
// Hook seq_read_iter, replace show on the fly for /proc/self/mounts
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

/* ---------- 替换用的过滤 show ---------- */
static int (*original_mounts_show)(struct seq_file *m, void *v) = NULL;

static int my_show(struct seq_file *m, void *v)
{
    char *tmp_buf;
    size_t produced;
    char *orig_buf;
    size_t orig_size, orig_count;
    int ret;

    if (!original_mounts_show)
        return 0;

    tmp_buf = kmalloc(m->size, GFP_KERNEL);
    if (!tmp_buf)
        return original_mounts_show(m, v);

    orig_buf  = m->buf;
    orig_size = m->size;
    orig_count = m->count;

    m->buf   = tmp_buf;
    m->count = 0;

    ret = original_mounts_show(m, v);
    produced = m->count;

    m->buf   = orig_buf;
    m->size  = orig_size;

    if (ret == 0 && produced > 0) {
        if (produced >= 4 && memcmp(tmp_buf, "KSU ", 4) == 0) {
            m->count = orig_count;
        } else {
            if (orig_count + produced <= orig_size) {
                memcpy(orig_buf + orig_count, tmp_buf, produced);
                m->count = orig_count + produced;
            } else {
                m->count = 0;
                ret = -ENOSPC;
            }
        }
    } else {
        m->count = orig_count;
    }

    kfree(tmp_buf);
    return ret;
}

/* ---------- seq_read_iter 的 kretprobe ---------- */
struct read_iter_data {
    struct file *file;
    struct seq_file *m;
    const struct seq_operations *old_ops;
    struct seq_operations *new_ops;
    bool replaced;
};

static int seq_read_iter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_data *data = (struct read_iter_data *)ri->data;
    struct kiocb *iocb = (struct kiocb *)regs->regs[0];
    struct file *file = iocb->ki_filp;
    struct seq_file *m;

    data->file = file;
    data->replaced = false;

    if (!file)
        return 0;

    m = file->private_data;
    data->m = m;
    if (!m || !m->op || !file->f_path.dentry)
        return 0;

    if (strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    if (m->op->show == my_show)
        return 0;

    data->old_ops = m->op;
    data->new_ops = kmalloc(sizeof(*data->new_ops), GFP_KERNEL);
    if (!data->new_ops)
        return 0;

    memcpy(data->new_ops, data->old_ops, sizeof(*data->new_ops));
    original_mounts_show = data->old_ops->show;
    data->new_ops->show = my_show;
    m->op = data->new_ops;
    data->replaced = true;

    printk(KERN_DEBUG "hm: replaced show for mounts (%p)\n", m);
    return 0;
}

static int seq_read_iter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_iter_data *data = (struct read_iter_data *)ri->data;

    if (!data->replaced || !data->m)
        return 0;

    data->m->op = data->old_ops;
    kfree(data->new_ops);
    data->replaced = false;
    return 0;
}

static struct kretprobe rp_seq_read_iter = {
    .entry_handler = seq_read_iter_entry,
    .handler       = seq_read_iter_ret,
    .data_size     = sizeof(struct read_iter_data),
    .maxactive     = 64,
    .kp            = { .symbol_name = "seq_read_iter" },
};

/* ---------- 模块加载/卸载 ---------- */
static int __init hide_mounts_init(void)
{
    int ret;
    ret = register_kretprobe(&rp_seq_read_iter);
    if (ret < 0) {
        printk(KERN_ERR "hm: register seq_read_iter kretprobe failed %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "hide_mounts: loaded (seq_read_iter hook)\n");
    return 0;
}

static void __exit hide_mounts_exit(void)
{
    unregister_kretprobe(&rp_seq_read_iter);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);