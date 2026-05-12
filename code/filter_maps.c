#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;
static int orig_seq_read_return;

static int seq_read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct file *file;
    struct seq_file *m;
    loff_t *ppos;
    size_t copied;
    char *kbuf;
    size_t size;
    size_t new_size = 0;
    char *new_buf;
    char *line_start, *line_end;
    int i;

    file = (struct file *)regs->di;
    ppos = (loff_t *)regs->cx;
    copied = regs->ax;

    if (copied <= 0 || !file)
        return 0;

    if (strcmp(file->f_path.dentry->d_name.name, "maps") != 0)
        return 0;
    if (!file->f_path.dentry->d_parent ||
        strcmp(file->f_path.dentry->d_parent->d_name.name, "self") != 0)
        return 0;

    m = (struct seq_file *)file->private_data;
    if (!m || !m->buf)
        return 0;

    kbuf = m->buf;
    size = m->size;

    new_buf = kmalloc(size + 1, GFP_KERNEL);
    if (!new_buf)
        return 0;

    line_start = kbuf;
    while (line_start < kbuf + m->count) {
        line_end = strchr(line_start, '\n');
        if (!line_end)
            line_end = kbuf + m->count;
        else
            line_end++;

        if (!strstr(line_start, "KSU")) {
            memcpy(new_buf + new_size, line_start, line_end - line_start);
            new_size += (line_end - line_start);
        }
        line_start = line_end;
    }

    if (new_size < m->count) {
        memcpy(kbuf, new_buf, new_size);
        m->count = new_size;
        m->index = 0;
        *ppos = 0;
        regs->ax = new_size;
    }

    kfree(new_buf);
    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "seq_read",
    .handler = seq_read_ret_handler,
    .maxactive = 20,
};

static int __init filter_init(void)
{
    int ret;

    ret = register_kretprobe(&rp);
    if (ret < 0) {
        printk(KERN_ERR "filter_maps: failed to register kretprobe on seq_read\n");
        return ret;
    }
    printk(KERN_INFO "filter_maps: kretprobe registered, filtering 'KSU' lines in /proc/self/maps\n");
    return 0;
}

static void __exit filter_exit(void)
{
    unregister_kretprobe(&rp);
    printk(KERN_INFO "filter_maps: module unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
