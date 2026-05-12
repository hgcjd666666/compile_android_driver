#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

#if defined(__aarch64__)
#define REG_PARM0 regs[0]   /* file */
#define REG_PARM1 regs[1]   /* buf */
#define REG_PARM2 regs[2]   /* size */
#define REG_PARM3 regs[3]   /* ppos */
#define REG_RET   regs[0]   /* return value (copied) */
#else
#define REG_PARM0 di
#define REG_PARM1 si
#define REG_PARM2 dx
#define REG_PARM3 cx
#define REG_RET   ax
#endif

static int seq_read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct file *file;
    struct seq_file *m;
    loff_t *ppos;
    size_t copied;
    char *kbuf;
    size_t new_size = 0;
    char *new_buf;
    char *line_start, *line_end;

    file = (struct file *)regs->REG_PARM0;
    ppos = (loff_t *)regs->REG_PARM3;
    copied = regs->REG_RET;

    if (copied <= 0 || !file || !file->f_path.dentry)
        return 0;

    if (strcmp(file->f_path.dentry->d_name.name, "maps") != 0)
        return 0;

    m = (struct seq_file *)file->private_data;
    if (!m || !m->buf || m->count == 0)
        return 0;

    kbuf = m->buf;

    new_buf = kmalloc(m->size + 1, GFP_KERNEL);
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
        if (ppos)
            *ppos = 0;
        regs->REG_RET = new_size;
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
        printk(KERN_ERR "filter_maps: failed to register kretprobe on seq_read, ret=%d\n", ret);
        return ret;
    }
    printk(KERN_INFO "filter_maps: loaded, filtering 'KSU' lines in /proc/self/maps\n");
    return 0;
}

static void __exit filter_exit(void)
{
    unregister_kretprobe(&rp);
    printk(KERN_INFO "filter_maps: unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
