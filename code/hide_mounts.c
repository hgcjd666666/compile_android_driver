#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);

struct probe_data {
    struct seq_file *m;
    size_t old_count;
};

static int seq_write_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_data *d = (struct probe_data *)ri->data;
    d->m = (struct seq_file *)regs->regs[0];
    d->old_count = d->m ? READ_ONCE(d->m->count) : 0;
    return 0;
}

static int seq_write_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_data *d = (struct probe_data *)ri->data;
    struct seq_file *m = d->m;
    struct file *file;
    size_t old_count = d->old_count;
    char *p;
    size_t len;

    if (!m || m->count <= old_count)
        return 0;

    file = READ_ONCE(m->file);
    if (!file || !file->f_path.dentry)
        return 0;

    if (strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    p = m->buf + old_count;
    len = m->count - old_count;

    if (len >= 4 && p[0] == 'K' && p[1] == 'S' && p[2] == 'U' && p[3] == ' ') {
        m->count = old_count;
        memset(p, 0, len);
        atomic64_inc(&nr_filtered);
    }

    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "seq_write",
    .entry_handler = seq_write_entry,
    .handler = seq_write_ret,
    .data_size = sizeof(struct probe_data),
    .maxactive = 128,
};

static int __init hide_init(void)
{
    int ret = register_kretprobe(&rp);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit hide_exit(void)
{
    unregister_kretprobe(&rp);
    printk(KERN_INFO "hide_mounts: unloaded, filtered=%lld\n",
           atomic64_read(&nr_filtered));
}

module_init(hide_init);
module_exit(hide_exit);
