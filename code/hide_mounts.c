#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);
static DEFINE_PER_CPU(bool, in_mounts_read);

struct probe_data {
    struct seq_file *m;
    size_t old_count;
};

/* ── seq_read_iter ── */
static int iter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kiocb *iocb = (struct kiocb *)regs->regs[0];
    struct file *file;

    if (!iocb || !iocb->ki_filp || !iocb->ki_filp->f_path.dentry)
        return 0;

    file = iocb->ki_filp;
    if (strcmp(file->f_path.dentry->d_name.name, "mounts") == 0)
        this_cpu_write(in_mounts_read, true);

    return 0;
}

static int iter_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (this_cpu_read(in_mounts_read))
        this_cpu_write(in_mounts_read, false);
    return 0;
}

static struct kretprobe rp_iter = {
    .kp.symbol_name = "seq_read_iter",
    .entry_handler = iter_entry,
    .handler = iter_exit,
    .maxactive = 64,
};

/* ── seq write helpers ── */
static int wr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (!this_cpu_read(in_mounts_read))
        return 0;

    struct probe_data *d = (struct probe_data *)ri->data;
    d->m = (struct seq_file *)regs->regs[0];
    d->old_count = d->m ? READ_ONCE(d->m->count) : 0;
    return 0;
}

static int wr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (!this_cpu_read(in_mounts_read))
        return 0;

    struct probe_data *d = (struct probe_data *)ri->data;
    struct seq_file *m = d->m;
    size_t old = d->old_count;
    char *p;
    size_t len;

    if (!m || m->count <= old || m->count > m->size)
        return 0;

    p = m->buf + old;
    len = m->count - old;

    if (len >= 4 && p[0] == 'K' && p[1] == 'S' && p[2] == 'U' && p[3] == ' ') {
        m->count = old;
        memset(p, 0, len);
        atomic64_inc(&nr_filtered);
    }

    return 0;
}

static struct kretprobe rp_puts = {
    .kp.symbol_name = "seq_puts",
    .entry_handler = wr_entry,
    .handler = wr_exit,
    .data_size = sizeof(struct probe_data),
    .maxactive = 128,
};

static struct kretprobe rp_vprintf = {
    .kp.symbol_name = "seq_vprintf",
    .entry_handler = wr_entry,
    .handler = wr_exit,
    .data_size = sizeof(struct probe_data),
    .maxactive = 128,
};

static int __init hide_init(void)
{
    int ret;

    ret = register_kretprobe(&rp_iter);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: seq_read_iter failed: %d\n", ret);
        return ret;
    }

    ret = register_kretprobe(&rp_puts);
    if (ret < 0)
        printk(KERN_WARNING "hide_mounts: seq_puts failed: %d\n", ret);

    ret = register_kretprobe(&rp_vprintf);
    if (ret < 0)
        printk(KERN_WARNING "hide_mounts: seq_vprintf failed: %d\n", ret);

    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit hide_exit(void)
{
    if (rp_vprintf.kp.addr) unregister_kretprobe(&rp_vprintf);
    if (rp_puts.kp.addr)    unregister_kretprobe(&rp_puts);
    if (rp_iter.kp.addr)    unregister_kretprobe(&rp_iter);
    printk(KERN_INFO "hide_mounts: unloaded, filtered=%lld\n",
           atomic64_read(&nr_filtered));
}

module_init(hide_init);
module_exit(hide_exit);
