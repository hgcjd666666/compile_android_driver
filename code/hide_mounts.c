#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");

struct puts_data {
    struct seq_file *m;
    size_t old_count;
};

static atomic64_t nr_filtered = ATOMIC64_INIT(0);

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct puts_data *d = (struct puts_data *)ri->data;
    d->m = (struct seq_file *)regs->regs[0];
    d->old_count = d->m ? READ_ONCE(d->m->count) : 0;
    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct puts_data *d = (struct puts_data *)ri->data;
    struct seq_file *m = d->m;
    size_t old = d->old_count;
    char *p;

    if (!m || m->count <= old || m->count > m->size)
        return 0;

    if (m->count - old >= 4) {
        p = m->buf + old;
        if (p[0] == 'K' && p[1] == 'S' && p[2] == 'U' && p[3] == ' ') {
            m->count = old;
            atomic64_inc(&nr_filtered);
        }
    }
    return 0;
}

static struct kretprobe rp_puts = {
    .kp.symbol_name = "seq_puts",
    .entry_handler = entry_handler,
    .handler = ret_handler,
    .data_size = sizeof(struct puts_data),
    .maxactive = 128,
};

static struct kretprobe rp_vprintf = {
    .kp.symbol_name = "seq_vprintf",
    .entry_handler = entry_handler,
    .handler = ret_handler,
    .data_size = sizeof(struct puts_data),
    .maxactive = 128,
};

static int __init init_mod(void)
{
    int r;

    r = register_kretprobe(&rp_puts);
    if (r < 0) printk(KERN_WARNING "hide_mounts: seq_puts failed: %d\n", r);

    r = register_kretprobe(&rp_vprintf);
    if (r < 0) {
        printk(KERN_WARNING "hide_mounts: seq_vprintf failed: %d\n", r);
        if (rp_puts.kp.addr) unregister_kretprobe(&rp_puts);
        return r;
    }

    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    if (rp_vprintf.kp.addr) unregister_kretprobe(&rp_vprintf);
    if (rp_puts.kp.addr)    unregister_kretprobe(&rp_puts);
    printk(KERN_INFO "hide_mounts: unloaded, filtered=%lld\n",
           atomic64_read(&nr_filtered));
}

module_init(init_mod);
module_exit(exit_mod);
