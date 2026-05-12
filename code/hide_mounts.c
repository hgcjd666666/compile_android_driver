#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);

struct show_data {
    struct seq_file *m;
    size_t old_count;
};

static unsigned long (*klp)(const char *);

static int kls_cb(struct kprobe *p, struct pt_regs *r)
{
    klp = (void *)p->addr;
    return 0;
}

static struct kprobe kp_kls = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = kls_cb,
};

static struct kretprobe rp_show;

static int show_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_data *d = (struct show_data *)ri->data;
    d->m = (struct seq_file *)regs->regs[0];
    d->old_count = d->m ? READ_ONCE(d->m->count) : 0;
    return 0;
}

static int show_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_data *d = (struct show_data *)ri->data;
    struct seq_file *m = d->m;
    size_t old = d->old_count;

    if (!m || m->count <= old || m->count > m->size)
        return 0;

    if (m->count - old >= 4 &&
        m->buf[old] == 'K' && m->buf[old+1] == 'S' && m->buf[old+2] == 'U' && m->buf[old+3] == ' ') {
        m->count = old;
        atomic64_inc(&nr_filtered);
    }
    return 0;
}

static int __init init_mod(void)
{
    unsigned long addr;
    char *names[] = {"mounts_show", "show_mount", NULL};
    int i, ret;

    klp = NULL;
    ret = register_kprobe(&kp_kls);
    if (ret < 0 || !klp) {
        printk(KERN_ERR "hm: can't get kallsyms_lookup_name\n");
        return -ENOENT;
    }
    unregister_kprobe(&kp_kls);

    addr = 0;
    for (i = 0; names[i]; i++) {
        addr = klp(names[i]);
        if (addr) {
            printk(KERN_INFO "hm: found %s at 0x%lx\n", names[i], addr);
            break;
        }
    }

    if (!addr) {
        printk(KERN_ERR "hm: no show function found\n");
        return -ENOENT;
    }

    memset(&rp_show, 0, sizeof(rp_show));
    rp_show.kp.addr = (kprobe_opcode_t *)addr;
    rp_show.entry_handler = show_entry;
    rp_show.handler = show_ret;
    rp_show.data_size = sizeof(struct show_data);
    rp_show.maxactive = 64;

    ret = register_kretprobe(&rp_show);
    if (ret < 0) {
        printk(KERN_ERR "hm: show kretprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    if (rp_show.kp.addr)
        unregister_kretprobe(&rp_show);
    printk(KERN_INFO "hide_mounts: unloaded, filtered=%lld\n",
           atomic64_read(&nr_filtered));
}

module_init(init_mod);
module_exit(exit_mod);
