#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);
static struct kretprobe rp_show;

struct show_data {
    struct seq_file *m;
    size_t old_count;
};

/* 用 kprobe 探测 show 函数地址 */
static unsigned long show_addr;
static int found;

static int probe_cb(struct kprobe *p, struct pt_regs *r)
{
    found = 1;
    return 0;
}

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
    struct kprobe kp;
    char *names[] = {"mounts_show", "show_mount", NULL};
    int i, ret;

    show_addr = 0;

    for (i = 0; names[i]; i++) {
        memset(&kp, 0, sizeof(kp));
        kp.symbol_name = names[i];
        kp.pre_handler = probe_cb;
        found = 0;

        ret = register_kprobe(&kp);
        if (ret == 0) {
            show_addr = (unsigned long)kp.addr;
            unregister_kprobe(&kp);
            printk(KERN_INFO "hm: found %s at 0x%lx\n", names[i], show_addr);
            break;
        }
    }

    if (!show_addr) {
        printk(KERN_ERR "hm: no show function found\n");
        return -ENOENT;
    }

    memset(&rp_show, 0, sizeof(rp_show));
    rp_show.kp.addr = (kprobe_opcode_t *)show_addr;
    rp_show.entry_handler = show_entry;
    rp_show.handler = show_ret;
    rp_show.data_size = sizeof(struct show_data);
    rp_show.maxactive = 64;

    ret = register_kretprobe(&rp_show);
    if (ret < 0) {
        printk(KERN_ERR "hm: kretprobe failed: %d\n", ret);
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
