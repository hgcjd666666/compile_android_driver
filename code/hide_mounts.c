#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);
static atomic64_t nr_calls = ATOMIC64_INIT(0);

static void remove_ksu_lines(struct seq_file *m)
{
    char *buf = m->buf;
    char *src, *dst;
    size_t cnt = m->count;
    char *end = buf + cnt;
    int n = 0;

    src = buf;
    dst = buf;

    while (src < end) {
        char *nl = memchr(src, '\n', end - src);
        size_t len = nl ? (nl + 1 - src) : (end - src);

        if (len >= 4 && src[0] == 'K' && src[1] == 'S' && src[2] == 'U' && src[3] == ' ') {
            n++;
        } else {
            if (dst != src) memmove(dst, src, len);
            dst += len;
        }
        src += len;
    }
    if (n) {
        m->count = dst - buf;
        atomic64_add(n, &nr_filtered);
        printk(KERN_INFO "hm: remove_ksu_lines: %d lines, count=%zu\n", n, m->count);
    }
}

struct write_data {
    struct seq_file *m;
    size_t old_count;
};

/* seq_read_iter */
static int iter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(struct kiocb **)ri->data = (struct kiocb *)regs->regs[0];
    return 0;
}

static int iter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kiocb *iocb = *(struct kiocb **)ri->data;
    struct file *file;
    struct seq_file *m;

    if (!iocb || !iocb->ki_filp || !iocb->ki_filp->f_path.dentry)
        return 0;

    file = iocb->ki_filp;
    if (strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    atomic64_inc(&nr_calls);

    m = (struct seq_file *)READ_ONCE(file->private_data);
    if (!m || !m->buf) {
        printk(KERN_INFO "hm: iter_ret: no buf\n");
        return 0;
    }
    printk(KERN_INFO "hm: iter_ret: count=%zu index=%lld size=%zu\n",
           m->count, m->index, m->size);

    if (m->count == 0)
        return 0;

    if (!mutex_trylock(&m->lock))
        return 0;

    remove_ksu_lines(m);

    mutex_unlock(&m->lock);
    return 0;
}

/* seq_puts / seq_vprintf */
static int wrt_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct write_data *d = (struct write_data *)ri->data;
    d->m = (struct seq_file *)regs->regs[0];
    d->old_count = d->m ? READ_ONCE(d->m->count) : 0;
    return 0;
}

static int wrt_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct write_data *d = (struct write_data *)ri->data;
    struct seq_file *m = d->m;
    size_t old = d->old_count;
    size_t wrote;

    if (!m || m->count <= old || m->count > m->size)
        return 0;

    wrote = m->count - old;

    if (wrote >= 4 &&
        m->buf[old] == 'K' && m->buf[old+1] == 'S' && m->buf[old+2] == 'U' && m->buf[old+3] == ' ') {
        m->count = old;
        atomic64_inc(&nr_filtered);
        printk(KERN_INFO "hm: blocked KSU line at %zu\n", old);
    } else if (wrote >= 3 &&
               m->buf[old] == 'K' && m->buf[old+1] == 'S' && m->buf[old+2] == 'U') {
        /* "KSU" without space - might be start of KSU field, log it */
        printk(KERN_INFO "hm: saw 'KSU' (no space) at %zu, wrote=%zu, '%.*s'\n",
               old, wrote, (int)min(wrote, (size_t)40), m->buf + old);
    }
    return 0;
}

static struct kretprobe rp_iter = {
    .kp.symbol_name = "seq_read_iter",
    .entry_handler = iter_entry,
    .handler = iter_ret,
    .data_size = sizeof(struct kiocb *),
    .maxactive = 64,
};

static struct kretprobe rp_puts = {
    .kp.symbol_name = "seq_puts",
    .entry_handler = wrt_entry,
    .handler = wrt_ret,
    .data_size = sizeof(struct write_data),
    .maxactive = 128,
};

static struct kretprobe rp_vprintf = {
    .kp.symbol_name = "seq_vprintf",
    .entry_handler = wrt_entry,
    .handler = wrt_ret,
    .data_size = sizeof(struct write_data),
    .maxactive = 128,
};

static int __init init_mod(void)
{
    int r;
    r = register_kretprobe(&rp_iter);
    if (r < 0) printk(KERN_WARNING "hm: iter failed: %d\n", r);
    r = register_kretprobe(&rp_puts);
    if (r < 0) printk(KERN_WARNING "hm: puts failed: %d\n", r);
    r = register_kretprobe(&rp_vprintf);
    if (r < 0) {
        printk(KERN_WARNING "hm: vprintf failed: %d\n", r);
        if (rp_puts.kp.addr)  unregister_kretprobe(&rp_puts);
        if (rp_iter.kp.addr)  unregister_kretprobe(&rp_iter);
        return r;
    }
    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    if (rp_vprintf.kp.addr) unregister_kretprobe(&rp_vprintf);
    if (rp_puts.kp.addr)    unregister_kretprobe(&rp_puts);
    if (rp_iter.kp.addr)    unregister_kretprobe(&rp_iter);
    printk(KERN_INFO "hide_mounts: unloaded, calls=%lld filtered=%lld\n",
           atomic64_read(&nr_calls), atomic64_read(&nr_filtered));
}

module_init(init_mod);
module_exit(exit_mod);
