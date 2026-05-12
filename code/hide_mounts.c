#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_filtered = ATOMIC64_INIT(0);

/* 扫描并移除 buf 中所有以 "KSU " 开头的行 */
static void remove_ksu_lines(struct seq_file *m)
{
    char *buf = m->buf;
    char *src, *dst;
    size_t cnt = m->count;
    char *end = buf + cnt;

    src = buf;
    dst = buf;

    while (src < end) {
        char *nl = memchr(src, '\n', end - src);
        size_t len = nl ? (nl + 1 - src) : (end - src);

        if (len >= 4 && src[0] == 'K' && src[1] == 'S' && src[2] == 'U' && src[3] == ' ') {
            atomic64_inc(&nr_filtered);
        } else {
            if (dst != src)
                memmove(dst, src, len);
            dst += len;
        }
        src += len;
    }
    m->count = dst - buf;
}

struct write_data {
    struct seq_file *m;
    size_t old_count;
};

/* ── seq_read_iter 用于识别 mounts ── */
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

    m = (struct seq_file *)READ_ONCE(file->private_data);
    if (!m || !m->buf || m->count == 0)
        return 0;

    if (!mutex_trylock(&m->lock))
        return 0;

    remove_ksu_lines(m);

    mutex_unlock(&m->lock);
    return 0;
}

/* ── seq_puts / seq_vprintf 写入时直接拦截 ── */
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

    if (!m || m->count <= old || m->count > m->size)
        return 0;

    if (m->count - old >= 4 &&
        m->buf[old] == 'K' && m->buf[old+1] == 'S' && m->buf[old+2] == 'U' && m->buf[old+3] == ' ') {
        m->count = old;
        atomic64_inc(&nr_filtered);
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
    if (r < 0) printk(KERN_WARNING "hide_mounts: iter failed: %d\n", r);

    r = register_kretprobe(&rp_puts);
    if (r < 0) printk(KERN_WARNING "hide_mounts: puts failed: %d\n", r);

    r = register_kretprobe(&rp_vprintf);
    if (r < 0) {
        printk(KERN_WARNING "hide_mounts: vprintf failed: %d\n", r);
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
    printk(KERN_INFO "hide_mounts: unloaded, filtered=%lld\n",
           atomic64_read(&nr_filtered));
}

module_init(init_mod);
module_exit(exit_mod);
