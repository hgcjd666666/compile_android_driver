#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");

static int entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(struct kiocb **)ri->data = (struct kiocb *)regs->regs[0];
    return 0;
}

static int ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kiocb *iocb = *(struct kiocb **)ri->data;
    struct file *file;
    struct seq_file *m;
    char *buf, *src, *dst;
    size_t total;
    int filtered;

    if (!iocb || !iocb->ki_filp || !iocb->ki_filp->f_path.dentry)
        return 0;

    file = iocb->ki_filp;
    if (strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    m = (struct seq_file *)READ_ONCE(file->private_data);
    if (!m || !m->buf || m->size == 0)
        return 0;

    if (!mutex_trylock(&m->lock))
        return 0;

    total = m->index + m->count;
    if (total == 0 || total > m->size) {
        mutex_unlock(&m->lock);
        return 0;
    }

    buf = m->buf;
    filtered = 0;
    src = buf;
    dst = buf;

    while (src < buf + total) {
        size_t remain = buf + total - src;
        char *nl = memchr(src, '\n', remain);
        size_t len;

        if (nl)
            len = nl + 1 - src;
        else
            len = remain;

        if (len >= 4 && src[0] == 'K' && src[1] == 'S' && src[2] == 'U' && src[3] == ' ') {
            filtered++;
        } else {
            if (dst != src)
                memmove(dst, src, len);
            dst += len;
        }
        src += len;
    }

    if (filtered) {
        size_t new_cnt = dst - buf;
        m->count = new_cnt;
        m->index = 0;
        printk(KERN_INFO "hide_mounts: filtered %d lines\n", filtered);
    }

    mutex_unlock(&m->lock);
    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "seq_read_iter",
    .entry_handler = entry,
    .handler = ret,
    .data_size = sizeof(struct kiocb *),
    .maxactive = 64,
};

static int __init init_mod(void)
{
    int r = register_kretprobe(&rp);
    if (r < 0) return r;
    printk(KERN_INFO "hide_mounts: loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    unregister_kretprobe(&rp);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(init_mod);
module_exit(exit_mod);
