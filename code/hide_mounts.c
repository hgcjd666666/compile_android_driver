#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");

static atomic64_t nr_calls = ATOMIC64_INIT(0);
static atomic64_t nr_mounts = ATOMIC64_INIT(0);
static atomic64_t nr_filtered = ATOMIC64_INIT(0);

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(struct kiocb **)ri->data = (struct kiocb *)regs->regs[0];
    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kiocb *iocb = *(struct kiocb **)ri->data;
    struct file *file;
    struct seq_file *m;
    ssize_t copied = (ssize_t)regs->regs[0];
    char *buf, *src, *dst;
    int filtered;
    const unsigned char *name;

    atomic64_inc(&nr_calls);

    if (copied <= 0 || !iocb)
        return 0;

    file = iocb->ki_filp;
    if (!file || !file->f_path.dentry)
        return 0;

    name = file->f_path.dentry->d_name.name;
    printk(KERN_INFO "hide_mounts: seq_read_iter called, file=%s\n", name);

    if (strcmp(name, "mounts") != 0)
        return 0;

    atomic64_inc(&nr_mounts);

    m = (struct seq_file *)READ_ONCE(file->private_data);
    if (!m || !m->buf || m->count == 0 || m->count > m->size) {
        printk(KERN_INFO "hide_mounts: no buf (count=%zu size=%zu)\n",
               m ? m->count : 0, m ? m->size : 0);
        return 0;
    }

    if (!mutex_trylock(&m->lock))
        return 0;

    buf = m->buf;
    filtered = 0;
    src = buf;
    dst = buf;

    while (src < buf + m->count) {
        char *nl = memchr(src, '\n', buf + m->count - src);
        size_t len;

        if (nl)
            len = nl + 1 - src;
        else
            len = buf + m->count - src;

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
        size_t new_count = dst - buf;
        m->count = new_count;
        m->index = 0;
        regs->regs[0] = new_count;
        atomic64_add(filtered, &nr_filtered);
    }

    mutex_unlock(&m->lock);

    printk(KERN_INFO "hide_mounts: mounts read, copied=%zd filtered=%d new_count=%zu\n",
           copied, filtered, filtered ? (size_t)(dst - buf) : m->count);
    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "seq_read_iter",
    .entry_handler = entry_handler,
    .handler = ret_handler,
    .data_size = sizeof(struct kiocb *),
    .maxactive = 64,
};

static int __init hide_init(void)
{
    int ret = register_kretprobe(&rp);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register_kretprobe failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "hide_mounts: loaded, probing seq_read_iter\n");
    return 0;
}

static void __exit hide_exit(void)
{
    unregister_kretprobe(&rp);
    printk(KERN_INFO "hide_mounts: unloaded: calls=%lld mounts=%lld filtered=%lld\n",
           atomic64_read(&nr_calls),
           atomic64_read(&nr_mounts),
           atomic64_read(&nr_filtered));
}

module_init(hide_init);
module_exit(hide_exit);
