#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("filter");
MODULE_DESCRIPTION("Filter KSU lines in /proc/*/maps via kretprobe");

#define DEBUG_LOG(fmt, ...) printk(KERN_INFO "filter_maps: " fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) printk(KERN_ERR "filter_maps: " fmt, ##__VA_ARGS__)

#if defined(__aarch64__)
#define REG_PARM0 regs[0]
#define REG_PARM1 regs[1]
#define REG_PARM2 regs[2]
#define REG_PARM3 regs[3]
#define REG_RET   regs[0]
#else
#define REG_PARM0 di
#define REG_PARM1 si
#define REG_PARM2 dx
#define REG_PARM3 cx
#define REG_RET   ax
#endif

static atomic_t nr_ksu_filtered = ATOMIC_INIT(0);
static atomic_t nr_calls = ATOMIC_INIT(0);
static atomic_t nr_hit = ATOMIC_INIT(0);

static bool contains_ksu(const char *buf, size_t len)
{
    size_t i;
    if (!buf || len < 3) return false;
    if (len > 4096) len = 4096;
    for (i = 0; i < len - 2; i++)
        if (buf[i] == 'K' && buf[i+1] == 'S' && buf[i+2] == 'U')
            return true;
    return false;
}

static int seq_read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct file *file;
    ssize_t copied;
    const unsigned char *fname;
    char __user *ubuf;
    size_t usize;
    char *kbuf;
    char *line_start, *line_end;
    size_t new_size;
    int filter_count;
    struct kprobe *kp;

    atomic_inc(&nr_calls);

    file = (struct file *)regs->REG_PARM0;
    ubuf = (char __user *)regs->REG_PARM1;
    usize = (size_t)regs->REG_PARM2;
    copied = (ssize_t)regs->REG_RET;

    if (copied <= 0 || !file || !file->f_path.dentry)
        return 0;

    fname = file->f_path.dentry->d_name.name;
    if (!fname || strcmp(fname, "maps") != 0)
        return 0;

    if (!ubuf || usize == 0)
        return 0;

    if (copied > usize)
        copied = usize;

    atomic_inc(&nr_hit);

    kbuf = kmalloc(copied + 1, GFP_KERNEL);
    if (!kbuf)
        return 0;

    if (copy_from_user(kbuf, ubuf, copied)) {
        kfree(kbuf);
        return 0;
    }
    kbuf[copied] = '\0';

    if (!contains_ksu(kbuf, copied)) {
        kfree(kbuf);
        return 0;
    }

    {
        char *new_buf;
        new_buf = kmalloc(copied + 1, GFP_KERNEL);
        if (!new_buf) {
            kfree(kbuf);
            return 0;
        }

        new_size = 0;
        filter_count = 0;
        line_start = kbuf;

        while (line_start < kbuf + copied) {
            size_t remain = kbuf + copied - line_start;
            line_end = memchr(line_start, '\n', remain);
            if (!line_end)
                line_end = kbuf + copied;
            else
                line_end++;

            size_t line_len = line_end - line_start;
            if (line_len > (size_t)(copied + 1)) {
                kfree(new_buf);
                kfree(kbuf);
                return 0;
            }

            if (!contains_ksu(line_start, line_len)) {
                memcpy(new_buf + new_size, line_start, line_len);
                new_size += line_len;
            } else {
                filter_count++;
            }
            line_start = line_end;
        }

        if (filter_count == 0) {
            kfree(new_buf);
            kfree(kbuf);
            return 0;
        }

        if (new_size > 0) {
            if (copy_to_user(ubuf, new_buf, new_size)) {
                kfree(new_buf);
                kfree(kbuf);
                return 0;
            }
            if (new_size < copied)
                clear_user(ubuf + new_size, copied - new_size);
        }

        regs->REG_RET = new_size;
        atomic_add(filter_count, &nr_ksu_filtered);

        DEBUG_LOG("hit: filtered %d lines, %zu->%zu bytes, total_filtered=%d\n",
                  filter_count, copied, new_size,
                  atomic_read(&nr_ksu_filtered));

        kfree(new_buf);
    }

    kfree(kbuf);
    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "seq_read",
    .handler = seq_read_ret_handler,
    .maxactive = 64,
};

static int __init filter_init(void)
{
    int ret;

    atomic_set(&nr_calls, 0);
    atomic_set(&nr_hit, 0);
    atomic_set(&nr_ksu_filtered, 0);

    ret = register_kretprobe(&rp);
    if (ret < 0) {
        ERROR_LOG("register_kretprobe on seq_read failed: %d\n", ret);

        rp.kp.symbol_name = "seq_read_iter";
        ret = register_kretprobe(&rp);
        if (ret < 0) {
            ERROR_LOG("register_kretprobe on seq_read_iter also failed: %d\n", ret);
            return ret;
        }
        DEBUG_LOG("loaded on seq_read_iter, addr=0x%px\n", rp.kp.addr);
        return 0;
    }

    DEBUG_LOG("loaded on seq_read, addr=0x%px\n", rp.kp.addr);
    return 0;
}

static void __exit filter_exit(void)
{
    unregister_kretprobe(&rp);
    DEBUG_LOG("unloaded: calls=%d hits=%d filtered=%d\n",
              atomic_read(&nr_calls),
              atomic_read(&nr_hit),
              atomic_read(&nr_ksu_filtered));
}

module_init(filter_init);
module_exit(filter_exit);
