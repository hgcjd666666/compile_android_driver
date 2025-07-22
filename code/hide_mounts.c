/* hide_mounts.c - Step 1: 骨架
 * 基于 proc_mounts_open + seq_release 的钩子
 * master 修正架构（Step 2 实现）
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide KSU mount traces via proc_mounts_open hook");
MODULE_AUTHOR("hgcjd666666");

/* ================ 全局符号指针 ================ */

static int (*proc_mounts_open_ptr)(struct inode *, struct file *) = NULL;
static int (*seq_release_ptr)(struct inode *, struct file *) = NULL;

/* ================ 缓存结构 ================ */

struct mount_cache {
    struct hlist_node node;
    struct seq_file *seq;
    struct file *file;
    atomic_t ref;
    atomic_t released;
};

#define CACHE_HASH_BITS 4
#define CACHE_HASH_SIZE (1 << CACHE_HASH_BITS)

static struct hlist_head cache_table[CACHE_HASH_SIZE];
static DEFINE_SPINLOCK(cache_lock);

static struct mount_cache *cache_alloc(struct seq_file *seq, struct file *file)
{
    struct mount_cache *c = kzalloc(sizeof(*c), GFP_KERNEL);
    if (!c) return NULL;
    c->seq = seq;
    c->file = file;
    atomic_set(&c->ref, 1);
    atomic_set(&c->released, 0);
    return c;
}

static void cache_put(struct mount_cache *c)
{
    if (atomic_dec_and_test(&c->ref))
        kfree(c);
}

static inline int cache_hash(struct seq_file *seq)
{
    return ((unsigned long)seq >> 4) & (CACHE_HASH_SIZE - 1);
}

static struct mount_cache *cache_lookup(struct seq_file *seq)
{
    struct mount_cache *c;
    int hash = cache_hash(seq);
    hlist_for_each_entry(c, &cache_table[hash], node) {
        if (c->seq == seq && !atomic_read(&c->released))
            return c;
    }
    return NULL;
}

static struct mount_cache *cache_ensure(struct seq_file *seq, struct file *file)
{
    struct mount_cache *c;
    unsigned long flags;
    spin_lock_bh(&cache_lock);
    c = cache_lookup(seq);
    if (!c) {
        c = cache_alloc(seq, file);
        if (c) {
            int hash = cache_hash(seq);
            hlist_add_head(&c->node, &cache_table[hash]);
        }
    }
    spin_unlock_bh(&cache_lock);
    return c;
}

static void cache_remove(struct seq_file *seq)
{
    struct mount_cache *c;
    unsigned long flags;
    spin_lock_bh(&cache_lock);
    c = cache_lookup(seq);
    if (c && !atomic_cmpxchg(&c->released, 0, 1)) {
        hlist_del(&c->node);
        spin_unlock_bh(&cache_lock);
        cache_put(c);
    } else {
        spin_unlock_bh(&cache_lock);
    }
}

/* ================ open 钩子 ================ */

struct open_hook_data {
    struct file *file;
};

static int open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_hook_data *d = (struct open_hook_data *)ri->data;
    d->file = (struct file *)regs_get_kernel_argument(regs, 1);
    return 0;
}

static int open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_hook_data *d = (struct open_hook_data *)ri->data;
    struct file *file = d->file;
    struct seq_file *seq;
    struct mount_cache *c;
    int ret = regs_return_value(regs);
    if (ret != 0 || !file || !file->private_data || !file->f_path.dentry)
        return 0;
    if (strcmp(file->f_path.dentry->d_name.name, "mountinfo") != 0)
        return 0;
    seq = file->private_data;
    if (!seq || !seq->op)
        return 0;
    c = cache_ensure(seq, file);
    if (c)
        try_module_get(THIS_MODULE);
    return 0;
}

/* ================ release 钩子 ================ */

struct release_hook_data {
    struct seq_file *seq;
};

static int release_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct release_hook_data *d = (struct release_hook_data *)ri->data;
    d->seq = NULL;
    struct file *file = (struct file *)regs_get_kernel_argument(regs, 1);
    if (file && file->private_data) {
        struct seq_file *s = file->private_data;
        d->seq = s;
        struct mount_cache *c;
        unsigned long flags;
        spin_lock_bh(&cache_lock);
        c = cache_lookup(s);
        if (c)
            atomic_set(&c->released, 1);
        spin_unlock_bh(&cache_lock);
    }
    return 0;
}

static int release_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct release_hook_data *d = (struct release_hook_data *)ri->data;
    struct seq_file *seq = d->seq;
    if (seq) {
        cache_remove(seq);
        module_put(THIS_MODULE);
    }
    return 0;
}

/* ================ 符号解析 ================ */

static int __init resolve_symbols(void)
{
    proc_mounts_open_ptr = (void *)kallsyms_lookup_name("proc_mounts_open");
    seq_release_ptr = (void *)kallsyms_lookup_name("seq_release");
    if (proc_mounts_open_ptr && seq_release_ptr)
        return 0;
    return -ENOENT;
}

/* ================ kretprobe 定义 ================ */

static struct kretprobe kp_open = {
    .entry_handler = open_entry,
    .handler       = open_ret,
    .data_size     = sizeof(struct open_hook_data),
    .maxactive     = 10,
};

static struct kretprobe kp_release = {
    .entry_handler = release_entry,
    .handler       = release_ret,
    .data_size     = sizeof(struct release_hook_data),
    .maxactive     = 10,
};

/* ================ 模块生命周期 ================ */

static int __init hide_mounts_init(void)
{
    int ret;
    ret = resolve_symbols();
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: symbol resolve failed\n");
        return ret;
    }
    kp_open.kp.symbol_name = "proc_mounts_open";
    ret = register_kretprobe(&kp_open);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register_kretprobe(proc_mounts_open) failed: %d\n", ret);
        return ret;
    }
    kp_release.kp.symbol_name = "seq_release";
    ret = register_kretprobe(&kp_release);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register_kretprobe(seq_release) failed: %d\n", ret);
        unregister_kretprobe(&kp_open);
        return ret;
    }
    printk(KERN_INFO "hide_mounts: loaded (Step 1 skeleton)\n");
    return 0;
}

static void __exit hide_mounts_exit(void)
{
    unregister_kretprobe(&kp_release);
    unregister_kretprobe(&kp_open);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);
