#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide KSU mounts from /proc/self/mounts");
MODULE_AUTHOR("hide_mounts");

/* ---------- 链表管理被劫持的 seq_file ---------- */
struct hijack_entry {
    struct list_head list;
    struct seq_file *m;
    struct seq_operations *new_ops;
    const struct seq_operations *old_ops;
};

static LIST_HEAD(hijack_list);
static DEFINE_SPINLOCK(hijack_lock);

/* ---------- 自定义过滤 show ---------- */
static int my_show(struct seq_file *m, void *v)
{
    struct hijack_entry *entry;
    const struct seq_operations *old_ops = NULL;
    char *tmp_buf;
    size_t produced;
    char *orig_buf;
    size_t orig_size, orig_count;
    int ret;

    /* 查找当前 m 对应的原始 show */
    spin_lock(&hijack_lock);
    list_for_each_entry(entry, &hijack_list, list) {
        if (entry->m == m) {
            old_ops = entry->old_ops;
            break;
        }
    }
    spin_unlock(&hijack_lock);
    if (!old_ops || !old_ops->show) {
        // 异常情况，直接返回空行
        return 0;
    }

    /* 分配临时缓冲区，大小与 m->size 一致 */
    tmp_buf = kmalloc(m->size, GFP_KERNEL);
    if (!tmp_buf) {
        // 内存不足，退回原始 show，不做过滤
        return old_ops->show(m, v);
    }

    /* 备份原缓冲区状态，并用临时缓冲区接管 */
    orig_buf  = m->buf;
    orig_size = m->size;
    orig_count = m->count;

    m->buf   = tmp_buf;
    m->count = 0;
    // m->size 保持不变 (临时缓冲区实际大小等于原 size)

    /* 调用原始 show，让输出落入临时缓冲区 */
    ret = old_ops->show(m, v);
    produced = m->count;   // 原始 show 实际写入的字节数

    /* 恢复原缓冲区 */
    m->buf   = orig_buf;
    m->size  = orig_size;

    if (ret == 0 && produced > 0) {
        // 检查是否以 "KSU " 开头
        if (produced >= 4 && memcmp(tmp_buf, "KSU ", 4) == 0) {
            // 是 KSU 行，直接丢弃，不写入原 buf
            m->count = orig_count;
        } else {
            // 正常行，追加入原 buf
            if (orig_count + produced <= orig_size) {
                memcpy(orig_buf + orig_count, tmp_buf, produced);
                m->count = orig_count + produced;
            } else {
                // 溢出保护：清空缓冲区，返回错误
                m->count = 0;
                ret = -ENOSPC;
            }
        }
    } else {
        // 原始 show 失败，恢复 count
        m->count = orig_count;
    }

    kfree(tmp_buf);
    return ret;
}

/* ---------- seq_open 的 kretprobe ---------- */
struct seq_open_data {
    struct file *file;
};

static int seq_open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_open_data *data = (struct seq_open_data *)ri->data;
    // ARM64 调用约定：x0 = file , x1 = ops
    data->file = (struct file *)regs->regs[0];
    return 0;
}

static int seq_open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_open_data *data = (struct seq_open_data *)ri->data;
    struct file *file = data->file;
    struct seq_file *m;
    int ret = (int)regs->regs[0]; // 返回值在 x0

    if (ret || !file)
        return 0;

    m = file->private_data;
    if (!m || !m->buf || !m->op)
        return 0;

    /* 确认是 /proc/self/mounts （或 /proc/<pid>/mounts） */
    if (!file->f_path.dentry ||
        strcmp(file->f_path.dentry->d_name.name, "mounts") != 0)
        return 0;

    /* 分配新的 seq_operations 副本 */
    struct seq_operations *new_ops = kmalloc(sizeof(*new_ops), GFP_KERNEL);
    if (!new_ops)
        return 0;

    memcpy(new_ops, m->op, sizeof(*new_ops));
    new_ops->show = my_show;

    /* 创建劫持记录 */
    struct hijack_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        kfree(new_ops);
        return 0;
    }

    entry->m = m;
    entry->new_ops = new_ops;
    entry->old_ops = m->op;

    m->op = new_ops;

    spin_lock(&hijack_lock);
    list_add(&entry->list, &hijack_list);
    spin_unlock(&hijack_lock);

    /* 增加模块引用计数，防止在有打开文件时卸载 */
    try_module_get(THIS_MODULE);

    printk(KERN_INFO "hm: hijacked mounts (%p)\n", m);
    return 0;
}

/* ---------- seq_release 的 kretprobe （用于恢复） ---------- */
struct seq_release_data {
    struct file *file;
    struct seq_file *m;
};

static int seq_release_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_release_data *data = (struct seq_release_data *)ri->data;
    // seq_release(struct inode *inode, struct file *file) -> x0=inode, x1=file
    struct file *file = (struct file *)regs->regs[1];
    data->file = file;
    data->m = (file) ? file->private_data : NULL;
    return 0;
}

static int seq_release_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_release_data *data = (struct seq_release_data *)ri->data;
    struct seq_file *m = data->m;
    struct hijack_entry *entry, *tmp;
    int found = 0;

    if (!m)
        return 0;

    spin_lock(&hijack_lock);
    list_for_each_entry_safe(entry, tmp, &hijack_list, list) {
        if (entry->m == m) {
            // 恢复原始 ops
            m->op = entry->old_ops;
            list_del(&entry->list);
            kfree(entry->new_ops);
            kfree(entry);
            found = 1;
            break;
        }
    }
    spin_unlock(&hijack_lock);

    if (found) {
        module_put(THIS_MODULE);
        printk(KERN_INFO "hm: restored seq_file (%p)\n", m);
    }
    return 0;
}

/* ---------- Kprobe 结构 ---------- */
static struct kretprobe rp_seq_open = {
    .entry_handler = seq_open_entry,
    .handler       = seq_open_ret,
    .data_size     = sizeof(struct seq_open_data),
    .maxactive     = 64,
    .kp            = { .symbol_name = "seq_open" },
};

static struct kretprobe rp_seq_release = {
    .entry_handler = seq_release_entry,
    .handler       = seq_release_ret,
    .data_size     = sizeof(struct seq_release_data),
    .maxactive     = 64,
    .kp            = { .symbol_name = "seq_release" },
};

/* ---------- 模块加载/卸载 ---------- */
static int __init hide_mounts_init(void)
{
    int ret;

    ret = register_kretprobe(&rp_seq_open);
    if (ret < 0) {
        printk(KERN_ERR "hm: register seq_open kretprobe failed %d\n", ret);
        return ret;
    }

    ret = register_kretprobe(&rp_seq_release);
    if (ret < 0) {
        unregister_kretprobe(&rp_seq_open);
        printk(KERN_ERR "hm: register seq_release kretprobe failed %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "hide_mounts: loaded (seq ops hijack)\n");
    return 0;
}

static void __exit hide_mounts_exit(void)
{
    unregister_kretprobe(&rp_seq_release);
    unregister_kretprobe(&rp_seq_open);

    /* 正常情况下链表应为空（所有文件已关闭），若还有残留，强制清理 */
    struct hijack_entry *entry, *tmp;
    spin_lock(&hijack_lock);
    list_for_each_entry_safe(entry, tmp, &hijack_list, list) {
        // 恢复 op 以防悬空指针
        entry->m->op = entry->old_ops;
        list_del(&entry->list);
        kfree(entry->new_ops);
        kfree(entry);
        module_put(THIS_MODULE);  // 对应残留引用
        printk(KERN_WARNING "hm: force restored seq_file (%p) at unload\n", entry->m);
    }
    spin_unlock(&hijack_lock);

    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);