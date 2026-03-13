/*
 * libart_bypass_lkm.c - LKM to intercept libart.so reads and return in-memory content.
 * Enhanced with path verification and inode tracking to prevent fake library detection.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Bypass libart.so integrity check with path verification");
MODULE_VERSION("2.0");

// ======================== 日志控制 ========================
#define ENABLE_DEBUG 0
#if ENABLE_DEBUG
    #define logv(fmt, ...) printk(KERN_INFO "[libart] " fmt, ##__VA_ARGS__)
#else
    #define logv(fmt, ...)
#endif

// ======================== 监控表 ========================
struct monitored_fd {
    int fd;
    pid_t pid;
    unsigned long ino;          // 文件的 inode 号
    dev_t dev;                   // 设备号
    unsigned long base;          // libart.so 在进程内存中的基址（0 表示未知）
    size_t size;                 // 模块大小（0 表示未知）
    struct list_head list;
};

static LIST_HEAD(monitored_fds);
static DEFINE_SPINLOCK(monitored_lock);

// 查找当前进程的监控项
static struct monitored_fd *find_my_monitored_fd(int fd)
{
    pid_t current_pid = current->tgid;
    struct monitored_fd *entry;

    spin_lock(&monitored_lock);
    list_for_each_entry(entry, &monitored_fds, list) {
        if (entry->pid == current_pid && entry->fd == fd) {
            spin_unlock(&monitored_lock);
            return entry;
        }
    }
    spin_unlock(&monitored_lock);
    return NULL;
}

// 添加监控项（需要文件对象以获取 inode 和设备号）
static void add_monitored_fd(int fd, struct file *filp)
{
    struct monitored_fd *m;
    pid_t current_pid = current->tgid;
    struct inode *inode = filp->f_inode;

    if (!inode)
        return;

    // 避免重复添加
    if (find_my_monitored_fd(fd))
        return;

    m = kmalloc(sizeof(*m), GFP_KERNEL);
    if (!m)
        return;

    m->fd = fd;
    m->pid = current_pid;
    m->ino = inode->i_ino;
    m->dev = inode->i_sb->s_dev;
    m->base = 0;
    m->size = 0;

    spin_lock(&monitored_lock);
    list_add(&m->list, &monitored_fds);
    spin_unlock(&monitored_lock);

    logv("monitoring libart.so: pid=%d, fd=%d, ino=%lu, dev=%u:%u\n",
         current_pid, fd, m->ino, MAJOR(m->dev), MINOR(m->dev));
}

// 移除监控项
static void del_monitored_fd(struct monitored_fd *m)
{
    if (!m)
        return;
    spin_lock(&monitored_lock);
    list_del(&m->list);
    spin_unlock(&monitored_lock);
    kfree(m);
}

// 检查文件是否为系统 libart.so（通过完整路径判断）
static bool is_system_libart(struct file *filp)
{
    char *path_buf;
    char *path;
    bool ret = false;

    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buf)
        return false;

    path = d_path(&filp->f_path, path_buf, PAGE_SIZE);
    if (!IS_ERR(path)) {
        // 检查路径是否以 /system/ 开头并包含 libart.so
        if (strstr(path, "/system/") && strstr(path, "libart.so"))
            ret = true;
        else
            logv("ignored non-system libart.so: %s\n", path);
    }

    free_page((unsigned long)path_buf);
    return ret;
}

// ======================== 获取当前进程中 libart.so 的基址和大小 ========================
static int get_libart_base(struct mm_struct *mm, unsigned long *base, size_t *size)
{
    struct vm_area_struct *vma;
    int ret = -ENOENT;

    if (!mm)
        return -EINVAL;

    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        struct file *vm_file = vma->vm_file;
        if (!vm_file)
            continue;
        // 通过 dentry 名称判断（内存中的映射名）
        struct dentry *dentry = vm_file->f_path.dentry;
        if (dentry && dentry->d_name.name &&
            strcmp(dentry->d_name.name, "libart.so") == 0) {
            *base = vma->vm_start;
            *size = vma->vm_end - vma->vm_start;
            ret = 0;
            break;
        }
    }
    up_read(&mm->mmap_lock);

    if (ret == 0)
        logv("found libart.so in pid %d: base=0x%lx, size=%zu\n", current->tgid, *base, *size);
    else
        logv("libart.so not found in pid %d\n", current->tgid);

    return ret;
}

// ======================== 系统调用 Hook 相关 ========================
static asmlinkage long (*orig_openat)(int dirfd, const char __user *filename, int flags, umode_t mode);
static asmlinkage long (*orig_read)(int fd, char __user *buf, size_t count);
static asmlinkage long (*orig_close)(int fd);

static unsigned long *sys_call_table = NULL;
static int (*set_memory_rw_fn)(unsigned long addr, int numpages) = NULL;

// openat hook
asmlinkage long hook_openat(int dirfd, const char __user *filename, int flags, umode_t mode)
{
    long ret = orig_openat(dirfd, filename, flags, mode);
    if (ret < 0)
        return ret;

    int fd = ret;
    char path[256];
    if (strncpy_from_user(path, filename, sizeof(path)) > 0) {
        path[sizeof(path)-1] = '\0';
        // 快速路径：如果路径包含 libart.so，进一步验证
        if (strstr(path, "libart.so")) {
            struct file *filp = fget(fd);
            if (filp) {
                if (is_system_libart(filp)) {
                    add_monitored_fd(fd, filp);
                }
                fput(filp);
            }
        }
    }
    return ret;
}

// read hook
asmlinkage long hook_read(int fd, char __user *ubuf, size_t count)
{
    struct monitored_fd *mfd = find_my_monitored_fd(fd);
    if (!mfd)
        return orig_read(fd, ubuf, count);

    struct file *filp = fget(fd);
    if (!filp) {
        del_monitored_fd(mfd);
        return orig_read(fd, ubuf, count);
    }

    // 验证文件是否仍然是当初监控的那个（通过 inode 和设备号）
    struct inode *inode = filp->f_inode;
    if (!inode || inode->i_ino != mfd->ino || inode->i_sb->s_dev != mfd->dev) {
        // 文件已被替换或 fd 重用，移除监控
        del_monitored_fd(mfd);
        fput(filp);
        return orig_read(fd, ubuf, count);
    }

    loff_t pos = vfs_llseek(filp, 0, SEEK_CUR);
    if (pos < 0) {
        fput(filp);
        return orig_read(fd, ubuf, count);
    }

    // 懒加载基址
    if (mfd->base == 0) {
        unsigned long base;
        size_t size;
        if (get_libart_base(current->mm, &base, &size) == 0) {
            mfd->base = base;
            mfd->size = size;
        } else {
            mfd->base = (unsigned long)-1; // 标记为不可用
        }
    }

    if (mfd->base == (unsigned long)-1) {
        fput(filp);
        return orig_read(fd, ubuf, count);
    }

    unsigned long mem_addr = mfd->base + pos;
    size_t to_read = count;
    if (mfd->size > 0 && pos + to_read > mfd->size)
        to_read = mfd->size - pos;

    if (to_read == 0) {
        fput(filp);
        return 0;
    }

    char *kbuf = kmalloc(to_read, GFP_KERNEL);
    if (!kbuf) {
        fput(filp);
        return orig_read(fd, ubuf, count);
    }

    if (copy_from_user(kbuf, (void __user *)mem_addr, to_read)) {
        kfree(kbuf);
        fput(filp);
        return orig_read(fd, ubuf, count);
    }

    if (copy_to_user(ubuf, kbuf, to_read)) {
        kfree(kbuf);
        fput(filp);
        return -EFAULT;
    }

    vfs_llseek(filp, pos + to_read, SEEK_SET);

    kfree(kbuf);
    fput(filp);
    return to_read;
}

// close hook
asmlinkage long hook_close(int fd)
{
    struct monitored_fd *mfd = find_my_monitored_fd(fd);
    if (mfd)
        del_monitored_fd(mfd);
    return orig_close(fd);
}

// ======================== 模块初始化与退出 ========================
static int __init libart_bypass_init(void)
{
    printk(KERN_INFO "libart bypass LKM loading (v2 with path verification)...\n");

    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "libart: failed to find sys_call_table\n");
        return -ENOENT;
    }

    set_memory_rw_fn = (void *)kallsyms_lookup_name("set_memory_rw");
    if (!set_memory_rw_fn)
        printk(KERN_WARNING "libart: set_memory_rw not found, assuming writable\n");

    orig_openat = (void *)sys_call_table[__NR_openat];
    orig_read = (void *)sys_call_table[__NR_read];
    orig_close = (void *)sys_call_table[__NR_close];

    if (set_memory_rw_fn)
        set_memory_rw_fn((unsigned long)sys_call_table, 1);

    sys_call_table[__NR_openat] = (unsigned long)hook_openat;
    sys_call_table[__NR_read] = (unsigned long)hook_read;
    sys_call_table[__NR_close] = (unsigned long)hook_close;

    printk(KERN_INFO "libart bypass LKM loaded successfully\n");
    return 0;
}

static void __exit libart_bypass_exit(void)
{
    if (sys_call_table) {
        if (set_memory_rw_fn)
            set_memory_rw_fn((unsigned long)sys_call_table, 1);
        sys_call_table[__NR_openat] = (unsigned long)orig_openat;
        sys_call_table[__NR_read] = (unsigned long)orig_read;
        sys_call_table[__NR_close] = (unsigned long)orig_close;
    }

    struct monitored_fd *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &monitored_fds, list) {
        del_monitored_fd(entry);
    }

    printk(KERN_INFO "libart bypass LKM unloaded\n");
}

module_init(libart_bypass_init);
module_exit(libart_bypass_exit);