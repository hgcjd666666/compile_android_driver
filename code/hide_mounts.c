/* hide_mounts.c - Step 2: master 修正 */

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
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/namei.h>
#include <linux/err.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide KSU mount traces: master fix + hide");
MODULE_AUTHOR("hgcjd666666");

/* ====== 参数 ====== */

static char mounts_extra[256] = "";
module_param_string(mounts_extra, mounts_extra, sizeof(mounts_extra), 0);
static char minfo_extra[256] = "";
module_param_string(minfo_extra, minfo_extra, sizeof(minfo_extra), 0);

#define MAX_PATTERNS 16
#define PATTERN_LEN_MAX 64
static char *mounts_pats[MAX_PATTERNS];
static int mounts_nr_pats;
static char *minfo_pats[MAX_PATTERNS];
static int minfo_nr_pats;

/* ====== 挂载点分组表 ====== */

#define MAX_GROUPS 64
struct mount_group_rule {
    const char *path_prefix;
    int group_id;
};

static const struct mount_group_rule group_rules[] = {
    { "/data/",            1 },
    { "/data_mirror/",     1 },
    { "/mnt/pass_through/", 1 },
    { "/mnt/user/0",       2 },
    { "/storage/emulated", 2 },
    { "/mnt/installer/0",  2 },
    { "/mnt/androidwritable/0", 2 },
    { "/mnt/user/999",     3 },
    { "/storage/emulated/999", 3 },
    { "/mnt/installer/999", 3 },
    { "/mnt/androidwritable/999", 3 },
    { "/dev/blkio",        4 },
    { "/dev/cpuctl",       4 },
    { "/dev/cpuset",       4 },
    { "/dev/memcg",        4 },
    { "/apex/",            5 },
    { "/bootstrap-apex/",  5 },
    { "/sys/",             6 },
    { "/proc/",            7 },
    { NULL, 0 },
};

static int get_group_id(const char *path)
{
    int i;
    if (!path) return -1;
    for (i = 0; group_rules[i].path_prefix; i++) {
        if (strncmp(path, group_rules[i].path_prefix,
                    strlen(group_rules[i].path_prefix)) == 0)
            return group_rules[i].group_id;
    }
    return -1;
}

/* ====== 修正映射表 ====== */

struct master_map_entry {
    int original;
    int corrected;
};

#define MAP_MAX 128

struct master_map {
    struct master_map_entry entries[MAP_MAX];
    int count;
};

/* ====== 符号指针 ====== */

static int (*proc_mounts_open_ptr)(struct inode *, struct file *) = NULL;
static int (*seq_release_ptr)(struct inode *, struct file *) = NULL;
static char *(*dentry_path_ptr)(const struct dentry *, char *, int) = NULL;

/* ====== 缓存结构 ====== */

struct mount_cache {
    struct hlist_node node;
    struct seq_file *seq;
    struct file *file;
    atomic_t ref;
    atomic_t released;
    struct seq_operations *new_ops;
    const struct seq_operations *orig_ops;
    struct master_map map;
    atomic_t map_ready;
};

#define CACHE_HASH_BITS 4
#define CACHE_HASH_SIZE (1 << CACHE_HASH_BITS)

static struct hlist_head cache_table[CACHE_HASH_SIZE];
static DEFINE_SPINLOCK(cache_lock);

/* ====== 工具: 从挂载点路径获取 group master 统计 ====== */

struct group_stat {
    int master_counts[MAP_MAX];
    int master_values[MAP_MAX];
    int count;
};

static struct group_stat group_stats[MAX_GROUPS];
static bool groups_initialized = false;

static void init_group_stats(void)
{
    if (groups_initialized) return;
    memset(group_stats, 0, sizeof(group_stats));
    groups_initialized = true;
}

static void record_master(int group_id, int master)
{
    struct group_stat *gs;
    int i;
    if (group_id < 0 || group_id >= MAX_GROUPS) return;
    gs = &group_stats[group_id];
    for (i = 0; i < gs->count; i++) {
        if (gs->master_values[i] == master) {
            gs->master_counts[i]++;
            return;
        }
    }
    if (gs->count < MAP_MAX) {
        gs->master_values[gs->count] = master;
        gs->master_counts[gs->count] = 1;
        gs->count++;
    }
}

/* 找锚点: 出现 >= 2 次的 master */
static int find_anchor(int group_id)
{
    struct group_stat *gs;
    int i;
    if (group_id < 0 || group_id >= MAX_GROUPS) return -1;
    gs = &group_stats[group_id];
    for (i = 0; i < gs->count; i++) {
        if (gs->master_counts[i] >= 2)
            return gs->master_values[i];
    }
    return -1;
}

/* 查映射: original -> corrected */
static int lookup_master(struct master_map *map, int original)
{
    int i;
    for (i = 0; i < map->count; i++) {
        if (map->entries[i].original == original)
            return map->entries[i].corrected;
    }
    return original; /* 未映射则保留 */
}

static void add_mapping(struct master_map *map, int original, int corrected)
{
    if (map->count >= MAP_MAX) return;
    map->entries[map->count].original = original;
    map->entries[map->count].corrected = corrected;
    map->count++;
}

/* ====== 构建修正映射表 ====== */

static void ensure_map_built(struct mount_cache *c)
static void ensure_map_built(struct mount_cache *c)
{
    if (atomic_read(&c->map_ready))
        return;
    if (!atomic_cmpxchg(&c->map_ready, 0, -1)) {
        struct rw_semaphore *ns_sem;
        struct mnt_namespace *ns;
        struct mount *mnt;
        struct list_head *p;
        int gid, anchor;
        int master;
        char path_buf[256];

        ns_sem = (void *)kallsyms_lookup_name("namespace_sem");
        if (!ns_sem || !dentry_path_ptr)
            goto done;

        ns = current->nsproxy->mnt_ns;
        if (!ns) goto done;

        init_group_stats();

        down_read(ns_sem);
        list_for_each(p, &ns->list) {
            char *path;
            mnt = list_entry(p, struct mount, mnt_list);

            path = dentry_path_ptr(mnt->mnt_mountpoint, path_buf, sizeof(path_buf));
            if (IS_ERR_OR_NULL(path))
                continue;

            gid = get_group_id(path);
            if (gid < 0)
                continue;

            /* 只关心 slave mount 的 master 值 */
            if (!IS_MNT_SLAVE(mnt))
                continue;

            master = mnt->mnt_master->mnt_group_id;
            if (master > 0)
                record_master(gid, master);
        }
        up_read(ns_sem);

        c->map.count = 0;
        for (gid = 0; gid < MAX_GROUPS; gid++) {
            anchor = find_anchor(gid);
            if (anchor > 0) {
                struct group_stat *gs = &group_stats[gid];
                int i;
                for (i = 0; i < gs->count; i++) {
                    if (gs->master_values[i] != anchor)
                        add_mapping(&c->map, gs->master_values[i], anchor);
                }
            }
        }

done:
        atomic_set(&c->map_ready, 1);
    } else {
        while (atomic_read(&c->map_ready) == -1)
            cpu_relax();
    }
}

/* ====== 缓存操作 ====== */

static struct mount_cache *cache_alloc(struct seq_file *seq, struct file *file)
{
    struct mount_cache *c = kzalloc(sizeof(*c), GFP_KERNEL);
    if (!c) return NULL;
    c->seq = seq;
    c->file = file;
    atomic_set(&c->ref, 1);
    atomic_set(&c->released, 0);
    atomic_set(&c->map_ready, 0);
    return c;
}

static void cache_free(struct mount_cache *c)
{
    if (c->new_ops) kfree(c->new_ops);
    kfree(c);
}

static void cache_put(struct mount_cache *c)
{
    if (atomic_dec_and_test(&c->ref))
        cache_free(c);
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

/* ====== show 函数替换 ====== */

static int (*orig_mounts_show)(struct seq_file *, void *);
static int (*orig_mountinfo_show)(struct seq_file *, void *);

/*
 * 修正 master 编号: 在行文本中查找 " master:NUM" 并替换
 */
static size_t fix_master_in_line(struct master_map *map, char *line, size_t len)
{
    const char prefix[] = " master:";
    char *p = line;
    int orig_master;
    int corrected;
    char *end;

    while ((p = strstr(p, prefix)) != NULL) {
        p += 8;
        orig_master = 0;
        end = p;
        while (*end >= '0' && *end <= '9') {
            orig_master = orig_master * 10 + (*end - '0');
            end++;
        }
        if (end == p) continue;
        corrected = lookup_master(map, orig_master);
        if (corrected != orig_master) {
            char buf[32];
            int newlen = snprintf(buf, sizeof(buf), "%d", corrected);
            int oldlen = end - p;
            if (newlen != oldlen)
                memmove(p + newlen, end, len - (end - line));
            memcpy(p, buf, newlen);
            len += (newlen - oldlen);
        }
    }
    return len;
}

/* 自定义 mountinfo show */
static int fixed_mountinfo_show(struct seq_file *seq, void *v)
{
    struct mount_cache *c;
    char *temp_buf;
    char *saved_buf;
    size_t saved_size, saved_count, bytes_written;
    int ret;

    c = cache_lookup(seq);
    if (!c || !c->orig_ops || !c->orig_ops->show) {
        /* 退化 */
        if (orig_mountinfo_show)
            return orig_mountinfo_show(seq, v);
        return 0;
    }

    /* 确保映射表已构建 */
    ensure_map_built(c);

    /* 临时缓冲区方案 (同旧版) */
    temp_buf = kmalloc(seq->size, GFP_KERNEL);
    if (!temp_buf) return c->orig_ops->show(seq, v);

    saved_buf = seq->buf;
    saved_size = seq->size;
    saved_count = seq->count;

    seq->buf = temp_buf;
    seq->count = 0;

    ret = c->orig_ops->show(seq, v);
    bytes_written = seq->count;

    seq->buf = saved_buf;
    seq->size = saved_size;

    if (ret == 0 && bytes_written > 0) {
        bool hide = false;
        int i;

        /* 隐藏匹配模式的行 */
        for (i = 0; i < minfo_nr_pats; i++) {
            if (strstr(temp_buf, minfo_pats[i])) {
                hide = true;
                break;
            }
        }

        if (!hide) {
            /* 修正 master 编号 */
            if (atomic_read(&c->map_ready) == 1)
                bytes_written = fix_master_in_line(&c->map, temp_buf, bytes_written);

            if (saved_count + bytes_written <= saved_size) {
                memcpy(saved_buf + saved_count, temp_buf, bytes_written);
                seq->count = saved_count + bytes_written;
            } else {
                seq->count = 0;
                ret = -ENOSPC;
            }
        }
        /* hide=true: 不追加，丢弃该行 */
    } else {
        seq->count = saved_count;
    }

    kfree(temp_buf);
    return ret;
}

/* 自定义 mounts show (同旧版) */
static int fixed_mounts_show(struct seq_file *seq, void *v)
{
    struct mount_cache *c;
    char *temp_buf;
    char *saved_buf;
    size_t saved_size, saved_count, bytes_written;
    int ret;

    c = cache_lookup(seq);
    if (!c || !c->orig_ops || !c->orig_ops->show)
        return orig_mounts_show ? orig_mounts_show(seq, v) : 0;

    temp_buf = kmalloc(seq->size, GFP_KERNEL);
    if (!temp_buf) return c->orig_ops->show(seq, v);

    saved_buf = seq->buf;
    saved_size = seq->size;
    saved_count = seq->count;

    seq->buf = temp_buf;
    seq->count = 0;

    ret = c->orig_ops->show(seq, v);
    bytes_written = seq->count;

    seq->buf = saved_buf;
    seq->size = saved_size;

    if (ret == 0 && bytes_written > 0) {
        bool hide = false;
        int i;

        for (i = 0; i < mounts_nr_pats; i++) {
            if (strstr(temp_buf, mounts_pats[i])) {
                hide = true;
                break;
            }
        }

        if (!hide) {
            if (saved_count + bytes_written <= saved_size) {
                memcpy(saved_buf + saved_count, temp_buf, bytes_written);
                seq->count = saved_count + bytes_written;
            } else {
                seq->count = 0;
                ret = -ENOSPC;
            }
        }
    } else {
        seq->count = saved_count;
    }

    kfree(temp_buf);
    return ret;
}

/* ====== open 钩子 ====== */

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
    int ret = regs_return_value(regs);

    if (ret != 0 || !file || !file->private_data || !file->f_path.dentry)
        return 0;

    /* 只处理 mountinfo 和 mounts */
    {
    const char *fname = file->f_path.dentry->d_name.name;
    bool is_mountinfo = (strcmp(fname, "mountinfo") == 0);
    bool is_mounts = (strcmp(fname, "mounts") == 0);
    if (!is_mountinfo && !is_mounts)
        return 0;
    }

    seq = file->private_data;
    if (!seq || !seq->op)
        return 0;

    {
    struct mount_cache *c = cache_ensure(seq, file);
    if (!c) return 0;

    try_module_get(THIS_MODULE);

    const char *fname = file->f_path.dentry->d_name.name;
    bool is_mountinfo = (strcmp(fname, "mountinfo") == 0);

    c->orig_ops = seq->op;

    {
    struct seq_operations *new_ops = kmalloc(sizeof(*new_ops), GFP_KERNEL);
    if (!new_ops) {
        module_put(THIS_MODULE);
        return 0;
    }

    memcpy(new_ops, seq->op, sizeof(*new_ops));

    if (is_mountinfo) {
        orig_mountinfo_show = seq->op->show;
        new_ops->show = fixed_mountinfo_show;
    } else {
        orig_mounts_show = seq->op->show;
        new_ops->show = fixed_mounts_show;
    }

    c->new_ops = new_ops;
    seq->op = new_ops;
    }
    }
    return 0;
}

/* ====== release 钩子 ====== */

struct release_hook_data {
    struct seq_file *seq;
};

static int release_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct release_hook_data *d = (struct release_hook_data *)ri->data;
    struct file *file = (struct file *)regs_get_kernel_argument(regs, 1);
    d->seq = NULL;
    if (file && file->private_data) {
        struct seq_file *s = file->private_data;
        d->seq = s;
        spin_lock_bh(&cache_lock);
        {
        struct mount_cache *c = cache_lookup(s);
        if (c) {
            atomic_set(&c->released, 1);
            if (c->orig_ops && c->seq && c->seq->op == c->new_ops)
                c->seq->op = c->orig_ops;
        }
        }
        spin_unlock_bh(&cache_lock);
    }
    return 0;
}

static int release_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct release_hook_data *d = (struct release_hook_data *)ri->data;
    struct seq_file *seq = d->seq;
    if (seq) {
        /* release_entry 已恢复 ops，此处只清理缓存 */
        cache_remove(seq);
        module_put(THIS_MODULE);
    }
    return 0;
}

/* ====== 符号解析 ====== */

static int __init resolve_symbols(void)
{
    proc_mounts_open_ptr = (void *)kallsyms_lookup_name("proc_mounts_open");
    seq_release_ptr = (void *)kallsyms_lookup_name("seq_release");
    dentry_path_ptr = (void *)kallsyms_lookup_name("__dentry_path");
    if (!dentry_path_ptr)
        dentry_path_ptr = (void *)kallsyms_lookup_name("dentry_path_raw");
    if (!dentry_path_ptr)
        dentry_path_ptr = (void *)kallsyms_lookup_name("dentry_path");
    if (proc_mounts_open_ptr && seq_release_ptr)
        return 0;
}

/* ====== kretprobe 定义 ====== */

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

/* ====== 模块生命周期 ====== */

static void __init parse_patterns(void)
{
    char *buf, *p;

    mounts_pats[0] = "KSU ";
    mounts_nr_pats = 1;
    if (mounts_extra[0]) {
        buf = kstrndup(mounts_extra, sizeof(mounts_extra) - 1, GFP_KERNEL);
        if (buf) {
            while ((p = strsep(&buf, ",")) && mounts_nr_pats < MAX_PATTERNS) {
                if (*p && strlen(p) <= PATTERN_LEN_MAX)
                    mounts_pats[mounts_nr_pats++] = kstrdup(p, GFP_KERNEL);
            }
            kfree(buf);
        }
    }

    minfo_pats[0] = " KSU ";
    minfo_nr_pats = 1;
    if (minfo_extra[0]) {
        buf = kstrndup(minfo_extra, sizeof(minfo_extra) - 1, GFP_KERNEL);
        if (buf) {
            while ((p = strsep(&buf, ",")) && minfo_nr_pats < MAX_PATTERNS) {
                if (*p && strlen(p) <= PATTERN_LEN_MAX)
                    minfo_pats[minfo_nr_pats++] = kstrdup(p, GFP_KERNEL);
            }
            kfree(buf);
        }
    }
}

static int __init hide_mounts_init(void)
{
    int ret;

    parse_patterns();

    ret = resolve_symbols();
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: symbol resolve failed\n");
        goto err_pats;
    }

    kp_open.kp.symbol_name = "proc_mounts_open";
    ret = register_kretprobe(&kp_open);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register proc_mounts_open failed: %d\n", ret);
        goto err_pats;
    }

    kp_release.kp.symbol_name = "seq_release";
    ret = register_kretprobe(&kp_release);
    if (ret < 0) {
        printk(KERN_ERR "hide_mounts: register seq_release failed: %d\n", ret);
        unregister_kretprobe(&kp_open);
        goto err_pats;
    }
	printk(KERN_INFO "hide_mounts: loaded (Step 2)\n");
");

err_pats: {
        int i;
        for (i = 1; i < mounts_nr_pats; i++) kfree(mounts_pats[i]);
        for (i = 1; i < minfo_nr_pats; i++) kfree(minfo_pats[i]);
        return ret;
    }
}

static void __exit hide_mounts_exit(void)
{
    int i;
    unregister_kretprobe(&kp_release);
    unregister_kretprobe(&kp_open);
    for (i = 1; i < mounts_nr_pats; i++) kfree(mounts_pats[i]);
    for (i = 1; i < minfo_nr_pats; i++) kfree(minfo_pats[i]);
    printk(KERN_INFO "hide_mounts: unloaded\n");
}

module_init(hide_mounts_init);
module_exit(hide_mounts_exit);
