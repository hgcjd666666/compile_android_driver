#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/uidgid.h>
#include <linux/miscdevice.h>
#include <asm/current.h>

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Hide specified files and directories from userspace (LKM)");
MODULE_AUTHOR("fshide-lkm");

#ifdef FSHIDE_DEBUG
#define LOG_TAG            "[fshide]"
#define DBG(fmt, ...)      pr_info(LOG_TAG" [DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...)      ((void)0)
#endif

#define MAX_HIDE_ENTRIES   128
#define MAX_PATH_LEN       512
#define MAX_UID_DIGITS     10
#define CONFIG_BUF_SIZE    2048
#define DIRENT64_BUF_SIZE  4096

struct linux_dirent64 {
	uint64_t        d_ino;
	int64_t         d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            d_name[];
};

struct hide_entry {
	char   path[MAX_PATH_LEN];
	uid_t  uid;
	uint8_t active;
	uint8_t has_uid;
};

static struct hide_entry hide_list[MAX_HIDE_ENTRIES];
static int hide_count;
static DEFINE_MUTEX(hide_lock);

static char config_path[MAX_PATH_LEN] = "/data/adb/fshide";
static int hide_from_root;

static int misc_registered;

static int find_path_locked(const char *path, uid_t uid, int has_uid)
{
	int i;
	if (!path || !*path || path[0] != '/') return -1;
	for (i = 0; i < hide_count; i++) {
		if (!hide_list[i].active) continue;
		if (strcmp(hide_list[i].path, path) != 0) continue;
		if (!has_uid && !hide_list[i].has_uid) return i;
		if (has_uid && hide_list[i].has_uid && hide_list[i].uid == uid) return i;
	}
	return -1;
}

static int add_path_with_uid_locked(const char *path, uid_t uid, int has_uid)
{
	if (!path || !*path || path[0] != '/') return -EINVAL;
	if (hide_count >= MAX_HIDE_ENTRIES) return -ENOSPC;
	if (find_path_locked(path, uid, has_uid) >= 0) return 0;
	strncpy(hide_list[hide_count].path, path, MAX_PATH_LEN - 1);
	hide_list[hide_count].path[MAX_PATH_LEN - 1] = '\0';
	hide_list[hide_count].active = 1;
	hide_list[hide_count].uid = uid;
	hide_list[hide_count].has_uid = has_uid ? 1 : 0;
	hide_count++;
	return 0;
}

static long parse_uid_str(const char *s, uid_t *out)
{
	long val = 0;
	int digits = 0;
	if (!s || !*s || *s < '0' || *s > '9') return -EINVAL;
	while (*s >= '0' && *s <= '9') {
		val = val * 10 + (*s++ - '0');
		digits++;
		if (digits > MAX_UID_DIGITS) return -ERANGE;
	}
	if (val < 0 || val > (long)(uid_t)-1) return -ERANGE;
	*out = (uid_t)val;
	return 0;
}

static void parse_config_line(const char *line)
{
	const char *p = line, *path_end, *uid_part;
	char path_buf[MAX_PATH_LEN];
	int plen;

	while (*p == ' ' || *p == '\t') p++;
	if (!*p || *p == '#' || *p == '\n' || *p == '\r') return;
	if (*p != '/') return;
	path_end = p;
	while (*path_end && *path_end != ' ' && *path_end != '\t' &&
	       *path_end != '\n' && *path_end != '\r') path_end++;
	plen = (int)(path_end - p);
	if (plen >= MAX_PATH_LEN) plen = MAX_PATH_LEN - 1;
	memcpy(path_buf, p, plen);
	path_buf[plen] = '\0';
	while (plen > 1 && path_buf[plen - 1] == '/') { path_buf[--plen] = '\0'; }
	uid_part = path_end;
	while (*uid_part == ' ' || *uid_part == '\t') uid_part++;

	mutex_lock(&hide_lock);
	if (!strncasecmp(uid_part, "uid:", 4)) {
		const char *up = uid_part + 4;
		while (*up) {
			uid_t uid;
			const char *uend = up;
			while (*uend && *uend != ',') uend++;
			if (parse_uid_str(up, &uid) >= 0)
				add_path_with_uid_locked(path_buf, uid, 1);
			up = (*uend == ',') ? uend + 1 : uend;
		}
	} else {
		add_path_with_uid_locked(path_buf, 0, 0);
	}
	mutex_unlock(&hide_lock);
}

static int load_config(void)
{
	struct file *fp;
	loff_t pos = 0;
	char *kbuf;
	ssize_t nread;
	const char *p;

	kbuf = kmalloc(CONFIG_BUF_SIZE, GFP_KERNEL);
	if (!kbuf) return -ENOMEM;
	memset(kbuf, 0, CONFIG_BUF_SIZE);

	fp = filp_open(config_path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		DBG("load_config: cannot open %s (err=%ld)", config_path, PTR_ERR(fp));
		kfree(kbuf);
		return -EIO;
	}

	nread = kernel_read(fp, kbuf, CONFIG_BUF_SIZE - 1, &pos);
	filp_close(fp, NULL);
	if (nread <= 0) {
		DBG("load_config: read failed or empty (%zd)", nread);
		kfree(kbuf);
		return -EIO;
	}
	kbuf[nread] = '\0';

	mutex_lock(&hide_lock);
	memset(hide_list, 0, sizeof(hide_list));
	hide_count = 0;
	mutex_unlock(&hide_lock);

	p = kbuf;
	while (*p) {
		const char *line_end = p;
		while (*line_end && *line_end != '\n' && *line_end != '\r')
			line_end++;
		parse_config_line(p);
		p = (*line_end == '\0') ? line_end : line_end + 1;
		while ((*p == '\n' || *p == '\r') && *p) p++;
	}

	DBG("load_config: loaded %d entries from '%s' (%zd bytes)", hide_count, config_path, nread);
	kfree(kbuf);
	return 0;
}

static int match_hide_path(const char *path, uid_t uid)
{
	int i;
	if (!path || !*path || path[0] != '/') return -1;
	if (!hide_from_root && uid == 0) return -1;
	mutex_lock(&hide_lock);
	for (i = 0; i < hide_count; i++) {
		if (!hide_list[i].active) continue;
		if (strcmp(hide_list[i].path, path) != 0) continue;
		if (hide_list[i].has_uid && hide_list[i].uid != uid) continue;
		mutex_unlock(&hide_lock);
		return i;
	}
	mutex_unlock(&hide_lock);
	return -1;
}

static int resolve_fd_path(int fd, char *buf, int buflen)
{
	struct file *file;
	char *path_ptr, *page;

	file = fget_task(current, fd);
	if (!file) return -EBADF;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		fput(file);
		return -ENOMEM;
	}

	path_ptr = d_path(&file->f_path, page, PAGE_SIZE);
	if (IS_ERR(path_ptr)) {
		free_page((unsigned long)page);
		fput(file);
		return PTR_ERR(path_ptr);
	}

	strncpy(buf, path_ptr, buflen - 1);
	buf[buflen - 1] = '\0';
	free_page((unsigned long)page);
	fput(file);
	return strlen(buf);
}

struct hook_data {
	int fd;
	void __user *buf;
	char path[MAX_PATH_LEN];
	int has_path;
};

static int getdents_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_data *data = (struct hook_data *)ri->data;
	int fd;

	data->has_path = 0;
	data->buf = NULL;
	fd = (int)regs->regs[0];
	data->fd = fd;
	data->buf = (void __user *)regs->regs[1];
	if (resolve_fd_path(fd, data->path, sizeof(data->path)) > 0)
		data->has_path = 1;
	return 0;
}

static int getdents_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_data *data = (struct hook_data *)ri->data;
	long total = regs->regs[0];
	char *kbuf;
	long pos, new_total;
	uid_t uid;

	if (!data->has_path || total <= 0 || !data->buf) return 0;
	if (total > DIRENT64_BUF_SIZE) total = DIRENT64_BUF_SIZE;

	kbuf = kmalloc(DIRENT64_BUF_SIZE, GFP_KERNEL);
	if (!kbuf) return 0;

	if (copy_from_user(kbuf, data->buf, total)) {
		kfree(kbuf);
		return 0;
	}

	uid = from_kuid(&init_user_ns, current_uid());
	if (!hide_from_root && uid == 0) {
		kfree(kbuf);
		return 0;
	}

	pos = 0;
	new_total = 0;
	while (pos < total) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + pos);
		unsigned short reclen = d->d_reclen;
		if (!reclen || pos + reclen > total) break;
		if (d->d_name[0]) {
			char full[MAX_PATH_LEN];
			scnprintf(full, sizeof(full), "%s/%s", data->path, d->d_name);
			if (match_hide_path(full, uid) >= 0) {
				pos += reclen;
				continue;
			}
		}
		if (new_total != pos)
			memmove(kbuf + new_total, kbuf + pos, reclen);
		new_total += reclen;
		pos += reclen;
	}

	if (new_total < total && new_total > 0) {
		if (copy_to_user(data->buf, kbuf, new_total) == 0)
			regs->regs[0] = new_total;
	}
	kfree(kbuf);
	return 0;
}

struct hook_entry_data {
	char path[MAX_PATH_LEN];
};

static int openat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	long ret;
	ret = strncpy_from_user(data->path, (const char __user *)regs->regs[1], sizeof(data->path) - 1);
	if (ret > 0) {
		data->path[ret] = '\0';
	} else {
		data->path[0] = '\0';
	}
	return 0;
}

static int openat_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	uid_t uid;
	if (!data->path[0]) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (match_hide_path(data->path, uid) >= 0) {
		DBG("openat: HIDE '%s' uid=%d", data->path, uid);
		regs->regs[0] = -ENOENT;
	}
	return 0;
}

static int faccessat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	long ret;
	ret = strncpy_from_user(data->path, (const char __user *)regs->regs[1], sizeof(data->path) - 1);
	if (ret > 0) {
		data->path[ret] = '\0';
	} else {
		data->path[0] = '\0';
	}
	return 0;
}

static int faccessat_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	uid_t uid;
	if (!data->path[0]) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (match_hide_path(data->path, uid) >= 0) {
		DBG("faccessat: HIDE '%s' uid=%d", data->path, uid);
		regs->regs[0] = -ENOENT;
	}
	return 0;
}

static int newfstatat_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	long ret;
	ret = strncpy_from_user(data->path, (const char __user *)regs->regs[1], sizeof(data->path) - 1);
	if (ret > 0) {
		data->path[ret] = '\0';
	} else {
		data->path[0] = '\0';
	}
	return 0;
}

static int newfstatat_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	uid_t uid;
	if (!data->path[0]) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (match_hide_path(data->path, uid) >= 0) {
		DBG("newfstatat: HIDE '%s' uid=%d", data->path, uid);
		regs->regs[0] = -ENOENT;
	}
	return 0;
}

static int chdir_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	long ret;
	ret = strncpy_from_user(data->path, (const char __user *)regs->regs[0], sizeof(data->path) - 1);
	if (ret > 0) {
		data->path[ret] = '\0';
	} else {
		data->path[0] = '\0';
	}
	return 0;
}

static int chdir_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	uid_t uid;
	if (!data->path[0]) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (match_hide_path(data->path, uid) >= 0) {
		DBG("chdir: HIDE '%s' uid=%d", data->path, uid);
		regs->regs[0] = -ENOENT;
	}
	return 0;
}

static int fchdir_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	int fd = (int)regs->regs[0];
	if (resolve_fd_path(fd, data->path, sizeof(data->path)) > 0) {
		DBG("fchdir: fd=%d path='%s' uid=%d", fd, data->path,
		    from_kuid(&init_user_ns, current_uid()));
	} else {
		data->path[0] = '\0';
	}
	return 0;
}

static int fchdir_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hook_entry_data *data = (struct hook_entry_data *)ri->data;
	uid_t uid;
	if (!data->path[0]) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (match_hide_path(data->path, uid) >= 0) {
		DBG("fchdir: HIDE '%s' uid=%d", data->path, uid);
		regs->regs[0] = -ENOENT;
	}
	return 0;
}

static struct kretprobe krp_openat = {
	.entry_handler = openat_entry_handler,
	.handler = openat_ret_handler,
	.data_size = sizeof(struct hook_entry_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_openat",
};

static struct kretprobe krp_faccessat = {
	.entry_handler = faccessat_entry_handler,
	.handler = faccessat_ret_handler,
	.data_size = sizeof(struct hook_entry_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_faccessat",
};

static struct kretprobe krp_newfstatat = {
	.entry_handler = newfstatat_entry_handler,
	.handler = newfstatat_ret_handler,
	.data_size = sizeof(struct hook_entry_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_newfstatat",
};

static struct kretprobe krp_getdents64 = {
	.entry_handler = getdents_entry_handler,
	.handler = getdents_ret_handler,
	.data_size = sizeof(struct hook_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

static struct kretprobe krp_chdir = {
	.entry_handler = chdir_entry_handler,
	.handler = chdir_ret_handler,
	.data_size = sizeof(struct hook_entry_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_chdir",
};

static struct kretprobe krp_fchdir = {
	.entry_handler = fchdir_entry_handler,
	.handler = fchdir_ret_handler,
	.data_size = sizeof(struct hook_entry_data),
	.maxactive = 64,
	.kp.symbol_name = "__arm64_sys_fchdir",
};

static struct kretprobe *all_krps[] = {
	&krp_openat, &krp_faccessat, &krp_newfstatat,
	&krp_getdents64, &krp_chdir, &krp_fchdir,
};
#define KRPOOL_COUNT (sizeof(all_krps) / sizeof(all_krps[0]))

static int register_all_hooks(void)
{
	int i, ret;

	for (i = 0; i < KRPOOL_COUNT; i++) {
		ret = register_kretprobe(all_krps[i]);
		if (ret < 0) {
			DBG("register_kretprobe(%s) FAILED err=%d",
			    all_krps[i]->kp.symbol_name, ret);
			goto fail;
		}
		DBG("registered kretprobe on %s", all_krps[i]->kp.symbol_name);
	}
	return 0;
fail:
	for (i--; i >= 0; i--)
		unregister_kretprobe(all_krps[i]);
	return ret;
}

static void unregister_all_hooks(void)
{
	int i;
	for (i = KRPOOL_COUNT - 1; i >= 0; i--)
		unregister_kretprobe(all_krps[i]);
	DBG("all kretprobes unregistered");
}

static ssize_t fshide_read(struct file *file, char __user *ubuf,
                           size_t len, loff_t *ppos)
{
	char *buf;
	int pos = 0, i, ret;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) return -ENOMEM;

	pos += scnprintf(buf + pos, PAGE_SIZE - pos,
	                 "config=%s\nentries=%d\nhide_root=%d\n",
	                 config_path, hide_count, hide_from_root);

	mutex_lock(&hide_lock);
	for (i = 0; i < hide_count && pos < PAGE_SIZE - 128; i++) {
		if (hide_list[i].active)
			pos += scnprintf(buf + pos, PAGE_SIZE - pos,
			                 "  [%d] '%s' uid=%u%s\n",
			                 i, hide_list[i].path,
			                 hide_list[i].uid,
			                 hide_list[i].has_uid ? "" : " [global]");
	}
	mutex_unlock(&hide_lock);

	if (*ppos >= pos) {
		kfree(buf);
		return 0;
	}
	ret = min((size_t)(pos - *ppos), len);
	if (copy_to_user(ubuf, buf + *ppos, ret)) {
		kfree(buf);
		return -EFAULT;
	}
	*ppos += ret;
	kfree(buf);
	return ret;
}

static ssize_t fshide_write(struct file *file, const char __user *ubuf,
                            size_t len, loff_t *ppos)
{
	char buf[256];
	char cmd[64], val[192];

	if (len >= sizeof(buf)) len = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, len)) return -EFAULT;
	buf[len] = '\0';
	if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

	if (sscanf(buf, "%63s %191s", cmd, val) < 1) {
		pr_info("[fshide] cmds: config <path> | reload | hide_root <0/1>\n");
		return len;
	}

	if (!strcmp(cmd, "config")) {
		if (val[0] == '/') {
			strncpy(config_path, val, sizeof(config_path) - 1);
			config_path[sizeof(config_path) - 1] = '\0';
			pr_info("[fshide] config path set to '%s'\n", config_path);
		}
	} else if (!strcmp(cmd, "reload")) {
		load_config();
		pr_info("[fshide] reloaded %d entries from '%s'\n", hide_count, config_path);
	} else if (!strcmp(cmd, "hide_root")) {
		hide_from_root = (!strcmp(val, "1") || !strcmp(val, "yes") || !strcmp(val, "true")) ? 1 : 0;
		pr_info("[fshide] hide_root=%d\n", hide_from_root);
	} else {
		pr_info("[fshide] unknown cmd: %s\n", cmd);
	}

	return len;
}

static int fshide_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int fshide_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations fshide_fops = {
	.owner   = THIS_MODULE,
	.open    = fshide_open,
	.release = fshide_release,
	.read    = fshide_read,
	.write   = fshide_write,
};

static struct miscdevice fshide_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "fshide",
	.fops  = &fshide_fops,
	.mode  = 0600,
};

static int __init fshide_init(void)
{
	int ret;

	pr_info("[fshide] loading v0.2.0-lkm\n");

	load_config();

	ret = register_all_hooks();
	if (ret < 0) {
		pr_err("[fshide] hook registration failed: %d\n", ret);
		return ret;
	}

	ret = misc_register(&fshide_misc);
	if (ret < 0) {
		pr_err("[fshide] misc_register failed: %d\n", ret);
		unregister_all_hooks();
		return ret;
	}
	misc_registered = 1;

	pr_info("[fshide] loaded (entries=%d hide_root=%d config=%s)\n",
	        hide_count, hide_from_root, config_path);
	return 0;
}

static void __exit fshide_exit(void)
{
	if (misc_registered)
		misc_deregister(&fshide_misc);

	unregister_all_hooks();

	mutex_lock(&hide_lock);
	memset(hide_list, 0, sizeof(hide_list));
	hide_count = 0;
	mutex_unlock(&hide_lock);

	pr_info("[fshide] unloaded\n");
}

module_init(fshide_init);
module_exit(fshide_exit);
