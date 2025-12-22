#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>        // alloc_chrdev_region, struct file_operations
#include <linux/cdev.h>      // cdev_init, cdev_add
#include <linux/uaccess.h>   // copy_to_user, copy_from_user
#include <linux/device.h> 	 // we need this for auto create of /dev/add  
#define DEVICE_NAME "add"
#define BUF_SIZE    64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IC3");
MODULE_DESCRIPTION("Simple add-device: write \"add X Y\" and read result");
MODULE_VERSION("0.2.0");

static dev_t        dev_number;    			// holds the allocated major/minor number
static struct cdev  add_cdev;      			// character device structure
static char         cmd_buf[BUF_SIZE];      // buffer for incoming command
static char         result_buf[BUF_SIZE];   // buffer for the computed result
static size_t       result_len;    			// length of the valid data in result_buf
static struct class *add_class; 			// class for the device 

// https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html#registration-and-unregistration-of-character-devices
static ssize_t add_read(struct file *file,    // pointer to this file
                        char __user *buf,     // user-space buffer to copy data into
                        size_t len,           // max bytes to read
                        loff_t *offset)       // current file offset
{
    // If we've already returned data once, report EOF
    if (*offset >= result_len)
        return 0;

    // Copy the computed result from kernel space to user space
    if (copy_to_user(buf, result_buf, result_len))
        return -EFAULT;  // fault if copy fails

    // Advance the offset so subsequent reads return EOF
    *offset = result_len;

    // Return number of bytes actually read
    return result_len;
}

// https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html#registration-and-unregistration-of-character-devices
static ssize_t add_write(struct file *file,           // pointer to this file
                         const char __user *buf,      // user-space buffer with input
                         size_t len,                  // number of bytes in input
                         loff_t *offset)              // current file offset (ignored)
{
    long a, b;
    int ret;

    // Protect against overly large writes
    if (len >= BUF_SIZE)
        return -EFAULT;

    // Copy the command from user space into our kernel buffer
    if (copy_from_user(cmd_buf, buf, len))
        return -EFAULT;
    cmd_buf[len] = '\0';  // null-terminate to make it a proper C‑string

    // Parse the command; expect exactly two numbers after "add"
    ret = sscanf(cmd_buf, "add %ld %ld", &a, &b);
    if (ret != 2) {
        // Parsing failed --> return an error message
        snprintf(result_buf, BUF_SIZE, "ERROR\n");
    } else {
        // Successfully parsed --> compute sum and store it
        snprintf(result_buf, BUF_SIZE, "%ld\n", a + b);
    }

    // Remember how many bytes we stored for the read() path
    result_len = strlen(result_buf);

    // Report to caller that we consumed all input bytes
    return len;
}

static int add_open(struct inode *inode, struct file *file)
{
    // return success
    return 0;
}

static int add_release(struct inode *inode, struct file *file)
{
    // return success
    return 0;
}

// File-ops structure: ties our handlers into the kernel's VFS
static const struct file_operations fops = {
    .owner   = THIS_MODULE,   // prevents module unloading while in use
    .open    = add_open,      // open()  // we dont need anything here
    .release = add_release,   // close() // we dont need anything here
    .read    = add_read,      // read()  // logic if we read from it
    .write   = add_write,     // write() // logic if we write to it
	};

static int __init add_init(void)
{
    int err;


	/*
	https://stackoverflow.com/questions/9835850/what-is-the-difference-between-register-chrdev-region-and-alloc-chrdev-region-to


	https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html

	*/
    // 1. allocate a major/minor number for our device and saves it to dev_number

	/*
	https://manpages.debian.org/jessie-backports/linux-manual-4.9/alloc_chrdev_region.9
	dev
		output parameter for first assigned number
	baseminor
		first of the requested range of minor numbers
	count
		the number of minor numbers required
	name
		the name of the associated device or driver


	Allocates a range of char device numbers.
	The major number will be chosen dynamically, and returned
	(along with the first minor number) in dev. Returns zero or
	a negative error code. 
	*/
    err = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
    if (err)
        return err;

    // 2. initialize our cdev object and add the file operations definde in fops 
	/*
	https://manpages.debian.org/testing/linux-manual-4.8/cdev_init.9.en.html
	cdev
		the structure to initialize

	fops
		the file_operations for this device

	Initializes cdev, remembering fops, making it ready to add to the system with cdev_add.
	*/
    cdev_init(&add_cdev, &fops);


	// 3. add a char device to the system 
	/*
	p
		the cdev structure for the device
	dev
		the first device number for which this device is responsible
	count
		the number of consecutive minor numbers corresponding to this device
	
	cdev_add adds the device represented by p to the system, making it live immediately.
	A negative error code is returned on failure. 
	*/

	// set the owner
    add_cdev.owner = THIS_MODULE;

	// we got the dev_number from the alloc_chrdev_region earlier
    err = cdev_add(&add_cdev, dev_number, 1);

    if (err) {
        // on failure, undo the alloc_chrdev_region
        unregister_chrdev_region(dev_number, 1);
        return err;
    }
	// 5. create the userspace device node /dev/add

    
    add_class = class_create("add_class");

	/*
	class
		pointer to the struct class that this device should be registered to
	parent
		pointer to the parent struct device of this new device, if any
	devt
		the dev_t for the char device to be added
	drvdata
		the data to be added to the device for callbacks
	fmt
		string for the device's name

	*/

    device_create(add_class, NULL, dev_number, NULL, DEVICE_NAME);

    pr_info("add: registered /dev/%s (major %d)\n",
            DEVICE_NAME, MAJOR(dev_number));
    return 0;
}

static void __exit add_exit(void)
{	
	device_destroy(add_class, dev_number);
	class_destroy(add_class);
    // remove the cdev and free our device number
    cdev_del(&add_cdev);
    unregister_chrdev_region(dev_number, 1);

    pr_info("add: unregistered\n");

}

module_init(add_init);
module_exit(add_exit);

/*

cat /proc/devices | grep add

--> returns 241 
this returns the number of the char device
c for char device and 0 as minor version

sudo mknod /dev/add c 241 0

or

sudo mknod /dev/add c $(awk '/add/ {print $1}' /proc/devices) 0

then write to it:

echo 'add 1 2' | sudo tee /dev/add

and read from it:


cat /dev/add


sudo rm /dev/add

*/