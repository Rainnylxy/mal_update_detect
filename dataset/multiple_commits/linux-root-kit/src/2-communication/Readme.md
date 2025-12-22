To communicate with the kernel module we need to add some more logic:

[What is a chr device?](https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html)
1. Reserve a device number 

```c
alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
```

2. Create a char device with file options

```c
cdev_init(&add_cdev, &fops);
```

File options:

```c
static const struct file_operations fops = {
    .owner   = THIS_MODULE,   // prevents module unloading while in use
    .open    = add_open,      // open()  // we dont need anything here
    .release = add_release,   // close() // we dont need anything here
    .read    = add_read,      // read()  // logic if we read from it
    .write   = add_write,     // write() // logic if we write to it
	};
``` 

and one of the options:

```c
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
``` 

3. Set the owner to prevent unloading of hte module while using the device

```c
static struct cdev  add_cdev;      // character device structure

add_cdev.owner = THIS_MODULE;
``` 

4. Add the device to the system
The dev_number is the major number of the device, 1 for one device (~minor number)

```c
err = cdev_add(&add_cdev, dev_number, 1);

    if (err) {
        // on failure, undo the alloc_chrdev_region
        unregister_chrdev_region(dev_number, 1);
        return err;
    }
``` 

5. create userspace device

First create the struct of a class then the class and create the device :D
```c
static struct class *add_class;

add_class = class_create("add_class");

device_create(add_class, NULL, dev_number, NULL, DEVICE_NAME);

``` 

6. Todo change the permissions of /dev/add so everyone can write to it
