Delete the kobject to hide from a simple `ls /sys/modules`


https://manpages.debian.org/testing/linux-manual-4.8/kobject_del.9.en.html
```c
kobject_del(&THIS_MODULE->mkobj.kobj);
```