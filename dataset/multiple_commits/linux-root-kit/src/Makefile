obj-m += rkit.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC   := gcc


# make resolves dependencies --> so only need to call this
all: shell

rkit.ko:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# .ko to C header (rkit_ko.h)
rkit_ko.h: rkit.ko
	xxd -i rkit.ko > rkit_ko.h

# userspace loader
shell: shell.c rkit_ko.h
	$(CC) -o shell shell.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f rkit_ko.h shell
test:
	sudo rmmod rkit || true
	sudo insmod rkit.ko
	sudo lsmod | grep -i rkit
	sudo dmesg | tail -n 500
