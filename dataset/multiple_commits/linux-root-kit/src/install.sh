sudo rmmod rkit
make
sudo insmod rkit.ko
make clean
sudo dmesg | tail -n 5