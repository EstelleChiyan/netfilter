This module is used to check the changes of TCP window size, which gives a view of congestion control.

Run "make" in this folder.

Run this command to enable the module:
sudo insmod window_size.ko

You can use this commmand to see output of the module:
dmesg | tail

To close the module, use command:
sudo rmmod window_size
