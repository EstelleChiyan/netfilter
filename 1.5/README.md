Run "make" in this folder.

Run this command to enable the module:
sudo insmod firewall.ko

You can use this commmand to see output of the module:
dmesg | tail

To close the module, use command:
sudo rmmod simple_firewall
