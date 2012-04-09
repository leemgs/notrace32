#!/bin/bash 
mount -t sysfs none /sysfs
mount -t debugfs none /sys/kernel/debug/
./busybox insmod nt32.ko
sleep 5
./busybox nc -l 1234 < /sys/kernel.debug/nt32 > /sys/kernel/debug/nt32 &
./busybox netstat -nat | grep 1234
