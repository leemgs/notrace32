#!/bin/bash 
./busybox ifconfig usb0 192.168.155.25 netmask 255.255.255.0 up
route add default gw 192.168.155.1
