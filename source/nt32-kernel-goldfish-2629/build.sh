#!/bin/bash 

cp goldfish_nt32_defconfig_20120419  ./.config

time make -j4 ARCH=arm CROSS_COMPILE=/opt/android/mydroid-ics403-20111225/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-  menuconfig

time make -j4 ARCH=arm CROSS_COMPILE=/opt/android/mydroid-ics403-20111225/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-  

