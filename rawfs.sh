#!/bin/bash

echo "Converting initramfs.cpio.gz to initramfs.raw"
if [ -f "./output/initramfs.cpio.gz" ]; then
    fullpath=$(realpath ./output/initramfs.cpio.gz)
    truncate -s 500M ./output/initramfs.raw
    mkfs.ext4 -F ./output/initramfs.raw
    mkdir -p /tmp/initramfs
    sudo mount -o loop ./output/initramfs.raw /tmp/initramfs
    cd /tmp/initramfs
    mkdir ./dev
    sudo  gunzip < $fullpath | sudo cpio -idv
    cd -
    sudo umount /tmp/initramfs
else 
    echo "initramfs.cpio.gz not found. Please run ginit.sh first."
fi