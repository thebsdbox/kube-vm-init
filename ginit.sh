#!/bin/bash
set -euo pipefail

#Lines from Tron: Legacy
echo "$ whoami"
echo "flynn"
sleep 0.5
echo "$ uname -a"
echo "SolarOS 4.0.1 Generic_50203-02 sun4m i386"
echo "Unknown.Unknown"
sleep 0.5
echo "$ login -n root"
echo "Login incorrect"
sleep 0.5
echo "login:backdoor"
echo "No home directory specified in password file!"
echo "Logging in with home=/"

echo "#"
echo "# bin/build_world"
sleep 3

echo "Creating your ramdisk"
mkdir -p output
docker buildx build  --platform linux/amd64 --load -t ginit:0.0 -f initrd.Dockerfile .
docker create --name exporter ginit:0.0 null
trap 'docker rm -f exporter >/dev/null 2>&1 || true' EXIT
docker cp exporter:/initramfs.cpio.gz output/initramfs.cpio.gz
docker rm exporter
trap - EXIT
echo "Here is a command you can run"
echo 'qemu-system-x86_64 -nographic -kernel ./linux -append "root=/dev/sda console=ttyS0" -initrd ./initramfs.cpio.gz'
