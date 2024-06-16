#!/bin/bash

set -eu

## extract filesystem
# sh ./extract.sh

# build and compile exploit
cwd=$(pwd)
rm -f ./extracted/bin/exploit
musl-gcc ./exploit.c -o ./exploit --static -g -O0 -masm=intel -pthread
cp ./exploit ./extracted/bin

# compress filesystem
rm ./initramfs.cpio
chmod 777 -R ./extracted
cd ./extracted
find ./ -print0 | cpio --owner root --null -o --format=newc > ../initramfs.cpio
cd ../

# find . | cpio -o -c -R root:root | gzip -9 > ../initrd

qemu-system-x86_64 \
     -m 64M \
     -nographic \
     -kernel bzImage \
     -initrd initramfs.cpio \
     -drive file=flag.txt,format=raw \
     -snapshot \
     -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr root=/dev/sda" \
     -no-reboot \
     -cpu qemu64,+smap,+smep \
     -monitor /dev/null \
     -net nic,model=virtio \
     -net user \
     -s

