mount
umount /mnt/hw2/
rmmod u2fs
cd /usr/src/hw2-akarim
make
cd /usr/src/hw2-akarim/fs/u2fs
insmod u2fs.ko
lsmod
mount -t u2fs -o ldir=/fruits,rdir=/veg null /mnt/hw2
mount
