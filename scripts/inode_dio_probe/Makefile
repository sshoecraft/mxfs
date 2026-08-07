# Build helper for inode_dio_probe.ko.  Pure in-tree VFS API.
# include trees needed, unlike scripts/scst_unwedge/.
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := inode_dio_probe.o

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
