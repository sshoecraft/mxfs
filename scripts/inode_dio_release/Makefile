# Build helper for inode_dio_release.ko.  Pure in-tree VFS API.
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := inode_dio_release.o

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
