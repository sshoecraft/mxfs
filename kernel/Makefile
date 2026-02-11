#
# MXFS kernel module (mxfs.ko)
#

obj-m := mxfs.o

mxfs-y := mxfs_main.o \
          mxfs_netlink.o \
          mxfs_hooks.o \
          mxfs_cache.o

KDIR ?= /lib/modules/$(shell uname -r)/build
MXFS_INCLUDE := $(src)/../include

ccflags-y := -I$(MXFS_INCLUDE)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
