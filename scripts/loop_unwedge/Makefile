# Build helper for loop_unwedge.ko.  Pure in-tree blk-mq API — no external
# include trees needed, unlike scripts/scst_unwedge/.
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := loop_unwedge.o

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
