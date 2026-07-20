# Build helper for scst_unwedge.ko — must use the SAME scst include tree the
# running scst.ko was built from so struct offsets match (no CONFIG_SCST_*
# defines were used in that build; see .scst_targ.o.cmd in the scst tree).
SCST_INC ?= /home/steve/src/scst/scst/include
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := scst_unwedge.o
ccflags-y := -I$(SCST_INC)

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
