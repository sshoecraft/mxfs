# SPDX-License-Identifier: GPL-2.0
#
# MXFS — Multinode XFS
# Top-level Makefile
#

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean modules tools

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C tools clean 2>/dev/null || true

tools:
	$(MAKE) -C tools

install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load: modules
	@if lsmod | grep -q '^mxfs '; then rmmod mxfs; fi
	insmod mxfs.ko

unload:
	@if lsmod | grep -q '^mxfs '; then rmmod mxfs; fi

package:
	./packaging/mkpackage.sh
