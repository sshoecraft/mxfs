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

# Everything the packages install, not only the module: the tools, the
# fence and witness helpers, the man pages, the module options and the udev
# rule (packaging/install_source.sh, sharing its file list with the .deb).
install: modules
	./packaging/install_source.sh check
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
	./packaging/install_source.sh files $(if $(OVERWRITE),--overwrite)

load: modules
	@if lsmod | grep -q '^mxfs '; then rmmod mxfs; fi
	insmod mxfs.ko

unload:
	@if lsmod | grep -q '^mxfs '; then rmmod mxfs; fi

package:
	./packaging/mkpackage.sh
