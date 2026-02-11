#
# MXFS — Multinode XFS
# Top-level build
#

.PHONY: all daemon kernel clean

all: daemon kernel

daemon:
	$(MAKE) -C daemon

kernel:
	$(MAKE) -C kernel

clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C kernel clean
