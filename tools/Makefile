CC ?= gcc

# Version from VERSION file — single source of truth
MXFS_VER := $(shell cat ../VERSION)
MXFS_VER_MAJOR := $(word 1,$(subst ., ,$(MXFS_VER)))
MXFS_VER_MINOR := $(word 2,$(subst ., ,$(MXFS_VER)))
MXFS_VER_PATCH := $(word 3,$(subst ., ,$(MXFS_VER)))

CFLAGS = -Wall -Wextra -O2 -I../include
CFLAGS += -DMXFS_VERSION_MAJOR=$(MXFS_VER_MAJOR)
CFLAGS += -DMXFS_VERSION_MINOR=$(MXFS_VER_MINOR)
CFLAGS += -DMXFS_VERSION_PATCH=$(MXFS_VER_PATCH)
LDFLAGS =

TOOLS = mkfs_mxfs chk_mxfs resize_mxfs fua_verify
HEADERS = ../include/mxfs/mxfs_super.h ../include/mxfs/mxfs_common.h ../VERSION

all: $(TOOLS)

mkfs_mxfs: mkfs_mxfs.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

chk_mxfs: chk_mxfs.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

resize_mxfs: resize_mxfs.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fua_verify: fua_verify.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TOOLS)

install: $(TOOLS)
	install -m 755 mkfs_mxfs /sbin/mkfs.mxfs
	install -m 755 chk_mxfs /sbin/chk_mxfs
	install -m 755 resize_mxfs /sbin/resize.mxfs

.PHONY: all clean install
