# SPDX-License-Identifier: GPL-2.0
#
# MXFS — NET2 user-mode protocol harness (standalone).
#
# Invoked as `make -C tests/net2`.  Deliberately NOT referenced by the
# top-level Makefile or Kbuild — integrating it there is approval-gated
# (DLM_IMPL_PLAN.md §11 step 12).  Objects build under obj/ so nothing
# collides with Kbuild's future dlm/net2_*.o kernel objects.

CC      ?= gcc
TOP     := $(abspath ../..)
CFLAGS  ?= -O2 -g -std=gnu11 -Wall -Wextra -Werror
CPPFLAGS = -I$(TOP)

OBJDIR := obj
BIN    := net2_harness
LDLIBS := -lpthread

NET2_HDRS := $(TOP)/dlm/net2.h $(TOP)/dlm/net2_wire.h $(TOP)/dlm/net2_stats.h \
             $(TOP)/dlm/net2_fault.h $(TOP)/dlm/net2_ctx.h \
             $(TOP)/dlm/net2_link.h $(TOP)/dlm/net2_overlay.h \
             $(TOP)/dlm/net2_midcomms.h $(TOP)/dlm/dlm_shared.h \
             $(TOP)/dlm/net2_msg.h $(TOP)/dlm/net2_shard.h \
             $(TOP)/dlm/net2_lock.h $(TOP)/dlm/net2_epoch.h \
             $(TOP)/dlm/net2_membership.h

OBJS := $(OBJDIR)/net2_harness.o \
        $(OBJDIR)/vcluster.o \
        $(OBJDIR)/scen_midcomms.o \
        $(OBJDIR)/scen_shard.o \
        $(OBJDIR)/scen_mepoch.o \
        $(OBJDIR)/net2_fault.o \
        $(OBJDIR)/net2.o \
        $(OBJDIR)/net2_link.o \
        $(OBJDIR)/net2_overlay.o \
        $(OBJDIR)/net2_midcomms.o \
        $(OBJDIR)/net2_shard.o \
        $(OBJDIR)/net2_lock.o \
        $(OBJDIR)/net2_epoch.o \
        $(OBJDIR)/net2_membership.o \
        $(OBJDIR)/dlm_shared.o \
        $(OBJDIR)/pal_user.o

all: $(BIN)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: harness/%.c harness/harness.h $(NET2_HDRS) | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: $(TOP)/dlm/%.c $(NET2_HDRS) | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/pal_user.o: $(TOP)/pal/linux/user.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean
