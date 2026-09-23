# SPDX-License-Identifier: GPL-2.0
#
# MXFS — TCP authority ledger shadow-page store, usermode unit test
# (docs/tcp-authority-ledger.md step 2).  `make -C tests/tauth && ./tauth_test`
# Standalone like tests/net2: not referenced by the top-level build.
TOP     := $(abspath ../..)
CFLAGS  ?= -O2 -g -std=gnu11 -Wall -Wextra -Werror
CPPFLAGS = -I$(TOP) -I$(TOP)/include
OBJDIR  := obj
BIN     := tauth_test
LDLIBS  := -lpthread

OBJS := $(OBJDIR)/tauth_test.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o
LBIN := ledger_test
LOBJS := $(OBJDIR)/ledger_test.o $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

DBIN := dlm_ledger_test
DOBJS := $(OBJDIR)/dlm_ledger_test.o $(OBJDIR)/dlm.o $(OBJDIR)/dlm_shared.o \
         $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

FBIN := formation_test
FOBJS := $(OBJDIR)/formation_test.o $(OBJDIR)/dlm.o $(OBJDIR)/dlm_shared.o \
         $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

CBIN := concurrent_release_test
COBJS := $(OBJDIR)/concurrent_release_test.o $(OBJDIR)/dlm.o $(OBJDIR)/dlm_shared.o \
         $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

UBIN := unowned_page_test
UOBJS := $(OBJDIR)/unowned_page_test.o $(OBJDIR)/dlm.o $(OBJDIR)/dlm_shared.o \
         $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

$(OBJDIR)/unowned_page_test.o: unowned_page_test.c dlm_mesh.h tauth_testlib.h $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(UBIN): $(UOBJS)
	$(CC) $(CFLAGS) -o $@ $(UOBJS) $(LDLIBS)

RBIN := bootstrap_race_test
ROBJS := $(OBJDIR)/bootstrap_race_test.o $(OBJDIR)/dlm.o $(OBJDIR)/dlm_shared.o \
         $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

$(OBJDIR)/bootstrap_race_test.o: bootstrap_race_test.c dlm_mesh.h tauth_testlib.h $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(RBIN): $(ROBJS)
	$(CC) $(CFLAGS) -o $@ $(ROBJS) $(LDLIBS)

PBIN := pageof
POBJS := $(OBJDIR)/pageof.o $(OBJDIR)/tauth_ledger.o $(OBJDIR)/tauth_store.o $(OBJDIR)/pal_user.o

$(OBJDIR)/pageof.o: pageof.c $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal $(CFLAGS) -c -o $@ $<

$(PBIN): $(POBJS)
	$(CC) $(CFLAGS) -o $@ $(POBJS) $(LDLIBS)

VBIN := view_format_test
VOBJS := $(OBJDIR)/view_format_test.o

$(OBJDIR)/view_format_test.o: view_format_test.c $(TOP)/include/mxfs/mxfs_tauth.h $(TOP)/include/mxfs/mxfs_sha256.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(VBIN): $(VOBJS)
	$(CC) $(CFLAGS) -o $@ $(VOBJS)

all: $(BIN) $(LBIN) $(DBIN) $(FBIN) $(CBIN) $(UBIN) $(RBIN) $(PBIN) $(VBIN)

test: all
	./$(BIN) && ./$(LBIN) && ./$(DBIN) && ./$(FBIN) && ./$(CBIN) && ./$(UBIN) && ./$(RBIN) && ./$(VBIN)

$(OBJDIR)/concurrent_release_test.o: concurrent_release_test.c dlm_mesh.h tauth_testlib.h $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(CBIN): $(COBJS)
	$(CC) $(CFLAGS) -o $@ $(COBJS) $(LDLIBS)

# The DLM engine carries decades of -Wextra-unfriendly probe lines; build it
# with -Wall only (the module build is the strict one).
$(OBJDIR)/formation_test.o: formation_test.c dlm_mesh.h tauth_testlib.h $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(FBIN): $(FOBJS)
	$(CC) $(CFLAGS) -o $@ $(FOBJS) $(LDLIBS)

$(OBJDIR)/dlm_ledger_test.o: dlm_ledger_test.c dlm_mesh.h tauth_testlib.h $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(OBJDIR)/dlm.o: $(TOP)/dlm/dlm.c $(TOP)/dlm/dlm.h $(TOP)/dlm/tauth_ledger.h $(TOP)/dlm/tauth_store.h $(TOP)/include/mxfs/mxfs_tauth.h $(TOP)/dlm/dlm_user_compat.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(OBJDIR)/dlm_shared.o: $(TOP)/dlm/dlm_shared.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal -O2 -g -std=gnu11 -Wall -c -o $@ $<

$(DBIN): $(DOBJS)
	$(CC) $(CFLAGS) -o $@ $(DOBJS) $(LDLIBS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/tauth_test.o: tauth_test.c $(TOP)/dlm/tauth_store.h $(TOP)/include/mxfs/mxfs_tauth.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/ledger_test.o: ledger_test.c tauth_testlib.h $(TOP)/dlm/tauth_ledger.h $(TOP)/dlm/tauth_store.h $(TOP)/include/mxfs/mxfs_tauth.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/tauth_store.o: $(TOP)/dlm/tauth_store.c $(TOP)/dlm/tauth_store.h $(TOP)/include/mxfs/mxfs_tauth.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/tauth_ledger.o: $(TOP)/dlm/tauth_ledger.c $(TOP)/dlm/tauth_ledger.h $(TOP)/dlm/tauth_store.h $(TOP)/include/mxfs/mxfs_tauth.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/pal_user.o: $(TOP)/pal/linux/user.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) -I$(TOP)/pal $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(LBIN): $(LOBJS)
	$(CC) $(CFLAGS) -o $@ $(LOBJS) $(LDLIBS)

clean:
	rm -rf $(OBJDIR) $(BIN) $(LBIN) $(DBIN) $(FBIN) $(CBIN) $(UBIN) $(RBIN) $(PBIN) $(VBIN)

.PHONY: all clean
