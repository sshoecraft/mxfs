#
# MXFS daemon (mxfsd)
#

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Werror -std=gnu11 -O2 -g
CFLAGS  += -I../include
LDFLAGS := -lpthread

TARGET  := mxfsd

SRCS    := mxfsd_main.c \
           mxfsd_config.c \
           mxfsd_peer.c \
           mxfsd_dlm.c \
           mxfsd_netlink.c \
           mxfsd_lease.c \
           mxfsd_journal.c \
           mxfsd_log.c \
           mxfsd_volume.c

OBJS    := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
