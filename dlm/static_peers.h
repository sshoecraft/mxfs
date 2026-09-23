/*
 * MXFS — Multinode XFS
 * Static peer list (mount option peers=)
 *
 * When the administrator lists the cluster's addresses, every datagram MXFS
 * would have sent to the multicast group — discovery announcements, lease
 * heartbeats, CAW BAST/grant nudges — is sent by unicast to each listed
 * address instead, no socket joins the group, and a datagram from an address
 * that is not on the list is dropped.  The packets themselves are unchanged,
 * so everything above the socket (peer registration, the lease state
 * machine, the TCP mesh) behaves exactly as it does under multicast.
 *
 * The list may include this node's own address, so every node can carry the
 * same option: each receiver already ignores its own packets by identity.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_STATIC_PEERS_H
#define MXFS_LIBMXFS_STATIC_PEERS_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"

/* "255.255.255.255" plus the terminator; entries are canonical dotted IPv4,
 * the same form mxfs_pal_udp_recvfrom reports a sender in. */
#define MXFS_PEER_ADDR_LEN      16

struct mxfs_static_peers {
    uint32_t    count;          /* 0 = no list: multicast as before */
    char        addr[MXFS_MAX_NODES][MXFS_PEER_ADDR_LEN];
};

static inline bool mxfs_static_peers_active(const struct mxfs_static_peers *p)
{
    return p && p->count > 0;
}

/* Is a datagram's sender on the list?  Always true without a list. */
static inline bool mxfs_static_peers_admit(const struct mxfs_static_peers *p,
                                           const char *host)
{
    uint32_t i;

    if (!mxfs_static_peers_active(p))
        return true;
    for (i = 0; i < p->count; i++)
        if (strcmp(p->addr[i], host) == 0)
            return true;
    return false;
}

/* Send one datagram to every listed address.  Returns the first error, after
 * trying every address, or 0. */
static inline int mxfs_static_peers_sendto(const struct mxfs_static_peers *p,
                                           mxfs_sock_t *s, const void *buf,
                                           uint32_t len, uint16_t port)
{
    uint32_t i;
    int rc, first = 0;

    for (i = 0; i < p->count; i++) {
        rc = mxfs_pal_udp_sendto(s, buf, len, p->addr[i], port);
        if (rc < 0 && !first)
            first = rc;
    }
    return first;
}

#endif /* MXFS_LIBMXFS_STATIC_PEERS_H */
