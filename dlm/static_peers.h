/*
 * MXFS — Multinode XFS
 * Static peer list (mount options peer= and peers=)
 *
 * Two ways to name addresses, one list:
 *
 *  peer=ADDR (repeatable) — ADDITIVE.  Multicast discovery runs as usual, and
 *  every datagram MXFS sends to the group — discovery announcements, lease
 *  heartbeats, CAW BAST/grant nudges — is also sent by unicast to each listed
 *  address.  Nobody is dropped.  For a node the group cannot reach, such as
 *  one on another network.
 *
 *  peers=ADDR[/ADDR...] — EXCLUSIVE.  The list is the whole cluster: every
 *  datagram goes by unicast to the listed addresses only, no socket joins the
 *  group, and a datagram or connection from an address not on the list is
 *  dropped.  For networks that cannot pass multicast at all.
 *
 * Either option adds to the list; any peers= makes the whole list exclusive.
 * The packets themselves are unchanged, so everything above the socket (peer
 * registration, the lease state machine, the TCP mesh) behaves exactly as it
 * does under multicast.
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
    bool        exclusive;      /* peers=: the list is the whole cluster */
    char        addr[MXFS_MAX_NODES][MXFS_PEER_ADDR_LEN];
};

/* Is there a list to unicast to (peer= or peers=)? */
static inline bool mxfs_static_peers_active(const struct mxfs_static_peers *p)
{
    return p && p->count > 0;
}

/* Is the list the whole cluster (peers=): no multicast, strangers dropped? */
static inline bool mxfs_static_peers_exclusive(const struct mxfs_static_peers *p)
{
    return mxfs_static_peers_active(p) && p->exclusive;
}

/* Is this address on the list (so this node unicasts to it)? */
static inline bool mxfs_static_peers_listed(const struct mxfs_static_peers *p,
                                            const char *host)
{
    uint32_t i;

    if (!mxfs_static_peers_active(p))
        return false;
    for (i = 0; i < p->count; i++)
        if (strcmp(p->addr[i], host) == 0)
            return true;
    return false;
}

/* Is a datagram's sender part of the cluster?  Only an exclusive list
 * (peers=) refuses anyone; an additive one (peer=) admits all, as multicast
 * does. */
static inline bool mxfs_static_peers_admit(const struct mxfs_static_peers *p,
                                           const char *host)
{
    return !mxfs_static_peers_exclusive(p) ||
           mxfs_static_peers_listed(p, host);
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

/* Send one datagram everywhere this node's discovery mode sends: to every
 * listed address, and to the group (multicast or broadcast address) unless
 * the list is exclusive.  Returns the first error, after trying every
 * destination, or 0. */
static inline int mxfs_static_peers_send(const struct mxfs_static_peers *p,
                                         mxfs_sock_t *s, const void *buf,
                                         uint32_t len, const char *group,
                                         uint16_t port)
{
    int rc = 0, grc;

    if (mxfs_static_peers_active(p))
        rc = mxfs_static_peers_sendto(p, s, buf, len, port);
    if (!mxfs_static_peers_exclusive(p)) {
        grc = mxfs_pal_udp_sendto(s, buf, len, group, port);
        if (grc < 0 && !rc)
            rc = grc;
    }
    return rc;
}

#endif /* MXFS_LIBMXFS_STATIC_PEERS_H */
