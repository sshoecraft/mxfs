/*
 * mxfs_ports.h — MXFS network port registry (single source of truth).
 *
 * Names reflect REALITY on the wire as of 0.10.x, not aspiration
 * (DLM_PLAN.md §14).  7602 is deliberately dual-use: the legacy mount
 * path's lease fallback (lease.c) and the CAW BAST multicast hint share
 * it, which only works because legacy mounts never run CAW BAST.  Both
 * v5 mount paths pass 7603 for the lease.  Unifying legacy lease onto
 * 7603 is a separately-versioned change — do NOT fold it into other work.
 */
#ifndef MXFS_PORTS_H
#define MXFS_PORTS_H

#define MXFS_PORT_DLM             7600  /* TCP: legacy DLM peer links      */
#define MXFS_PORT_DISCOVERY       7601  /* UDP mcast: peer discovery       */
#define MXFS_PORT_CAW_BAST        7602  /* UDP mcast: CAW BAST hints       */
#define MXFS_PORT_LEASE_LEGACY    7602  /* UDP mcast: legacy mount lease
                                         * fallback; coexists with CAW_BAST
                                         * only because legacy mounts don't
                                         * run CAW BAST                    */
#define MXFS_PORT_LEASE_V5        7603  /* UDP mcast: v5 lease (canonical) */
/* 7604 spare */
#define MXFS_PORT_NET2_MEMBERSHIP 7605  /* UDP: NET2 membership probe/vote */
#define MXFS_PORT_NET2_LINK_BASE  7610  /* TCP: NET2 link listen = base +
                                         * slot, one port per slot (range
                                         * 7610..7673); 7605 stays
                                         * membership-only               */

#endif /* MXFS_PORTS_H */
