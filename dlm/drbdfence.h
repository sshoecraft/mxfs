/*
 * MXFS — Multinode XFS
 * The DRBD attachment's judgments over a witness report.
 *
 * pal/linux/drbd.c runs the witness and parses its report; it decides
 * nothing.  These functions decide, from the report alone, whether a DRBD
 * device may be admitted and whether a dead peer is excluded.  Every state is
 * matched exactly: DRBD's DUnknown, Inconsistent and Diskless are not
 * Outdated, and an enum ordering is never a proof
 * (docs/rulings/drbd-dual-primary-attachment.md).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef MXFS_DRBDFENCE_H
#define MXFS_DRBDFENCE_H

#include "../pal/pal.h"

/* The fence-peer handler this attachment's evidence is built on. */
#define MXFS_DRBD_FENCE_HANDLER "/usr/sbin/mxfs-drbd-fence-peer"

/*
 * May this node mount the DRBD device read-write?  0 to admit; -EPERM with
 * `why` naming the first unmet condition.  Two shapes admit:
 *   connected  — both disks UpToDate, the link Connected, and the fence
 *                authority reachable and holding no inhibit on the peer;
 *   survivor   — the peer fenced in the current episode: disconnected, the
 *                peer's disk Outdated, and the authority reporting the peer
 *                off and still inhibited under the receipt's episode.
 * Both require protocol C, two primaries, `fencing resource-and-stonith`
 * with this attachment's handler, no automatic split-brain resolution, no
 * suspended I/O, and this node Primary and UpToDate.
 */
int mxfs_drbd_judge_arm(const struct mxfs_pal_drbd_report *r,
                        char *why, size_t whylen);

/*
 * Which exclusion held.  The two are different proofs and are certified as
 * different fence kinds; neither is ever accepted as the other.
 *   STONITH  — a node fence powered the peer off and holds it off
 *              (STONITHED receipt, authority "shut off"): kind 25.
 *   EXCLUDED — the built-in two-node authority: this node won the pair's
 *              fixed tie-break, isolated the peer from this host's network
 *              and left DRBD StandAlone under a durable inhibit (EXCLUDED
 *              receipt, authority "excluded").  It proves the peer can no
 *              longer reach this replica or this lock manager, not that the
 *              peer is off: kind 26.
 */
enum mxfs_drbd_exclusion {
    MXFS_DRBD_EXCLUSION_NONE    = 0,
    MXFS_DRBD_EXCLUSION_STONITH = 1,
    MXFS_DRBD_EXCLUSION_EXCLUDED = 2,
};

/*
 * Is the peer excluded RIGHT NOW?  0 when it is: disconnected, its disk
 * Outdated, a receipt naming it, and the fence authority reporting it
 * excluded under that receipt's episode, by one of the two shapes above
 * (*how, when non-NULL, says which).  This is both the fence evidence and the
 * re-check before every irreversible recovery step: a peer that was started
 * again, or reconnected, fails it.
 */
int mxfs_drbd_judge_excluded_how(const struct mxfs_pal_drbd_report *r,
                                 enum mxfs_drbd_exclusion *how,
                                 char *why, size_t whylen);
int mxfs_drbd_judge_excluded(const struct mxfs_pal_drbd_report *r,
                             char *why, size_t whylen);

/*
 * Is the peer Secondary on a Connected link?  0 when this node is a working
 * Primary (as for admission), the link is exactly Connected, both disks are
 * UpToDate and the peer is Secondary, with no inhibit on it.  This is the
 * evidence of fence kind 27 (MXFS_FENCE_KIND_DRBD_PEER_SECONDARY_V1): no
 * incarnation is alive on the peer, and every write any earlier one made is
 * on this disk.  It is a fact about incarnations that have ENDED, never a
 * continuing fence: the peer may be promoted the moment after the report
 * was taken, so nothing may be re-checked or cleared against it.
 *
 * The /proc/drbd line the report's connection, role and disk states come
 * from is printed from one copy of the device's state word, so they are one
 * instant's state, not fields read at different times.
 */
int mxfs_drbd_judge_peer_secondary(const struct mxfs_pal_drbd_report *r,
                                   char *why, size_t whylen);

/*
 * This node's participant index in the pair's compare-and-swap: 0 for the
 * endpoint with the lower IPv4 address.  Connected, each side's local address
 * is the other's peer address, so the two sides always compute complementary
 * indices.  -EINVAL when either address does not parse or they are equal.
 */
int mxfs_drbd_participant_index(const struct mxfs_pal_drbd_report *r);

#endif /* MXFS_DRBDFENCE_H */
