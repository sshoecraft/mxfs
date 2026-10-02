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
 * Is the peer excluded RIGHT NOW?  0 when it is: disconnected, its disk
 * Outdated, a STONITHED receipt naming it, and the fence authority reporting
 * it off and inhibited under that receipt's episode.  This is both the fence
 * evidence and the re-check before every irreversible recovery step: a peer
 * that was started again, or reconnected, fails it.
 */
int mxfs_drbd_judge_excluded(const struct mxfs_pal_drbd_report *r,
                             char *why, size_t whylen);

/*
 * This node's participant index in the pair's compare-and-swap: 0 for the
 * endpoint with the lower IPv4 address.  Connected, each side's local address
 * is the other's peer address, so the two sides always compute complementary
 * indices.  -EINVAL when either address does not parse or they are equal.
 */
int mxfs_drbd_participant_index(const struct mxfs_pal_drbd_report *r);

#endif /* MXFS_DRBDFENCE_H */
