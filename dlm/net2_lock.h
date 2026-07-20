/*
 * MXFS — Multinode XFS
 * NET2 lock plane — client API (§7.B, §11 step 4)
 *
 * Effect-idempotent lock operations against the sharded replicated
 * service in net2_shard.{c,h}.  Every mutating op carries the full §6
 * identity {slot+inc, request_id, resource, epoch, term}; a duplicate
 * (client re-issue after leader failover) returns its ORIGINAL result
 * from the replicated completed-op cache.
 *
 * grant_gen tokens are u64 and never 0 (XFS gen==0 discriminator
 * sites); transport_caw() stays false, so XFS compares tokens with
 * the monotone `>` paths.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_LOCK_H
#define MXFS_LIBMXFS_NET2_LOCK_H

#include "net2_shard.h"

/*
 * Blocking acquire (convert = acquire with a different mode while
 * holding).  Returns 0 with gen_out/dir_epoch_out set on grant;
 * -ETIMEDOUT past deadline_ms (op stays pending client-side and keeps
 * re-issuing until cancelled by release or lockspace stop);
 * -EAGAIN if the local held-cap (max_held) is reached;
 * -ENOSPC if the client request table is full.
 */
int net2_lock_acquire(struct net2_lockspace *ls,
                      const struct mxfs_resource_id *resource, uint8_t mode,
                      uint32_t deadline_ms, uint64_t *gen_out,
                      uint64_t *dir_epoch_out);

/*
 * Gen-qualified release.  Blocks for the quorum-committed RELEASE_ACK.
 * Returns 0, -ESTALE (tenure moved on — caller re-arms per the XFS
 * release-fencing contract), or -ETIMEDOUT.
 */
int net2_lock_release(struct net2_lockspace *ls,
                      const struct mxfs_resource_id *resource, uint64_t gen,
                      uint32_t deadline_ms);

/* Client-held table introspection (harness asserts + the §7.B
 * recovery-report source).  Returns held mode or MXFS_LOCK_NL. */
uint8_t net2_lock_held_mode(struct net2_lockspace *ls,
                            const struct mxfs_resource_id *resource,
                            uint64_t *gen_out);

#endif /* MXFS_LIBMXFS_NET2_LOCK_H */
