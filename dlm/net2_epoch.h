/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net2_epoch — MEPOCH single-decree membership-epoch authority (§7.C).
 *
 * One committed record {epoch, member_mask, fenced_mask, slot→inc} is
 * the single source of truth; it persists in each node's OWN disklock
 * heartbeat record (single-writer sector) and replicates by a
 * single-decree round over the voters of the CURRENT epoch: the 3
 * lowest member slots (5 at ≥16 members).  Voters stage the candidate
 * PREPARED in their own record before ACKing, so a proposer crash can
 * never fork the epoch — the next deterministic proposer adopts any
 * PREPARED candidate it finds on disk.
 *
 * Storage access is a vtable so the module builds and verifies in the
 * user harness against a file-backed 64×512 B disklock image; the
 * kernel wiring backs it with the real disklock I/O path at its
 * integration step.  Message delivery is caller-wired: the owner
 * registers a ctx recv callback and routes N2_MEPOCH_* frames into
 * net2_mepoch_rx().  Both builds, PAL only.
 */
#ifndef MXFS_NET2_EPOCH_H
#define MXFS_NET2_EPOCH_H

#include "net2.h"
#include "disklock.h"

struct net2_mepoch;

/* Read any slot's record (-ENOENT if absent/invalid); write goes to the
 * caller's OWN slot only (single-writer discipline). */
struct net2_mepoch_storage {
	void *data;
	int (*read_rec)(void *data, uint16_t slot,
	                struct mxfs_mepoch_rec *out);
	int (*write_rec)(void *data, const struct mxfs_mepoch_rec *rec);
};

/* NACK/failure reasons (also gate-5 evidence) */
enum net2_mepoch_reason {
	N2ME_OK = 0,
	N2ME_NOT_MONOTONIC,     /* cand epoch != committed + 1            */
	N2ME_FENCED_SHRANK,     /* fenced' does not cover fenced          */
	N2ME_NO_FENCE_PROOF,    /* exclusion without incarnation-qualified
	                         * fence_done evidence                    */
	N2ME_NOT_VOTER,         /* I am not a voter of the current epoch  */
	N2ME_STALE_ROUND,       /* candidate older than a staged one      */
};

struct net2_mepoch_cfg {
	uint16_t self_slot;
	uint32_t self_inc;              /* persisted, already bumped (§5)  */
	uint32_t lease_ms;              /* 0 → 10000 (§7.C mepoch_lease)   */
	uint32_t probe_interval_ms;     /* 0 → 1000; ×2 = proposer takeover */
	uint32_t round_retry_ms;        /* 0 → 500; re-broadcast cadence   */
	struct net2_mepoch_storage st;
	struct mxfs_net2_ctx *net;

	/* A record COMMITTED (bootstrap, rx, or own round): the consumer
	 * re-derives everything (shard configs via
	 * net2_lockspace_epoch_commit, freeze require_epoch, ...). */
	void (*committed_cb)(void *cb_data, const struct mxfs_mepoch_rec *r,
	                     const uint32_t *member_incs);
	/* Lease self-freeze visibility (§7.E: visible, never silent). */
	void (*freeze_cb)(void *cb_data, bool frozen);
	/* Disk-visible self-fence: a committed record excludes ME. */
	void (*self_fence_cb)(void *cb_data, uint64_t epoch);
	void *cb_data;
};

int  net2_mepoch_create(const struct net2_mepoch_cfg *cfg,
                        struct net2_mepoch **out);
void net2_mepoch_destroy(struct net2_mepoch *mp);

/* Mount-time: read all 64 HB records, adopt the max valid COMMITTED
 * record; none found → commit epoch 1 with self as sole member (a
 * 1-member cluster is its own quorum).  Fires committed_cb. */
int  net2_mepoch_bootstrap(struct net2_mepoch *mp);

/* Start a single-decree round toward {member', fenced'}.  fence_ok_mask
 * = slots whose removal carries incarnation-qualified fence_done proof
 * (§7.D supplies this at step 6; the harness passes it explicitly).
 * incs = candidate slot→incarnation table (NULL → carry the current
 * view, with self always stamped from cfg).  Returns -EPERM when this
 * node is not the current deterministic proposer. */
int  net2_mepoch_propose(struct net2_mepoch *mp, uint64_t member_mask,
                         uint64_t fenced_mask, uint64_t fence_ok_mask,
                         const uint32_t *incs);

/* Deliver one N2_MEPOCH_* frame (caller routes by type). */
void net2_mepoch_rx(struct net2_mepoch *mp, const struct mxfs_net2_id *src,
                    const void *payload, uint32_t len);

/* Observer input: refresh/dirty a slot's liveness for proposer
 * determinism (the §7.C SUSPECT machine feeds this; the harness drives
 * it directly). */
void net2_mepoch_suspect(struct net2_mepoch *mp, uint16_t slot,
                         bool suspected);

/* Drive timers: round retry, proposer takeover, lease self-freeze,
 * periodic disk scan (PREPARED adoption + self-fence check). */
void net2_mepoch_tick(struct net2_mepoch *mp, uint64_t now_ms);

/* Committed view (returns false before any commit is known). */
bool net2_mepoch_committed(struct net2_mepoch *mp,
                           struct mxfs_mepoch_rec *out,
                           uint32_t *incs_out /* MXFS_MAX_NODES or NULL */);

/* Round observability (gate-5 evidence: a NACKed exclusion leaves the
 * round dead with the reason recorded, never a commit). */
void net2_mepoch_round_status(struct net2_mepoch *mp, bool *active,
                              uint8_t *last_reason);

/* Pack/unpack + crc for the on-disk record (LE; crc over bytes 0..39). */
void mxfs_mepoch_rec_seal(struct mxfs_mepoch_rec *r);
bool mxfs_mepoch_rec_valid(const struct mxfs_mepoch_rec *r);

#endif /* MXFS_NET2_EPOCH_H */
