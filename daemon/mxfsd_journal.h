/*
 * MXFS — Multinode XFS
 * Journal recovery coordination
 *
 * Each node gets a dedicated journal slot on the shared device. When a
 * node dies (lease expires), another node must replay the dead node's
 * journal before any of its previously locked resources can be reused.
 *
 * XFS handles the actual journal replay mechanics — we coordinate
 * which node does the replay and ensure proper lock ordering.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_JOURNAL_H
#define MXFSD_JOURNAL_H

#include <mxfs/mxfs_common.h>
#include <stdbool.h>
#include <pthread.h>

/* Journal slot state */
enum mxfsd_journal_slot_state {
	MXFSD_JSLOT_FREE = 0,
	MXFSD_JSLOT_ACTIVE,          /* node is alive and using this slot */
	MXFSD_JSLOT_NEEDS_RECOVERY,  /* node died, journal needs replay */
	MXFSD_JSLOT_RECOVERING,      /* replay in progress */
};

/* Per-slot tracking */
struct mxfsd_journal_slot {
	uint32_t                      slot_id;
	mxfs_node_id_t                owner;
	enum mxfsd_journal_slot_state state;
	mxfs_node_id_t                recovering_node;  /* who is doing recovery */
};

/* Journal subsystem context */
struct mxfsd_journal_ctx {
	struct mxfsd_journal_slot slots[MXFS_MAX_NODES];
	int                       slot_count;
	mxfs_node_id_t            local_node;
	uint32_t                  local_slot;
	pthread_mutex_t           lock;
};

int  mxfsd_journal_init(struct mxfsd_journal_ctx *ctx,
                        mxfs_node_id_t local_node, int slot_count);
void mxfsd_journal_shutdown(struct mxfsd_journal_ctx *ctx);

/* Slot management */
int  mxfsd_journal_claim_slot(struct mxfsd_journal_ctx *ctx);
void mxfsd_journal_release_slot(struct mxfsd_journal_ctx *ctx);

/* Recovery */
int  mxfsd_journal_mark_needs_recovery(struct mxfsd_journal_ctx *ctx,
                                       mxfs_node_id_t dead_node);
int  mxfsd_journal_begin_recovery(struct mxfsd_journal_ctx *ctx,
                                  mxfs_node_id_t dead_node);
int  mxfsd_journal_finish_recovery(struct mxfsd_journal_ctx *ctx,
                                   mxfs_node_id_t dead_node);

bool mxfsd_journal_needs_recovery(struct mxfsd_journal_ctx *ctx,
                                  mxfs_node_id_t node);

#endif /* MXFSD_JOURNAL_H */
