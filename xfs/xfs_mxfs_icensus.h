/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS intent/done census for untrusted (foreign or adopted) slice replay
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED interim step; design-consult
 * mount-barrier ruling stop-ship 1:
 * docs/rulings/mount-barrier-items-3-4-6c-window-arm.md).
 *
 * An untrusted replay applies no intent/done item — a dead peer's intents
 * cannot be inserted into this node's live AIL, and completing them from a
 * replay context is illegal on the mount barrier (see the ledger record's
 * item 5 for the real completion design).  Before this file every such item
 * was dropped silently (P226-UNTRUSTED-INTENT-SKIP) and the slice was then
 * PUBLISHED as recovered, extinguishing the obligation with no owner and no
 * durable record.
 *
 * The census records every intent the slice carries by its log id together
 * with the AG set its extents/inodes name, and retires each id when its done
 * item is seen.  At the end of the replay the OPEN set is the slice's
 * undischarged obligations: a foreign replay with any open entry FAILS
 * BEFORE PURGE — refused through the D-513 terminal-outcome path with reason
 * INTENTS_UNDISCHARGED and a quarantine domain equal to the union of the open
 * intents' AGs (FSWIDE when any of them is unmappable).  Nothing is purged,
 * no heartbeat sector is zeroed; the slot stays a quarantined guard until
 * repair, exactly like every other refused slice.
 *
 * Transaction admission is honoured on BOTH sides by construction: an
 * ATOMIC-SKIPped transaction never reaches the item loop, so neither its
 * intents nor its dones enter the census, and that replay already fails
 * POLICY_REFUSED — the census domain is folded into that verdict so the
 * quarantine also covers the open obligations.
 *
 * (item 5 increment 1, design-consult ruling
 * ruling-intents-item5-efi-completion-design): the census now keeps, per
 * intent, the EXTENTS it names and the whole-transaction verdict of the
 * intent's transaction and of the done's transaction, and CLASSIFIES every
 * entry still open at the end of the slice:
 *
 *   intent txn      done                          class
 *   admitted        admitted done                 CLOSED   (retired, as before)
 *   admitted        none                          RECOVER  (a real obligation:
 *                                                 the extents are parked
 *                                                 allocated-and-unreferenced)
 *   admitted        done in a non-admitted txn    QUARANTINE (ambiguous —
 *                                                 never guess)
 *   not admitted    any                           QUARANTINE
 *   any             malformed / duplicate id / overlapping RECOVER extents /
 *                   realtime / non-EFI class / unmappable   QUARANTINE
 *
 * "admitted" = the transaction's images applied: MXFS_TXNV_ADMIT (every
 * image tokenized), MXFS_TXNV_UNTAINTED (nothing gated rides in it; inode
 * items keep their node-independent changecount gate, a proven-safe redo)
 * or MXFS_TXNV_SNLOCAL (kind-17 + victim snlocal marker).  SKIP, SBCLEAN,
 * PREINC and UNSET are not admission.
 *
 * Increment 1 changes NO disposition: any open entry still refuses the
 * slice terminally.  It makes the RECOVER/QUARANTINE split visible so the
 * completion increments can act on RECOVER only.
 */
#ifndef	__XFS_MXFS_ICENSUS_H__
#define	__XFS_MXFS_ICENSUS_H__

struct xlog;
struct xlog_recover_item;

/* the per-entry classification of an OPEN census entry. */
#define MXFS_ICENSUS_CLS_UNCLASSIFIED	0
#define MXFS_ICENSUS_CLS_RECOVER	1
#define MXFS_ICENSUS_CLS_QUARANTINE	2

/*
 * Account one skipped intent/done item of an untrusted replay.  `verdict`
 * is the enclosing transaction's MXFS_TXNV_* whole-transaction verdict.
 */
void mxfs_icensus_note(struct xlog *log, struct xlog_recover_item *item,
		       uint64_t lsn, uint8_t verdict);

/*
 * Undischarged obligations after the replay: returns open + overflow (plus
 * 1 with *fswide set when the census itself could not be kept — allocation
 * failure — so the caller fails closed).  Fills the quarantine domain of the
 * open set and the malformed count.  Prints the P226-ICENSUS summary line
 * exactly once per log.
 */
uint32_t mxfs_icensus_undischarged(struct xlog *log, const char *src,
				   uint64_t *ag_mask, bool *fswide,
				   uint32_t *malformed);

/*
 * classify every open entry (idempotent; runs once per log) and
 * report the split.  *recover = entries whose extents may be completed by
 * the recovery owner (their AG union in *recover_mask); *quarantine =
 * entries that must keep the terminal refusal (AG union *q_mask, *q_fswide
 * when any of them is unmappable).  A lost/overflowed census counts as one
 * FSWIDE quarantine entry.  Prints one P226-ICENSUS-CLASS line per entry
 * (bounded) and the P226-ICENSUS-SPLIT summary.
 */
void mxfs_icensus_classify(struct xlog *log, const char *src,
			   uint32_t *recover, uint64_t *recover_mask,
			   uint32_t *quarantine, uint64_t *q_mask,
			   bool *q_fswide);

void mxfs_icensus_free(struct xlog *log);

struct mxfs_recov_obl_ext;

/*
 * (item 5 increment 2): copy the RECOVER entries' extents out of the
 * census into a caller-owned obligation list (recov_obl.h entries: fsbno,
 * agno, len) so they outlive the shadow log.  Runs the classification if it
 * has not run.  *ext is kvmalloc'd (caller frees with kvfree), *n the entry
 * count (0 with *ext NULL when there is nothing to recover).  Returns 0, or
 * -ENOMEM (the caller then quarantines: a lost list is never "no
 * obligations"), or -EOVERFLOW when the RECOVER extents exceed
 * MXFS_RECOV_OBL_MAX_EXTENTS (quarantine, ruling P1 bounded memory).
 */
int mxfs_icensus_export_recover(struct xlog *log,
				struct mxfs_recov_obl_ext **ext, uint32_t *n);

#endif	/* __XFS_MXFS_ICENSUS_H__ */
