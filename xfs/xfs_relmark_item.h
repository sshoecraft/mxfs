/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS clean-release marker log item (sess403, design-consult ruling
 * docs/rulings/release-marker-log-item-redundant-clean.md).
 *
 * A node that cleanly releases an EX/PW tenure {class, resource, lineage,
 * grant_epoch} logs ONE of these into its OWN journal slice after the
 * Invariant-1 drain has completed and BEFORE the on-disk unlock CAS, and
 * forces it to disk synchronously.  It certifies: "every image this node
 * logged under that tenure is on the platter".  Foreign replay of the node's
 * slice collects the markers in pass 1 and classifies buffer images whose
 * token names a marked tenure as REDUNDANT_CLEAN — skipped silently, never
 * applied, never refused (no quarantine).  Without the marker a released
 * tenure's records evaluate not_held / stale_epoch at replay and refuse the
 * slice (kill5b, D-TMPFILE-CHURN-KILL-FOREIGN-REPLAY-EFSCORRUPTED-402).
 *
 * The marker lives in the same ordered slice as the records it covers, so
 * its lifetime is matched to theirs automatically (a tail that still covers
 * a tenure's records also covers its later marker), and it is immune to the
 * CAW slot being tombstoned, recycled or re-bound — the reason the
 * slot-resident design was rejected.
 */
#ifndef	__XFS_RELMARK_ITEM_H__
#define	__XFS_RELMARK_ITEM_H__

struct xfs_trans;
struct xfs_mount;
struct xlog;

struct xfs_relmark_item {
	struct xfs_log_item		mr_item;
	struct mxfs_relmark_log_format	mr_format;
};

extern struct kmem_cache	*xfs_relmark_cache;

/* per-token verdict of the untrusted-replay authority gate (stored on
 * xlog_recover_item.ri_mxfs_verdict, see mxfs_shadow_eval_token) */
#define MXFS_RI_VERDICT_NONE		0	/* not evaluated / not a buf item */
#define MXFS_RI_VERDICT_REFUSE		1
#define MXFS_RI_VERDICT_APPLY		2	/* held at death: enforceable */
#define MXFS_RI_VERDICT_REDUNDANT	3	/* cleanly released: skip silently */
#define MXFS_RI_VERDICT_PREINC		4	/* sess434: another incarnation of an
						 * ADOPTED victim's slot — published
						 * by construction; whole txn skips */

/*
 * Publish a clean-release marker for a tenure this node is about to unlock.
 * Blocks until the marker is durable (sync log force).  Returns 0, or a
 * negative errno when the marker could not be made durable (shutdown, no
 * log) — the caller decides whether the release may proceed.
 */
int mxfs_relmark_publish(struct xfs_mount *mp, uint16_t auth_class,
			 uint64_t resource, uint64_t lineage,
			 uint64_t grant_epoch, const char *who);

void mxfs_relmark_counters(uint64_t *published, uint64_t *failed,
			   uint64_t *skipped_noid);
/* xfs_mxfs_dlm.c: per-release-site production counters */
void mxfs_relmark_site_counters(uint64_t *ino_marked, uint64_t *ino_failed,
				uint64_t *ag_marked, uint64_t *ag_failed,
				uint64_t *iclus_unmarked);
/* sess448: cluster-class marker counters (mxfs_iclus_disk_release) */
void mxfs_relmark_iclus_counters(uint64_t *marked, uint64_t *failed,
				 uint64_t *reinstall_refused);

/* pass-1 table on an untrusted-replay xlog */
bool mxfs_relmark_lookup(struct xlog *log, uint16_t auth_class,
			 uint64_t resource, uint64_t lineage,
			 uint64_t grant_epoch, uint32_t owner_slot,
			 uint64_t owner_epoch);
void mxfs_relmark_tbl_free(struct xlog *log);
uint32_t mxfs_relmark_tbl_count(struct xlog *log, uint32_t *overflow);

#endif	/* __XFS_RELMARK_ITEM_H__ */
