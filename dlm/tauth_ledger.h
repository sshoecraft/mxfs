/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS TCP durable-authority ledger — the LEDGER LAYER
 * (docs/tcp-authority-ledger.md step 3c, sess422; design-consult rulings in ccmemory
 * docs/rulings/tauth-step3-master-ledger-design.md).
 *
 * Sits on the shadow-page store (tauth_store.h) and owns the ENTRIES: one
 * authority record per resource-hash slot (mxfs_tauth.h).  The DLM master
 * (dlm/dlm.c) never touches a page image directly; it describes a page
 * transition as a batch of operations on ONE page and this layer applies it
 * as ONE durable store write:
 *
 *   decide (dlm.c, table_rwlock)  ->  commit here (page mutex, no table
 *   lock)  ->  deliver (dlm.c)
 *
 * Invariants this layer enforces (fail closed = the batch is refused and
 * nothing is written):
 *   - every page has a committed cached image, loaded under the current
 *     page-OWNERSHIP GENERATION; a batch against a page loaded under an
 *     older generation, or with no image, is refused (-ESTALE) — the
 *     caller re-`ensure`s, which re-reads BOTH copies from the platter;
 *   - an ACTIVE record is never overwritten by a different resource
 *     (slot collision, -EEXIST) and never granted over (a conflicting
 *     live holder in the record = a double grant, -EBUSY);
 *   - grant_seq64 is minted from the page header's persisted allocator;
 *     exhaustion refuses (-ENOSPC); 0 is never a grant_seq;
 *   - UNKNOWN records and pages with no valid copy refuse every operation
 *     (-EUCLEAN); nothing here ever synthesises FREE or EMPTY;
 *   - a write whose outcome is uncertain POISONS the page: both copies are
 *     re-read and reconciled before any further operation, and an
 *     uncertain ACTIVE is never rolled back to FREE in memory.
 *
 * Usermode-buildable (tests/tauth links it against pal/linux/user.c).
 */
#ifndef MXFS_TAUTH_LEDGER_H
#define MXFS_TAUTH_LEDGER_H

#include "tauth_store.h"
#include "../include/mxfs/mxfs_dlm.h"     /* lock modes / types */

/* One page's cached committed image. */
struct mxfs_tauth_lpage {
    mxfs_mutex_t            *lock;
    struct mxfs_tauth_page  *img;           /* committed image, NULL = unloaded */
    uint64_t                load_gen;       /* ownership generation at load */
    bool                    poisoned;       /* uncertain write outstanding */
    /* 0.75.65 (D-0925): an image this node held was dropped by an
     * unreadable reload.  The page's platter authority is unknown until it
     * reads again, so a cache-driven purge must still visit it. */
    bool                    dropped;
    uint64_t                uncertain_seq;  /* the seq that write would carry */
    uint64_t                loads;
};

struct mxfs_tauth_ledger {
    struct mxfs_tauth_store store;
    struct mxfs_tauth_lpage *pages;
    uint32_t                npages;
    uint32_t                local_node;
    uint64_t                local_inc;      /* this mount's incarnation */
    uint16_t                local_slot;     /* this mount's heartbeat slot */
    /* Writer generation stamped on every record this master mints.  It is
     * the master's mount incarnation: unique per mount lifetime, never
     * reused (the disklock draws it), and `auth_node` on the record names
     * the master.  Existing records keep their epoch across takeovers. */
    uint64_t                authority_epoch;
    /* Page-ownership generation.  Set by the DLM on every membership
     * change (mxfs_tauth_ledger_set_owner_gen); a page image is valid only
     * while its load_gen equals it.  Plain 64-bit store/load. */
    volatile uint64_t       owner_gen;
    /* sess423 (step 4): the configuration id this node writes into every
     * page header (config_epoch) — a rendezvous cookie for the handoff
     * protocol, NEVER an authority.  Set by the DLM on every view change. */
    volatile uint64_t       config_id;
    /* test fault knobs (usermode test only; 0 = off) */
    uint32_t                torn_after_bytes;   /* one-shot: next commit tears */
    uint32_t                commit_delay_once_ms; /* one-shot: next commit sleeps
                                                   * before taking the page (lets
                                                   * a concurrent commit land first) */
    uint32_t                refuse_grant_once;  /* one-shot: next GRANT op -EBUSY */
    int                     fail_commit_once_rc;/* one-shot: next commit returns
                                                 * this rc before applying */
    uint32_t                fail_commit_skip;   /* ... after letting this many
                                                 * commits through */
    uint32_t                activate_hold_once_ms; /* one-shot: next activate
                                                 * sleeps between its platter
                                                 * read and its write (D-0347:
                                                 * lets a second claimer land
                                                 * in the window) */
    /* One-shot, page-exact (stored as page + 1; 0 = off).  The two outcomes a
     * bulk takeover pass must not report as a transferred page: an activate
     * that refuses (the page stays PREPARED under the departed authority) and
     * an import that fails after a successful activate (the page is durably
     * ours but not yet servable).  They are different states and are counted
     * differently, so each needs to be reachable on demand. */
    uint32_t                fail_activate_once_page;
    int                     fail_activate_once_rc;
    uint32_t                fail_scan_active_once_page;
    int                     fail_scan_active_once_rc;
    /* counters (forensic; read by the unit test and the P-lines) */
    uint64_t                commits, noop_commits, grants_ex, grants_pr,
                            releases_ex, releases_pr, stale_ops, collisions,
                            busy_denies, exhausted, poisons, reconciled,
                            uncommitted, purged, gen_refusals,
                            purge_kept,     /* 0.75.30: records a selective purge left frozen */
                            purge_inc_spared, /* EX records carrying the departed node id under
                                               * ANOTHER incarnation, left alone because retiring
                                               * one revokes a tenure its holder still holds */
                            prepares, activates, authority_refusals,
                            stale_writes,   /* sess426: -ESTALE/-EBUSY from the store */
                            page_full,      /* sess426 (D-0348): no free entry on the home page */
                            probes,         /* sess426 (D-0348): records found off their home index */
                            open_pinned,    /* 0.89.0 (D-0977): a full home page held at least one
                                             * tombstone kept only by open-holder marks */
                            open_marks;     /* 0.89.0: open-mark ops applied (set, clear, zero) */
    /* sess424 (instrumentation): durable page-write latency of the
     * commit path — total / max ms, printed as P-TAUTH-STATS every 1000
     * commits and at close.  The s422 rig run of step 3 hung a 30 s
     * workload with nothing measured; this names the cost per grant. */
    uint64_t                commit_ms_total, commit_ms_max, commit_ms_last_report;
};

void mxfs_tauth_ledger_stats(struct mxfs_tauth_ledger *l, const char *why);

/* sess423 (step 4): a page's durable authority as the platter (fresh) or
 * the cache reports it. */
struct mxfs_tauth_page_auth {
    uint8_t     state;          /* MXFS_TAUTH_PG_* */
    uint32_t    auth_node;
    uint64_t    auth_inc;
    uint32_t    target_node;    /* PREPARED only */
    uint64_t    target_inc;
    uint64_t    seq;            /* the record's commit seq */
    uint64_t    config_id;      /* the writer's configuration cookie */
    uint32_t    writer_node;
    uint64_t    writer_inc;
};

/* Ledger operations — a batch is applied to ONE page as ONE transition. */
enum mxfs_tauth_op_kind {
    MXFS_TAUTH_OP_GRANT_EX = 1,     /* mode PW/EX: explicit exclusive holder */
    MXFS_TAUTH_OP_GRANT_PR,         /* mode CR/CW/PR: holders[slot] bit */
    MXFS_TAUTH_OP_RELEASE_EX,       /* validated by {node, inc, grant_id} */
    MXFS_TAUTH_OP_RELEASE_PR,       /* validated by {lineage, slot, node, inc} */
    /*
     * 0.89.0 (D-0977): an open-mark change on a record this node holds NO
     * grant on any more (the master found no table entry for the releaser,
     * so no release op could carry it).  Applies open_op to an existing
     * record of the resource (ACTIVE or a tombstone); -ESTALE when the page
     * has no record — nothing to mark.  Never allocates.
     */
    MXFS_TAUTH_OP_OPEN_MARK,
};

/* open_op values (the wire carries the same ones in the LOCK_RELEASE) */
#define MXFS_TAUTH_OPEN_NONE     0      /* leave the releaser's mark as it is */
#define MXFS_TAUTH_OPEN_SET      1      /* releasing while the file is open here */
#define MXFS_TAUTH_OPEN_CLEAR   -1      /* releasing with no protected activity */
#define MXFS_TAUTH_OPEN_ZERO    -2      /* the genuine free: the incarnation is gone */

struct mxfs_tauth_op {
    uint8_t                 kind;           /* mxfs_tauth_op_kind */
    uint8_t                 mode;           /* granted / held mode */
    uint16_t                slot;           /* holder's heartbeat slot */
    uint32_t                node;           /* holder node id */
    uint64_t                inc;            /* holder mount incarnation */
    struct mxfs_resource_id res;
    uint64_t                lineage;        /* GRANT: lineage to record (0 =
                                             * keep/derive); RELEASE_PR: the
                                             * lineage the releaser holds */
    uint32_t                dir_epoch;
    /* grant_id: IN for RELEASE_EX (the grant being released), OUT for
     * GRANT_EX (the grant just minted). */
    uint64_t                authority_epoch;
    uint64_t                grant_seq64;
    uint64_t                lineage_out;    /* the record's lineage after the op */
    /*
     * 0.89.0 (D-0977): the releaser's open-mark change riding a RELEASE_*
     * (or an OPEN_MARK), applied to the record's open_holders inside the
     * same transition that retires the grant — publication is inseparable
     * from release.  open_holders_out is the record's mask AFTER the op;
     * for a GRANT_EX it is the snapshot the grant reply carries to the new
     * exclusive holder, whose destructive-inactivation guard reads it.
     */
    int8_t                  open_op;
    uint64_t                open_holders_out;
    int                     rc;             /* per-op outcome after commit:
                                             * 0 applied, -ESTALE not applied
                                             * (release of a superseded /
                                             * absent grant: ACK, no change) */
};

/* Open on the region; the store validates the header for THIS fs.  The
 * ledger starts with owner_gen 0 and no page loaded. */
int  mxfs_tauth_ledger_open(struct mxfs_tauth_ledger *l, mxfs_bdev_t *dev,
                            uint64_t base, uint64_t size,
                            const uint8_t fs_uuid[16],
                            uint32_t local_node, uint64_t local_inc,
                            uint16_t local_slot);
void mxfs_tauth_ledger_close(struct mxfs_tauth_ledger *l);

/* Membership / page-ownership changed: every cached image becomes stale
 * and is re-read from BOTH copies on its next ensure (takeover reload). */
void mxfs_tauth_ledger_set_owner_gen(struct mxfs_tauth_ledger *l, uint64_t gen);

/* sess427 (D-0348 step 2): a resource's HOME PAGE (routing) and preferred
 * home index, from the seeded hash and the region's page count.  Only
 * meaningful for an OPEN ledger (geometry comes from the region header);
 * every node on the same region routes identically. */
uint32_t mxfs_tauth_ledger_hash(const struct mxfs_tauth_ledger *l,
                                const struct mxfs_resource_id *res);
uint32_t mxfs_tauth_ledger_page(const struct mxfs_tauth_ledger *l,
                                const struct mxfs_resource_id *res);
uint32_t mxfs_tauth_ledger_home(const struct mxfs_tauth_ledger *l,
                                const struct mxfs_resource_id *res);

/* Make page_id's image current under `gen`: loads it (both copies) when
 * unloaded or loaded under an older generation; reconciles a poisoned page
 * (re-read both copies; the highest valid seq is the truth).  Does I/O;
 * call WITHOUT the DLM table lock.  0, -ESTALE (gen != owner_gen now),
 * -EUCLEAN (no valid copy: every resource on it is UNKNOWN), -EIO. */
int  mxfs_tauth_ledger_ensure(struct mxfs_tauth_ledger *l, uint32_t page_id,
                              uint64_t gen);

/* Copy out the record for `res` from the cached image (no I/O).  -ENOENT
 * when the page is not loaded under `gen`; -EUCLEAN when the record is
 * UNKNOWN.  0 otherwise (state may be EMPTY / FREE / ACTIVE). */
int  mxfs_tauth_ledger_lookup(struct mxfs_tauth_ledger *l,
                              const struct mxfs_resource_id *res, uint64_t gen,
                              struct mxfs_tauth_entry *out);

/* Visit every ACTIVE record of a loaded page (blocker import).  The
 * callback receives a COPY; it must not call back into the ledger. */
typedef void (*mxfs_tauth_scan_cb)(void *data, uint32_t slot,
                                   const struct mxfs_tauth_entry *e);
int  mxfs_tauth_ledger_scan_active(struct mxfs_tauth_ledger *l, uint32_t page_id,
                                   uint64_t gen, mxfs_tauth_scan_cb cb, void *data);

/*
 * The fence-time manifest source on the TCP transport (the replay gate's
 * authority: docs/tcp-authority-ledger.md step 5).  Visit every ACTIVE
 * record whose EXCLUSIVE holder is {node, slot} — the CAW slot table's
 * holders_ex/holders_pw scan, on the ledger.  Every page is read FRESH from
 * the platter (both copies, bulk runs, no cache): the prover may not master
 * the pages, and a dead authority's pages are never loaded through ensure().
 * A record naming the node and slot under a DIFFERENT incarnation is
 * counted in *inc_mismatch and NOT reported (the manifest is per victim
 * incarnation; the evaluator refuses other incarnations' images anyway).
 * *scanned = pages visited.  Returns 0, or -EUCLEAN when any page has no
 * committed image (the caller fails closed: an unreadable page could hide a
 * grant), -EIO, -ENOMEM, -EINVAL.  The callback receives a COPY and must not
 * call back into the ledger.
 */
typedef void (*mxfs_tauth_holder_cb)(void *data, uint32_t slot_idx,
                                     const struct mxfs_tauth_entry *e);
int  mxfs_tauth_ledger_collect_ex_holder(struct mxfs_tauth_ledger *l,
                                         uint32_t node, uint64_t inc, uint16_t slot,
                                         mxfs_tauth_holder_cb cb, void *data,
                                         uint32_t *scanned, uint32_t *inc_mismatch);

/*
 * The CURRENT platter record for `res`: both copies of its home page read
 * fresh, no cache side effect (the replay gate's current-safety check).
 * *slot_idx = page * MXFS_TAUTH_ENTRIES_PER_PAGE + entry index the record
 * was found at (UINT32_MAX when the resource has no record: *out is zeroed,
 * state EMPTY).  0 (out may be EMPTY / FREE / ACTIVE), -EUCLEAN (page or
 * record UNKNOWN), -EIO, -ENOMEM, -EINVAL.
 */
int  mxfs_tauth_ledger_read_fresh(struct mxfs_tauth_ledger *l,
                                  const struct mxfs_resource_id *res,
                                  struct mxfs_tauth_entry *out, uint32_t *slot_idx);

/*
 * Apply ops[0..nops) as ONE durable page transition.  All ops must name
 * resources on the same page.  Returns:
 *   0                  committed (or nothing to write: every op -ESTALE);
 *                      each op->rc says whether it was applied
 *   -ESTALE            gen mismatch / page not loaded under gen — refused,
 *                      nothing written
 *   -EEXIST            slot collision (ACTIVE record of another resource)
 *   -EBUSY             a conflicting live holder in the record (double grant)
 *   -ENOSPC            grant_seq / transition_seq exhausted
 *   -EUCLEAN           UNKNOWN record, or page has no valid copy
 *   -EIO               PROVEN not committed (re-read shows the old image)
 *   -ENOTRECOVERABLE   outcome UNCERTAIN: page poisoned; the caller must not
 *                      assume either way and must ensure() before any
 *                      further operation on the page
 *   -EINVAL / -ENOMEM
 */
int  mxfs_tauth_ledger_commit(struct mxfs_tauth_ledger *l,
                              struct mxfs_tauth_op *ops, int nops,
                              uint64_t gen, uint64_t config_epoch);

/*
 * Recovery purge: clear every record of holder `node` (exclusive holder
 * by node id; shared holder by heartbeat `slot` when slot >= 0) on the
 * pages this master owns (`owns_page` decides; NULL = all pages).  Called
 * only after the victim is PROVEN fenced and its slice replayed — the only
 * event that may retire a ledger-backed blocker.  Loads pages on demand.
 * Returns the number of records cleared, or a negative error (a failed
 * page aborts the walk: partial purge is reported, never hidden). */
typedef bool (*mxfs_tauth_owns_page_fn)(void *data, uint32_t page_id);
int  mxfs_tauth_ledger_purge_owner(struct mxfs_tauth_ledger *l, uint32_t node,
                                   int slot, uint64_t gen, uint64_t config_epoch,
                                   mxfs_tauth_owns_page_fn owns_page, void *data);
/* The same retirement on ONE page this node has just become master of (a
 * takeover activation): records cleared, or a negative error.
 *
 * `inc` NAMES THE DEPARTED INCARNATION AND IS NOT OPTIONAL HERE.  This form
 * runs while other mounts are live and writing — a page becomes servable the
 * moment the takeover activates it, before this purge — so an EX record
 * carrying the same node id under a different incarnation is a tenure
 * somebody still holds.  The page purge retires only records that match the
 * incarnation exactly; the rest are counted in purge_inc_spared and named by
 * P-TAUTH-PURGE-INC-SPARED.  Pass 0 only where no incarnation is knowable. */
int  mxfs_tauth_ledger_purge_owner_page(struct mxfs_tauth_ledger *l, uint32_t node,
                                        uint64_t inc, int slot, uint64_t gen,
                                        uint64_t config_epoch, uint32_t page);
/*
 * 0.75.30: the SELECTIVE forms of the two purges above.  `keep` is asked
 * about every record of the owner the walk would retire; nonzero keeps the
 * record untouched (its holder bits and EX included).  Used for a victim
 * whose slice replay was terminally refused with an AG-scoped verdict: the
 * records inside the quarantined domain stay frozen for the life of the
 * mount, the provably out-of-domain ones are retired so the rest of the
 * filesystem stays in service.  NULL keep = the unconditional purge.
 */
typedef int (*mxfs_tauth_purge_keep_fn)(void *data, const struct mxfs_tauth_entry *e);
int  mxfs_tauth_ledger_purge_owner_keep(struct mxfs_tauth_ledger *l, uint32_t node,
                                        int slot, uint64_t gen, uint64_t config_epoch,
                                        mxfs_tauth_owns_page_fn owns_page, void *data,
                                        mxfs_tauth_purge_keep_fn keep, void *keep_data);
int  mxfs_tauth_ledger_purge_owner_page_keep(struct mxfs_tauth_ledger *l, uint32_t node,
                                             uint64_t inc, int slot, uint64_t gen,
                                             uint64_t config_epoch, uint32_t page,
                                             mxfs_tauth_purge_keep_fn keep, void *keep_data);

/*
 * ─── sess423 step 4: page authority (docs/tcp-authority-ledger.md, ruling
 * docs/rulings/tauth-step4-ordered-handoff.md) ───
 *
 * Every entry transition (commit / purge) requires the page's durable
 * authority to be THIS node {local_node, local_inc} in state ACTIVE; any
 * other page refuses with -EPERM (the engine parks / re-routes; nothing is
 * written).  Authority moves ONLY through PREPARED -> ACTIVE:
 *
 *   prepare   the authority (or, for a fenced dead authority, the certified
 *             recovery coordinator naming it as `victim`) writes PREPARED
 *             {target} at seq+1 with the ENTRIES UNCHANGED, from a FRESH
 *             two-copy read; idempotent for the same target (returns the
 *             existing record's seq); a PREPARED page is retargeted only
 *             with `retarget` = the caller has PROVED the old target's
 *             incarnation can no longer write (recovery-purged)
 *   activate  the named target consumes the EXACT record (state PREPARED,
 *             target == self, seq == expect_seq) with ACTIVE(self) at
 *             seq+1, entries unchanged, from a FRESH read; or, with
 *             `bootstrap`, claims an UNOWNED page (the caller certifies it
 *             holds the lowest live heartbeat slot — the shared-disk
 *             arbitration for formation)
 *
 * A mismatch between what the caller expects and what the platter holds
 * is -ESTALE (nothing written).  -EUCLEAN = no valid copy / conflicted.
 */
void mxfs_tauth_ledger_set_config_id(struct mxfs_tauth_ledger *l, uint64_t id);

/* Report page_id's authority.  fresh = read BOTH copies from the platter
 * (no cache side effects); else from the cached image (-ENOENT when the
 * page is not loaded). */
int  mxfs_tauth_ledger_page_auth(struct mxfs_tauth_ledger *l, uint32_t page_id,
                                 bool fresh, struct mxfs_tauth_page_auth *out);

/* No I/O: is the cached image ACTIVE with authority == this node? */
bool mxfs_tauth_ledger_page_mine(struct mxfs_tauth_ledger *l, uint32_t page_id);

/*
 * 0.75.1: report EVERY page's authority from the platter in one bulk pass
 * (the store's run reads, both copies, 16 pages per transfer) instead of a
 * fresh two-copy read per page.  `auth` is NULL when the page has no valid
 * image (rc = -EIO unreadable, -EUCLEAN unknown/conflicted).  The takeover
 * of a departed authority's pages is the caller: on a 26k-page ledger over
 * iSCSI the per-page walk cost the heartbeat thread 48 s.
 */
typedef void (*mxfs_tauth_auth_cb)(void *data, uint32_t page_id,
                                   const struct mxfs_tauth_page_auth *auth,
                                   int rc);
int  mxfs_tauth_ledger_scan_auth(struct mxfs_tauth_ledger *l,
                                 mxfs_tauth_auth_cb cb, void *data,
                                 uint32_t *scanned);

/*
 * Nonzero while a BULK authority-takeover pass is running with per-page
 * logging suppressed.  A pass over a large ledger emits four lines a page
 * (31979 for one 7984-page pass), which on a node whose kernel log also goes
 * to a serial console is a cost paid inside the recovery completion the
 * cluster is waiting on.  Set only by the bulk passes, and only when the
 * dl_takeover_quiet knob asks; the per-page lines are unchanged everywhere
 * else, including the on-demand takeover of a single page.
 */
extern int mxfs_tauth_pass_quiet;

int  mxfs_tauth_ledger_prepare(struct mxfs_tauth_ledger *l, uint32_t page_id,
                               uint64_t gen, uint32_t target_node,
                               uint64_t target_inc, uint32_t victim_node,
                               uint64_t victim_inc, bool retarget,
                               uint64_t *prepared_seq);

/* sess428 (D-0349): bootstrap node only — UNOWNED -> PREPARED(target) in one
 * durable transition (design-consult ruling option (c)). */
int  mxfs_tauth_ledger_prepare_unowned(struct mxfs_tauth_ledger *l, uint32_t page_id,
                                       uint64_t gen, uint32_t target_node,
                                       uint64_t target_inc, uint64_t *prepared_seq);
int  mxfs_tauth_ledger_activate(struct mxfs_tauth_ledger *l, uint32_t page_id,
                                uint64_t gen, uint64_t expect_seq, bool bootstrap);

/* Pure helpers: does the record describe this exact resource? / rebuild
 * the resource id a record describes. */
bool mxfs_tauth_entry_is_res(const struct mxfs_tauth_entry *e,
                             const struct mxfs_resource_id *res);
void mxfs_tauth_entry_res(const struct mxfs_tauth_entry *e,
                          struct mxfs_resource_id *res);

#endif /* MXFS_TAUTH_LEDGER_H */
