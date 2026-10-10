// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS TCP durable-authority ledger — ledger layer (see tauth_ledger.h).
 */
#include "tauth_ledger.h"

/* see the declaration in tauth_ledger.h */
int mxfs_tauth_pass_quiet;
int mxfs_tauth_group_commit;

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

/*
 * One committer waiting in the group commit (see gc_lock in tauth_ledger.h).
 * Lives on the committer's stack for as long as it waits; the batch's writer
 * sets rc and then done, under gc_lock.
 */
struct tauth_gc_ent {
	struct tauth_gc_ent     *next;
	struct mxfs_tauth_page  *img;
	struct mxfs_tauth_wslot *ws;    /* its base, read by the committer itself */
	int                      rc;
	bool                     done;
};

/* The batch's vectors, kept with the ledger: only the writer of the batch in
 * flight (gc_busy) uses them, and they are too big for a kernel stack frame
 * this deep in the lock path. */
struct tauth_gc_vec {
	struct tauth_gc_ent     *batch[MXFS_TAUTH_WRITE_BATCH];
	struct mxfs_tauth_wslot *wsp[MXFS_TAUTH_WRITE_BATCH];
	struct mxfs_tauth_wreq   w[MXFS_TAUTH_WRITE_BATCH];
};

/* (D-0348 step 2): the seeded fnv1a-32 in mxfs_tauth.h over the
 * identity bytes of a resource id, routed by the region's page count.  The
 * DLM engine (dlm_shared.c resource_hash_raw) keeps its own unseeded fold
 * for its in-memory tables; the ledger's routing is the region's. */
uint32_t mxfs_tauth_ledger_hash(const struct mxfs_tauth_ledger *l,
				const struct mxfs_resource_id *res)
{
	return mxfs_tauth_res_hash(res, sizeof(*res), l ? l->store.hash_seed : 0);
}

uint32_t mxfs_tauth_ledger_page(const struct mxfs_tauth_ledger *l,
				const struct mxfs_resource_id *res)
{
	return mxfs_tauth_home_page(mxfs_tauth_ledger_hash(l, res),
				    l ? l->npages : MXFS_TAUTH_NPAGES);
}

uint32_t mxfs_tauth_ledger_home(const struct mxfs_tauth_ledger *l,
				const struct mxfs_resource_id *res)
{
	return mxfs_tauth_home_index(mxfs_tauth_ledger_hash(l, res),
				     l ? l->npages : MXFS_TAUTH_NPAGES);
}

bool mxfs_tauth_entry_is_res(const struct mxfs_tauth_entry *e,
			     const struct mxfs_resource_id *res)
{
	return e->res_type == res->type && e->ino == res->ino &&
	       e->offset == res->offset && e->ag_number == res->ag_number &&
	       e->volume == (uint64_t)res->volume;
}

static void entry_set_res(struct mxfs_tauth_entry *e,
			  const struct mxfs_resource_id *res)
{
	e->res_type = res->type;
	e->ino = res->ino;
	e->offset = res->offset;
	e->ag_number = res->ag_number;
	e->volume = (uint64_t)res->volume;
}

void mxfs_tauth_entry_res(const struct mxfs_tauth_entry *e,
			  struct mxfs_resource_id *res)
{
	memset(res, 0, sizeof(*res));
	res->type = e->res_type;
	res->ino = e->ino;
	res->offset = e->offset;
	res->ag_number = e->ag_number;
	res->volume = (mxfs_volume_id_t)e->volume;
}

static inline bool mode_is_exclusive(uint8_t mode)
{
	return mode >= MXFS_LOCK_PW;
}

/* ─── open / close ─── */

int mxfs_tauth_ledger_open(struct mxfs_tauth_ledger *l, mxfs_bdev_t *dev,
			   uint64_t base, uint64_t size,
			   const uint8_t fs_uuid[16],
			   uint32_t local_node, uint64_t local_inc,
			   uint16_t local_slot)
{
	uint32_t p;
	int rc;

	if (!l)
		return -EINVAL;
	memset(l, 0, sizeof(*l));
	rc = mxfs_tauth_store_open(&l->store, dev, base, size, fs_uuid,
				   local_node, local_inc);
	if (rc)
		return rc;
	l->npages = l->store.npages;
	l->local_node = local_node;
	l->local_inc = local_inc;
	l->local_slot = local_slot;
	l->authority_epoch = local_inc;
	l->pages = mxfs_pal_alloc(sizeof(*l->pages) * l->npages);
	if (!l->pages)
		return -ENOMEM;
	memset(l->pages, 0, sizeof(*l->pages) * l->npages);
	for (p = 0; p < l->npages; p++) {
		l->pages[p].lock = mxfs_pal_mutex_create();
		if (!l->pages[p].lock) {
			mxfs_tauth_ledger_close(l);
			return -ENOMEM;
		}
	}
	/* the group commit's queue; without it every commit is written alone */
	l->gc_lock = mxfs_pal_mutex_create();
	l->gc_cond = mxfs_pal_cond_create();
	l->gc_vec = mxfs_pal_alloc(sizeof(*l->gc_vec));
	if (!l->gc_lock || !l->gc_cond || !l->gc_vec) {
		if (l->gc_lock)
			mxfs_pal_mutex_destroy(l->gc_lock);
		if (l->gc_cond)
			mxfs_pal_cond_destroy(l->gc_cond);
		mxfs_pal_free(l->gc_vec);
		l->gc_lock = NULL;
		l->gc_cond = NULL;
		l->gc_vec = NULL;
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "tauth: P-TAUTH-LEDGER-OPEN node=%u inc=%llu slot=%u pages=%u "
		     "base=%llu",
		     local_node, (unsigned long long)local_inc, local_slot,
		     l->npages, (unsigned long long)base);
	return 0;
}

void mxfs_tauth_ledger_stats(struct mxfs_tauth_ledger *l, const char *why)
{
	if (!l)
		return;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "tauth: P-TAUTH-STATS why=%s node=%u commits=%llu noop=%llu "
		     "avg_ms=%llu max_ms=%llu grants_ex=%llu grants_pr=%llu "
		     "rel_ex=%llu rel_pr=%llu stale=%llu busy=%llu coll=%llu "
		     "poison=%llu recon=%llu uncommitted=%llu purged=%llu "
		     "genref=%llu authref=%llu prep=%llu act=%llu "
		     "gc_batches=%llu gc_pages=%llu gc_max=%llu",
		     why, l->local_node, (unsigned long long)l->commits,
		     (unsigned long long)l->noop_commits,
		     (unsigned long long)(l->commits ? l->commit_ms_total / l->commits : 0),
		     (unsigned long long)l->commit_ms_max,
		     (unsigned long long)l->grants_ex, (unsigned long long)l->grants_pr,
		     (unsigned long long)l->releases_ex, (unsigned long long)l->releases_pr,
		     (unsigned long long)l->stale_ops, (unsigned long long)l->busy_denies,
		     (unsigned long long)l->collisions, (unsigned long long)l->poisons,
		     (unsigned long long)l->reconciled, (unsigned long long)l->uncommitted,
		     (unsigned long long)l->purged, (unsigned long long)l->gen_refusals,
		     (unsigned long long)l->authority_refusals,
		     (unsigned long long)l->prepares, (unsigned long long)l->activates,
		     (unsigned long long)l->gc_batches, (unsigned long long)l->gc_pages,
		     (unsigned long long)l->gc_max);
	/* (D-0349): where a commit's milliseconds go, by phase */
	{
		struct mxfs_tauth_store *s = &l->store;
		uint64_t n = s->ph_commits ? s->ph_commits : 1;

		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "tauth: P-TAUTH-STORE-STATS why=%s node=%u commits=%llu "
			     "read_avg/max=%llu/%llu ticket=%llu/%llu body=%llu/%llu "
			     "publish=%llu/%llu flush=%llu/%llu stale_base=%llu busy=%llu "
			     "takeover=%llu resume=%llu stolen=%llu superseded=%llu "
				 "page_full=%llu probes=%llu span=%llu",
				     why, l->local_node, (unsigned long long)s->ph_commits,
				     (unsigned long long)(s->ph_read_ms / n),
				     (unsigned long long)s->ph_read_max,
				     (unsigned long long)(s->ph_ticket_ms / n),
				     (unsigned long long)s->ph_ticket_max,
				     (unsigned long long)(s->ph_body_ms / n),
				     (unsigned long long)s->ph_body_max,
				     (unsigned long long)(s->ph_publish_ms / n),
				     (unsigned long long)s->ph_publish_max,
				     (unsigned long long)(s->ph_flush_ms / n),
				     (unsigned long long)s->ph_flush_max,
				     (unsigned long long)s->stale_bases,
				     (unsigned long long)s->ticket_busy,
				     (unsigned long long)s->ticket_takeovers,
				     (unsigned long long)s->ticket_resumes,
				     (unsigned long long)s->stolen,
				     (unsigned long long)s->superseded,
				     (unsigned long long)l->page_full,
				     (unsigned long long)l->probes,
				     (unsigned long long)s->span_commits);
	}
	l->commit_ms_last_report = l->commits;
}

void mxfs_tauth_ledger_close(struct mxfs_tauth_ledger *l)
{
	uint32_t p;

	if (!l || !l->pages)
		return;
	mxfs_tauth_ledger_stats(l, "close");
	for (p = 0; p < l->npages; p++) {
		if (l->pages[p].img)
			mxfs_pal_free(l->pages[p].img);
		if (l->pages[p].lock)
			mxfs_pal_mutex_destroy(l->pages[p].lock);
	}
	mxfs_pal_free(l->pages);
	l->pages = NULL;
	l->npages = 0;
	if (l->gc_lock)
		mxfs_pal_mutex_destroy(l->gc_lock);
	if (l->gc_cond)
		mxfs_pal_cond_destroy(l->gc_cond);
	mxfs_pal_free(l->gc_vec);
	l->gc_lock = NULL;
	l->gc_cond = NULL;
	l->gc_vec = NULL;
}

void mxfs_tauth_ledger_set_owner_gen(struct mxfs_tauth_ledger *l, uint64_t gen)
{
	if (!l)
		return;
	l->owner_gen = gen;
}

/* ─── page images ─── */

/* Caller holds pg->lock.  Re-read both copies and install the winner. */
static int lpage_load_locked(struct mxfs_tauth_ledger *l, uint32_t page_id,
			     struct mxfs_tauth_lpage *pg, uint64_t gen)
{
	struct mxfs_tauth_page *img = pg->img;
	bool had = img != NULL;
	int rc;

	if (!img) {
		img = mxfs_pal_alloc(sizeof(*img));
		if (!img)
			return -ENOMEM;
	}
	rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
	if (rc) {
		/* keep no stale image around: an unreadable page is UNKNOWN */
		mxfs_pal_free(img);
		pg->img = NULL;
		if (had)
			pg->dropped = true;
		return rc;
	}
	pg->img = img;
	pg->load_gen = gen;
	pg->dropped = false;
	pg->loads++;
	return 0;
}

/* Caller holds pg->lock and the page is poisoned.  Reconcile: the platter
 * decides.  0 = reconciled (image current, poison cleared), else the page
 * stays poisoned. */
static int lpage_reconcile_locked(struct mxfs_tauth_ledger *l, uint32_t page_id,
				  struct mxfs_tauth_lpage *pg)
{
	struct mxfs_tauth_page *fresh = mxfs_pal_alloc(sizeof(*fresh));
	uint64_t old_seq = pg->img ? pg->img->hdr.seq : 0;
	int rc;

	if (!fresh)
		return -ENOMEM;
	rc = mxfs_tauth_page_read(&l->store, page_id, fresh, NULL);
	if (rc) {
		mxfs_pal_free(fresh);
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-RECONCILE-FAIL page=%u rc=%d -- stays poisoned",
			     page_id, rc);
		return rc;
	}
	if (pg->img)
		mxfs_pal_free(pg->img);
	pg->img = fresh;
	pg->poisoned = false;
	l->reconciled++;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "tauth: P-TAUTH-RECONCILE page=%u old_seq=%llu uncertain_seq=%llu "
		     "platter_seq=%llu committed=%d",
		     page_id, (unsigned long long)old_seq,
		     (unsigned long long)pg->uncertain_seq,
		     (unsigned long long)fresh->hdr.seq,
		     fresh->hdr.seq == pg->uncertain_seq ? 1 : 0);
	pg->uncertain_seq = 0;
	return 0;
}

int mxfs_tauth_ledger_ensure(struct mxfs_tauth_ledger *l, uint32_t page_id,
			     uint64_t gen)
{
	struct mxfs_tauth_lpage *pg;
	int rc = 0;

	if (!l || !l->pages || page_id >= l->npages)
		return -EINVAL;
	if (gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	if (pg->poisoned)
		rc = lpage_reconcile_locked(l, page_id, pg);
	if (rc == 0 && (!pg->img || pg->load_gen != gen))
		rc = lpage_load_locked(l, page_id, pg, gen);
	if (rc == 0 && pg->load_gen != gen)
		rc = -ESTALE;
	mxfs_pal_mutex_unlock(pg->lock);
	if (rc == 0 && gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	return rc;
}

/*
 * (D-0348, design-consult ruling tauth-
 * slot-collision-page-open-addressing): PAGE-LOCAL OPEN ADDRESSING.  A
 * resource's hash names its HOME PAGE (and a preferred home index on it);
 * the record may live in ANY of the page's entries, keyed by the FULL
 * resource identity.  Lookup: the home index first, then every entry.
 * Allocation (alloc=true): a FREE record of the same resource (keeps its
 * last_grant_seq), else the home index if EMPTY/FREE, else the lowest
 * EMPTY/FREE entry.  NULL = not present (lookup) / page full (alloc).
 * UNKNOWN entries are never allocated over.  idx_out = the entry index.
 */
static struct mxfs_tauth_entry *page_find_entry(struct mxfs_tauth_ledger *l,
						struct mxfs_tauth_page *img,
						const struct mxfs_resource_id *res,
						bool alloc, int *idx_out)
{
	uint32_t home = mxfs_tauth_ledger_home(l, res);
	int i, freelow = -1;

	if (idx_out)
		*idx_out = -1;
	if (img->ent[home].state != MXFS_TAUTH_ST_EMPTY &&
	    mxfs_tauth_entry_is_res(&img->ent[home], res)) {
		if (idx_out)
			*idx_out = (int)home;
		return &img->ent[home];
	}
	for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++) {
		struct mxfs_tauth_entry *e = &img->ent[i];

		if (e->state != MXFS_TAUTH_ST_EMPTY && mxfs_tauth_entry_is_res(e, res)) {
			if (idx_out)
				*idx_out = i;
			if (l)
				l->probes++;
			return e;
		}
		/*
		 * 0.89.0 (D-0977): a tombstone still carrying open-holder marks is
		 * a live lifetime record of ITS resource — a peer has that inode
		 * open and its next exclusive holder's guard must read the mark.
		 * It is never handed to another resource; only its own resource
		 * finds it (the same-resource match above).
		 */
		if (freelow < 0 && (e->state == MXFS_TAUTH_ST_EMPTY ||
				    (e->state == MXFS_TAUTH_ST_FREE && e->open_holders == 0)))
			freelow = i;
	}
	if (!alloc)
		return NULL;
	if (img->ent[home].state == MXFS_TAUTH_ST_EMPTY ||
	    (img->ent[home].state == MXFS_TAUTH_ST_FREE && img->ent[home].open_holders == 0)) {
		if (idx_out)
			*idx_out = (int)home;
		return &img->ent[home];
	}
	if (freelow < 0)
		return NULL;
	if (idx_out)
		*idx_out = freelow;
	if (l)
		l->probes++;
	return &img->ent[freelow];
}

int mxfs_tauth_ledger_lookup(struct mxfs_tauth_ledger *l,
			     const struct mxfs_resource_id *res, uint64_t gen,
			     struct mxfs_tauth_entry *out)
{
	uint32_t page_id;
	struct mxfs_tauth_lpage *pg;
	int rc = 0;

	if (!l || !l->pages || !res || !out)
		return -EINVAL;
	page_id = mxfs_tauth_ledger_page(l, res);
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	if (!pg->img || pg->load_gen != gen || pg->poisoned) {
		rc = -ENOENT;
	} else {
		const struct mxfs_tauth_entry *e = page_find_entry(l, pg->img, res, false, NULL);

		if (e)
			*out = *e;
		else
			memset(out, 0, sizeof(*out));       /* EMPTY: never recorded */
		if (out->state == MXFS_TAUTH_ST_UNKNOWN)
			rc = -EUCLEAN;
	}
	mxfs_pal_mutex_unlock(pg->lock);
	return rc;
}

int mxfs_tauth_ledger_scan_active(struct mxfs_tauth_ledger *l, uint32_t page_id,
				  uint64_t gen, mxfs_tauth_scan_cb cb, void *data)
{
	struct mxfs_tauth_lpage *pg;
	uint32_t i;
	int n = 0;

	if (!l || !l->pages || page_id >= l->npages || !cb)
		return -EINVAL;
	/*
	 * TEST FAULT (usermode): fail the scan ONE named page's import walks,
	 * once.  A page that activated but did not import is durably OURS and
	 * still unservable, which is a different outcome from a refused activate
	 * and has to be counted differently; this makes that case reachable.
	 */
	if (l->fail_scan_active_once_page == page_id + 1) {
		l->fail_scan_active_once_page = 0;
		return l->fail_scan_active_once_rc ? l->fail_scan_active_once_rc : -EIO;
	}
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	if (!pg->img || pg->load_gen != gen || pg->poisoned) {
		mxfs_pal_mutex_unlock(pg->lock);
		return -ENOENT;
	}
	for (i = 0; i < MXFS_TAUTH_ENTRIES_PER_PAGE; i++) {
		const struct mxfs_tauth_entry *e = &pg->img->ent[i];

		if (e->state == MXFS_TAUTH_ST_ACTIVE ||
		    e->state == MXFS_TAUTH_ST_UNKNOWN) {
			struct mxfs_tauth_entry copy = *e;

			cb(data, page_id * MXFS_TAUTH_ENTRIES_PER_PAGE + i, &copy);
			n++;
		}
	}
	mxfs_pal_mutex_unlock(pg->lock);
	return n;
}

/* ─── fence-time manifest source (TCP replay authority) ─── */

struct tauth_collect {
	uint32_t                node;
	uint64_t                inc;
	uint16_t                slot;
	mxfs_tauth_holder_cb    cb;
	void                    *data;
	uint32_t                scanned, unknown, io_err, inc_mismatch, found;
	uint32_t                first_bad;      /* first UNKNOWN/unreadable page */
};

static void tauth_collect_page(void *data, uint32_t page_id,
			       const struct mxfs_tauth_page *pg, int rc)
{
	struct tauth_collect *c = data;
	uint32_t i;

	c->scanned++;
	if (rc) {
		if (rc == -EIO)
			c->io_err++;
		else
			c->unknown++;
		if (c->unknown + c->io_err == 1)
			c->first_bad = page_id;
		return;
	}
	for (i = 0; i < MXFS_TAUTH_ENTRIES_PER_PAGE; i++) {
		const struct mxfs_tauth_entry *e = &pg->ent[i];

		if (e->state != MXFS_TAUTH_ST_ACTIVE || !e->ex_node)
			continue;
		if (e->ex_node != c->node || e->ex_slot != c->slot)
			continue;
		if (c->inc && e->ex_inc != c->inc) {
			c->inc_mismatch++;
			continue;
		}
		c->found++;
		c->cb(c->data, page_id * MXFS_TAUTH_ENTRIES_PER_PAGE + i, e);
	}
}

int mxfs_tauth_ledger_collect_ex_holder(struct mxfs_tauth_ledger *l,
					uint32_t node, uint64_t inc, uint16_t slot,
					mxfs_tauth_holder_cb cb, void *data,
					uint32_t *scanned, uint32_t *inc_mismatch)
{
	struct tauth_collect c;
	int rc;

	if (scanned)
		*scanned = 0;
	if (inc_mismatch)
		*inc_mismatch = 0;
	if (!l || !cb || !node)
		return -EINVAL;
	memset(&c, 0, sizeof(c));
	c.node = node;
	c.inc = inc;
	c.slot = slot;
	c.cb = cb;
	c.data = data;
	rc = mxfs_tauth_store_scan(&l->store, 0, l->npages, tauth_collect_page, &c);
	if (scanned)
		*scanned = c.scanned;
	if (inc_mismatch)
		*inc_mismatch = c.inc_mismatch;
	if (rc == 0 && (c.unknown || c.io_err)) {
		/* fail closed: a page without a committed image may hold a grant */
		rc = c.io_err ? -EIO : -EUCLEAN;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-COLLECT-INCOMPLETE node=%u slot=%u pages=%u "
			     "unknown=%u unreadable=%u first_bad=%u found=%u rc=%d -- "
			     "fence-time manifest cannot be complete (fail closed)",
			     node, slot, c.scanned, c.unknown, c.io_err, c.first_bad,
			     c.found, rc);
	}
	return rc;
}

int mxfs_tauth_ledger_read_fresh(struct mxfs_tauth_ledger *l,
				 const struct mxfs_resource_id *res,
				 struct mxfs_tauth_entry *out, uint32_t *slot_idx)
{
	struct mxfs_tauth_page *img;
	const struct mxfs_tauth_entry *e;
	uint32_t page_id;
	int idx = -1, rc;

	if (slot_idx)
		*slot_idx = UINT32_MAX;
	if (!l || !l->store.dev || !res || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	page_id = mxfs_tauth_ledger_page(l, res);
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
	if (rc == 0) {
		e = page_find_entry(l, img, res, false, &idx);
		if (e) {
			*out = *e;
			if (slot_idx)
				*slot_idx = page_id * MXFS_TAUTH_ENTRIES_PER_PAGE + (uint32_t)idx;
			if (out->state == MXFS_TAUTH_ST_UNKNOWN)
				rc = -EUCLEAN;
		}
	}
	mxfs_pal_free(img);
	return rc;
}

/* ─── step 4: page authority ─── */

/* Caller holds pg->lock and pg->img is loaded. */
static inline bool lpage_mine_locked(const struct mxfs_tauth_ledger *l,
				     const struct mxfs_tauth_lpage *pg)
{
	return pg->img &&
	       pg->img->hdr.auth_state == MXFS_TAUTH_PG_ACTIVE &&
	       pg->img->hdr.auth_node == l->local_node &&
	       pg->img->hdr.authority_epoch == l->local_inc;
}

static void page_auth_from(const struct mxfs_tauth_page *img,
			   struct mxfs_tauth_page_auth *out)
{
	memset(out, 0, sizeof(*out));
	out->state = img->hdr.auth_state;
	out->auth_node = img->hdr.auth_node;
	out->auth_inc = img->hdr.authority_epoch;
	out->target_node = img->hdr.target_node;
	out->target_inc = img->hdr.target_inc;
	out->seq = img->hdr.seq;
	out->config_id = img->hdr.config_epoch;
	out->writer_node = img->hdr.writer_node;
	out->writer_inc = img->hdr.writer_inc;
}

void mxfs_tauth_ledger_set_config_id(struct mxfs_tauth_ledger *l, uint64_t id)
{
	if (l)
		l->config_id = id;
}

bool mxfs_tauth_ledger_page_mine(struct mxfs_tauth_ledger *l, uint32_t page_id)
{
	struct mxfs_tauth_lpage *pg;
	bool mine;

	if (!l || !l->pages || page_id >= l->npages)
		return false;
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	mine = !pg->poisoned && lpage_mine_locked(l, pg);
	mxfs_pal_mutex_unlock(pg->lock);
	return mine;
}

/*
 * For a request that asked not to queue: never sleeps and never touches the
 * platter.  The page lock is held across every read and commit of the page,
 * so on a slow disk a thread that waits for it can wait behind several of
 * them; measured on the physical DRBD pair, the allocator's trylock slept
 * over 30 s in an activation's mutex_lock while it held a VM image's ILOCK.
 */
int mxfs_tauth_ledger_page_ready_nowait(struct mxfs_tauth_ledger *l, uint32_t page_id,
					uint64_t gen)
{
	struct mxfs_tauth_lpage *pg;
	bool ready;

	if (!l || !l->pages || page_id >= l->npages || gen != l->owner_gen)
		return 0;
	pg = &l->pages[page_id];
	if (!mxfs_pal_mutex_trylock(pg->lock))
		return -EBUSY;
	ready = !pg->poisoned && pg->img && pg->load_gen == gen &&
		lpage_mine_locked(l, pg);
	mxfs_pal_mutex_unlock(pg->lock);
	return ready ? 1 : 0;
}

struct tauth_auth_scan {
	mxfs_tauth_auth_cb  cb;
	void               *data;
	uint32_t            scanned;
};

static void tauth_auth_scan_page(void *data, uint32_t page_id,
				 const struct mxfs_tauth_page *pg, int rc)
{
	struct tauth_auth_scan *s = data;
	struct mxfs_tauth_page_auth a;

	s->scanned++;
	if (rc || !pg) {
		s->cb(s->data, page_id, NULL, rc ? rc : -EUCLEAN);
		return;
	}
	page_auth_from(pg, &a);
	s->cb(s->data, page_id, &a, 0);
}

int mxfs_tauth_ledger_scan_auth(struct mxfs_tauth_ledger *l,
				mxfs_tauth_auth_cb cb, void *data,
				uint32_t *scanned)
{
	struct tauth_auth_scan s;
	int rc;

	if (scanned)
		*scanned = 0;
	if (!l || !cb)
		return -EINVAL;
	memset(&s, 0, sizeof(s));
	s.cb = cb;
	s.data = data;
	rc = mxfs_tauth_store_scan(&l->store, 0, l->npages, tauth_auth_scan_page, &s);
	if (scanned)
		*scanned = s.scanned;
	return rc;
}

int mxfs_tauth_ledger_page_auth(struct mxfs_tauth_ledger *l, uint32_t page_id,
				bool fresh, struct mxfs_tauth_page_auth *out)
{
	struct mxfs_tauth_lpage *pg;
	int rc = 0;

	if (!l || !l->pages || page_id >= l->npages || !out)
		return -EINVAL;
	pg = &l->pages[page_id];
	if (fresh) {
		struct mxfs_tauth_page *img = mxfs_pal_alloc(sizeof(*img));

		if (!img)
			return -ENOMEM;
		rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
		if (rc == 0)
			page_auth_from(img, out);
		mxfs_pal_free(img);
		return rc;
	}
	mxfs_pal_mutex_lock(pg->lock);
	if (!pg->img || pg->poisoned)
		rc = -ENOENT;
	else
		page_auth_from(pg->img, out);
	mxfs_pal_mutex_unlock(pg->lock);
	return rc;
}

/* Caller holds pg->lock.  Write `img` (a patched FRESH image) as the next
 * seq and, on verified success, make it the cached image under `gen`.
 * The store's exact readback makes a lost same-seq race -EIO; the caller
 * treats every non-zero rc as "nothing changed" after a reconcile. */
static int lpage_write_fresh_locked(struct mxfs_tauth_ledger *l,
				    struct mxfs_tauth_lpage *pg,
				    struct mxfs_tauth_page *img, uint64_t gen)
{
	int rc = mxfs_tauth_page_write(&l->store, img, img->hdr.authority_epoch,
				       l->config_id, 0);

	if (rc == 0) {
		if (!pg->img) {
			pg->img = mxfs_pal_alloc(sizeof(*pg->img));
			if (!pg->img)
				return -ENOMEM;
		}
		memcpy(pg->img, img, sizeof(*img));
		pg->load_gen = gen;
		pg->poisoned = false;
		pg->uncertain_seq = 0;
		return 0;
	}
	if (rc == -EOVERFLOW)
		return -ENOSPC;
	if (rc == -ESTALE || rc == -EBUSY) {
		/* (D-0347): nothing was written — the platter moved past
		 * the image we patched (or another writer holds the spare).  The
		 * cache is refreshed so the caller's re-derivation starts from the
		 * truth; never poison (nothing is uncertain). */
		l->stale_writes++;
		(void)lpage_load_locked(l, img->hdr.page_id, pg, gen);
		return rc;
	}
	/* uncertain: poison and reconcile now; the caller re-reads before any
	 * further decision.  If the platter shows our image the write DID
	 * land (the caller re-verifies through a fresh read). */
	pg->poisoned = true;
	pg->uncertain_seq = img->hdr.seq;
	l->poisons++;
	(void)lpage_reconcile_locked(l, img->hdr.page_id, pg);
	return rc;
}

int mxfs_tauth_ledger_prepare(struct mxfs_tauth_ledger *l, uint32_t page_id,
			      uint64_t gen, uint32_t target_node,
			      uint64_t target_inc, uint32_t victim_node,
			      uint64_t victim_inc, bool retarget,
			      uint64_t *prepared_seq)
{
	struct mxfs_tauth_lpage *pg;
	struct mxfs_tauth_page *img;
	uint32_t want_node = victim_node ? victim_node : l->local_node;
	uint64_t want_inc = victim_node ? victim_inc : l->local_inc;
	int rc;

	if (!l || !l->pages || page_id >= l->npages || !target_node)
		return -EINVAL;
	if (gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	/* ruling 9: from a FRESH two-copy read, never the cache */
	rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
	if (rc)
		goto out;
	if (img->hdr.auth_state == MXFS_TAUTH_PG_PREPARED &&
	    img->hdr.auth_node == want_node && img->hdr.authority_epoch == want_inc &&
	    img->hdr.target_node == target_node && img->hdr.target_inc == target_inc) {
		/* idempotent: already prepared to this target */
		if (prepared_seq)
			*prepared_seq = img->hdr.seq;
		if (!pg->img || pg->img->hdr.seq != img->hdr.seq) {
			if (!pg->img)
				pg->img = mxfs_pal_alloc(sizeof(*pg->img));
			if (pg->img) {
				memcpy(pg->img, img, sizeof(*img));
				pg->load_gen = gen;
			}
		}
		rc = 0;
		goto out;
	}
	if (img->hdr.auth_state == MXFS_TAUTH_PG_ACTIVE) {
		if (img->hdr.auth_node != want_node || img->hdr.authority_epoch != want_inc) {
			l->authority_refusals++;
			rc = -EPERM;
			goto out;
		}
	} else if (img->hdr.auth_state == MXFS_TAUTH_PG_PREPARED) {
		if (img->hdr.auth_node != want_node || img->hdr.authority_epoch != want_inc ||
		    !retarget) {
			l->authority_refusals++;
			rc = -EPERM;
			goto out;
		}
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "tauth: P-TAUTH-RETARGET page=%u old_target=%u/%llu new_target=%u/%llu "
			     "-- the old target's incarnation is recovery-purged",
			     page_id, img->hdr.target_node,
			     (unsigned long long)img->hdr.target_inc, target_node,
			     (unsigned long long)target_inc);
	} else {
		/* UNOWNED pages are never prepared: the bootstrap node activates */
		rc = -EPERM;
		goto out;
	}
	img->hdr.auth_state = MXFS_TAUTH_PG_PREPARED;
	img->hdr.target_node = target_node;
	img->hdr.target_inc = target_inc;
	/* authority_epoch / auth_node stay = the (dead or live) authority */
	rc = lpage_write_fresh_locked(l, pg, img, gen);
	if (rc == 0) {
		l->prepares++;
		if (prepared_seq)
			*prepared_seq = pg->img->hdr.seq;
		if (!mxfs_tauth_pass_quiet)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				 "tauth: P-TAUTH-PREPARED page=%u seq=%llu auth=%u/%llu target=%u/%llu "
				 "by=%u/%llu cfg=%#llx",
				 page_id, (unsigned long long)pg->img->hdr.seq, want_node,
				 (unsigned long long)want_inc, target_node,
				 (unsigned long long)target_inc, l->local_node,
				 (unsigned long long)l->local_inc,
				 (unsigned long long)l->config_id);
	}
out:
	mxfs_pal_mutex_unlock(pg->lock);
	mxfs_pal_free(img);
	return rc;
}

/*
 * (D-0349, design-consult ruling option (c)): the BOOTSTRAP node prepares a
 * never-owned page straight to its view-owner in ONE durable transition —
 * UNOWNED -> PREPARED(auth=self, target) — instead of ACTIVE(self) followed
 * by PREPARED.  Nothing is drained from UNOWNED, so the intermediate ACTIVE
 * image bought no safety and cost a second serialized write per page on the
 * one node every requester is queued behind at formation.  The CAW is
 * conditioned on the complete fresh UNOWNED image (seq included) by
 * lpage_write_fresh_locked; the caller has already established that it is
 * the exclusive bootstrap node under a settled membership (D-0347).  The
 * target still performs the ordinary PREPARED -> ACTIVE(target) activation
 * (seq-checked) before it may decide anything.  Idempotent for a repeat.
 */
int mxfs_tauth_ledger_prepare_unowned(struct mxfs_tauth_ledger *l, uint32_t page_id,
				      uint64_t gen, uint32_t target_node,
				      uint64_t target_inc, uint64_t *prepared_seq)
{
	struct mxfs_tauth_lpage *pg;
	struct mxfs_tauth_page *img;
	int rc;

	if (!l || !l->pages || page_id >= l->npages || !target_node || !target_inc)
		return -EINVAL;
	if (gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
	if (rc)
		goto out;
	if (img->hdr.auth_state == MXFS_TAUTH_PG_PREPARED &&
	    img->hdr.auth_node == l->local_node && img->hdr.authority_epoch == l->local_inc &&
	    img->hdr.target_node == target_node && img->hdr.target_inc == target_inc) {
		if (prepared_seq)
			*prepared_seq = img->hdr.seq;
		if (!pg->img)
			pg->img = mxfs_pal_alloc(sizeof(*pg->img));
		if (pg->img) {
			memcpy(pg->img, img, sizeof(*img));
			pg->load_gen = gen;
		}
		rc = 0;
		goto out;
	}
	if (img->hdr.auth_state != MXFS_TAUTH_PG_UNOWNED) {
		l->authority_refusals++;
		rc = -EPERM;
		goto out;
	}
	img->hdr.auth_state = MXFS_TAUTH_PG_PREPARED;
	img->hdr.auth_node = l->local_node;
	img->hdr.authority_epoch = l->local_inc;
	img->hdr.target_node = target_node;
	img->hdr.target_inc = target_inc;
	rc = lpage_write_fresh_locked(l, pg, img, gen);
	if (rc == 0) {
		l->prepares++;
		if (prepared_seq)
			*prepared_seq = pg->img->hdr.seq;
		if (!mxfs_tauth_pass_quiet)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				 "tauth: P-TAUTH-PREPARED page=%u seq=%llu from=UNOWNED auth=%u/%llu "
				 "target=%u/%llu cfg=%#llx",
				 page_id, (unsigned long long)pg->img->hdr.seq, l->local_node,
				 (unsigned long long)l->local_inc, target_node,
				 (unsigned long long)target_inc, (unsigned long long)l->config_id);
	}
out:
	mxfs_pal_mutex_unlock(pg->lock);
	mxfs_pal_free(img);
	return rc;
}

int mxfs_tauth_ledger_activate(struct mxfs_tauth_ledger *l, uint32_t page_id,
			       uint64_t gen, uint64_t expect_seq, bool bootstrap)
{
	struct mxfs_tauth_lpage *pg;
	struct mxfs_tauth_page *img;
	uint8_t from;
	int rc;

	if (!l || !l->pages || page_id >= l->npages)
		return -EINVAL;
	/*
	 * TEST FAULT (usermode): refuse the activation of ONE named page, once.
	 * A refused activate is the case a bulk takeover pass must not mistake
	 * for a transfer — the page stays PREPARED under the departed authority,
	 * not ours, its records unpurged and unimported — so the accounting that
	 * says so has to be exercised rather than read.
	 */
	if (l->fail_activate_once_page == page_id + 1) {
		l->fail_activate_once_page = 0;
		return l->fail_activate_once_rc ? l->fail_activate_once_rc : -EIO;
	}
	if (gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	pg = &l->pages[page_id];
	mxfs_pal_mutex_lock(pg->lock);
	rc = mxfs_tauth_page_read(&l->store, page_id, img, NULL);
	if (rc)
		goto out;
	from = img->hdr.auth_state;
	if (from == MXFS_TAUTH_PG_ACTIVE && img->hdr.auth_node == l->local_node &&
	    img->hdr.authority_epoch == l->local_inc) {
		/* already ours (a retry after a lost response): adopt the image */
		if (!pg->img)
			pg->img = mxfs_pal_alloc(sizeof(*pg->img));
		if (!pg->img) {
			rc = -ENOMEM;
			goto out;
		}
		memcpy(pg->img, img, sizeof(*img));
		pg->load_gen = gen;
		pg->poisoned = false;
		rc = 0;
		goto out;
	}
	if (bootstrap) {
		if (from != MXFS_TAUTH_PG_UNOWNED) {
			rc = -ESTALE;
			goto out;
		}
	} else {
		if (from != MXFS_TAUTH_PG_PREPARED ||
		    img->hdr.target_node != l->local_node ||
		    img->hdr.target_inc != l->local_inc ||
		    img->hdr.seq != expect_seq) {
			l->authority_refusals++;
			rc = -ESTALE;
			goto out;
		}
	}
	if (l->activate_hold_once_ms) {
		uint32_t d = l->activate_hold_once_ms;

		l->activate_hold_once_ms = 0;
		mxfs_pal_sleep_ms(d);              /* usermode fault knob (D-0347) */
	}
	img->hdr.auth_state = MXFS_TAUTH_PG_ACTIVE;
	img->hdr.auth_node = l->local_node;
	img->hdr.authority_epoch = l->local_inc;
	img->hdr.target_node = 0;
	img->hdr.target_inc = 0;
	rc = lpage_write_fresh_locked(l, pg, img, gen);
	if (rc == 0) {
		l->activates++;
		if (!mxfs_tauth_pass_quiet)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				 "tauth: P-TAUTH-ACTIVATE page=%u seq=%llu from=%s auth=%u/%llu cfg=%#llx",
				 page_id, (unsigned long long)pg->img->hdr.seq,
				 bootstrap ? "UNOWNED" : "PREPARED", l->local_node,
				 (unsigned long long)l->local_inc,
				 (unsigned long long)l->config_id);
	}
out:
	mxfs_pal_mutex_unlock(pg->lock);
	mxfs_pal_free(img);
	return rc;
}

/* ─── transitions ─── */

/*
 * 0.89.0 (D-0977): the releaser's open-mark change, applied to the record
 * inside the transition that retires its grant.  `bit` is the releaser's
 * heartbeat-slot bit; ZERO erases every node's mark (the genuine free —
 * the guard that ran under this EX already proved no live peer holds the
 * incarnation open, so what it erases is residue of retired slots).
 */
static void entry_apply_open_op(struct mxfs_tauth_ledger *l,
				struct mxfs_tauth_entry *e,
				const struct mxfs_tauth_op *op, uint64_t bit)
{
	switch (op->open_op) {
	case MXFS_TAUTH_OPEN_SET:
		e->open_holders |= bit;
		break;
	case MXFS_TAUTH_OPEN_CLEAR:
		e->open_holders &= ~bit;
		break;
	case MXFS_TAUTH_OPEN_ZERO:
		e->open_holders = 0;
		break;
	default:
		return;
	}
	l->open_marks++;
}

/* Apply one op to the scratch image.  Returns 0 (applied), -ESTALE (not
 * applicable, recorded in op->rc, batch continues) or a fatal code that
 * refuses the whole batch. */
static int apply_op(struct mxfs_tauth_ledger *l, struct mxfs_tauth_page *img,
		    struct mxfs_tauth_op *op, uint64_t config_epoch,
		    uint64_t stamp_ms)
{
	uint32_t slot = mxfs_tauth_ledger_hash(l, &op->res);   /* forensic: the routing hash */
	bool grant = (op->kind == MXFS_TAUTH_OP_GRANT_EX || op->kind == MXFS_TAUTH_OP_GRANT_PR);
	int idx = -1;
	struct mxfs_tauth_entry *e = page_find_entry(l, img, &op->res, grant, &idx);
	uint64_t bit = (op->slot < 64) ? (1ULL << op->slot) : 0;
	bool same_res;

	op->rc = 0;
	if (!e) {
		if (grant) {
			/* (D-0348): every entry of the home page is occupied
			 * by another live/unknown record — capacity, not a fault;
			 * the requester waits and retries (MXFS_ERR_LEDGER_FULL).
			 * 0.89.0: count the tombstones that open-holder marks keep
			 * on this page — a page full of them is the open-mark
			 * capacity bound (docs/tcp-authority-ledger.md), released
			 * only by the openers' last close or their fence purge. */
			int k, pinned = 0;

			for (k = 0; k < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; k++)
				if (img->ent[k].state == MXFS_TAUTH_ST_FREE &&
				    img->ent[k].open_holders)
					pinned++;
			l->page_full++;
			if (pinned)
				l->open_pinned++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "tauth: P-TAUTH-PAGE-FULL page=%u hash=%u type=%u ino=%llu ag=%u "
				     "open_pinned=%d -- no free entry among %u; requester waits",
				     img->hdr.page_id, slot, op->res.type,
				     (unsigned long long)op->res.ino, op->res.ag_number,
				     pinned, MXFS_TAUTH_ENTRIES_PER_PAGE);
			return -EDQUOT;
		}
		/* a release of a resource this page never recorded */
		l->stale_ops++;
		op->rc = -ESTALE;
		op->lineage_out = 0;
		return -ESTALE;
	}
	same_res = mxfs_tauth_entry_is_res(e, &op->res);
	if (e->state == MXFS_TAUTH_ST_UNKNOWN) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-UNKNOWN-RECORD page=%u entry=%d hash=%u type=%u ino=%llu "
			     "ag=%u op=%u -- refused",
			     img->hdr.page_id, idx, slot, op->res.type,
			     (unsigned long long)op->res.ino, op->res.ag_number, op->kind);
		return -EUCLEAN;
	}

	switch (op->kind) {
	case MXFS_TAUTH_OP_GRANT_EX:
	case MXFS_TAUTH_OP_GRANT_PR: {
		bool ex_op = (op->kind == MXFS_TAUTH_OP_GRANT_EX);

		if (ex_op != mode_is_exclusive(op->mode) || bit == 0)
			return -EINVAL;
		if (l->refuse_grant_once) {
			l->refuse_grant_once = 0;
			l->busy_denies++;
			return -EBUSY;
		}
		if (e->state == MXFS_TAUTH_ST_ACTIVE && !same_res) {
			/* unreachable by construction (page_find_entry allocates only
			 * EMPTY/FREE or a same-resource record): a corruption guard */
			l->collisions++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "tauth: P-TAUTH-COLLISION page=%u entry=%d held type=%u ino=%llu "
				     "ag=%u vs req type=%u ino=%llu ag=%u -- refused (fail closed)",
				     img->hdr.page_id, idx, e->res_type, (unsigned long long)e->ino,
				     e->ag_number, op->res.type,
				     (unsigned long long)op->res.ino, op->res.ag_number);
			return -EEXIST;
		}
		if (e->state == MXFS_TAUTH_ST_ACTIVE) {
			bool ex_is_me = (e->ex_node == op->node && e->ex_inc == op->inc);
			bool ex_other = (e->ex_node != 0 && !ex_is_me);
			uint64_t others = e->holders & ~bit;

			if (ex_other || (ex_op && others)) {
				l->busy_denies++;
				mxfs_pal_log(MXFS_LOG_ERR,
					     "tauth: P-TAUTH-DOUBLE-GRANT page=%u entry=%d type=%u ino=%llu "
					     "ag=%u req node=%u inc=%llu mode=%u vs record ex=%u/%llu "
					     "holders=%#llx -- the master decided a conflicting grant; refused",
					     img->hdr.page_id, idx, op->res.type, (unsigned long long)op->res.ino,
					     op->res.ag_number, op->node,
					     (unsigned long long)op->inc, op->mode, e->ex_node,
					     (unsigned long long)e->ex_inc,
					     (unsigned long long)e->holders);
				return -EBUSY;
			}
		} else {
			/* EMPTY or FREE: (re)claim the slot for this resource.  A
			 * same-resource tombstone keeps its superseded grant seq AND
			 * its open-holder marks (0.89.0: the marks outlive the grant
			 * history; page_find_entry never hands a marked tombstone to
			 * another resource, so a foreign reclaim here starts from an
			 * empty mask by construction). */
			uint64_t last = (e->state == MXFS_TAUTH_ST_FREE && same_res) ?
					e->last_grant_seq64 : 0;
			uint64_t marks = (e->state == MXFS_TAUTH_ST_FREE && same_res) ?
					 e->open_holders : 0;

			memset(e, 0, sizeof(*e));
			entry_set_res(e, &op->res);
			e->last_grant_seq64 = last;
			e->open_holders = marks;
		}
		e->state = MXFS_TAUTH_ST_ACTIVE;
		/* An exclusive grant starts a new lineage (a new authority
		 * episode for the images); a shared grant JOINS the lineage the
		 * record already carries — every PR holder must later name the
		 * same lineage in its release, so the record's must not move
		 * under the earlier holders (harness-proven: the first PR
		 * holder's release went -ESTALE and its bit stuck). */
		if (op->lineage && (ex_op || e->resource_lineage == 0))
			e->resource_lineage = op->lineage;
		if (ex_op) {
			uint64_t seq = img->hdr.grant_seq_next;

			if (seq == 0 || seq == ~0ULL) {
				l->exhausted++;
				mxfs_pal_log(MXFS_LOG_ERR,
					     "tauth: P-TAUTH-EXHAUST page=%u grant_seq_next=%llu -- refused",
					     img->hdr.page_id, (unsigned long long)seq);
				return -ENOSPC;
			}
			img->hdr.grant_seq_next = seq + 1;
			if (e->ex_node)
				e->last_grant_seq64 = e->grant_seq64;   /* re-grant episode */
			e->holders &= ~bit;                         /* PR -> EX upgrade */
			if (e->holders == 0)
				e->shared_mode = 0;
			e->ex_node = op->node;
			e->ex_inc = op->inc;
			e->ex_slot = op->slot;
			e->ex_mode = op->mode;
			e->authority_epoch = l->authority_epoch;
			e->auth_node = l->local_node;
			e->auth_slot = l->local_slot;
			e->grant_seq64 = seq;
			op->authority_epoch = e->authority_epoch;
			op->grant_seq64 = seq;
			l->grants_ex++;
		} else {
			if (e->ex_node == op->node && e->ex_inc == op->inc) {
				/* EX -> PR downgrade by the exclusive holder */
				e->last_grant_seq64 = e->grant_seq64;
				e->ex_node = 0;
				e->ex_inc = 0;
				e->ex_slot = 0;
				e->ex_mode = 0;
				e->grant_seq64 = 0;
			}
			e->holders |= bit;
			if (op->mode > e->shared_mode)
				e->shared_mode = op->mode;
			l->grants_pr++;
		}
		e->dir_epoch = op->dir_epoch;
		break;
	}
	case MXFS_TAUTH_OP_RELEASE_EX:
		if (e->state != MXFS_TAUTH_ST_ACTIVE || !same_res ||
		    e->ex_node != op->node || e->ex_inc != op->inc ||
		    e->authority_epoch != op->authority_epoch ||
		    e->grant_seq64 != op->grant_seq64) {
			l->stale_ops++;
			op->rc = -ESTALE;
			op->lineage_out = same_res ? e->resource_lineage : 0;
			op->open_holders_out = same_res ? e->open_holders : 0;
			return -ESTALE;
		}
		e->last_grant_seq64 = e->grant_seq64;
		e->ex_node = 0;
		e->ex_inc = 0;
		e->ex_slot = 0;
		e->ex_mode = 0;
		e->grant_seq64 = 0;
		entry_apply_open_op(l, e, op, bit);
		if (e->holders == 0)
			e->state = MXFS_TAUTH_ST_FREE;
		l->releases_ex++;
		break;
	case MXFS_TAUTH_OP_RELEASE_PR:
		if (e->state != MXFS_TAUTH_ST_ACTIVE || !same_res || bit == 0 ||
		    !(e->holders & bit) ||
		    (op->lineage && e->resource_lineage != op->lineage)) {
			l->stale_ops++;
			op->rc = -ESTALE;
			op->lineage_out = same_res ? e->resource_lineage : 0;
			op->open_holders_out = same_res ? e->open_holders : 0;
			return -ESTALE;
		}
		e->holders &= ~bit;
		entry_apply_open_op(l, e, op, bit);
		if (e->holders == 0) {
			e->shared_mode = 0;
			if (e->ex_node == 0)
				e->state = MXFS_TAUTH_ST_FREE;
		}
		l->releases_pr++;
		break;
	case MXFS_TAUTH_OP_OPEN_MARK:
		/*
		 * 0.89.0 (D-0977): a mark change with no grant to ride.  Only an
		 * existing record of THIS resource (live or tombstone) takes it;
		 * a foreign occupant of the probed entry, or no record at all,
		 * is -ESTALE (nothing to mark, nothing allocated).  The zero op
		 * is refused here: only the genuine free's own release may erase
		 * every node's marks, and that release names its grant.
		 */
		if (!same_res || bit == 0 || op->open_op == MXFS_TAUTH_OPEN_ZERO ||
		    op->open_op == MXFS_TAUTH_OPEN_NONE) {
			l->stale_ops++;
			op->rc = -ESTALE;
			op->lineage_out = same_res ? e->resource_lineage : 0;
			op->open_holders_out = same_res ? e->open_holders : 0;
			return -ESTALE;
		}
		if (((e->open_holders & bit) != 0) ==
		    (op->open_op == MXFS_TAUTH_OPEN_SET)) {
			/* already in the requested state: durable as it stands */
			op->rc = 0;
			op->lineage_out = e->resource_lineage;
			op->open_holders_out = e->open_holders;
			return -ESTALE;
		}
		entry_apply_open_op(l, e, op, bit);
		break;
	default:
		return -EINVAL;
	}
	e->config_epoch = config_epoch;
	(void)stamp_ms;     /* the page header carries the transition's clock */
	op->lineage_out = e->resource_lineage;
	op->open_holders_out = e->open_holders;
	return 0;
}

/* Caller holds pg->lock; `img` was written from the page's cache, whose seq
 * was `old_seq`, and the store returned rc.  Decide what happened: see
 * lpage_commit_locked. */
static int lpage_commit_settle_locked(struct mxfs_tauth_ledger *l,
				      struct mxfs_tauth_lpage *pg,
				      struct mxfs_tauth_page *img, uint64_t old_seq,
				      int rc)
{
	if (rc == 0) {
		memcpy(pg->img, img, sizeof(*img));
		l->commits++;
		if (l->commits - l->commit_ms_last_report >= 200)
			mxfs_tauth_ledger_stats(l, "periodic");
		return 0;
	}
	if (rc == -EOVERFLOW) {
		l->exhausted++;
		return -ENOSPC;      /* seq space exhausted: nothing was written */
	}
	if (rc == -ESTALE || rc == -EBUSY) {
		/* (D-0347): refused before any byte landed.  -ESTALE on a
		 * page we serve means another writer committed to OUR page: our
		 * cache is stale — reload it and let the caller re-decide. */
		l->stale_writes++;
		(void)lpage_load_locked(l, img->hdr.page_id, pg, pg->load_gen);
		return rc;
	}
	/* The write may or may not have landed: poison, then let the platter
	 * decide right away.  Only a failed re-read leaves the poison in
	 * place — and then no operation touches this page until ensure()
	 * reconciles it. */
	pg->poisoned = true;
	pg->uncertain_seq = img->hdr.seq;
	l->poisons++;
	mxfs_pal_log(MXFS_LOG_ERR,
		     "tauth: P-TAUTH-POISON page=%u seq=%llu write_rc=%d -- outcome uncertain; reconciling",
		     img->hdr.page_id, (unsigned long long)img->hdr.seq, rc);
	if (lpage_reconcile_locked(l, img->hdr.page_id, pg) != 0)
		return -ENOTRECOVERABLE;
	/*
	 * Durable only when the platter holds exactly the image this commit
	 * stamped.  The store stamps the image (its next seq, a fresh nonce) only
	 * once the ticket is acquired and flushed; a failure before that — the
	 * base read, the ticket swap, the flush after it — leaves img at old_seq,
	 * and an image never stamped was never published.  Matching on the seq
	 * alone read that unchanged platter as this transition, and the commit
	 * was delivered with nothing on disk.
	 */
	if (img->hdr.seq != old_seq && !memcmp(pg->img, img, sizeof(*img))) {
		/* the platter holds our transition: it IS durable */
		l->commits++;
		return 0;
	}
	if (pg->img->hdr.seq == old_seq) {
		l->uncommitted++;
		return -EIO;         /* proven not committed */
	}
	/* neither the old nor the new image: another writer owns this page
	 * (ownership changed under us) — refuse, the caller re-ensures */
	l->gen_refusals++;
	return -ESTALE;
}

/*
 * Write `img` (its page's lock held by the caller) as part of whatever batch
 * forms around it, and return what mxfs_tauth_page_write would have returned
 * for it.
 *
 * Why: on a DRBD pair every page commit is two emulated compare-and-swaps
 * (each a bakery acquisition of the pair-wide swap lock: three replicated
 * register writes and a replicated FUA target write), three flushes and a FUA
 * body write, all in series.  Measured on the physical pair (0.90.95): a
 * commit alone takes ~70 ms, 85% of it the two swaps; when a peer's exclusive
 * request makes a host release its idle read grants all at once, ~880
 * releases each paid that whole sequence for themselves, about 30 of them in
 * flight at a time, and a commit took 1.1-1.8 s — long enough that releasers
 * re-sent and the peer's own commits waited behind them on the shared swap
 * lock.  Committed together, N pages pay one ticket swap batch, one body
 * write, one publish swap batch and three flushes between them.
 *
 * Only the barriers are shared.  Each committer reads its own page's base
 * (both copies) before it queues and reads its published copy back after its
 * batch, in its own thread, so those reads run in parallel exactly as single
 * commits' do.  Measured on the rig's DRBD pair with the reads done by the
 * batch's writer instead: a batch of N cost 3N reads in series, the release
 * storm's commits took twice as long as committed one by one, and a walk
 * running beside it slowed 2.4x.
 *
 * What stays exactly as it was: each page is still its own conditional commit
 * (its own base token, ticket, body, publish and readback), its body is
 * written FUA as a single commit's is, and each committer learns its own
 * page's outcome before it returns, so nothing is delivered before its record
 * is durable.  Two commits of one page can never share a batch: each
 * committer holds its page's lock until it has its result.
 */
static int lpage_write_grouped(struct mxfs_tauth_ledger *l, struct mxfs_tauth_page *img)
{
	struct tauth_gc_ent me = { .img = img, .rc = -EINPROGRESS };
	struct tauth_gc_vec *v = l->gc_vec;     /* the writer's alone: gc_busy */
	int n, i, rc;

	me.ws = mxfs_pal_alloc(sizeof(*me.ws));
	if (!me.ws)
		return -ENOMEM;
	/* 1-2. this page's base, in this thread */
	rc = mxfs_tauth_page_write_base(&l->store, img, me.ws);
	if (rc) {
		mxfs_pal_free(me.ws);
		return rc;
	}

	mxfs_pal_mutex_lock(l->gc_lock);
	if (l->gc_tail)
		l->gc_tail->next = &me;
	else
		l->gc_head = &me;
	l->gc_tail = &me;
	while (!me.done) {
		if (l->gc_busy) {
			mxfs_pal_cond_wait(l->gc_cond, l->gc_lock);
			continue;
		}
		/* nobody is writing: write everything queued, ours first in line
		 * or behind the earlier arrivals it queued after */
		l->gc_busy = true;
		for (n = 0; n < (int)MXFS_TAUTH_WRITE_BATCH && l->gc_head; n++) {
			v->batch[n] = l->gc_head;
			l->gc_head = l->gc_head->next;
		}
		if (!l->gc_head)
			l->gc_tail = NULL;
		mxfs_pal_mutex_unlock(l->gc_lock);

		/* 3-5. the barriers, once for the whole batch */
		for (i = 0; i < n; i++) {
			v->w[i].pg = v->batch[i]->img;
			v->w[i].authority_epoch = v->batch[i]->img->hdr.authority_epoch;
			v->w[i].rc = 0;
			v->wsp[i] = v->batch[i]->ws;
		}
		mxfs_tauth_page_write_barriers(&l->store, v->w, v->wsp, n, l->config_id, true);

		mxfs_pal_mutex_lock(l->gc_lock);
		if (n > 1) {
			l->gc_batches++;
			l->gc_pages += (uint64_t)n;
			if ((uint64_t)n > l->gc_max)
				l->gc_max = (uint64_t)n;
		}
		for (i = 0; i < n; i++) {
			v->batch[i]->rc = v->w[i].rc;
			v->batch[i]->done = true;
		}
		l->gc_busy = false;
		mxfs_pal_cond_broadcast(l->gc_cond);
	}
	mxfs_pal_mutex_unlock(l->gc_lock);

	/* 6. this page's published copy, read back in this thread */
	rc = me.rc;
	if (rc == 0)
		rc = mxfs_tauth_page_write_readback(&l->store, img, me.ws);
	mxfs_pal_free(me.ws);
	return rc;
}

/* Caller holds pg->lock; `img` is the patched scratch image.  Write it and
 * decide what happened.  Returns 0 (durable, cache updated), -EIO (proven
 * not committed, cache untouched), -ENOTRECOVERABLE (uncertain; poisoned). */
static int lpage_commit_locked(struct mxfs_tauth_ledger *l, struct mxfs_tauth_lpage *pg,
			       struct mxfs_tauth_page *img, uint64_t config_epoch)
{
	uint32_t torn = l->torn_after_bytes;
	uint64_t old_seq = pg->img->hdr.seq;
	int rc;

	uint64_t t0 = mxfs_pal_time_ms(), dt;

	l->torn_after_bytes = 0;
	(void)config_epoch;
	/* the page's authority fields ride unchanged: an entry transition is
	 * only ever written by the ACTIVE authority itself.  A torn-write test
	 * commit is written alone: the fault is the store's single-page one.  So
	 * is every commit while the group commit is off (mxfs_tauth_group_commit,
	 * tauth_ledger.h says why it is off by default). */
	if (torn || !l->gc_lock || !mxfs_tauth_group_commit)
		rc = mxfs_tauth_page_write(&l->store, img, img->hdr.authority_epoch,
					   l->config_id, torn);
	else
		rc = lpage_write_grouped(l, img);
	dt = mxfs_pal_time_ms() - t0;
	l->commit_ms_total += dt;
	if (dt > l->commit_ms_max)
		l->commit_ms_max = dt;
	return lpage_commit_settle_locked(l, pg, img, old_seq, rc);
}

/*
 * n pages at once: the caller holds every pgs[i]->lock and imgs[i] is that
 * page's patched image.  One batched store commit (mxfs_tauth_page_write_many:
 * the pages share its barriers), then each page settled exactly as
 * lpage_commit_locked settles one; rcs[i] is what it would have returned.
 * n <= MXFS_TAUTH_WRITE_BATCH.  The commit-latency counters take the batch's
 * wall once: their average stays the cost of a page.
 */
static void lpage_commit_many_locked(struct mxfs_tauth_ledger *l,
				     struct mxfs_tauth_lpage **pgs,
				     struct mxfs_tauth_page **imgs, int n,
				     struct mxfs_tauth_wreq *w, int *rcs)
{
	uint64_t t0 = mxfs_pal_time_ms(), dt;
	int i, rc;

	for (i = 0; i < n; i++) {
		w[i].pg = imgs[i];
		/* as lpage_commit_locked: the authority fields ride unchanged */
		w[i].authority_epoch = imgs[i]->hdr.authority_epoch;
		w[i].rc = 0;
	}
	rc = mxfs_tauth_page_write_many(&l->store, w, n, l->config_id);
	dt = mxfs_pal_time_ms() - t0;
	l->commit_ms_total += dt;
	if (dt > l->commit_ms_max)
		l->commit_ms_max = dt;
	for (i = 0; i < n; i++)
		rcs[i] = lpage_commit_settle_locked(l, pgs[i], imgs[i], pgs[i]->img->hdr.seq,
						    rc ? rc : w[i].rc);
}

int mxfs_tauth_ledger_commit(struct mxfs_tauth_ledger *l,
			     struct mxfs_tauth_op *ops, int nops,
			     uint64_t gen, uint64_t config_epoch)
{
	struct mxfs_tauth_lpage *pg;
	struct mxfs_tauth_page *img;
	uint32_t page_id;
	uint64_t stamp;
	int i, rc = 0, applied = 0;

	if (!l || !l->pages || !ops || nops <= 0)
		return -EINVAL;
	page_id = mxfs_tauth_ledger_page(l, &ops[0].res);
	for (i = 1; i < nops; i++)
		if (mxfs_tauth_ledger_page(l, &ops[i].res) != page_id)
			return -EINVAL;
	for (i = 0; i < nops; i++)
		ops[i].rc = -ECANCELED;
	if (l->commit_delay_once_ms) {
		uint32_t d = l->commit_delay_once_ms;

		l->commit_delay_once_ms = 0;
		mxfs_pal_sleep_ms(d);
	}
	if (l->fail_commit_once_rc && l->fail_commit_skip) {
		l->fail_commit_skip--;
	} else if (l->fail_commit_once_rc) {
		rc = l->fail_commit_once_rc;
		l->fail_commit_once_rc = 0;
		for (i = 0; i < nops; i++)
			ops[i].rc = rc;
		return rc;
	}
	if (gen != l->owner_gen) {
		l->gen_refusals++;
		return -ESTALE;
	}
	pg = &l->pages[page_id];
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;

	mxfs_pal_mutex_lock(pg->lock);
	if (pg->poisoned) {
		rc = -ENOTRECOVERABLE;
		goto out;
	}
	if (!pg->img || pg->load_gen != gen || gen != l->owner_gen) {
		l->gen_refusals++;
		rc = -ESTALE;
		goto out;
	}
	if (!lpage_mine_locked(l, pg)) {
		l->authority_refusals++;
		rc = -EPERM;
		goto out;
	}
	memcpy(img, pg->img, sizeof(*img));
	stamp = mxfs_pal_time_ms();
	for (i = 0; i < nops; i++) {
		int r = apply_op(l, img, &ops[i], config_epoch, stamp);

		if (r == 0) {
			applied++;
		} else if (r != -ESTALE) {
			rc = r;
			goto out;
		}
	}
	if (applied == 0) {
		l->noop_commits++;
		rc = 0;
		goto out;
	}
	if (img->hdr.transition_seq_next == 0 || img->hdr.transition_seq_next == ~0ULL) {
		l->exhausted++;
		rc = -ENOSPC;
		goto out;
	}
	{
		uint64_t tseq = img->hdr.transition_seq_next++;

		for (i = 0; i < nops; i++)
			if (ops[i].rc == 0) {
				struct mxfs_tauth_entry *te = page_find_entry(NULL, img, &ops[i].res, false, NULL);

				if (te)
					te->transition_seq64 = tseq;
			}
	}
	rc = lpage_commit_locked(l, pg, img, config_epoch);
out:
	if (rc) {
		/* nothing applied: report every op as not applied */
		for (i = 0; i < nops; i++)
			if (ops[i].rc == 0)
				ops[i].rc = rc;
	}
	mxfs_pal_mutex_unlock(pg->lock);
	mxfs_pal_free(img);
	return rc;
}

/* ─── recovery purge ─── */

/*
 * 0.75.2: the purge's candidate set comes from ONE bulk pass over the
 * ledger (the store's 16-page runs, both copies), not from loading every
 * page one 4 KiB read at a time.  A page is a candidate when its platter
 * image is this authority's and an ACTIVE entry names the departed owner
 * (EX by node, or a shared holder bit by slot); an unreadable or unknown
 * page stays a candidate so the per-page path below fails closed on it
 * exactly as before.  Measured before this on the 2-node TCP rig (QNAP
 * LUN, 26426 pages): the departed peer's clean-release purge sat 14 s in
 * page reads on the heartbeat thread (P278-HB-STALL stack in
 * mxfs_tauth_ledger_ensure under mxfs_tauth_ledger_purge_owner).
 * 0.75.65 (D-0925): the images now come from the page cache (see
 * mxfs_tauth_ledger_purge_owner_keep); the same callback classifies them.
 */
struct tauth_purge_scan {
	const struct mxfs_tauth_ledger *l;
	uint32_t    node;
	uint64_t    bit;
	uint8_t    *cand;       /* bitmap over npages */
	uint32_t    ncand, bad, notmine;
};

static void tauth_purge_scan_page(void *data, uint32_t page_id,
				  const struct mxfs_tauth_page *pg, int rc)
{
	struct tauth_purge_scan *s = data;
	int i;

	if (rc || !pg) {
		s->bad++;
		s->cand[page_id >> 3] |= (uint8_t)(1u << (page_id & 7));
		s->ncand++;
		return;
	}
	if (pg->hdr.auth_state != MXFS_TAUTH_PG_ACTIVE ||
	    pg->hdr.auth_node != s->l->local_node ||
	    pg->hdr.authority_epoch != s->l->local_inc) {
		s->notmine++;
		return;
	}
	for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++) {
		const struct mxfs_tauth_entry *e = &pg->ent[i];

		if (e->state != MXFS_TAUTH_ST_ACTIVE)
			continue;
		if (e->ex_node == s->node || (s->bit && (e->holders & s->bit))) {
			s->cand[page_id >> 3] |= (uint8_t)(1u << (page_id & 7));
			s->ncand++;
			return;
		}
	}
}

/*
 * One page of a purge, up to its commit: patch into `img` (the caller's
 * scratch page) the retirement of every ACTIVE record of holder `node` (and
 * of heartbeat bit `bit` when non-zero) on page `p`, if this node masters it.
 * Returns the number of records changed, with the page's lock HELD and `img`
 * ready to commit (its transition seq taken); 0 = nothing to do, or not this
 * node's page (a frozen / handed off / never activated page is its
 * authority's to purge, never written here); or a negative error.  Only a
 * positive return leaves the lock held.
 */
static int tauth_purge_prepare(struct mxfs_tauth_ledger *l, uint32_t p, uint32_t node,
			       uint64_t inc, uint64_t bit, uint64_t gen,
			       uint64_t config_epoch, struct mxfs_tauth_page *img,
			       mxfs_tauth_purge_keep_fn keep, void *keep_data)
{
	struct mxfs_tauth_lpage *pg = &l->pages[p];
	uint32_t touched_mask = 0;
	int i, changed = 0, rc;

	rc = mxfs_tauth_ledger_ensure(l, p, gen);
	if (rc)
		return rc;
	mxfs_pal_mutex_lock(pg->lock);
	if (!pg->img || pg->load_gen != gen || pg->poisoned) {
		mxfs_pal_mutex_unlock(pg->lock);
		return -ESTALE;
	}
	if (!lpage_mine_locked(l, pg)) {
		mxfs_pal_mutex_unlock(pg->lock);
		return 0;
	}
	memcpy(img, pg->img, sizeof(*img));
	for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++) {
		struct mxfs_tauth_entry *e = &img->ent[i];
		int touched = 0;
		bool ex_is_departed;

		/*
		 * 0.89.0 (D-0977): the departed slot's open-holder mark is
		 * stripped from every record that carries it, tombstones
		 * included — the owner is fenced (this purge runs at its
		 * recovery completion, never on suspicion), so the mark protects
		 * nothing and only pins the entry.  When the caller could not
		 * name the slot (bit == 0: the slot already belongs to a live
		 * successor) the marks are left alone: a slot-keyed bit cannot
		 * be told from the successor's own, and keeping it is the
		 * integrity-safe side (a stale mark defers a reap; a lost one
		 * frees an open file).  The successor's next release of that
		 * inode publishes its own absolute state over it.
		 */
		if (e->state == MXFS_TAUTH_ST_FREE && bit && (e->open_holders & bit)) {
			e->open_holders &= ~bit;
			e->config_epoch = config_epoch;
			touched_mask |= 1u << i;
			changed++;
			l->open_marks++;
			continue;
		}
		if (e->state != MXFS_TAUTH_ST_ACTIVE)
			continue;
		/*
		 * A NODE ID IS NOT AN IDENTITY.  When the caller names the departed
		 * incarnation, an EX record carrying that node id but a DIFFERENT
		 * incarnation belongs to a mount this purge was never told about —
		 * the same node back with the same id (a resumed term adopts its
		 * predecessor's node_id, and a pinned id does the same), or this
		 * mount's own records when the departed incarnation shares its id.
		 * Retiring one of those revokes a tenure its holder still believes
		 * it has, which is a lost lock, not stale residue.  An ex_inc the
		 * caller cannot match is spared for the same reason: unknown
		 * provenance is not evidence that removal is safe.  inc == 0 means
		 * the caller has no incarnation to match on and keeps the old
		 * id-only behaviour.
		 */
		ex_is_departed = (e->ex_node == node) &&
				 (inc == 0 || e->ex_inc == inc);
		if (e->ex_node == node && !ex_is_departed) {
			l->purge_inc_spared++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "tauth: P-TAUTH-PURGE-INC-SPARED page=%u ent=%d node=%u "
				     "departed_inc=%llu record_inc=%llu mode=%u -- the record "
				     "carries the departed node id under another incarnation; "
				     "it is a live or unproven tenure and is NOT retired",
				     p, i, node, (unsigned long long)inc,
				     (unsigned long long)e->ex_inc, e->ex_mode);
		}
		if (!ex_is_departed && !(bit && ((e->holders | e->open_holders) & bit)))
			continue;
		/* 0.75.30: a selective purge keeps the records the caller's
		 * classifier names (a terminally refused victim's grants inside
		 * its quarantined domain stay frozen; only the provably
		 * out-of-domain ones are retired). */
		if (keep && keep(keep_data, e)) {
			l->purge_kept++;
			continue;
		}
		if (ex_is_departed) {
			e->last_grant_seq64 = e->grant_seq64;
			e->ex_node = 0;
			e->ex_inc = 0;
			e->ex_slot = 0;
			e->ex_mode = 0;
			e->grant_seq64 = 0;
			touched = 1;
		}
		if (bit && (e->holders & bit)) {
			e->holders &= ~bit;
			if (e->holders == 0)
				e->shared_mode = 0;
			touched = 1;
		}
		if (bit && (e->open_holders & bit)) {
			e->open_holders &= ~bit;
			l->open_marks++;
			touched = 1;
		}
		if (touched) {
			if (e->ex_node == 0 && e->holders == 0)
				e->state = MXFS_TAUTH_ST_FREE;
			e->config_epoch = config_epoch;
			touched_mask |= 1u << i;
			changed++;
		}
	}
	if (!changed) {
		mxfs_pal_mutex_unlock(pg->lock);
		return 0;
	}
	{
		uint64_t tseq = img->hdr.transition_seq_next;

		if (tseq == 0 || tseq == ~0ULL) {
			mxfs_pal_mutex_unlock(pg->lock);
			return -ENOSPC;
		}
		img->hdr.transition_seq_next = tseq + 1;
		for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++)
			if (touched_mask & (1u << i))
				img->ent[i].transition_seq64 = tseq;
	}
	return changed;
}

/*
 * One page of a purge, committed alone (tauth_purge_prepare, then this page's
 * own commit).  Returns the number of records cleared, 0, or a negative error.
 */
static int tauth_purge_page(struct mxfs_tauth_ledger *l, uint32_t p, uint32_t node,
			    uint64_t inc, uint64_t bit, uint64_t gen,
			    uint64_t config_epoch, struct mxfs_tauth_page *img,
			    mxfs_tauth_purge_keep_fn keep, void *keep_data)
{
	struct mxfs_tauth_lpage *pg = &l->pages[p];
	int changed, rc;

	changed = tauth_purge_prepare(l, p, node, inc, bit, gen, config_epoch, img,
				      keep, keep_data);
	if (changed <= 0)
		return changed;
	if (l->fail_commit_once_rc && l->fail_commit_skip) {
		l->fail_commit_skip--;
		rc = lpage_commit_locked(l, pg, img, config_epoch);
	} else if (l->fail_commit_once_rc) {
		rc = l->fail_commit_once_rc;        /* usermode fault knob */
		l->fail_commit_once_rc = 0;
	} else {
		rc = lpage_commit_locked(l, pg, img, config_epoch);
	}
	mxfs_pal_mutex_unlock(pg->lock);
	if (rc)
		return rc;
	l->purged += changed;
	return changed;
}

/* — see tauth_ledger.h. */
int mxfs_tauth_ledger_retire_page(struct mxfs_tauth_ledger *l, uint32_t page,
				  uint64_t gen, uint64_t config_epoch,
				  struct mxfs_tauth_retire *r, int n)
{
	struct mxfs_tauth_lpage *pg;
	struct mxfs_tauth_page *img;
	uint32_t touched_mask = 0;
	int i, changed = 0, rc;

	if (!l || !l->pages || page >= l->npages || !r || n <= 0)
		return -EINVAL;
	for (i = 0; i < n; i++)
		r[i].rc = -ECANCELED;
	rc = mxfs_tauth_ledger_ensure(l, page, gen);
	if (rc)
		return rc;
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	pg = &l->pages[page];
	mxfs_pal_mutex_lock(pg->lock);
	if (!pg->img || pg->load_gen != gen || pg->poisoned) {
		rc = -ESTALE;
		goto out;
	}
	if (!lpage_mine_locked(l, pg)) {
		l->authority_refusals++;
		rc = -EPERM;
		goto out;
	}
	memcpy(img, pg->img, sizeof(*img));
	for (i = 0; i < n; i++) {
		struct mxfs_tauth_entry *e;
		int idx = -1, touched = 0;

		if (mxfs_tauth_ledger_page(l, &r[i].res) != page) {
			r[i].rc = -EINVAL;
			continue;
		}
		e = page_find_entry(l, img, &r[i].res, false, &idx);
		if (!e || e->state != MXFS_TAUTH_ST_ACTIVE) {
			l->stale_ops++;
			r[i].rc = -ESTALE;
			continue;
		}
		if (e->transition_seq64 != r[i].tseq) {
			/* the record moved after the caller read it: what it judged
			 * is not what stands here now */
			l->retire_moved++;
			r[i].rc = -EAGAIN;
			continue;
		}
		if (r[i].ex_node && e->ex_node == r[i].ex_node &&
		    e->ex_inc == r[i].ex_inc) {
			e->last_grant_seq64 = e->grant_seq64;
			e->ex_node = 0;
			e->ex_inc = 0;
			e->ex_slot = 0;
			e->ex_mode = 0;
			e->grant_seq64 = 0;
			touched = 1;
		}
		if (e->holders & r[i].bits) {
			e->holders &= ~r[i].bits;
			if (e->holders == 0)
				e->shared_mode = 0;
			touched = 1;
		}
		if (e->open_holders & r[i].open_bits) {
			e->open_holders &= ~r[i].open_bits;
			l->open_marks++;
			touched = 1;
		}
		if (!touched) {
			l->stale_ops++;
			r[i].rc = -ESTALE;
			continue;
		}
		if (e->ex_node == 0 && e->holders == 0)
			e->state = MXFS_TAUTH_ST_FREE;
		e->config_epoch = config_epoch;
		touched_mask |= 1u << idx;
		r[i].rc = 0;
		changed++;
	}
	rc = 0;
	if (changed) {
		uint64_t tseq = img->hdr.transition_seq_next;

		if (tseq == 0 || tseq == ~0ULL) {
			l->exhausted++;
			rc = -ENOSPC;
		} else {
			img->hdr.transition_seq_next = tseq + 1;
			for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++)
				if (touched_mask & (1u << i))
					img->ent[i].transition_seq64 = tseq;
			if (l->fail_commit_once_rc && l->fail_commit_skip) {
				l->fail_commit_skip--;
				rc = lpage_commit_locked(l, pg, img, config_epoch);
			} else if (l->fail_commit_once_rc) {
				rc = l->fail_commit_once_rc;    /* usermode fault knob */
				l->fail_commit_once_rc = 0;
			} else {
				rc = lpage_commit_locked(l, pg, img, config_epoch);
			}
		}
	}
out:
	if (rc)
		for (i = 0; i < n; i++)
			if (r[i].rc == 0)
				r[i].rc = rc;
	mxfs_pal_mutex_unlock(pg->lock);
	mxfs_pal_free(img);
	if (rc)
		return rc;
	l->retired_named += changed;
	return changed;
}

/*
 * 0.75.14 (D-...-0906 hand-on hole): retire holder `node`'s records on ONE
 * page — the page a takeover has just activated for this node.  Measured
 * (sameboot_remount arm 1 with the peer's join held 12 s): the departed
 * authority's AG 0 EX record survived the takeover on the platter, the page
 * was handed on by the next view change with this node as writer AND
 * authority, and the receiver imported the dead grant as a live blocker
 * (P-TAUTH-IMPORT-ACTIVE owner=<departed> ... mode=EX; its mount parked on
 * AG 0 to the bound).  The bulk purge that precedes a takeover walks only the
 * pages this node already masters, so a page that becomes ours BY the
 * takeover is never purged until something imports it.
 */
int mxfs_tauth_ledger_purge_owner_page_keep(struct mxfs_tauth_ledger *l, uint32_t node,
					    uint64_t inc, int slot, uint64_t gen,
					    uint64_t config_epoch, uint32_t page,
					    mxfs_tauth_purge_keep_fn keep, void *keep_data)
{
	struct mxfs_tauth_page *img;
	uint64_t bit = (slot >= 0 && slot < 64) ? (1ULL << slot) : 0;
	int rc;

	if (!l || !l->pages || page >= l->npages)
		return -EINVAL;
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	rc = tauth_purge_page(l, page, node, inc, bit, gen, config_epoch, img, keep, keep_data);
	mxfs_pal_free(img);
	return rc;
}

int mxfs_tauth_ledger_purge_owner_page(struct mxfs_tauth_ledger *l, uint32_t node,
				       uint64_t inc, int slot, uint64_t gen,
				       uint64_t config_epoch, uint32_t page)
{
	return mxfs_tauth_ledger_purge_owner_page_keep(l, node, inc, slot, gen, config_epoch,
						       page, NULL, NULL);
}

int mxfs_tauth_ledger_purge_owner(struct mxfs_tauth_ledger *l, uint32_t node,
				  int slot, uint64_t gen, uint64_t config_epoch,
				  mxfs_tauth_owns_page_fn owns_page, void *data)
{
	return mxfs_tauth_ledger_purge_owner_keep(l, node, slot, gen, config_epoch,
						  owns_page, data, NULL, NULL);
}

/* One batch of a purge walk (mxfs_tauth_ledger_purge_owner_keep). */
struct tauth_purge_batch {
	uint32_t                 page[MXFS_TAUTH_WRITE_BATCH];  /* its candidates, ascending */
	struct mxfs_tauth_lpage *pg[MXFS_TAUTH_WRITE_BATCH];    /* the prepared ones, locked */
	struct mxfs_tauth_page  *img[MXFS_TAUTH_WRITE_BATCH];   /* allocated as first needed */
	uint32_t                 pid[MXFS_TAUTH_WRITE_BATCH];
	int                      changed[MXFS_TAUTH_WRITE_BATCH];
	int                      rc[MXFS_TAUTH_WRITE_BATCH];
	struct mxfs_tauth_wreq   w[MXFS_TAUTH_WRITE_BATCH];
};

int mxfs_tauth_ledger_purge_owner_keep(struct mxfs_tauth_ledger *l, uint32_t node,
				       int slot, uint64_t gen, uint64_t config_epoch,
				       mxfs_tauth_owns_page_fn owns_page, void *data,
				       mxfs_tauth_purge_keep_fn keep, void *keep_data)
{
	struct mxfs_tauth_page *img;
	struct tauth_purge_batch *b = NULL;
	struct tauth_purge_scan sc;
	struct mxfs_tauth_store *s;
	uint64_t bit = (slot >= 0 && slot < 64) ? (1ULL << slot) : 0;
	uint64_t t0, scan_ms = 0, total_ms;
	uint64_t ph0_read, ph0_ticket, ph0_body, ph0_publish, ph0_flush;
	uint32_t p, visited = 0, fail_page = 0, committed = 0, batches = 0, k;
	int cleared = 0, rc = 0;

	if (!l || !l->pages)
		return -EINVAL;
	img = mxfs_pal_alloc(sizeof(*img));
	if (!img)
		return -ENOMEM;
	s = &l->store;
	ph0_read = s->ph_read_ms;
	ph0_ticket = s->ph_ticket_ms;
	ph0_body = s->ph_body_ms;
	ph0_publish = s->ph_publish_ms;
	ph0_flush = s->ph_flush_ms;
	t0 = mxfs_pal_time_ms();
	memset(&sc, 0, sizeof(sc));
	sc.l = l;
	sc.node = node;
	sc.bit = bit;
	sc.cand = l->store.dev ? mxfs_pal_alloc(((size_t)l->npages + 7) / 8) : NULL;
	if (sc.cand) {
		/*
		 * 0.75.65 (D-0925): the candidates come from the CACHED images,
		 * not from a platter scan.  Only tauth_purge_page writes a page
		 * here, and it writes only a page whose image is ACTIVE under this
		 * node's own incarnation; every transition that makes a page
		 * ACTIVE(self) — activate, prepare, prepare_unowned, and every
		 * commit on it since — installs the image it wrote into pg->img,
		 * so a page this node masters is always in its cache.  A page whose
		 * image was dropped by an unreadable reload (dropped) or whose
		 * last write is uncertain (poisoned) stays a candidate: the
		 * per-page path ensures/reconciles it and fails closed exactly as
		 * the platter pass did for an unreadable page.  Measured before
		 * this on the 2-node TCP rig (QNAP LUN, 26426 pages): the platter
		 * pass read both copies of the whole region (206 MiB) in 64 KiB
		 * runs for cand=0..5 — purge_ms 3969..4568 on every departure,
		 * which was most of the peer's unmount wall.
		 */
		for (p = 0; p < l->npages; p++) {
			struct mxfs_tauth_lpage *pg = &l->pages[p];

			mxfs_pal_mutex_lock(pg->lock);
			if (pg->poisoned || pg->dropped)
				tauth_purge_scan_page(&sc, p, NULL, -EUCLEAN);
			else if (pg->img)
				tauth_purge_scan_page(&sc, p, pg->img, 0);
			mxfs_pal_mutex_unlock(pg->lock);
		}
		scan_ms = mxfs_pal_time_ms() - t0;
	}
	/*
	 * The whole-ledger purge names a node id only.  Its two callers run it
	 * where no other incarnation can be carrying that id: the recovery
	 * completion, before the barrier publishes and while the departed node
	 * is still fenced, and the departure worker, which skips these purges
	 * entirely when the departed incarnation shares this mount's own id.  So
	 * 0 here is "no incarnation to match on", not a wildcard over live
	 * records.
	 */
	if (l->fail_commit_once_rc || l->torn_after_bytes) {
		/* a test knob is armed: the per-page commit it acts on */
		for (p = 0; p < l->npages; p++) {
			if (sc.cand && !(sc.cand[p >> 3] & (1u << (p & 7))))
				continue;
			if (owns_page && !owns_page(data, p))
				continue;
			visited++;
			rc = tauth_purge_page(l, p, node, 0, bit, gen, config_epoch, img,
					      keep, keep_data);
			if (rc < 0) {
				fail_page = p;
				break;
			}
			if (rc > 0) {
				committed++;
				l->purge_pages++;
			}
			cleared += rc;
			rc = 0;
		}
		goto done;
	}
	b = mxfs_pal_alloc(sizeof(*b));
	if (!b) {
		rc = -ENOMEM;
		goto done;
	}
	memset(b, 0, sizeof(*b));
	/*
	 * BATCHED.  The pages are committed MXFS_TAUTH_WRITE_BATCH at a time.  A
	 * batch's candidates that this node masters are chosen first, with no
	 * page lock held (owns_page takes the DLM's membership lock); then each
	 * is patched under its own lock, taken in ascending page order and held
	 * to its commit; then the batch goes to the store as ONE commit whose
	 * barriers its pages share; then each page is settled and unlocked.  A
	 * failure ends the walk after its batch, as a failed page ended the
	 * page-at-a-time walk.  Measured on the physical DRBD pair (0.90.81, a
	 * peer reset under load), committing a page at a time held the dead
	 * peer's grants for 17.8 s of a 24 s recovery completion.
	 */
	p = 0;
	while (p < l->npages && !rc) {
		uint32_t nc = 0, nb = 0;
		int commit_rc = 0;

		for (; p < l->npages && nc < MXFS_TAUTH_WRITE_BATCH; p++) {
			if (sc.cand && !(sc.cand[p >> 3] & (1u << (p & 7))))
				continue;
			if (owns_page && !owns_page(data, p))
				continue;
			b->page[nc++] = p;
		}
		visited += nc;
		for (k = 0; k < nc; k++) {
			int ch;

			if (!b->img[nb]) {
				b->img[nb] = mxfs_pal_alloc(sizeof(*b->img[nb]));
				if (!b->img[nb]) {
					rc = -ENOMEM;
					fail_page = b->page[k];
					break;
				}
			}
			ch = tauth_purge_prepare(l, b->page[k], node, 0, bit, gen,
						 config_epoch, b->img[nb], keep, keep_data);
			if (ch < 0) {
				rc = ch;
				fail_page = b->page[k];
				break;
			}
			if (!ch)
				continue;
			b->pg[nb] = &l->pages[b->page[k]];
			b->pid[nb] = b->page[k];
			b->changed[nb++] = ch;
		}
		if (!nb)
			continue;
		lpage_commit_many_locked(l, b->pg, b->img, (int)nb, b->w, b->rc);
		batches++;
		l->purge_batches++;
		for (k = 0; k < nb; k++) {
			mxfs_pal_mutex_unlock(b->pg[k]->lock);
			if (b->rc[k]) {
				if (!commit_rc) {
					/* the lowest page that failed: below any
					 * page a prepare stopped at */
					commit_rc = b->rc[k];
					fail_page = b->pid[k];
				}
				continue;
			}
			committed++;
			l->purge_pages++;
			l->purged += (uint64_t)b->changed[k];
			cleared += b->changed[k];
		}
		if (commit_rc)
			rc = commit_rc;
	}
done:
	if (b)
		for (k = 0; k < MXFS_TAUTH_WRITE_BATCH; k++)
			mxfs_pal_free(b->img[k]);
	mxfs_pal_free(b);
	mxfs_pal_free(img);
	mxfs_pal_free(sc.cand);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-PURGE-PARTIAL node=%u slot=%d cleared=%d rc=%d "
			     "at page=%u -- blockers beyond this page remain",
			     node, slot, cleared, rc, fail_page);
		return rc;
	}
	/*
	 * Said once per purge, at warning level only when it took a second or
	 * more: the recovery completion waits for it, and where its time went
	 * (pages committed, batches, the store's phases) is what decides whether
	 * a slow recovery is this walk.
	 */
	total_ms = mxfs_pal_time_ms() - t0;
	mxfs_pal_log(total_ms >= 1000 ? MXFS_LOG_WARN : MXFS_LOG_DEBUG,
		     "tauth: P-TAUTH-PURGE node=%u slot=%d cleared=%d pages=%u cand=%u "
		     "bad=%u notmine=%u visited=%u committed=%u batches=%u selective=%d "
		     "kept_total=%llu scan_ms=%llu total_ms=%llu store_ms: read=%llu "
		     "ticket=%llu body=%llu publish=%llu flush=%llu",
		     node, slot, cleared, l->npages, sc.ncand, sc.bad, sc.notmine,
		     visited, committed, batches, keep ? 1 : 0,
		     (unsigned long long)l->purge_kept,
		     (unsigned long long)scan_ms, (unsigned long long)total_ms,
		     (unsigned long long)(s->ph_read_ms - ph0_read),
		     (unsigned long long)(s->ph_ticket_ms - ph0_ticket),
		     (unsigned long long)(s->ph_body_ms - ph0_body),
		     (unsigned long long)(s->ph_publish_ms - ph0_publish),
		     (unsigned long long)(s->ph_flush_ms - ph0_flush));
	return cleared;
}
