// SPDX-License-Identifier: GPL-2.0
/*
 * group_commit_test — the ledger's group commit (gc_lock in
 * dlm/tauth_ledger.h): single-page commits of different pages that are in
 * flight at once are written as one batched store commit, and every committer
 * still gets exactly its own page's outcome.  Against a temp file through the
 * usermode PAL: the SAME dlm/tauth_ledger.c + dlm/tauth_store.c the module
 * links.
 *
 * A batch is made to form on demand: the test holds the group commit busy
 * (gc_busy, as a batch in flight would) while NP committer threads queue,
 * then lets them go, so the first to wake writes everything queued.
 *
 *   1  a lone commit is written alone (no batch counted)
 *   2  NP concurrent grants, one per page: every commit 0, batches formed
 *      (32 + the rest), and every record ACTIVE on the platter under a fresh
 *      generation
 *   3  a stale page inside a batch: its commit alone is refused (-ESTALE,
 *      cache reloaded), every other page's release is durable, the stale
 *      page's record unchanged on the platter; its retry then lands
 *   4  a ticket swap that fails inside a batch: that one commit is -EIO and
 *      proven not committed (record unchanged on the platter), every other
 *      page's commit is durable; the failed page's retry lands
 *   5  (run first) the knob off (mxfs_tauth_group_commit = 0, the default):
 *      concurrent commits are each written alone, as before the group commit
 *
 * Cases 1-4 run with the knob on.  A page whose base read is already stale
 * (case 3) is refused in its own committer's thread before it ever queues.
 */
#include <pthread.h>
#include "tauth_testlib.h"
#include "dlm/tauth_ledger.h"

enum { NP = 48 };

static struct mxfs_tauth_ledger L;
static struct mxfs_resource_id res[NP];
static uint32_t pages[NP];
static uint64_t gen = 1;

struct committer {
    pthread_t   th;
    int         k;
    uint8_t     kind;
    int         rc;
};

static struct mxfs_resource_id mkres(uint64_t ino)
{
    struct mxfs_resource_id r;

    memset(&r, 0, sizeof(r));
    r.ino = ino;
    r.type = MXFS_LTYPE_INODE;
    return r;
}

static struct mxfs_tauth_op mkop(uint8_t kind, const struct mxfs_resource_id *r)
{
    struct mxfs_tauth_op op;

    memset(&op, 0, sizeof(op));
    op.kind = kind;
    op.res = *r;
    op.node = 55;
    op.inc = 5500;
    op.slot = 13;
    op.mode = MXFS_LOCK_EX;
    return op;
}

/* a release names the grant it retires: take its id from the cached record */
static void name_grant(struct mxfs_tauth_op *op, int k)
{
    struct mxfs_tauth_entry e;

    if (mxfs_tauth_ledger_lookup(&L, &res[k], gen, &e) == 0) {
        op->authority_epoch = e.authority_epoch;
        op->grant_seq64 = e.grant_seq64;
    }
}

static void *commit_one(void *arg)
{
    struct committer *c = arg;
    struct mxfs_tauth_op op = mkop(c->kind, &res[c->k]);

    if (c->kind == MXFS_TAUTH_OP_RELEASE_EX)
        name_grant(&op, c->k);
    c->rc = mxfs_tauth_ledger_commit(&L, &op, 1, gen, 90);
    if (c->rc == 0 && op.rc != 0)
        c->rc = op.rc;
    return NULL;
}

/* Hold the group commit busy, start one committer per page, let them queue,
 * then release them all at once.  Results land in cs[k].rc. */
static void commit_all_at_once(struct committer *cs, uint8_t kind)
{
    int k;

    mxfs_pal_mutex_lock(L.gc_lock);
    L.gc_busy = true;
    mxfs_pal_mutex_unlock(L.gc_lock);
    for (k = 0; k < NP; k++) {
        cs[k].k = k;
        cs[k].kind = kind;
        cs[k].rc = -EINPROGRESS;
        pthread_create(&cs[k].th, NULL, commit_one, &cs[k]);
    }
    usleep(500 * 1000);
    mxfs_pal_mutex_lock(L.gc_lock);
    L.gc_busy = false;
    mxfs_pal_cond_broadcast(L.gc_cond);
    mxfs_pal_mutex_unlock(L.gc_lock);
    for (k = 0; k < NP; k++)
        pthread_join(cs[k].th, NULL);
}

/* the record of page k as the platter holds it: a fresh generation makes
 * ensure() reload every page from both copies */
static int platter_entry(int k, uint64_t fresh_gen, struct mxfs_tauth_entry *e)
{
    int rc = mxfs_tauth_ledger_ensure(&L, pages[k], fresh_gen);

    return rc ? rc : mxfs_tauth_ledger_lookup(&L, &res[k], fresh_gen, e);
}

/* move page k's platter one commit past this node's cache, as another
 * writer would leave it (the ledger_test case 19 method) */
static int make_stale(int k)
{
    struct mxfs_tauth_page *raw = calloc(1, sizeof(*raw));
    int copy, rc;

    rc = mxfs_tauth_page_read(&L.store, pages[k], raw, &copy);
    rc |= mxfs_tauth_page_write(&L.store, raw, raw->hdr.authority_epoch, 1, 0);
    free(raw);
    return rc;
}

int main(void)
{
    static const uint8_t uuid[16] = {9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6};
    const uint64_t base = 65536;
    static struct committer cs[NP];
    struct mxfs_tauth_entry e;
    struct mxfs_tauth_op op;
    mxfs_bdev_t *dev;
    uint64_t b0, p0, ino;
    int np = 0, k, rc, bad, n_err, err_k;

    tl_mktemp("group_commit_test");
    printf("=== group_commit_test file=%s np=%d ===\n", tl_path, NP);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&L, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 5, 100, 3);
    CHECK(rc == 0 && L.gc_lock && L.gc_cond, "0 open rc=%d group commit queue=%d", rc,
          L.gc_lock && L.gc_cond);
    if (rc)
        return 1;
    mxfs_tauth_ledger_set_owner_gen(&L, gen);

    /* NP resources on NP distinct pages, each page bootstrapped to this node */
    for (ino = 4000000; np < NP && ino < 9000000; ino++) {
        struct mxfs_resource_id c = mkres(ino);
        uint32_t pg = tl_page(&c);

        for (k = 0; k < np; k++)
            if (pages[k] == pg)
                break;
        if (k < np)
            continue;
        if (mxfs_tauth_ledger_ensure(&L, pg, gen) != 0 ||
            mxfs_tauth_ledger_activate(&L, pg, gen, 0, true) != 0)
            continue;
        pages[np] = pg;
        res[np] = c;
        np++;
    }
    CHECK(np == NP, "0 %d pages of this node's, one resource each", np);

    /* 5 (first, while the pages are fresh) the knob off: NP concurrent
     * grants each written alone, every one durable, no batch.  The
     * releases then put every page back to FREE for the cases below. */
    mxfs_tauth_group_commit = 0;
    b0 = L.gc_batches;
    for (k = 0; k < NP; k++) {
        cs[k].k = k;
        cs[k].kind = MXFS_TAUTH_OP_GRANT_EX;
        pthread_create(&cs[k].th, NULL, commit_one, &cs[k]);
    }
    for (k = 0; k < NP; k++)
        pthread_join(cs[k].th, NULL);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (cs[k].rc != 0)
            bad++;
    CHECK(bad == 0 && L.gc_batches == b0,
          "5 knob off: %d concurrent grants each written alone (%d refused, batches +%llu)",
          NP, bad, (unsigned long long)(L.gc_batches - b0));
    for (k = 0; k < NP; k++) {
        cs[k].kind = MXFS_TAUTH_OP_RELEASE_EX;
        pthread_create(&cs[k].th, NULL, commit_one, &cs[k]);
    }
    for (k = 0; k < NP; k++)
        pthread_join(cs[k].th, NULL);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (cs[k].rc != 0)
            bad++;
    CHECK(bad == 0, "5 knob off: and released (%d refused)", bad);
    mxfs_tauth_group_commit = 1;

    /* 1 a lone commit */
    b0 = L.gc_batches;
    op = mkop(MXFS_TAUTH_OP_GRANT_EX, &res[0]);
    rc = mxfs_tauth_ledger_commit(&L, &op, 1, gen, 90);
    CHECK(rc == 0 && op.rc == 0 && L.gc_batches == b0,
          "1 a lone commit lands, written alone rc=%d op=%d batches +%llu", rc, op.rc,
          (unsigned long long)(L.gc_batches - b0));
    op = mkop(MXFS_TAUTH_OP_RELEASE_EX, &res[0]);
    name_grant(&op, 0);
    rc = mxfs_tauth_ledger_commit(&L, &op, 1, gen, 90);
    CHECK(rc == 0 && op.rc == 0, "1 and its release rc=%d op=%d", rc, op.rc);

    /* 2 NP concurrent grants */
    b0 = L.gc_batches;
    p0 = L.gc_pages;
    commit_all_at_once(cs, MXFS_TAUTH_OP_GRANT_EX);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (cs[k].rc != 0)
            bad++;
    CHECK(bad == 0, "2 every concurrent grant committed (%d refused)", bad);
    CHECK(L.gc_batches - b0 == 2 && L.gc_pages - p0 == NP && L.gc_max == MXFS_TAUTH_WRITE_BATCH,
          "2 written as batches: %llu batches carrying %llu pages, largest %llu (want 2, %d, %u)",
          (unsigned long long)(L.gc_batches - b0), (unsigned long long)(L.gc_pages - p0),
          (unsigned long long)L.gc_max, NP, MXFS_TAUTH_WRITE_BATCH);
    gen = 2;
    mxfs_tauth_ledger_set_owner_gen(&L, gen);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (platter_entry(k, gen, &e) != 0 || e.state != MXFS_TAUTH_ST_ACTIVE ||
            e.ex_node != 55 || e.ex_inc != 5500)
            bad++;
    CHECK(bad == 0, "2 on the platter: every grant ACTIVE for 55/5500 (%d wrong)", bad);

    /* 3 a stale page inside a batch of releases */
    rc = make_stale(7);
    CHECK(rc == 0, "3 page %u's platter moved past this node's cache rc=%d", pages[7], rc);
    commit_all_at_once(cs, MXFS_TAUTH_OP_RELEASE_EX);
    bad = 0;
    for (k = 0; k < NP; k++)
        if ((k == 7) != (cs[k].rc != 0))
            bad++;
    CHECK(bad == 0 && cs[7].rc == -ESTALE,
          "3 only the stale page's commit refused (rc=%d, %d others wrong)", cs[7].rc, bad);
    gen = 3;
    mxfs_tauth_ledger_set_owner_gen(&L, gen);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (platter_entry(k, gen, &e) != 0 ||
            e.state != (k == 7 ? MXFS_TAUTH_ST_ACTIVE : MXFS_TAUTH_ST_FREE))
            bad++;
    CHECK(bad == 0, "3 on the platter: %d released, the stale page's record still held (%d wrong)",
          NP - 1, bad);
    op = mkop(MXFS_TAUTH_OP_RELEASE_EX, &res[7]);
    name_grant(&op, 7);
    rc = mxfs_tauth_ledger_commit(&L, &op, 1, gen, 91);
    gen = 4;
    mxfs_tauth_ledger_set_owner_gen(&L, gen);
    for (k = 0; k < NP; k++)
        (void)mxfs_tauth_ledger_ensure(&L, pages[k], gen);
    CHECK(rc == 0 && op.rc == 0 && platter_entry(7, gen, &e) == 0 && e.state == MXFS_TAUTH_ST_FREE,
          "3 the stale page's retry lands rc=%d op=%d state=%u", rc, op.rc, e.state);

    /* 4 a ticket swap that fails inside a batch: the store's knob takes the
     * batch's first page, issued with its answer lost */
    L.store.ticket_fail_once_rc = -EIO;
    L.store.ticket_fail_landed = 1;
    commit_all_at_once(cs, MXFS_TAUTH_OP_GRANT_EX);
    n_err = 0;
    err_k = -1;
    bad = 0;
    for (k = 0; k < NP; k++) {
        if (cs[k].rc == -EIO) {
            n_err++;
            err_k = k;
        } else if (cs[k].rc != 0) {
            bad++;
        }
    }
    CHECK(n_err == 1 && bad == 0, "4 exactly one commit failed -EIO, the rest landed (%d -EIO, %d other)",
          n_err, bad);
    gen = 5;
    mxfs_tauth_ledger_set_owner_gen(&L, gen);
    bad = 0;
    for (k = 0; k < NP; k++)
        if (platter_entry(k, gen, &e) != 0 ||
            e.state != (k == err_k ? MXFS_TAUTH_ST_FREE : MXFS_TAUTH_ST_ACTIVE))
            bad++;
    CHECK(err_k >= 0 && bad == 0,
          "4 on the platter: the failed commit left nothing, every other grant held (%d wrong)", bad);
    if (err_k >= 0) {
        uint64_t resumes = L.store.ticket_resumes;

        op = mkop(MXFS_TAUTH_OP_GRANT_EX, &res[err_k]);
        rc = mxfs_tauth_ledger_commit(&L, &op, 1, gen, 92);
        gen = 6;
        mxfs_tauth_ledger_set_owner_gen(&L, gen);
        CHECK(rc == 0 && op.rc == 0 && L.store.ticket_resumes == resumes + 1 &&
              platter_entry(err_k, gen, &e) == 0 && e.state == MXFS_TAUTH_ST_ACTIVE,
              "4 the failed page's retry resumes its own ticket and lands rc=%d op=%d state=%u",
              rc, op.rc, e.state);
    }

    mxfs_tauth_ledger_close(&L);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== group_commit_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
