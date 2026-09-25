// SPDX-License-Identifier: GPL-2.0
/*
 * ledger_test — the TCP authority ledger LAYER (docs/tcp-authority-ledger.md
 * step 3c) against a temp file through the usermode PAL: the SAME
 * dlm/tauth_ledger.c + dlm/tauth_store.c the kernel module links.
 *
 * Every case is an assertion (RESULT line per case, non-zero exit on any
 * failure).  The cases are the grant/release/regrant crash rows of the
 * ruling plus every fail-closed refusal:
 *   1  open/ensure/lookup: fresh region, EMPTY record
 *   2  grant EX mints grant_id {authority_epoch = master inc, seq 1}
 *   3  double grant refused: EX over EX (other node) -EBUSY, PR over EX -EBUSY
 *   4  release with a stale grant_id: ACK semantics (op -ESTALE), no write
 *   5  release EX -> FREE keeps last_grant_seq64
 *   6  shared holders: two PR grants in ONE transition, EX over PR refused,
 *      PR release validates lineage + bit, last release -> FREE
 *   7  slot collision: a second resource on the same slot is refused while
 *      ACTIVE (-EEXIST) and may claim the slot once FREE
 *   8  batch atomicity: a refused op leaves the whole batch unwritten
 *   9  ownership generation: stale gen refused, ensure reloads from platter
 *  10  torn write: proven-not-committed (-EIO), record unchanged, poison
 *      reconciled, the next commit succeeds
 *  11  exhaustion: grant_seq_next at the ceiling refuses (-ENOSPC)
 *  12  persistence/takeover: reopen as another master; records keep their
 *      original authority_epoch; scan_active finds them
 *  13  recovery purge by {node, slot} clears EX + PR holders -> FREE
 *  14  PR -> EX upgrade by the same holder clears its bit; EX re-grant by
 *      the same holder mints a new seq and keeps the old in last_grant_seq64
 *  15  UNKNOWN record refuses every op (-EUCLEAN)
 *  16  fence-time manifest source: collect the exclusive holder's records
 *      fresh from the platter; incarnation / slot mismatches excluded
 *  17  the per-page purge names the INCARNATION: one page carrying EX for
 *      {5,100} and EX for {5,101}, purged naming inc 100 — only the first is
 *      retired, the second survives and is counted in purge_inc_spared, and
 *      the same call with inc = 0 retires it too, which is what makes the
 *      case non-vacuous
 */
#include "tauth_testlib.h"
#include "dlm/tauth_ledger.h"

static struct mxfs_resource_id mkres(uint64_t ino, uint8_t type, uint32_t ag)
{
    struct mxfs_resource_id r;

    memset(&r, 0, sizeof(r));
    r.ino = ino;
    r.type = type;
    r.ag_number = ag;
    return r;
}

static struct mxfs_tauth_op mkop(uint8_t kind, const struct mxfs_resource_id *r,
                                 uint32_t node, uint64_t inc, uint16_t slot,
                                 uint8_t mode)
{
    struct mxfs_tauth_op op;

    memset(&op, 0, sizeof(op));
    op.kind = kind;
    op.res = *r;
    op.node = node;
    op.inc = inc;
    op.slot = slot;
    op.mode = mode;
    return op;
}

/* a "slot" in this test = page * 31 + home index (the v1 slot
 * identity, kept as the test's own encoding of {home page, home index}). */
static uint32_t enc_slot(const struct mxfs_resource_id *r)
{
    return tl_page(r) * MXFS_TAUTH_ENTRIES_PER_PAGE + tl_home(r);
}

/* find a resource whose slot equals `want` (same page + same index) or whose
 * page equals want/31 with a different index (same_page_only) */
static struct mxfs_resource_id find_res(uint32_t want_slot, int same_page_only)
{
    uint64_t ino;

    for (ino = 1000000; ; ino++) {
        struct mxfs_resource_id r = mkres(ino, MXFS_LTYPE_INODE, 0);
        uint32_t s = enc_slot(&r);

        if (!same_page_only && s == want_slot)
            return r;
        if (same_page_only && s != want_slot &&
            s / MXFS_TAUTH_ENTRIES_PER_PAGE == want_slot / MXFS_TAUTH_ENTRIES_PER_PAGE)
            return r;
    }
}

struct scan_acc { int n; uint32_t last_slot; struct mxfs_tauth_entry last; };

/* step 4: page authority.  bootstrap = claim an UNOWNED page as the
 * lowest live slot; takeover = the certified recovery coordinator PREPAREs
 * the dead authority {vnode, vinc}'s page to itself and consumes it. */
static int page_bootstrap(struct mxfs_tauth_ledger *L, uint32_t page, uint64_t gen)
{
    int rc = mxfs_tauth_ledger_ensure(L, page, gen);

    if (rc)
        return rc;
    return mxfs_tauth_ledger_activate(L, page, gen, 0, true);
}

static int page_takeover(struct mxfs_tauth_ledger *L, uint32_t page, uint64_t gen,
                         uint32_t vnode, uint64_t vinc)
{
    uint64_t pseq = 0;
    int rc = mxfs_tauth_ledger_ensure(L, page, gen);

    if (rc)
        return rc;
    rc = mxfs_tauth_ledger_prepare(L, page, gen, L->local_node, L->local_inc,
                                   vnode, vinc, false, &pseq);
    if (rc)
        return rc;
    return mxfs_tauth_ledger_activate(L, page, gen, pseq, false);
}

static void scan_cb(void *data, uint32_t slot, const struct mxfs_tauth_entry *e)
{
    struct scan_acc *a = data;

    a->n++;
    a->last_slot = slot;
    a->last = *e;
}

int main(int argc, char **argv)
{
    static const uint8_t uuid[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const uint64_t base = 65536;
    struct mxfs_tauth_ledger L;
    struct mxfs_tauth_entry e;
    struct mxfs_tauth_op ops[4];
    struct mxfs_resource_id R = mkres(131, MXFS_LTYPE_INODE, 0), R2, R3, R4;
    uint32_t slotR, pageR;
    uint64_t gid_epoch, gid_seq;
    uint64_t gid2 = 0;
    mxfs_bdev_t *dev;
    int rc;

    (void)argc; (void)argv;
    tl_mktemp("ledger_test");
    printf("=== ledger_test file=%s ===\n", tl_path);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }

    slotR = enc_slot(&R);
    pageR = tl_page(&R);
    R2 = find_res(slotR, 0);            /* collides with R */
    R3 = find_res(slotR, 1);            /* same page, other slot */
    R4 = mkres(4096, MXFS_LTYPE_AG, 7); /* anywhere */

    /* 1 open / ensure / lookup */
    rc = mxfs_tauth_ledger_open(&L, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 5, 100, 3);
    CHECK(rc == 0 && L.authority_epoch == 100, "1 open rc=%d authority_epoch=%llu", rc,
          (unsigned long long)L.authority_epoch);
    mxfs_tauth_ledger_set_owner_gen(&L, 1);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == -ENOENT, "1 lookup before ensure = -ENOENT (rc=%d)", rc);
    rc = mxfs_tauth_ledger_ensure(&L, pageR, 1);
    CHECK(rc == 0, "1 ensure page %u rc=%d", pageR, rc);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_EMPTY, "1 lookup fresh = EMPTY rc=%d state=%u", rc, e.state);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == -EPERM && L.authority_refusals == 1 && !mxfs_tauth_ledger_page_mine(&L, pageR),
          "1 commit on an UNOWNED page = -EPERM (rc=%d refusals=%llu)", rc,
          (unsigned long long)L.authority_refusals);
    rc = mxfs_tauth_ledger_activate(&L, pageR, 1, 0, false);
    CHECK(rc == -ESTALE, "1 non-bootstrap activate of an UNOWNED page = -ESTALE (rc=%d)", rc);
    rc = mxfs_tauth_ledger_activate(&L, pageR, 1, 0, true);
    CHECK(rc == 0 && L.activates == 1 && mxfs_tauth_ledger_page_mine(&L, pageR),
          "1 bootstrap activate page %u rc=%d mine=%d", pageR, rc, mxfs_tauth_ledger_page_mine(&L, pageR));
    {
        struct mxfs_tauth_page_auth pa;

        rc = mxfs_tauth_ledger_page_auth(&L, pageR, true, &pa);
        CHECK(rc == 0 && pa.state == MXFS_TAUTH_PG_ACTIVE && pa.auth_node == 5 && pa.auth_inc == 100 &&
              pa.seq == 2 && pa.writer_node == 5,
              "1 platter: ACTIVE auth=%u/%llu seq=%llu", pa.auth_node,
              (unsigned long long)pa.auth_inc, (unsigned long long)pa.seq);
    }
    rc = mxfs_tauth_ledger_activate(&L, pageR, 1, 0, true);
    CHECK(rc == 0 && L.activates == 1, "1 re-activate of my own page is an idempotent adopt (rc=%d)", rc);
    rc = mxfs_tauth_ledger_ensure(&L, pageR, 2);
    CHECK(rc == -ESTALE, "1 ensure with a gen that is not current = -ESTALE (rc=%d)", rc);

    /* 2 grant EX */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    ops[0].lineage = 0xABCD;
    ops[0].dir_epoch = 9;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == 0 && ops[0].rc == 0 && ops[0].authority_epoch == 100 && ops[0].grant_seq64 == 1,
          "2 grant EX rc=%d op.rc=%d grant_id={%llu,%llu}", rc, ops[0].rc,
          (unsigned long long)ops[0].authority_epoch, (unsigned long long)ops[0].grant_seq64);
    gid_epoch = ops[0].authority_epoch;
    gid_seq = ops[0].grant_seq64;
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 5 && e.ex_inc == 100 &&
          e.ex_slot == 3 && e.ex_mode == MXFS_LOCK_EX && e.resource_lineage == 0xABCD &&
          e.dir_epoch == 9 && e.config_epoch == 77 && e.auth_node == 5 && e.auth_slot == 3 &&
          e.holders == 0 && e.transition_seq64 == 1,
          "2 record ACTIVE ex=%u/%llu slot=%u mode=%u lineage=%#llx tseq=%llu auth_node=%u",
          e.ex_node, (unsigned long long)e.ex_inc, e.ex_slot, e.ex_mode,
          (unsigned long long)e.resource_lineage, (unsigned long long)e.transition_seq64, e.auth_node);
    CHECK(L.commits == 1, "2 commits=%llu", (unsigned long long)L.commits);

    /* 3 double grant refused */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 6, 200, 4, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == -EBUSY && ops[0].rc == -EBUSY && L.busy_denies == 1, "3 EX over another EX = -EBUSY (rc=%d)", rc);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 6, 200, 4, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == -EBUSY && L.busy_denies == 2, "3 PR over EX = -EBUSY (rc=%d)", rc);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.ex_node == 5 && e.holders == 0 && L.commits == 1, "3 record unchanged, nothing written");

    /* 4 stale release = ACK, no write */
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    ops[0].authority_epoch = gid_epoch;
    ops[0].grant_seq64 = gid_seq + 5;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == 0 && ops[0].rc == -ESTALE && L.noop_commits == 1 && L.commits == 1,
          "4 release with stale grant_id: batch rc=%d op.rc=%d noop=%llu", rc, ops[0].rc,
          (unsigned long long)L.noop_commits);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R, 5, 999, 3, MXFS_LOCK_EX);   /* wrong inc */
    ops[0].authority_epoch = gid_epoch;
    ops[0].grant_seq64 = gid_seq;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 77);
    CHECK(rc == 0 && ops[0].rc == -ESTALE, "4 release with wrong incarnation: op.rc=%d", ops[0].rc);

    /* 5 release EX -> FREE */
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    ops[0].authority_epoch = gid_epoch;
    ops[0].grant_seq64 = gid_seq;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 78);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE && e.ex_node == 0 && e.grant_seq64 == 0 &&
          e.last_grant_seq64 == 1 && e.ino == 131 && e.config_epoch == 78 && L.commits == 2,
          "5 release EX -> FREE last_grant_seq64=%llu", (unsigned long long)e.last_grant_seq64);

    /* 6 shared holders */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 6, 200, 4, MXFS_LOCK_PR);
    ops[0].lineage = 0x5151;
    ops[1] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 7, 300, 5, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 2, 1, 79);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.holders == ((1ULL << 4) | (1ULL << 5)) &&
          e.shared_mode == MXFS_LOCK_PR && e.ex_node == 0 && e.resource_lineage == 0x5151 &&
          L.commits == 3 && ops[1].lineage_out == 0x5151,
          "6 two PR grants in one transition holders=%#llx commits=%llu", (unsigned long long)e.holders,
          (unsigned long long)L.commits);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 8, 400, 6, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 79);
    CHECK(rc == -EBUSY, "6 EX over PR holders = -EBUSY (rc=%d)", rc);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_PR, &R, 6, 200, 4, MXFS_LOCK_PR);
    ops[0].lineage = 0x9999;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 79);
    CHECK(rc == 0 && ops[0].rc == -ESTALE, "6 PR release with wrong lineage is stale (op.rc=%d)", ops[0].rc);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_PR, &R, 6, 200, 9, MXFS_LOCK_PR);   /* bit not set */
    ops[0].lineage = 0x5151;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 79);
    CHECK(rc == 0 && ops[0].rc == -ESTALE, "6 PR release of a clear bit is stale (op.rc=%d)", ops[0].rc);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_PR, &R, 6, 200, 4, MXFS_LOCK_PR);
    ops[0].lineage = 0x5151;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 79);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.holders == (1ULL << 5),
          "6 PR release clears its bit holders=%#llx", (unsigned long long)e.holders);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_PR, &R, 7, 300, 5, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 79);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE && e.holders == 0 && e.shared_mode == 0,
          "6 last PR release -> FREE");

    /* 7 slot collision */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 80);
    CHECK(rc == 0 && ops[0].grant_seq64 == 2, "7 re-grant R: seq=%llu (allocator continues)",
          (unsigned long long)ops[0].grant_seq64);
    gid_seq = ops[0].grant_seq64;
    /* (D-0348): page-local open addressing — R2 shares R's home
     * index but gets its OWN entry on the page; nothing is refused. */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R2, 6, 200, 4, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 80);
    CHECK(rc == 0 && ops[0].rc == 0 && L.collisions == 0 && L.probes >= 1,
          "7 R2 (same home index %u as ACTIVE R) lands in another entry: rc=%d probes=%llu",
          slotR, rc, (unsigned long long)L.probes);
    gid2 = ops[0].grant_seq64;
    rc = mxfs_tauth_ledger_lookup(&L, &R2, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ino == R2.ino && e.ex_node == 6,
          "7 lookup R2 finds its own record (ino=%llu ex=%u)", (unsigned long long)e.ino, e.ex_node);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ino == R.ino && e.ex_node == 5,
          "7 lookup R still finds R (ino=%llu ex=%u)", (unsigned long long)e.ino, e.ex_node);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    ops[0].authority_epoch = 100;
    ops[0].grant_seq64 = gid_seq;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 80);
    CHECK(rc == 0 && ops[0].rc == 0, "7 release R -> FREE (rc=%d)", rc);
    ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R2, 6, 200, 4, MXFS_LOCK_EX);
    ops[0].authority_epoch = 100;
    ops[0].grant_seq64 = gid2;
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 80);
    CHECK(rc == 0 && ops[0].rc == 0, "7 release R2 -> FREE (rc=%d)", rc);

    /* 8 batch atomicity */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 81);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R3, 7, 300, 5, MXFS_LOCK_PR);
    ops[1] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 6, 200, 4, MXFS_LOCK_EX);    /* R is ACTIVE(5): double grant */
    rc = mxfs_tauth_ledger_commit(&L, ops, 2, 1, 81);
    CHECK(rc == -EBUSY && ops[0].rc == -EBUSY, "8 batch refused rc=%d op0.rc=%d", rc, ops[0].rc);
    rc = mxfs_tauth_ledger_lookup(&L, &R3, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_EMPTY, "8 R3 untouched (state=%u)", e.state);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 5, 100, 3, MXFS_LOCK_EX);
    ops[1] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R4, 5, 100, 3, MXFS_LOCK_EX);   /* other page */
    rc = mxfs_tauth_ledger_commit(&L, ops, 2, 1, 81);
    CHECK(rc == -EINVAL, "8 ops on two pages = -EINVAL (rc=%d)", rc);

    /* 9 ownership generation */
    mxfs_tauth_ledger_set_owner_gen(&L, 2);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R3, 7, 300, 5, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 82);
    CHECK(rc == -ESTALE && L.commits == 10, "9 commit under old gen = -ESTALE (rc=%d commits=%llu)", rc,
          (unsigned long long)L.commits);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 2, &e);
    CHECK(rc == -ENOENT, "9 lookup under new gen before ensure = -ENOENT");
    rc = mxfs_tauth_ledger_ensure(&L, pageR, 2);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 2, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 5 && L.pages[pageR].loads == 2,
          "9 ensure reloads from the platter: ACTIVE ex=%u loads=%llu", e.ex_node,
          (unsigned long long)L.pages[pageR].loads);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 2, 82);
    CHECK(rc == 0 && ops[0].rc == 0, "9 commit under the current gen rc=%d", rc);

    /* 10 torn write */
    rc = page_bootstrap(&L, tl_page(&R4), 2);
    CHECK(rc == 0, "10 bootstrap R4's page rc=%d", rc);
    L.torn_after_bytes = 1024;
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R4, 5, 100, 3, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 2, 83);
    CHECK(rc == -EIO && ops[0].rc == -EIO && L.poisons == 1 && L.reconciled == 1 && L.uncommitted == 1,
          "10 torn commit = proven not committed rc=%d poisons=%llu reconciled=%llu", rc,
          (unsigned long long)L.poisons, (unsigned long long)L.reconciled);
    rc = mxfs_tauth_ledger_lookup(&L, &R4, 2, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_EMPTY && !L.pages[tl_page(&R4)].poisoned,
          "10 record unchanged, page not poisoned after reconcile");
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R4, 5, 100, 3, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 2, 83);
    rc |= mxfs_tauth_ledger_lookup(&L, &R4, 2, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && ops[0].grant_seq64 == 1 && L.store.torn_seen >= 1,
          "10 next commit repairs the torn copy and succeeds (seq=%llu)", (unsigned long long)ops[0].grant_seq64);

    /* 11 exhaustion */
    {
        struct mxfs_tauth_page *raw = calloc(1, sizeof(*raw));
        struct mxfs_resource_id R5 = mkres(777777, MXFS_LTYPE_INODE, 0);
        uint32_t p5 = tl_page(&R5);

        raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, p5, 0), raw, sizeof(*raw));
        raw->hdr.grant_seq_next = ~0ULL;
        raw->hdr.crc32c = mxfs_tauth_page_crc(raw, tl_crc);
        raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, p5, 0), raw, sizeof(*raw));
        rc = page_bootstrap(&L, p5, 2);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R5, 5, 100, 3, MXFS_LOCK_EX);
        rc |= mxfs_tauth_ledger_commit(&L, ops, 1, 2, 84);
        CHECK(rc == -ENOSPC && L.exhausted == 1, "11 grant_seq exhaustion = -ENOSPC (rc=%d)", rc);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R5, 5, 100, 3, MXFS_LOCK_PR);
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, 2, 84);
        CHECK(rc == 0 && ops[0].rc == 0, "11 PR grant needs no grant_seq: rc=%d", rc);
        free(raw);
    }

    /* 12 persistence / takeover */
    /* 7b (D-0348): a FULL home page is a capacity WAIT, never EIO:
     * fill R4's page with 31 distinct ACTIVE records, the 32nd -> -EDQUOT
     * (P-TAUTH-PAGE-FULL); release one and it lands. */
    {
        struct mxfs_resource_id fr[MXFS_TAUTH_ENTRIES_PER_PAGE + 1];
        uint32_t fpage = tl_page(&R4);
        uint64_t fino = R4.ino + 1, fseq[MXFS_TAUTH_ENTRIES_PER_PAGE + 1];
        int k, nfull = 0;
        uint64_t fgen = L.owner_gen;

        for (k = 0; k < (int)MXFS_TAUTH_ENTRIES_PER_PAGE + 1; k++) {
            memset(&fr[k], 0, sizeof(fr[k]));
            fr[k].type = MXFS_LTYPE_INODE;
            for (;; fino++) {
                fr[k].ino = fino;
                if (tl_page(&fr[k]) == fpage) { fino++; break; }
            }
        }
        rc = mxfs_tauth_ledger_activate(&L, fpage, fgen, 0, true);
        rc |= mxfs_tauth_ledger_ensure(&L, fpage, fgen);
        CHECK(rc == 0, "7b page %u activated + ensured under the live gen (rc=%d)", fpage, rc);
        /* the page may already hold records from earlier groups: fill until
         * the first capacity refusal, which must be -EDQUOT and must leave
         * exactly 31 occupied entries */
        {
            int full_k = -1, full_rc = 0;

            for (k = 0; k < (int)MXFS_TAUTH_ENTRIES_PER_PAGE + 1; k++) {
                ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &fr[k], 5, 100, 3, MXFS_LOCK_EX);
                rc = mxfs_tauth_ledger_commit(&L, ops, 1, fgen, 82);
                if (rc == 0) { nfull++; fseq[k] = ops[0].grant_seq64; continue; }
                full_k = k; full_rc = rc; break;
            }
            CHECK(full_k >= 1 && full_rc == -EDQUOT && L.page_full == 1,
                  "7b page %u filled with %d fresh records, then -EDQUOT (rc=%d page_full=%llu)",
                  fpage, nfull, full_rc, (unsigned long long)L.page_full);
            /* the refused one is the waiter below */
            fr[MXFS_TAUTH_ENTRIES_PER_PAGE] = fr[full_k < 0 ? 0 : full_k];
            nfull = full_k < 0 ? nfull : full_k;
        }
        ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &fr[0], 5, 100, 3, MXFS_LOCK_EX);
        ops[0].authority_epoch = 100;
        ops[0].grant_seq64 = fseq[0];
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, fgen, 82);
        CHECK(rc == 0 && ops[0].rc == 0, "7b release one (rc=%d op.rc=%d)", rc, ops[0].rc);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &fr[MXFS_TAUTH_ENTRIES_PER_PAGE], 5, 100, 3, MXFS_LOCK_EX);
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, fgen, 82);
        rc |= mxfs_tauth_ledger_lookup(&L, &fr[MXFS_TAUTH_ENTRIES_PER_PAGE], fgen, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ino == fr[MXFS_TAUTH_ENTRIES_PER_PAGE].ino,
              "7b the waiter lands once an entry frees (rc=%d state=%u)", rc, e.state);
        fseq[MXFS_TAUTH_ENTRIES_PER_PAGE] = ops[0].grant_seq64;
        for (k = 1; k < nfull; k++) {
            ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &fr[k], 5, 100, 3, MXFS_LOCK_EX);
            ops[0].authority_epoch = 100;
            ops[0].grant_seq64 = fseq[k];
            (void)mxfs_tauth_ledger_commit(&L, ops, 1, fgen, 82);
        }
        ops[0] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &fr[MXFS_TAUTH_ENTRIES_PER_PAGE], 5, 100, 3, MXFS_LOCK_EX);
        ops[0].authority_epoch = 100;
        ops[0].grant_seq64 = fseq[MXFS_TAUTH_ENTRIES_PER_PAGE];
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, fgen, 82);
        CHECK(rc == 0 && ops[0].rc == 0, "7b page %u drained again (rc=%d)", fpage, rc);
    }

    mxfs_tauth_ledger_close(&L);
    rc = mxfs_tauth_ledger_open(&L, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 9, 900, 11);
    mxfs_tauth_ledger_set_owner_gen(&L, 1);
    rc |= mxfs_tauth_ledger_ensure(&L, pageR, 1);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 5 && e.authority_epoch == 100 &&
          e.auth_node == 5 && e.grant_seq64 == 4,
          "12 reopened as master 9: R keeps authority_epoch=%llu auth_node=%u seq=%llu",
          (unsigned long long)e.authority_epoch, e.auth_node, (unsigned long long)e.grant_seq64);
    {
        struct scan_acc acc = {0, 0, {0}};

        rc = mxfs_tauth_ledger_scan_active(&L, pageR, 1, scan_cb, &acc);
        CHECK(rc == 2 && acc.n == 2, "12 scan_active on page %u finds R and R3 (n=%d)", pageR, rc);
    }
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R3, 9, 900, 11, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 90);
    CHECK(rc == -EPERM, "12 commit on the dead authority's page before takeover = -EPERM (rc=%d)", rc);
    rc = mxfs_tauth_ledger_activate(&L, pageR, 1, 0, true);
    CHECK(rc == -ESTALE, "12 bootstrap of an ACTIVE page refused (rc=%d)", rc);
    rc = mxfs_tauth_ledger_prepare(&L, pageR, 1, 9, 900, 5, 999, false, NULL);
    CHECK(rc == -EPERM && L.authority_refusals == 2, "12 prepare naming the wrong victim inc = -EPERM (rc=%d)", rc);
    {
        uint64_t pseq = 0, pseq2 = 0;
        struct mxfs_tauth_page_auth pa;

        rc = mxfs_tauth_ledger_prepare(&L, pageR, 1, 9, 900, 5, 100, false, &pseq);
        CHECK(rc == 0 && L.prepares == 1 && pseq != 0, "12 coordinator PREPAREs page %u to 9/900 seq=%llu rc=%d",
              pageR, (unsigned long long)pseq, rc);
        rc = mxfs_tauth_ledger_page_auth(&L, pageR, true, &pa);
        CHECK(rc == 0 && pa.state == MXFS_TAUTH_PG_PREPARED && pa.auth_node == 5 && pa.auth_inc == 100 &&
              pa.target_node == 9 && pa.target_inc == 900 && pa.seq == pseq,
              "12 platter: PREPARED auth=5/100 target=%u/%llu seq=%llu", pa.target_node,
              (unsigned long long)pa.target_inc, (unsigned long long)pa.seq);
        rc = mxfs_tauth_ledger_prepare(&L, pageR, 1, 9, 900, 5, 100, false, &pseq2);
        CHECK(rc == 0 && pseq2 == pseq && L.prepares == 1, "12 repeat prepare is idempotent (seq=%llu)",
              (unsigned long long)pseq2);
        rc = mxfs_tauth_ledger_prepare(&L, pageR, 1, 10, 1000, 5, 100, false, NULL);
        CHECK(rc == -EPERM, "12 retarget without proof refused (rc=%d)", rc);
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 90);
        CHECK(rc == -EPERM, "12 PREPARED page still refuses commits (rc=%d)", rc);
        rc = mxfs_tauth_ledger_activate(&L, pageR, 1, pseq + 1, false);
        CHECK(rc == -ESTALE, "12 activate with the wrong expect_seq = -ESTALE (rc=%d)", rc);
        rc = mxfs_tauth_ledger_activate(&L, pageR, 1, pseq, false);
        CHECK(rc == 0 && L.activates == 1 && mxfs_tauth_ledger_page_mine(&L, pageR),
              "12 target consumes the exact PREPARED record: ACTIVE(9/900) rc=%d", rc);
        rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 5 && e.grant_seq64 == 4,
              "12 entries unchanged across the handoff (ex=%u seq=%llu)", e.ex_node,
              (unsigned long long)e.grant_seq64);
    }
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 90);
    CHECK(rc == -EBUSY, "12 new master honours the imported PR holder on R3 (rc=%d)", rc);
    {
        struct mxfs_resource_id R5b = mkres(777777, MXFS_LTYPE_INODE, 0);

        rc = page_takeover(&L, tl_page(&R4), 1, 5, 100);
        rc |= page_takeover(&L, tl_page(&R5b), 1, 5, 100);
    }
    CHECK(rc == 0 && L.prepares == 3 && L.activates == 3, "12 takeover of R4's and R5's pages rc=%d", rc);

    /* 13 recovery purge by {node, slot} */
    rc = mxfs_tauth_ledger_purge_owner(&L, 5, 3, 1, 91, NULL, NULL);
    CHECK(rc == 3 && L.purged == 3, "13 purge node 5 slot 3 cleared %d records (R, R4, R5's PR bit)", rc);
    rc = mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE && e.last_grant_seq64 == 4, "13 R -> FREE last=%llu",
          (unsigned long long)e.last_grant_seq64);
    rc = mxfs_tauth_ledger_purge_owner(&L, 7, 5, 1, 91, NULL, NULL);
    CHECK(rc == 1, "13 purge node 7 slot 5 cleared %d record", rc);
    rc = mxfs_tauth_ledger_lookup(&L, &R3, 1, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE, "13 purge PR holder slot 5 -> R3 FREE");
    rc = mxfs_tauth_ledger_purge_owner(&L, 5, 3, 1, 91, NULL, NULL);
    CHECK(rc == 0, "13 second purge is a no-op (rc=%d)", rc);

    /* 14 upgrade / re-grant by the same holder */
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 9, 900, 11, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 92);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 9, 900, 11, MXFS_LOCK_EX);
    rc |= mxfs_tauth_ledger_commit(&L, ops, 1, 1, 92);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.holders == 0 && e.ex_node == 9 && e.authority_epoch == 900 && e.grant_seq64 == 5 &&
          e.auth_node == 9 && e.auth_slot == 11,
          "14 PR->EX upgrade clears the bit; grant_id={%llu,%llu} auth_node=%u",
          (unsigned long long)e.authority_epoch, (unsigned long long)e.grant_seq64, e.auth_node);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 9, 900, 11, MXFS_LOCK_EX);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 92);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.grant_seq64 == 6 && e.last_grant_seq64 == 5,
          "14 EX re-grant by the holder mints seq %llu, last=%llu", (unsigned long long)e.grant_seq64,
          (unsigned long long)e.last_grant_seq64);
    ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 9, 900, 11, MXFS_LOCK_PR);
    rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 92);
    rc |= mxfs_tauth_ledger_lookup(&L, &R, 1, &e);
    CHECK(rc == 0 && e.ex_node == 0 && e.holders == (1ULL << 11) && e.last_grant_seq64 == 6,
          "14 EX->PR downgrade by the holder");

    /* 16 fence-time manifest source (TCP replay authority): collect the
     * exclusive holder's records fresh from the platter; read one record
     * fresh; incarnation / slot mismatches excluded; a page with no
     * committed image fails the collection closed */
    {
        struct scan_acc acc;
        struct mxfs_tauth_entry fe;
        uint32_t scanned = 0, mism = 0, idx = 0;
        uint64_t g4_epoch, g4_seq;
        struct mxfs_tauth_page *zero;
        uint32_t page_r5b;

        /* after 14: R has holder 9/900 slot 11 in PR only -> no EX holder */
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 900, 11, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == 0 && acc.n == 0 && scanned == L.npages && mism == 0,
              "16 no EX holder: 0 entries, %u pages scanned rc=%d", scanned, rc);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R, 9, 900, 11, MXFS_LOCK_EX);
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 94);
        ops[1] = mkop(MXFS_TAUTH_OP_GRANT_EX, &R4, 9, 900, 11, MXFS_LOCK_PW);
        ops[1].lineage = 0x5151;
        rc |= mxfs_tauth_ledger_commit(&L, &ops[1], 1, 1, 94);
        g4_epoch = ops[1].authority_epoch;
        g4_seq = ops[1].grant_seq64;
        CHECK(rc == 0, "16 EX on R + PW on R4 for 9/900 slot 11 rc=%d", rc);
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 900, 11, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == 0 && acc.n == 2 && mism == 0,
              "16 collect 9/900 slot 11: %d entries (want 2) mism=%u rc=%d", acc.n, mism, rc);
        rc = mxfs_tauth_ledger_read_fresh(&L, &R4, &fe, &idx);
        CHECK(rc == 0 && fe.state == MXFS_TAUTH_ST_ACTIVE && fe.ex_node == 9 && fe.ex_inc == 900 &&
              fe.ex_slot == 11 && fe.ex_mode == MXFS_LOCK_PW && fe.resource_lineage == 0x5151 &&
              fe.authority_epoch == g4_epoch && fe.grant_seq64 == g4_seq &&
              idx / MXFS_TAUTH_ENTRIES_PER_PAGE == tl_page(&R4),
              "16 read_fresh R4: ACTIVE PW 9/900/11 lineage=%llx grant_id={%llu,%llu} idx=%u (page %u)",
              (unsigned long long)fe.resource_lineage, (unsigned long long)fe.authority_epoch,
              (unsigned long long)fe.grant_seq64, idx, tl_page(&R4));
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 901, 11, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == 0 && acc.n == 0 && mism == 2,
              "16 another incarnation of 9/slot 11: 0 entries, %u excluded", mism);
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 900, 12, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == 0 && acc.n == 0 && mism == 0, "16 another slot of node 9: 0 entries");
        ops[2] = mkop(MXFS_TAUTH_OP_RELEASE_EX, &R4, 9, 900, 11, MXFS_LOCK_PW);
        ops[2].authority_epoch = g4_epoch;
        ops[2].grant_seq64 = g4_seq;
        rc = mxfs_tauth_ledger_commit(&L, &ops[2], 1, 1, 94);
        rc |= mxfs_tauth_ledger_read_fresh(&L, &R4, &fe, &idx);
        CHECK(rc == 0 && fe.state == MXFS_TAUTH_ST_FREE && fe.last_grant_seq64 == g4_seq && idx != UINT32_MAX,
              "16 after release read_fresh R4 = FREE last=%llu", (unsigned long long)fe.last_grant_seq64);
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 900, 11, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == 0 && acc.n == 1 && acc.last.ino == 131,
              "16 collect after the release: %d entry (R only)", acc.n);
        rc = mxfs_tauth_ledger_read_fresh(&L, &R3, &fe, &idx);
        CHECK(rc == 0 && fe.state == MXFS_TAUTH_ST_FREE, "16 read_fresh of a FREE record rc=%d state=%u", rc, fe.state);
        {
            struct mxfs_resource_id never = mkres(31337, MXFS_LTYPE_INODE, 0);

            rc = mxfs_tauth_ledger_read_fresh(&L, &never, &fe, &idx);
            CHECK(rc == 0 && fe.state == MXFS_TAUTH_ST_EMPTY && idx == UINT32_MAX,
                  "16 read_fresh of a never-recorded resource: EMPTY idx=%u", idx);
        }
        /* destroy both copies of one page (R5b's): the collection must
         * refuse rather than report a possibly incomplete manifest */
        {
            struct mxfs_resource_id r5b = mkres(777777, MXFS_LTYPE_INODE, 0);

            page_r5b = tl_page(&r5b);
        }
        zero = calloc(1, sizeof(*zero));
        raw_write(base + mxfs_tauth_page_off(L.npages, page_r5b, 0), zero, sizeof(*zero));
        raw_write(base + mxfs_tauth_page_off(L.npages, page_r5b, 1), zero, sizeof(*zero));
        free(zero);
        memset(&acc, 0, sizeof(acc));
        rc = mxfs_tauth_ledger_collect_ex_holder(&L, 9, 900, 11, scan_cb, &acc, &scanned, &mism);
        CHECK(rc == -EUCLEAN && scanned == L.npages,
              "16 a page with no committed image fails the collection closed rc=%d scanned=%u", rc, scanned);
    }

    /* 17 the per-page purge names the INCARNATION, not just the node id.
     * A takeover activates a page and then retires the departed owner's
     * records on it — but the page is servable from the activation onward,
     * and the departed node id can be carried by a mount that is very much
     * alive (a resumed term adopts its predecessor's node id; a pinned id
     * does the same).  Matching on the id alone retired that live tenure. */
    {
        struct mxfs_resource_id dead, live;
        struct mxfs_tauth_entry de, le;
        uint64_t spared0 = L.purge_inc_spared;
        uint64_t ino;
        int found = 0, prc;

        memset(&dead, 0, sizeof(dead));
        memset(&live, 0, sizeof(live));
        for (ino = 200000; ino < 900000 && found < 2; ino++) {
            struct mxfs_resource_id c = mkres(ino, MXFS_LTYPE_INODE, 0);

            if (tl_page(&c) != pageR)
                continue;
            if (found == 0)
                dead = c;
            else
                live = c;
            found++;
        }
        CHECK(found == 2, "17 two resources share page %u (found=%d)", pageR, found);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &dead, 5, 100, 3, MXFS_LOCK_EX);
        rc = mxfs_tauth_ledger_commit(&L, ops, 1, 1, 95);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_EX, &live, 5, 101, 3, MXFS_LOCK_EX);
        rc |= mxfs_tauth_ledger_commit(&L, ops, 1, 1, 95);
        CHECK(rc == 0, "17 node 5 holds EX under inc 100 AND inc 101 on page %u rc=%d", pageR, rc);
        prc = mxfs_tauth_ledger_purge_owner_page(&L, 5, 100, -1, 1, 95, pageR);
        CHECK(prc == 1, "17 the page purge naming inc 100 cleared %d record (want 1)", prc);
        rc = mxfs_tauth_ledger_lookup(&L, &dead, 1, &de);
        CHECK(rc == 0 && de.state == MXFS_TAUTH_ST_FREE,
              "17 the departed incarnation's record IS retired (state=%u)", de.state);
        rc = mxfs_tauth_ledger_lookup(&L, &live, 1, &le);
        CHECK(rc == 0 && le.state == MXFS_TAUTH_ST_ACTIVE && le.ex_node == 5 && le.ex_inc == 101,
              "17 the same node id under inc 101 SURVIVES (state=%u ex=%u/%llu)",
              le.state, le.ex_node, (unsigned long long)le.ex_inc);
        CHECK(L.purge_inc_spared == spared0 + 1,
              "17 the spared record is counted (purge_inc_spared=%llu)",
              (unsigned long long)L.purge_inc_spared);
        /* NON-VACUITY: the id-only form retires that very record, so the
         * fixture is exercising the entry the old call would have eaten. */
        prc = mxfs_tauth_ledger_purge_owner_page(&L, 5, 0, -1, 1, 95, pageR);
        rc = mxfs_tauth_ledger_lookup(&L, &live, 1, &le);
        CHECK(prc == 1 && rc == 0 && le.state == MXFS_TAUTH_ST_FREE,
              "17 the id-only purge retires the same record (cleared=%d state=%u) — "
              "the fixture is not vacuous", prc, le.state);
    }

    /* 15 UNKNOWN record refuses */
    {
        struct mxfs_tauth_page *raw = calloc(1, sizeof(*raw));
        int copy;

        mxfs_tauth_ledger_set_owner_gen(&L, 3);
        rc = mxfs_tauth_page_read(&L.store, pageR, raw, &copy);
        raw->ent[slotR % MXFS_TAUTH_ENTRIES_PER_PAGE].state = MXFS_TAUTH_ST_UNKNOWN;
        rc |= mxfs_tauth_page_write(&L.store, raw, raw->hdr.authority_epoch, 1, 0);
        rc |= mxfs_tauth_ledger_ensure(&L, pageR, 3);
        rc |= (mxfs_tauth_ledger_lookup(&L, &R, 3, &e) == -EUCLEAN ? 0 : 1);
        ops[0] = mkop(MXFS_TAUTH_OP_GRANT_PR, &R, 9, 900, 11, MXFS_LOCK_PR);
        CHECK(rc == 0 && mxfs_tauth_ledger_commit(&L, ops, 1, 3, 93) == -EUCLEAN,
              "15 UNKNOWN record: lookup -EUCLEAN, commit -EUCLEAN");
        free(raw);
    }

    mxfs_tauth_ledger_close(&L);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== ledger_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
