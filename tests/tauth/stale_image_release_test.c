// SPDX-License-Identifier: GPL-2.0
/*
 * stale_image_release_test — a locally mastered release committed after a
 * membership change must reach the platter.
 *
 * Measured on the 4/tcp rig (0.90.17, chk_clean run 20260929T020716Z, the
 * old test1 incarnation's own log in emission order): the last node to
 * unmount became the root inode's page authority by departure handoff (its
 * page image loaded under the two-member generation), a further peer's
 * GOODBYE then moved the page-ownership generation, and its release-all
 * released its own root-inode PR.  The ledger refused that commit because
 * the cached image was loaded under the older generation (gen_refusals=1 in
 * its close statistics, one PR release counted where two had happened),
 * dlm_txn_commit reported -ESTALE, the finalize freed the table entry as
 * "superseded / remastered: the releaser holds nothing", the unlock returned
 * 0, and the node departed as the last member with its PR bit still on the
 * platter.  The next mount's page takeover imported that bit as a GRANTED
 * PR with an UNKNOWN owner (its slot re-occupied by the node's new
 * incarnation), nothing could BAST or retire it, and every mount's EX
 * request on the root inode queued behind it for its whole 60-retry budget.
 *
 * The ledger answers -ESTALE for two different things: a page that is no
 * longer this node's (the remaster the DLM assumes) and a page image loaded
 * under an OLDER ownership generation, which every membership change makes
 * of every page a node keeps.  A grant survives that because its requester
 * re-sends through a path that re-ensures the page; a local release was
 * committed once from the table and dropped.
 *
 * Shape: M masters R and holds PR on it (the image loaded under the view
 * {M, A}); A leaves and the view becomes {M} (the generation moves, every
 * cached page is stale); M unlocks its PR.  Assert: the unlock reports 0,
 * the platter record has no holder, M holds nothing, and the engine counted
 * the stale-image retry it took.  Lap 2 holds the PR through two view
 * changes (B joins, then leaves), so the retry must re-ensure under the
 * latest generation.  Lap 3 is the incident's own order: M's page is
 * imported by a remote holder's grant (the image loaded under the wider
 * view), the peer releases and leaves, and M's own release follows.
 */
#define NNODES 3
#include "dlm_mesh.h"

static int holders_clean(const struct mxfs_resource_id *R, const char *lap)
{
    struct mxfs_tauth_entry e;
    int rc = probe_lookup(R, &e);

    CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
          "%s platter record clean: rc=%d state=%u holders=%#llx ex=%u",
          lap, rc, e.state, (unsigned long long)e.holders, e.ex_node);
    return rc == 0 && e.holders == 0 && e.ex_node == 0;
}

int main(void)
{
    struct mxfs_resource_id R;
    struct mxfs_tauth_entry e;
    mxfs_node_id_t ids[NNODES];
    struct vnode *M, *A, *B = NULL;
    uint8_t granted = 0;
    uint64_t gr0, sr0;
    int rc;

    tl_mktemp("stale_image_release_test");
    printf("=== stale_image_release_test file=%s ===\n", tl_path);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    M = node_up(0, 1000, 5000, 1, 1);
    A = node_up(1, 2000, 5001, 2, 1);
    ids[0] = M->id; ids[1] = A->id;
    membership(ids, 2);
    mxfs_pal_sleep_ms(50);
    /* a resource M masters under {M, A}; the view {M} maps every page to M
     * and {M, B} sorts M first exactly as {M, A} did, so R stays M's */
    R = res_mastered_by(M, M->id, 128);
    printf("  R ino=%llu master=%u\n", (unsigned long long)R.ino, M->id);

    /* ── lap 1: one view change between the grant and the release ── */
    rc = lock_sync(M, &R, MXFS_LOCK_PR, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap1 M PR rc=%d granted=%u", rc, granted);
    settle(M);
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.holders == (1ULL << M->slot),
          "lap1 the grant is on the platter: rc=%d holders=%#llx", rc,
          (unsigned long long)e.holders);
    node_down(A);                       /* A leaves; the view is now {M} */
    A = NULL;
    membership(ids, 1);
    mxfs_pal_sleep_ms(30);
    gr0 = M->ledger.gen_refusals;
    sr0 = M->dlm->ledger_stale_image_retries;
    rc = mxfs_dlm_unlock(M->dlm, &R);
    CHECK(rc == 0, "lap1 M unlock rc=%d", rc);
    settle(M);
    holders_clean(&R, "lap1");
    CHECK(mxfs_dlm_held_mode(M->dlm, &R) == MXFS_LOCK_NL, "lap1 M holds nothing (%u)",
          mxfs_dlm_held_mode(M->dlm, &R));
    CHECK(M->ledger.gen_refusals == gr0 + 1,
          "lap1 the first commit was refused for the stale image (gen_refusals +%llu)",
          (unsigned long long)(M->ledger.gen_refusals - gr0));
    CHECK(M->dlm->ledger_stale_image_retries == sr0 + 1,
          "lap1 the commit re-read the page under the moved generation and retried (+%llu)",
          (unsigned long long)(M->dlm->ledger_stale_image_retries - sr0));
    CHECK(mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)) == 0,
          "lap1 no in-flight entry on M's page (%d)",
          mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)));

    /* ── lap 2: two view changes (B joins and leaves) before the release ── */
    if (!tl_fails) {
        rc = lock_sync(M, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap2 M PR rc=%d", rc);
        settle(M);
        B = node_up(2, 3000, 5002, 3, 1);
        ids[0] = M->id; ids[1] = B->id;
        membership(ids, 2);
        mxfs_pal_sleep_ms(30);
        CHECK(mxfs_dlm_resource_master(M->dlm, &R) == M->id, "lap2 R still mastered by M under {M, B}");
        node_down(B);
        B = NULL;
        membership(ids, 1);
        mxfs_pal_sleep_ms(30);
        sr0 = M->dlm->ledger_stale_image_retries;
        rc = mxfs_dlm_unlock(M->dlm, &R);
        CHECK(rc == 0, "lap2 M unlock rc=%d", rc);
        settle(M);
        holders_clean(&R, "lap2");
        CHECK(mxfs_dlm_held_mode(M->dlm, &R) == MXFS_LOCK_NL, "lap2 M holds nothing");
        CHECK(M->dlm->ledger_stale_image_retries == sr0 + 1,
              "lap2 one re-read under the latest generation (+%llu)",
              (unsigned long long)(M->dlm->ledger_stale_image_retries - sr0));
    }

    /* ── lap 3: the incident's order — a remote PR is granted and released
     * (the image loaded under {M, B}), B leaves, then M's own release ── */
    if (!tl_fails) {
        B = node_up(2, 3000, 5003, 3, 1);
        ids[0] = M->id; ids[1] = B->id;
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        rc = lock_sync(M, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap3 M PR rc=%d", rc);
        rc = lock_sync(B, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap3 B PR rc=%d", rc);
        settle(M);
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == ((1ULL << M->slot) | (1ULL << B->slot)),
              "lap3 both PRs on the platter: holders=%#llx", (unsigned long long)e.holders);
        mxfs_dlm_release_all(B->dlm);   /* B's clean departure releases its PR */
        settle(M);
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == (1ULL << M->slot),
              "lap3 B's release retired: holders=%#llx", (unsigned long long)e.holders);
        node_down(B);
        B = NULL;
        membership(ids, 1);
        mxfs_pal_sleep_ms(30);
        mxfs_dlm_release_all(M->dlm);   /* the last member's own release-all */
        settle(M);
        holders_clean(&R, "lap3");
        CHECK(mxfs_dlm_held_mode(M->dlm, &R) == MXFS_LOCK_NL, "lap3 M holds nothing");
    }

    printf("  INFO gen_refusals=%llu stale_image_retries=%llu releases_pr=%llu commits=%llu\n",
           (unsigned long long)M->ledger.gen_refusals,
           (unsigned long long)M->dlm->ledger_stale_image_retries,
           (unsigned long long)M->ledger.releases_pr,
           (unsigned long long)M->ledger.commits);
    if (B)
        node_down(B);
    if (A)
        node_down(A);
    B = A = NULL;

    /*
     * ── laps 4-8: a record whose holder has left for good ──
     *
     * The other way a record outlives its mount: the release never reached
     * the platter at all.  Measured on the 4/tcp rig (0.90.18,
     * tests/quiesce_remount_access.sh): a clean four-way unmount left 39
     * exclusive inode records behind, the next era's master of one page
     * imported one of them as a live holder, and a stat of that inode from
     * another node was still waiting when it was killed at 30 s.  The holder
     * is in nobody's view, so nothing can ask it to let go and no departure
     * will ever name it; the heartbeat table is the only record of how its
     * tenancy ended.
     *
     *   4  control, the engine with no oracle: the next era's request waits
     *      behind the departed holder for its whole budget and fails, and
     *      the record still names the holder
     *   5  with the oracle the same record is retired at the page import and
     *      the request is granted at once; the platter names the new holder
     *   6  members that are there are never asked about: a contended grant
     *      between two live members reads the table not once
     *   7  a holder whose slot is still ACTIVE is kept (the request waits),
     *      a failed table read keeps it too, and the release tick retires it
     *      once the slot shows its release stamp; the waiter is granted
     *   8  a shared-holder bit on a slot with no tenant is retired the same
     *      way, by the slot alone
     *
     * ── laps 9-11: a shared bit on a slot a later tenant holds ──
     *
     * Such a bit cannot be retired by the slot (it may be the tenant's own),
     * so the tenant has to answer for it, and the master can only ask a node
     * it can name.  Measured on the 4/tcp rig (0.90.21, lap v21c_lap5 of
     * tests/quiesce_remount_access.sh): a page imported during a four-way
     * mount carried a bit a departed incarnation had left on slot 1; the
     * oracle's table read showed the slot's new tenant, the monitor's
     * tracking had not sampled the claim yet, and the bit was installed with
     * no owner.  Here the tracking stays blind for the whole lap, which is
     * that instant held still.
     *
     *   9  control, an oracle that names no tenant (the engine as it was):
     *      the bit is installed with no owner, nobody is notified, and the
     *      request waits its whole budget and fails
     *  10  the release tick, with the oracle naming the tenant: the entry
     *      lap 9 left gets its owner, the tenant answers the notification
     *      for a grant it does not hold, and the request is granted
     *  11  the page import: the bit is installed under the tenant's identity
     *      and the request is granted at once
     */
    if (!tl_fails) {
        struct vnode *H, *M2, *W, *X;
        struct mxfs_resource_id R4, R7, R8, R9, R11;
        struct lock_job *j;
        uint64_t t0, wall, ret0, err0, att0, res0;
        int reads0, basts0;

        /* era 1: H holds EX on a resource M masters; every member then
         * leaves and H's release never reaches the platter */
        H = node_up(1, 2100, 6001, 2, 1);
        ids[0] = M->id; ids[1] = H->id;
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        R4 = res_mastered_by(M, M->id, 200000);
        rc = lock_sync(H, &R4, MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX, "lap4 H holds EX on R4 ino=%llu (master M) rc=%d",
              (unsigned long long)R4.ino, rc);
        settle(M);
        rc = probe_lookup(&R4, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 2100 &&
              e.ex_inc == 6001 && e.ex_slot == 2,
              "lap4 the platter names H: rc=%d state=%u ex=%u/%llu slot=%u", rc, e.state,
              e.ex_node, (unsigned long long)e.ex_inc, e.ex_slot);
        node_down(H);
        node_down(M);
        H = M = NULL;
        vhb_set(1, VHB_RELEASED, 1000, 5000, 1);
        vhb_set(2, VHB_RELEASED, 2100, 6001, 1);

        /* lap 4: era 2 with no oracle */
        vhb_oracle = 0;
        M2 = node_up(0, 3100, 7001, 1, 1);
        W = node_up(1, 3200, 7002, 2, 1);
        vhb_set(1, VHB_ACTIVE, 3100, 7001, 1);
        vhb_set(2, VHB_ACTIVE, 3200, 7002, 1);
        ids[0] = M2->id; ids[1] = W->id;
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        rc = mxfs_dlm_handoff_takeover(M2->dlm, 1000, 5000);
        CHECK(rc > 0, "lap4 era 2 takes the departed authority's pages over rc=%d", rc);
        settle(M2);
        j = lock_async(W, &R4, MXFS_LOCK_EX, 2);
        CHECK(!lock_wait(j, 1500),
              "lap4 control: with no oracle the EX waits behind the departed holder");
        CHECK(lock_wait(j, 10000) && j->rc != 0,
              "lap4 control: and fails when its budget is spent rc=%d wall=%llums", j->rc,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
        rc = probe_lookup(&R4, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 2100,
              "lap4 control: the record still names H (ex=%u)", e.ex_node);
        node_down(W);
        node_down(M2);
        vhb_set(1, VHB_RELEASED, 3100, 7001, 1);
        vhb_set(2, VHB_RELEASED, 3200, 7002, 1);

        /* lap 5: era 3 with the oracle */
        vhb_oracle = 1;
        M2 = node_up(0, 3300, 7003, 1, 1);
        W = node_up(1, 3400, 7004, 2, 1);
        vhb_set(1, VHB_ACTIVE, 3300, 7003, 1);
        vhb_set(2, VHB_ACTIVE, 3400, 7004, 1);
        ids[0] = M2->id; ids[1] = W->id;
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        rc = mxfs_dlm_handoff_takeover(M2->dlm, 3100, 7001);
        rc += mxfs_dlm_handoff_takeover(M2->dlm, 3200, 7002);
        CHECK(rc > 0, "lap5 era 3 takes the departed authorities' pages over rc=%d", rc);
        settle(M2);
        t0 = mxfs_pal_time_ms();
        rc = lock_sync(W, &R4, MXFS_LOCK_EX, &granted);
        wall = mxfs_pal_time_ms() - t0;
        CHECK(rc == 0 && granted == MXFS_LOCK_EX && wall < 1000,
              "lap5 the EX is granted at once rc=%d granted=%u wall=%llums", rc, granted,
              (unsigned long long)wall);
        rc = probe_lookup(&R4, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 3400 &&
              e.ex_inc == 7004,
              "lap5 the platter names the new holder: ex=%u/%llu", e.ex_node,
              (unsigned long long)e.ex_inc);
        CHECK(M2->dlm->ledger_settled_retired + W->dlm->ledger_settled_retired == 1 &&
              M2->ledger.retired_named + W->ledger.retired_named == 1,
              "lap5 one holder retired by name (engine %llu+%llu ledger %llu+%llu)",
              (unsigned long long)M2->dlm->ledger_settled_retired,
              (unsigned long long)W->dlm->ledger_settled_retired,
              (unsigned long long)M2->ledger.retired_named,
              (unsigned long long)W->ledger.retired_named);

        /* lap 6: two live members contend; nobody reads the table */
        reads0 = vhb_reads;
        W->auto_release = 1;
        rc = lock_sync(M2, &R4, MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX, "lap6 M2 takes R4 from W by notification rc=%d",
              rc);
        W->auto_release = 0;
        rc = mxfs_dlm_unlock(M2->dlm, &R4);
        settle(M2);
        CHECK(rc == 0 && vhb_reads == reads0,
              "lap6 the table was not read for members that are there (reads +%d)",
              vhb_reads - reads0);

        /* lap 7: X holds EX on a page M2 masters under both views, says
         * goodbye and is still finishing its unmount: its slot is ACTIVE */
        X = node_up(2, 3500, 7005, 3, 1);
        vhb_set(3, VHB_ACTIVE, 3500, 7005, 1);
        ids[0] = M2->id; ids[1] = W->id; ids[2] = X->id;
        membership(ids, 3);
        mxfs_pal_sleep_ms(50);
        R7 = res_mastered_by(M2, M2->id, 300000);
        while (tl_page(&R7) % 6 != 0)
            R7 = res_mastered_by(M2, M2->id, R7.ino + 1);
        rc = lock_sync(X, &R7, MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX, "lap7 X holds EX on R7 ino=%llu page=%u rc=%d",
              (unsigned long long)R7.ino, tl_page(&R7), rc);
        settle(M2);
        node_down(X);
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        CHECK(mxfs_dlm_resource_master(M2->dlm, &R7) == M2->id, "lap7 R7 is still M2's under {M2, W}");
        ret0 = M2->dlm->ledger_settled_retired;
        err0 = M2->dlm->ledger_settled_errors;
        j = lock_async(W, &R7, MXFS_LOCK_EX, 12);
        CHECK(!lock_wait(j, 2500),
              "lap7 the holder's slot is ACTIVE: the record is kept and the EX waits");
        rc = probe_lookup(&R7, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 3500 &&
              M2->dlm->ledger_settled_retired == ret0,
              "lap7 the record still names X and nothing was retired (ex=%u kept=%llu)",
              e.ex_node, (unsigned long long)M2->dlm->ledger_settled_kept);
        vhb_fail = 1;                   /* the next read of the table fails */
        vhb_set(3, VHB_RELEASED, 3500, 7005, 1);
        CHECK(lock_wait(j, 5000) && j->rc == 0 && j->granted == MXFS_LOCK_EX,
              "lap7 granted once the slot shows X's release stamp rc=%d wall=%llums", j->rc,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
        CHECK(M2->dlm->ledger_settled_errors == err0 + 1 &&
              M2->dlm->ledger_settled_retired == ret0 + 1,
              "lap7 one failed read kept it, the next retired it (errors +%llu retired +%llu)",
              (unsigned long long)(M2->dlm->ledger_settled_errors - err0),
              (unsigned long long)(M2->dlm->ledger_settled_retired - ret0));
        rc = probe_lookup(&R7, &e);
        CHECK(rc == 0 && e.ex_node == 3400, "lap7 the platter names W (ex=%u)", e.ex_node);
        mxfs_dlm_unlock(W->dlm, &R7);
        settle(M2);

        /* lap 8: a shared bit on a slot that is left with no tenant */
        X = node_up(2, 3600, 7006, 3, 1);
        vhb_set(3, VHB_ACTIVE, 3600, 7006, 1);
        ids[0] = M2->id; ids[1] = W->id; ids[2] = X->id;
        membership(ids, 3);
        mxfs_pal_sleep_ms(50);
        R8 = res_mastered_by(M2, M2->id, R7.ino + 1);
        while (tl_page(&R8) % 6 != 0)
            R8 = res_mastered_by(M2, M2->id, R8.ino + 1);
        rc = lock_sync(X, &R8, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap8 X holds PR on R8 ino=%llu rc=%d",
              (unsigned long long)R8.ino, rc);
        settle(M2);
        rc = probe_lookup(&R8, &e);
        CHECK(rc == 0 && e.holders == (1ULL << 3), "lap8 the platter carries slot 3's bit (%#llx)",
              (unsigned long long)e.holders);
        node_down(X);
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        vhb_set(3, VHB_RELEASED, 3600, 7006, 1);
        ret0 = M2->dlm->ledger_settled_retired;
        t0 = mxfs_pal_time_ms();
        rc = lock_sync(W, &R8, MXFS_LOCK_EX, &granted);
        wall = mxfs_pal_time_ms() - t0;
        CHECK(rc == 0 && granted == MXFS_LOCK_EX && wall < 1000,
              "lap8 the EX is granted at once rc=%d wall=%llums", rc, (unsigned long long)wall);
        rc = probe_lookup(&R8, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 3400 &&
              M2->dlm->ledger_settled_retired == ret0 + 1,
              "lap8 the bit is gone and W holds (holders=%#llx ex=%u retired +%llu)",
              (unsigned long long)e.holders, e.ex_node,
              (unsigned long long)(M2->dlm->ledger_settled_retired - ret0));
        mxfs_dlm_unlock(W->dlm, &R8);
        settle(M2);

        /* lap 9: X holds PR on R9 and leaves with the bit on the platter; a
         * later tenant claims slot 3 and joins, and no tracking has sampled
         * the claim.  Control: the oracle names no tenant. */
        X = node_up(2, 3700, 7007, 3, 1);
        vhb_set(3, VHB_ACTIVE, 3700, 7007, 1);
        ids[0] = M2->id; ids[1] = W->id; ids[2] = X->id;
        membership(ids, 3);
        mxfs_pal_sleep_ms(50);
        R9 = res_mastered_by(M2, M2->id, R8.ino + 1);
        while (tl_page(&R9) % 6 != 0)
            R9 = res_mastered_by(M2, M2->id, R9.ino + 1);
        rc = lock_sync(X, &R9, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap9 X holds PR on R9 ino=%llu page=%u rc=%d",
              (unsigned long long)R9.ino, tl_page(&R9), rc);
        settle(M2);
        rc = probe_lookup(&R9, &e);
        CHECK(rc == 0 && e.holders == (1ULL << 3), "lap9 the platter carries slot 3's bit (%#llx)",
              (unsigned long long)e.holders);
        node_down(X);
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        vhb_set(3, VHB_ACTIVE, 3800, 7008, 1);
        vslot_blind = 1ULL << 3;
        vhb_name_tenant = 0;
        X = node_up(2, 3800, 7008, 3, 1);
        X->nak_unheld = 1;
        ids[2] = X->id;
        membership(ids, 3);
        mxfs_pal_sleep_ms(50);
        CHECK(mxfs_dlm_resource_master(M2->dlm, &R9) == M2->id, "lap9 R9 is still M2's under {M2, W, X}");
        att0 = M2->dlm->ledger_tenant_attributed;
        j = lock_async(W, &R9, MXFS_LOCK_EX, 2);
        CHECK(!lock_wait(j, 1500),
              "lap9 control: the bit has no owner and the EX waits behind it");
        CHECK(lock_wait(j, 10000) && j->rc != 0,
              "lap9 control: and fails when its budget is spent rc=%d wall=%llums", j->rc,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
        rc = probe_lookup(&R9, &e);
        CHECK(rc == 0 && e.holders == (1ULL << 3) && X->basts == 0 &&
              M2->dlm->ledger_tenant_attributed == att0,
              "lap9 control: the bit is still there and nobody was asked "
              "(holders=%#llx basts=%d attributed +%llu)",
              (unsigned long long)e.holders, X->basts,
              (unsigned long long)(M2->dlm->ledger_tenant_attributed - att0));

        /* lap 10: the oracle names the tenant; the release tick gives the
         * entry lap 9 installed its owner, with the tracking still blind */
        vhb_name_tenant = 1;
        j = lock_async(W, &R9, MXFS_LOCK_EX, 12);
        CHECK(lock_wait(j, 5000) && j->rc == 0 && j->granted == MXFS_LOCK_EX,
              "lap10 granted once the tick named the tenant rc=%d wall=%llums", j->rc,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
        rc = probe_lookup(&R9, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 3400 && X->basts > 0 &&
              M2->dlm->ledger_tenant_attributed == att0 + 1,
              "lap10 the tenant answered for the bit and W holds "
              "(holders=%#llx ex=%u basts=%d attributed +%llu)",
              (unsigned long long)e.holders, e.ex_node, X->basts,
              (unsigned long long)(M2->dlm->ledger_tenant_attributed - att0));
        mxfs_dlm_unlock(W->dlm, &R9);
        settle(M2);

        /* lap 11: the same residue met at a page import */
        vslot_blind = 0;
        R11 = res_mastered_by(M2, M2->id, R9.ino + 1);
        while (tl_page(&R11) % 6 != 0 || tl_page(&R11) == tl_page(&R9))
            R11 = res_mastered_by(M2, M2->id, R11.ino + 1);
        rc = lock_sync(X, &R11, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap11 X holds PR on R11 ino=%llu page=%u rc=%d",
              (unsigned long long)R11.ino, tl_page(&R11), rc);
        settle(M2);
        rc = probe_lookup(&R11, &e);
        CHECK(rc == 0 && e.holders == (1ULL << 3), "lap11 the platter carries slot 3's bit (%#llx)",
              (unsigned long long)e.holders);
        node_down(X);
        membership(ids, 2);
        mxfs_pal_sleep_ms(50);
        vhb_set(3, VHB_ACTIVE, 3900, 7009, 1);
        vslot_blind = 1ULL << 3;
        X = node_up(2, 3900, 7009, 3, 1);
        X->nak_unheld = 1;
        ids[2] = X->id;
        membership(ids, 3);
        mxfs_pal_sleep_ms(50);
        CHECK(mxfs_dlm_resource_master(M2->dlm, &R11) == M2->id, "lap11 R11 is still M2's under {M2, W, X}");
        att0 = M2->dlm->ledger_tenant_attributed;
        res0 = M2->dlm->ledger_imports_resolved;
        basts0 = X->basts;
        t0 = mxfs_pal_time_ms();
        rc = lock_sync(W, &R11, MXFS_LOCK_EX, &granted);
        wall = mxfs_pal_time_ms() - t0;
        CHECK(rc == 0 && granted == MXFS_LOCK_EX && wall < 1000,
              "lap11 the EX is granted at once rc=%d wall=%llums", rc, (unsigned long long)wall);
        rc = probe_lookup(&R11, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 3400 && X->basts > basts0,
              "lap11 the tenant answered for the bit and W holds (holders=%#llx ex=%u basts +%d)",
              (unsigned long long)e.holders, e.ex_node, X->basts - basts0);
        CHECK(M2->dlm->ledger_tenant_attributed == att0 + 1 &&
              M2->dlm->ledger_imports_resolved == res0,
              "lap11 the bit was named at its import and never stood with no owner "
              "(attributed +%llu, named later +%llu)",
              (unsigned long long)(M2->dlm->ledger_tenant_attributed - att0),
              (unsigned long long)(M2->dlm->ledger_imports_resolved - res0));
        mxfs_dlm_unlock(W->dlm, &R11);
        settle(M2);
        vslot_blind = 0;

        /*
         * laps 12-14: the named tenant has to ANSWER.  Measured on the rig
         * (0.90.22 before this, v22a_inj6 and v22b_lap2): the bit was named
         * for its slot's tenant and stood all the same, because a tenant
         * that is still mounting parks the notification and a mounted one
         * finds nothing to release.
         *
         *  12  control, a tenant with no handler: the request waits its
         *      whole budget behind the named bit and fails
         *  13  the lock layer answers on receipt: granted within one
         *      notification
         *  14  that answer cannot take away a grant the master made: sent
         *      against a real grant it changes nothing
         */
        {
            struct mxfs_resource_id R12, R13, R14;
            struct mxfs_dlm_lock_release rel;

            R12 = res_mastered_by(M2, M2->id, R11.ino + 1);
            while (tl_page(&R12) % 6 != 0 || tl_page(&R12) == tl_page(&R11) ||
                   tl_page(&R12) == tl_page(&R9))
                R12 = res_mastered_by(M2, M2->id, R12.ino + 1);
            rc = lock_sync(X, &R12, MXFS_LOCK_PR, &granted);
            CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap12 X holds PR on R12 ino=%llu page=%u rc=%d",
                  (unsigned long long)R12.ino, tl_page(&R12), rc);
            settle(M2);
            /* a second bit of the same kind, for the lap that answers: the
             * control leaves its own wait queued on R12 */
            R13 = res_mastered_by(M2, M2->id, R12.ino + 1);
            while (tl_page(&R13) % 6 != 0 || tl_page(&R13) == tl_page(&R12))
                R13 = res_mastered_by(M2, M2->id, R13.ino + 1);
            rc = lock_sync(X, &R13, MXFS_LOCK_PR, &granted);
            CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap13 X holds PR on R13 ino=%llu page=%u rc=%d",
                  (unsigned long long)R13.ino, tl_page(&R13), rc);
            settle(M2);
            node_down(X);
            membership(ids, 2);
            mxfs_pal_sleep_ms(50);
            vhb_set(3, VHB_ACTIVE, 4000, 7010, 1);
            X = node_up(2, 4000, 7010, 3, 1);       /* no handler of any kind */
            ids[2] = X->id;
            membership(ids, 3);
            mxfs_pal_sleep_ms(50);
            j = lock_async(W, &R12, MXFS_LOCK_EX, 2);
            CHECK(!lock_wait(j, 1500), "lap12 control: the EX waits behind the named bit");
            CHECK(lock_wait(j, 10000) && j->rc != 0,
                  "lap12 control: and fails when its budget is spent rc=%d wall=%llums", j->rc,
                  (unsigned long long)(j->t1 - j->t0));
            lock_finish(j);
            rc = probe_lookup(&R12, &e);
            CHECK(rc == 0 && e.holders == (1ULL << 3) && X->basts > 0 && X->answered == 0,
                  "lap12 control: the tenant was notified and the bit still stands "
                  "(holders=%#llx basts=%d)", (unsigned long long)e.holders, X->basts);

            X->answer_unheld = 1;
            t0 = mxfs_pal_time_ms();
            rc = lock_sync(W, &R13, MXFS_LOCK_EX, &granted);
            wall = mxfs_pal_time_ms() - t0;
            CHECK(rc == 0 && granted == MXFS_LOCK_EX && wall < 1000,
                  "lap13 granted once the lock layer answered rc=%d wall=%llums", rc,
                  (unsigned long long)wall);
            rc = probe_lookup(&R13, &e);
            CHECK(rc == 0 && e.holders == 0 && e.ex_node == 3400 && X->answered > 0 &&
                  X->dlm->unheld_answers > 0,
                  "lap13 the bit is gone and W holds (holders=%#llx ex=%u answered=%d)",
                  (unsigned long long)e.holders, e.ex_node, X->answered);
            mxfs_dlm_unlock(W->dlm, &R13);
            settle(M2);

            R14 = res_mastered_by(M2, M2->id, R13.ino + 1);
            while (tl_page(&R14) % 6 != 0)
                R14 = res_mastered_by(M2, M2->id, R14.ino + 1);
            rc = lock_sync(X, &R14, MXFS_LOCK_PR, &granted);
            CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap14 X holds a PR the master granted rc=%d", rc);
            settle(M2);
            CHECK(mxfs_dlm_answer_unheld(X->dlm, &R14, M2->id) == -EBUSY,
                  "lap14 the lock layer does not answer for a grant its table records");
            memset(&rel, 0, sizeof(rel));
            rel.hdr.magic = MXFS_DLM_MAGIC;
            rel.hdr.version = MXFS_DLM_VERSION;
            rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
            rel.hdr.length = sizeof(rel);
            rel.hdr.sender = X->id;
            rel.hdr.target = M2->id;
            rel.resource = R14;
            rel.grant_gen = MXFS_DLM_GEN_UNHELD;
            rel.owner_inc = X->inc;
            rel.owner_slot = X->slot;
            vsend(X->dlm, M2->id, &rel, sizeof(rel));   /* an answer that crossed the grant */
            mxfs_pal_sleep_ms(200);
            settle(M2);
            rc = probe_lookup(&R14, &e);
            CHECK(rc == 0 && e.holders == (1ULL << 3) &&
                  mxfs_dlm_held_mode(X->dlm, &R14) == MXFS_LOCK_PR,
                  "lap14 the master's grant stands (holders=%#llx, X holds %u)",
                  (unsigned long long)e.holders, mxfs_dlm_held_mode(X->dlm, &R14));
            rc = mxfs_dlm_unlock(X->dlm, &R14);
            settle(M2);
            rc = probe_lookup(&R14, &e);
            CHECK(e.holders == 0, "lap14 and X's own release retires it (holders=%#llx)",
                  (unsigned long long)e.holders);
        }
        node_down(X);
        printf("  INFO settled: judgements=%llu retired=%llu kept=%llu errors=%llu table_reads=%d\n",
               (unsigned long long)M2->dlm->ledger_settled_judgements,
               (unsigned long long)M2->dlm->ledger_settled_retired,
               (unsigned long long)M2->dlm->ledger_settled_kept,
               (unsigned long long)M2->dlm->ledger_settled_errors, vhb_reads);
        node_down(W);
        node_down(M2);
    }
    if (M)
        node_down(M);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== stale_image_release_test RESULT %s fails=%d ===\n",
           tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
