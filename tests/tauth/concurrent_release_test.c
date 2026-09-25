// SPDX-License-Identifier: GPL-2.0
/*
 * concurrent_release_test — two shared holders release at once while an EX
 * waiter is queued (instrument step 2 for the 0.35.0 32/tcp wedge).
 *
 * On the rig (0.35.0, s424) test2 took over the root inode's page, imported
 * three PR holders, and 8 ms later logged P-TAUTH-DOUBLE-GRANT "req ... EX
 * vs record holders=0x10": the table decided EX while the ledger still
 * carried one shared holder.  Then 94 x P-TAUTH-FREEZE-DRAIN-TIMEOUT on
 * that page, every requester REMASTER, 26 mounts aborted.
 *
 * Hypothesis H2: promote_waiters ignores EVERY PENDING_RELEASE holder, not
 * only the one retiring in the current transition.  With two releases in
 * flight the second one's round decides EX over the first holder's still
 * durable bit; the bundled commit [release, grant] is refused -EBUSY; the
 * refused round leaves its release entry PENDING_RELEASE with nothing to
 * retire it (the releaser's retry is ACKed OK as a "duplicate"), so the
 * record keeps the bit, every later EX blocks on the table entry, and the
 * page never drains for a handoff.
 *
 * Shape: master M and peer A hold PR on R (mastered by M); B queues EX.
 * M's ledger gets a one-shot commit delay; M unlocks locally (its release
 * transition sleeps before touching the page) and A releases meanwhile —
 * A's release is processed on M's rx thread while M's entry is
 * PENDING_RELEASE.  Asserts: B gets EX within budget, no DOUBLE-GRANT, the
 * platter record ends clean, A's release is durably retired (not a stuck
 * PENDING_RELEASE on M), and M's page reports no in-flight transition.
 */
#define NNODES 3
#include "dlm_mesh.h"

struct unlock_job {
    struct vnode *n;
    struct mxfs_resource_id res;
    int rc;
    volatile int done;
    mxfs_thread_t *t;
};

static void unlock_job_fn(void *arg)
{
    struct unlock_job *u = arg;

    u->rc = mxfs_dlm_unlock(u->n->dlm, &u->res);
    u->done = 1;
}

int main(int argc, char **argv)
{
    struct mxfs_resource_id R;
    struct mxfs_tauth_entry e;
    mxfs_node_id_t ids[NNODES];
    struct vnode *M, *A, *B;
    struct lock_job *jb;
    struct unlock_job um;
    uint8_t granted = 0;
    int rc, laps = argc > 1 ? atoi(argv[1]) : 3, lap;
    uint64_t busy = 0;

    tl_mktemp("concurrent_release_test");
    printf("=== concurrent_release_test file=%s laps=%d ===\n", tl_path, laps);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    M = node_up(0, 1000, 5000, 1, 1);
    A = node_up(1, 2000, 5001, 2, 1);
    B = node_up(2, 3000, 5002, 3, 1);
    ids[0] = M->id; ids[1] = A->id; ids[2] = B->id;
    membership(ids, 3);
    mxfs_pal_sleep_ms(50);
    R = res_mastered_by(M, M->id, 128);
    printf("  R ino=%llu master=%u\n", (unsigned long long)R.ino, M->id);

    for (lap = 0; lap < laps; lap++) {
        rc = lock_sync(M, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap %d M PR rc=%d", lap, rc);
        rc = lock_sync(A, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "lap %d A PR rc=%d", lap, rc);
        settle(M);
        jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
        mxfs_pal_sleep_ms(40);                   /* B is WAITING at M */

        /* M's release transition sleeps 150 ms before the page; A's
         * release lands on M's rx thread inside that window */
        M->ledger.commit_delay_once_ms = 150;
        memset(&um, 0, sizeof(um));
        um.n = M; um.res = R;
        um.t = mxfs_pal_thread_create(unlock_job_fn, &um);
        mxfs_pal_sleep_ms(30);
        rc = mxfs_dlm_unlock(A->dlm, &R);
        CHECK(rc == 0, "lap %d A unlock rc=%d", lap, rc);
        mxfs_pal_thread_join(um.t);
        CHECK(um.rc == 0, "lap %d M unlock rc=%d", lap, um.rc);

        /* budget: two commits + the retry ladder (10 retries) — 2 s */
        lock_wait(jb, 2000);
        CHECK(jb->done && jb->rc == 0 && jb->granted == MXFS_LOCK_EX,
              "lap %d B EX granted after both PR releases: done=%d rc=%d granted=%u %llums",
              lap, jb->done, jb->rc, jb->granted, (unsigned long long)(jb->t1 - jb->t0));
        if (jb->done && jb->rc == 0)
            mxfs_dlm_unlock(B->dlm, &R);
        if (!jb->done)
            lock_wait(jb, 3000);
        lock_finish(jb);
        settle(M);
        CHECK(rel_pending_count(A) == 0, "lap %d A has no un-ACKed release (%d)",
              lap, rel_pending_count(A));
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
              "lap %d platter record clean: rc=%d state=%u holders=%#llx ex=%u",
              lap, rc, e.state, (unsigned long long)e.holders, e.ex_node);
        CHECK(mxfs_dlm_held_mode(M->dlm, &R) == MXFS_LOCK_NL &&
              mxfs_dlm_held_mode(A->dlm, &R) == MXFS_LOCK_NL &&
              mxfs_dlm_held_mode(B->dlm, &R) == MXFS_LOCK_NL,
              "lap %d nobody holds R", lap);
        CHECK(mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)) == 0,
              "lap %d M's page has no in-flight transition (%d)", lap,
              mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)));
        busy = M->ledger.busy_denies;
        CHECK(busy == 0, "lap %d no P-TAUTH-DOUBLE-GRANT at M (busy_denies=%llu)",
              lap, (unsigned long long)busy);
        /* after the wedge nothing below can pass; stop the lap loop */
        if (tl_fails)
            break;
    }
    /*
     * Scenario 2 — a bundled transition refused for a grant reason must not
     * strand its release: A holds PR (remote), B waits EX; the ledger
     * refuses the next GRANT op (-EBUSY, the DOUBLE-GRANT shape).  Expect
     * the master to re-commit A's release alone (rel_recommits=1), B to be
     * denied LEDGER_BUSY and retry to a grant, the record clean, no
     * pending entry on the page, and A's release ACKed exactly once.
     */
    if (!tl_fails) {
        uint64_t rc0 = M->dlm->ledger_release_recommits;

        rc = lock_sync(A, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "s2 A PR rc=%d", rc);
        settle(M);
        jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
        mxfs_pal_sleep_ms(40);
        M->ledger.refuse_grant_once = 1;
        rc = mxfs_dlm_unlock(A->dlm, &R);
        CHECK(rc == 0, "s2 A unlock rc=%d", rc);
        lock_wait(jb, 2000);
        CHECK(jb->done && jb->rc == 0 && jb->granted == MXFS_LOCK_EX,
              "s2 B EX granted after the refused bundle: done=%d rc=%d granted=%u %llums",
              jb->done, jb->rc, jb->granted, (unsigned long long)(jb->t1 - jb->t0));
        if (jb->done && jb->rc == 0)
            mxfs_dlm_unlock(B->dlm, &R);
        if (!jb->done)
            lock_wait(jb, 3000);
        lock_finish(jb);
        settle(M);
        CHECK(M->dlm->ledger_release_recommits == rc0 + 1,
              "s2 the master re-committed the release alone (recommits=%llu)",
              (unsigned long long)(M->dlm->ledger_release_recommits - rc0));
        CHECK(M->ledger.refuse_grant_once == 0, "s2 the refusal knob fired");
        CHECK(rel_pending_count(A) == 0, "s2 A's release ACKed (%d pending)",
              rel_pending_count(A));
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
              "s2 platter record clean: rc=%d holders=%#llx ex=%u",
              rc, (unsigned long long)e.holders, e.ex_node);
        CHECK(mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)) == 0,
              "s2 no in-flight entry on M's page (%d)",
              mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)));
        CHECK(M->dlm->ledger_release_stuck == 0, "s2 nothing stuck (%llu)",
              (unsigned long long)M->dlm->ledger_release_stuck);
    }
    /*
     * Scenario 3 — the release-only re-commit fails too (-EUCLEAN, an
     * UNKNOWN record): the entry stays PENDING_RELEASE and the MASTER
     * re-drives it from its tick (the releaser is not involved).  Expect
     * rel_stuck=1, a re-drive, the record clean within the retry interval
     * (1 s) + commit, and a later EX to succeed.
     */
    if (!tl_fails) {
        uint64_t st0 = M->dlm->ledger_release_stuck, rd0 = M->dlm->ledger_release_redrives;
        uint64_t t0;

        rc = lock_sync(A, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "s3 A PR rc=%d", rc);
        settle(M);
        jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
        mxfs_pal_sleep_ms(40);
        M->ledger.refuse_grant_once = 1;         /* the bundle: -EBUSY */
        M->ledger.fail_commit_once_rc = -EUCLEAN; /* the release-only re-commit */
        M->ledger.fail_commit_skip = 1;
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_unlock(A->dlm, &R);
        CHECK(rc == 0, "s3 A unlock rc=%d", rc);
        mxfs_pal_sleep_ms(200);
        CHECK(M->dlm->ledger_release_stuck == st0 + 1,
              "s3 the release was marked stuck after the failed re-commit (%llu)",
              (unsigned long long)(M->dlm->ledger_release_stuck - st0));
        /* budget: retry interval 1000 ms + one commit + B's retry ladder
         * (A's own retry may re-drive it sooner — either driver is right) */
        lock_wait(jb, 3000);
        CHECK(jb->done && jb->rc == 0 && jb->granted == MXFS_LOCK_EX,
              "s3 B EX granted once the master re-drove the release: done=%d rc=%d "
              "granted=%u %llums after A's unlock",
              jb->done, jb->rc, jb->granted, (unsigned long long)(jb->t1 - t0));
        if (jb->done && jb->rc == 0)
            mxfs_dlm_unlock(B->dlm, &R);
        if (!jb->done)
            lock_wait(jb, 3000);
        lock_finish(jb);
        settle(M);
        CHECK(M->dlm->ledger_release_redrives >= rd0 + 1, "s3 re-driven (%llu)",
              (unsigned long long)(M->dlm->ledger_release_redrives - rd0));
        CHECK(rel_pending_count(A) == 0, "s3 A's release ACKed (%d pending)",
              rel_pending_count(A));
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
              "s3 platter record clean: rc=%d holders=%#llx ex=%u",
              rc, (unsigned long long)e.holders, e.ex_node);
        CHECK(mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)) == 0,
              "s3 no in-flight entry on M's page (%d)",
              mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)));
    }
    /*
     * Scenario 4 — same failure, but the releaser CRASHES right after its
     * release (no retry ever arrives): only the master's tick can retire
     * the record.  Expect the re-drive within the retry interval and B's
     * EX to be granted; the record clean afterwards.
     */
    if (!tl_fails) {
        uint64_t rd0 = M->dlm->ledger_release_redrives, t0;
        mxfs_node_id_t a_id = A->id;

        rc = lock_sync(A, &R, MXFS_LOCK_PR, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_PR, "s4 A PR rc=%d", rc);
        settle(M);
        jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
        mxfs_pal_sleep_ms(40);
        M->ledger.refuse_grant_once = 1;
        M->ledger.fail_commit_once_rc = -EUCLEAN;
        M->ledger.fail_commit_skip = 1;
        node_halt(A);                            /* A's last act: the release; no
                                                  * retry tick, no ACK consumer */
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_unlock(A->dlm, &R);
        CHECK(rc == 0, "s4 A unlock rc=%d", rc);
        node_down(A);                            /* crash */
        A = NULL;
        lock_wait(jb, 3000);
        CHECK(jb->done && jb->rc == 0 && jb->granted == MXFS_LOCK_EX,
              "s4 B EX granted after the MASTER re-drove the crashed releaser's record: "
              "done=%d rc=%d granted=%u %llums after A's unlock",
              jb->done, jb->rc, jb->granted, (unsigned long long)(jb->t1 - t0));
        CHECK(jb->done && jb->t1 - t0 >= 1000,
              "s4 the grant followed the master's retry interval, not a releaser retry (%llums)",
              (unsigned long long)(jb->t1 - t0));
        if (jb->done && jb->rc == 0)
            mxfs_dlm_unlock(B->dlm, &R);
        if (!jb->done)
            lock_wait(jb, 3000);
        lock_finish(jb);
        settle(M);
        CHECK(M->dlm->ledger_release_redrives >= rd0 + 1, "s4 re-driven by the tick (%llu)",
              (unsigned long long)(M->dlm->ledger_release_redrives - rd0));
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
              "s4 platter record clean: rc=%d holders=%#llx ex=%u",
              rc, (unsigned long long)e.holders, e.ex_node);
        CHECK(mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)) == 0,
              "s4 no in-flight entry on M's page (%d)",
              mxfs_dlm_page_pending_count(M->dlm, tl_page(&R)));
        (void)a_id;
    }
    /*
     * Scenario 5 — a LOCAL requester on the master abandons its request
     * (retry budget exhausted) while its grant is PENDING_DURABLE; the
     * commit then lands with no waiter.  The remote analogue answers an
     * unsolicited GRANT with a LOCK_RELEASE; the local one must release
     * the orphan the same way or the master itself becomes a durable EX
     * holder nobody can ever unlock.  Expect: M's request fails (budget),
     * afterwards B takes EX within budget and the record is clean.
     */
    if (!tl_fails) {
        uint8_t g = 0;
        uint64_t t0;

        struct lock_job *jm;

        settle(M);
        /* A (remote) holds EX; M queues EX behind it (WAITING, 1 attempt =
         * 1000 ms); A's release — whose transition carries M's grant — is
         * delayed past M's budget */
        rc = lock_sync(B, &R, MXFS_LOCK_EX, &g);
        CHECK(rc == 0 && g == MXFS_LOCK_EX, "s5 B EX rc=%d", rc);
        settle(M);
        t0 = mxfs_pal_time_ms();
        jm = lock_async(M, &R, MXFS_LOCK_EX, 1);
        mxfs_pal_sleep_ms(200);
        M->ledger.commit_delay_once_ms = 1600;
        rc = mxfs_dlm_unlock(B->dlm, &R);
        CHECK(rc == 0, "s5 B unlock rc=%d", rc);
        lock_wait(jm, 3000);
        rc = jm->rc; g = jm->granted;
        lock_finish(jm);
        printf("  INFO s5 M EX with 1 retry: rc=%d granted=%u after %llums\n", rc, g,
               (unsigned long long)(mxfs_pal_time_ms() - t0));
        if (rc == 0) {
            /* the wait outlived the delay: not the shape under test */
            mxfs_dlm_unlock(M->dlm, &R);
            CHECK(0, "s5 shape not reached (M was granted before its budget ran out)");
        } else {
            mxfs_pal_sleep_ms(1200);              /* the delayed commit lands (~1.8 s) */
            CHECK(mxfs_dlm_held_mode(M->dlm, &R) == MXFS_LOCK_NL,
                  "s5 M holds nothing after abandoning its request (held=%u)",
                  mxfs_dlm_held_mode(M->dlm, &R));
            CHECK(M->dlm->ledger_local_orphans == 1,
                  "s5 the orphaned grant was released by the master (local_orphans=%llu)",
                  (unsigned long long)M->dlm->ledger_local_orphans);
            jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
            lock_wait(jb, 2000);
            CHECK(jb->done && jb->rc == 0 && jb->granted == MXFS_LOCK_EX,
                  "s5 B EX granted after M's orphaned grant was released: done=%d rc=%d %llums",
                  jb->done, jb->rc, (unsigned long long)(jb->t1 - jb->t0));
            if (jb->done && jb->rc == 0)
                mxfs_dlm_unlock(B->dlm, &R);
            if (!jb->done)
                lock_wait(jb, 3000);
            lock_finish(jb);
            settle(M);
            rc = probe_lookup(&R, &e);
            CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
                  "s5 platter record clean: rc=%d holders=%#llx ex=%u",
                  rc, (unsigned long long)e.holders, e.ex_node);
        }
    }
    printf("  INFO busy_denies=%llu ledger_denies=%llu ghosts=%llu release_acks=%llu\n",
           (unsigned long long)M->ledger.busy_denies,
           (unsigned long long)M->dlm->ledger_denies,
           (unsigned long long)M->dlm->ledger_ghosts,
           (unsigned long long)(A ? A->dlm->release_acks : 0));
    mxfs_dlm_release_all(M->dlm);
    if (A)
        mxfs_dlm_release_all(A->dlm);
    mxfs_dlm_release_all(B->dlm);
    node_down(B);
    if (A)
        node_down(A);
    node_down(M);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== concurrent_release_test RESULT %s fails=%d ===\n",
           tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
