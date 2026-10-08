// SPDX-License-Identifier: GPL-2.0
/*
 * acq_release_deadlock_test — a locally mastered acquire that must queue may
 * not release an idle wait's adopted grant, because it holds table_rwlock and
 * the release takes that lock for writing.
 *
 * Measured on the physical pair 2026-10-07: the kernel reported 'task
 * bash:52508 <writer> blocked on an rw-semaphore likely owned by task
 * bash:52508 <writer>'.  dlm_lock_impl's local queue path calls dlm_acq_begin
 * holding table_rwlock for writing; the acquisition table's idle scan found a
 * record past MXFS_DLM_ACQ_IDLE_MS that held an adopted grant, retired it, and
 * released the grant through dlm_acq_release_grant, which write-locks
 * table_rwlock again.  The task waited on itself and every later lock
 * operation on the host queued behind it.
 *
 * In user mode the same recursion is answered EDEADLK by glibc, and the PAL
 * stops the process on it (pal/linux/user.c), so the unfixed path aborts here
 * where the kernel hangs.
 *
 * Shape, every step through the public lock paths:
 *   1. B holds EX on Rb (B masters it).  A asks for EX on Rb with a one-attempt
 *      budget: the request queues at B, A's attempt times out, and A's
 *      acquisition record stays (a timed-out attempt is "no answer yet").
 *      B unlocks; the grant lands on A with no pending entry and is ADOPTED
 *      into that record.
 *   2. The record goes idle past MXFS_DLM_ACQ_IDLE_MS (the user-mode clock is
 *      the real monotonic clock, so the test waits it out).
 *   3. B holds EX on Ra (A masters it); A asks for EX on Ra, which queues on
 *      A's own table — the path that calls dlm_acq_begin under table_rwlock.
 *      Expected: the attempt queues and times out normally, nothing is
 *      released, and the grant-holding record is left in place.
 *   4. A asks for Rb2 (B masters it): the remote path may release, so its idle
 *      scan retires the record and hands the grant back.  B can then take EX
 *      on Rb again.
 */
#define NNODES 2
#include "dlm_mesh.h"

/* A's acquisition record for (res, mode), copied out under its lock; 0 when
 * there is none */
static int acq_find(struct vnode *n, const struct mxfs_resource_id *res, uint8_t mode,
                    uint64_t *last_ms, struct mxfs_dlm_acq_grant *g)
{
    int i, found = 0;

    mxfs_pal_spinlock_lock(n->dlm->acq_lock);
    for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
        if (n->dlm->acq[i].in_use && n->dlm->acq[i].mode == mode &&
            memcmp(&n->dlm->acq[i].resource, res, sizeof(*res)) == 0) {
            if (last_ms)
                *last_ms = n->dlm->acq[i].last_ms;
            if (g)
                *g = n->dlm->acq[i].grant;
            found = 1;
            break;
        }
    }
    mxfs_pal_spinlock_unlock(n->dlm->acq_lock);
    return found;
}

static int wait_counter(volatile uint64_t *c, uint64_t want, uint64_t timeout_ms)
{
    uint64_t t0 = mxfs_pal_time_ms();

    while (*c < want && mxfs_pal_time_ms() - t0 < timeout_ms)
        mxfs_pal_sleep_ms(5);
    return *c >= want;
}

int main(void)
{
    struct mxfs_resource_id Ra, Rb, Rb2;
    struct mxfs_dlm_acq_grant g;
    mxfs_node_id_t ids[NNODES];
    struct vnode *A, *B;
    uint8_t granted = 0;
    uint64_t last_ms = 0, t0, rel0;
    int rc, basts0;

    /* the control run dies in abort(); its progress lines must already be out */
    setvbuf(stdout, NULL, _IOLBF, 0);
    tl_mktemp("acq_release_deadlock_test");
    printf("=== acq_release_deadlock_test file=%s ===\n", tl_path);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    A = node_up(0, 1000, 5000, 1, 1);
    B = node_up(1, 2000, 5001, 2, 1);
    /* every user holds its own descriptor from here, so an abort below
     * leaves no file behind */
    unlink(tl_path);
    ids[0] = A->id; ids[1] = B->id;
    membership(ids, 2);
    mxfs_pal_sleep_ms(50);
    Rb = res_mastered_by(A, B->id, 128);
    Rb2 = res_mastered_by(A, B->id, Rb.ino + 1);
    Ra = res_mastered_by(A, A->id, 128);
    printf("  Ra ino=%llu (master %u)  Rb ino=%llu Rb2 ino=%llu (master %u)\n",
           (unsigned long long)Ra.ino, A->id, (unsigned long long)Rb.ino,
           (unsigned long long)Rb2.ino, B->id);

    /* ── 1. an adopted grant in A's acquisition record ── */
    rc = lock_sync(B, &Rb, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX, "1 B EX on Rb rc=%d", rc);
    t0 = mxfs_pal_time_ms();
    rc = mxfs_dlm_lock_retries(A->dlm, &Rb, MXFS_LOCK_EX, 0, &granted, 1);
    CHECK(rc == -ETIMEDOUT, "1 A's one-attempt EX on Rb queued at B and timed out "
          "(rc=%d after %llums, wait %dms)", rc,
          (unsigned long long)(mxfs_pal_time_ms() - t0), MXFS_LOCK_ACQUIRE_WAIT_MS);
    CHECK(acq_find(A, &Rb, MXFS_LOCK_EX, NULL, &g) && !g.have,
          "1 A's acquisition record for Rb survives the timeout, no grant yet");
    rc = mxfs_dlm_unlock(B->dlm, &Rb);
    CHECK(rc == 0, "1 B unlock Rb rc=%d", rc);
    /* budget: one release commit at B, the promoted grant's commit, one
     * message to A — tens of ms; 1 s */
    CHECK(wait_counter(&A->dlm->acq_grant_adopted, 1, 1000),
          "1 the grant landed between attempts and was adopted (adopted=%llu bounced=%llu)",
          (unsigned long long)A->dlm->acq_grant_adopted,
          (unsigned long long)A->dlm->acq_grant_bounced);
    CHECK(acq_find(A, &Rb, MXFS_LOCK_EX, &last_ms, &g) && g.have && g.mode == MXFS_LOCK_EX,
          "1 A's record for Rb holds the adopted EX grant (have=%u mode=%u gen=%u)",
          g.have, g.mode, g.grant_gen);
    CHECK(mxfs_dlm_held_mode(A->dlm, &Rb) == MXFS_LOCK_EX,
          "1 A's table carries the adopted grant's mirror (held=%u)",
          mxfs_dlm_held_mode(A->dlm, &Rb));
    if (tl_fails)
        goto out;

    /* the holder step 3 queues behind, taken now so nothing touches A's
     * acquisition table after the record's last stamp */
    rc = lock_sync(B, &Ra, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX, "3 B EX on Ra rc=%d", rc);
    settle(A);

    /* ── 2. the record goes idle ── */
    printf("  INFO waiting out MXFS_DLM_ACQ_IDLE_MS=%d from the record's last stamp\n",
           MXFS_DLM_ACQ_IDLE_MS);
    {
        int probe_n = 0;
        uint64_t rec_ms = 0;

        while (mxfs_pal_time_ms() - last_ms <= (uint64_t)MXFS_DLM_ACQ_IDLE_MS + 100) {
            if (probe_n++ % 20 == 0 && probe_n < 500) {
                int f = acq_find(A, &Rb, MXFS_LOCK_EX, &rec_ms, NULL);
                printf("  PROBE now=%llu last_ms=%llu diff=%llu rec_found=%d rec_last=%llu\n",
                       (unsigned long long)mxfs_pal_time_ms(), (unsigned long long)last_ms,
                       (unsigned long long)(mxfs_pal_time_ms() - last_ms), f,
                       (unsigned long long)rec_ms);
            }
            mxfs_pal_sleep_ms(50);
        }
    }
    CHECK(acq_find(A, &Rb, MXFS_LOCK_EX, NULL, &g) && g.have,
          "2 the idle record still holds its grant (idle %llums)",
          (unsigned long long)(mxfs_pal_time_ms() - last_ms));

    /* ── 3. a locally mastered acquire that queues ── */
    rel0 = A->dlm->acq_grant_released;
    basts0 = B->basts;
    printf("  INFO A queues EX on Ra under its own table lock\n");
    t0 = mxfs_pal_time_ms();
    rc = mxfs_dlm_lock_retries(A->dlm, &Ra, MXFS_LOCK_EX, 0, &granted, 1);
    CHECK(rc == -ETIMEDOUT, "3 A's EX on Ra queued behind B and timed out (rc=%d after %llums)",
          rc, (unsigned long long)(mxfs_pal_time_ms() - t0));
    CHECK(wait_until(&B->basts,basts0 + 1, 500),
          "3 the queue path notified B (basts %d -> %d)", basts0, B->basts);
    CHECK(A->dlm->acq_grant_released == rel0,
          "3 the under-lock call released nothing (released=%llu)",
          (unsigned long long)(A->dlm->acq_grant_released - rel0));
    CHECK(acq_find(A, &Rb, MXFS_LOCK_EX, NULL, &g) && g.have,
          "3 the grant-holding idle record was left for a later call");
    CHECK(mxfs_dlm_held_mode(A->dlm, &Rb) == MXFS_LOCK_EX,
          "3 its mirror is still in A's table (held=%u)", mxfs_dlm_held_mode(A->dlm, &Rb));
    rc = mxfs_dlm_unlock(B->dlm, &Ra);
    CHECK(rc == 0, "3 B unlock Ra rc=%d", rc);
    settle(A);

    /* ── 4. a call that may release retires it ── */
    rc = lock_sync(A, &Rb2, MXFS_LOCK_PR, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_PR, "4 A PR on Rb2 (remote path) rc=%d", rc);
    CHECK(A->dlm->acq_grant_released == rel0 + 1,
          "4 the remote path's idle scan handed the adopted grant back (released=%llu)",
          (unsigned long long)(A->dlm->acq_grant_released - rel0));
    CHECK(!acq_find(A, &Rb, MXFS_LOCK_EX, NULL, NULL), "4 Rb's record is retired");
    CHECK(mxfs_dlm_held_mode(A->dlm, &Rb) == MXFS_LOCK_NL,
          "4 A holds nothing on Rb (held=%u)", mxfs_dlm_held_mode(A->dlm, &Rb));
    mxfs_dlm_unlock(A->dlm, &Rb2);
    settle(A);
    rc = lock_sync(B, &Rb, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX,
          "4 B takes EX on Rb again once A's grant is back (rc=%d)", rc);
    if (rc == 0)
        mxfs_dlm_unlock(B->dlm, &Rb);
    settle(A);
    CHECK(rel_pending_count(A) == 0, "4 A's release was ACKed (%d pending)",
          rel_pending_count(A));

out:
    printf("  INFO adopted=%llu claimed=%llu released=%llu bounced=%llu\n",
           (unsigned long long)A->dlm->acq_grant_adopted,
           (unsigned long long)A->dlm->acq_grant_claimed,
           (unsigned long long)A->dlm->acq_grant_released,
           (unsigned long long)A->dlm->acq_grant_bounced);
    mxfs_dlm_release_all(A->dlm);
    mxfs_dlm_release_all(B->dlm);
    node_down(B);
    node_down(A);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    printf("=== acq_release_deadlock_test RESULT %s fails=%d ===\n",
           tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
