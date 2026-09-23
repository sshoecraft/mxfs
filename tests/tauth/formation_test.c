// SPDX-License-Identifier: GPL-2.0
/*
 * formation_test — the 0.34.0 rig failure shape, in usermode (sess424,
 * instrument step 2 for D-0287's step-3/4 landing).
 *
 * On the 32/tcp rig (0.34.0, s422) four mounts failed "can't read
 * superblock": mount's EX on the root inode (ino=128) was refused for
 * 125-208 s, the masters logged P-TAUTH-DOUBLE-GRANT "req ... mode=5 vs
 * record ex=0/0 holders=0x10000000" — the ledger record still carried a
 * SHARED holder bit the table no longer counted — and a requester spun
 * 115 x REMASTER (status=12) in one second and gave up ("lock request
 * failed after 10 retries").  All of it during the 32-node join ramp,
 * where every join re-keys the ledger generation.
 *
 * Hypothesis H1: a shared grant committed durably under a generation that
 * moves before delivery (a ghost), or a requester that abandons after its
 * retries, leaves a holder bit no one retires.  This harness ramps NN
 * nodes into the view one at a time while every joined node runs the
 * mount pattern on ONE resource (PR, unlock, EX, unlock) with the
 * kernel's retry budget (10), then quiesces and asserts:
 *   1  no lock request failed (every PR/EX eventually granted)
 *   2  the platter record of R carries no holder bit and no ex holder
 *   3  no P-TAUTH-DOUBLE-GRANT (busy_denies) on any node
 *   4  after the ramp every node can take EX on R (the mount check)
 * A FAIL on 2/3/4 with the harness otherwise healthy reproduces the rig
 * defect; the P-lines say which transition left the bit.
 */
#define NNODES 12
#include "dlm_mesh.h"

struct worker {
    struct vnode *n;
    struct mxfs_resource_id res;
    volatile int stop;
    volatile int done;
    int iters, fails, fail_rc;
    /* the FIRST failure, so the budget is not what is measured: which
     * request, its rc, how long the call took (a retry costs >= 4 ms of
     * park or a 1000 ms wait; a deny returned at once costs ~0), and the
     * held mode at the time (an EX asked while PR is still held is an
     * upgrade) */
    int first_mode, first_rc, first_iter, first_held;
    uint64_t first_ms;
    int deadlk_pr, deadlk_ex, p109_max;
    mxfs_thread_t *t;
};

static void note_fail(struct worker *w, int mode, int rc, int held, uint64_t ms)
{
    w->fails++;
    w->fail_rc = rc;
    if (rc == -EDEADLK) {
        if (mode == MXFS_LOCK_PR)
            w->deadlk_pr++;
        else
            w->deadlk_ex++;
    }
    if (w->fails == 1) {
        w->first_mode = mode;
        w->first_rc = rc;
        w->first_iter = w->iters;
        w->first_held = held;
        w->first_ms = ms;
    }
}

static void worker_fn(void *arg)
{
    struct worker *w = arg;
    uint8_t granted;
    uint64_t t0;
    int rc, held;

    while (!w->stop) {
        held = mxfs_dlm_held_mode(w->n->dlm, &w->res);
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_lock_retries(w->n->dlm, &w->res, MXFS_LOCK_PR, 0, &granted, 10);
        if (rc) { note_fail(w, MXFS_LOCK_PR, rc, held, mxfs_pal_time_ms() - t0); mxfs_pal_sleep_ms(5); continue; }
        mxfs_pal_sleep_ms(1);
        mxfs_dlm_unlock(w->n->dlm, &w->res);
        held = mxfs_dlm_held_mode(w->n->dlm, &w->res);
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_lock_retries(w->n->dlm, &w->res, MXFS_LOCK_EX, 0, &granted, 10);
        /*
         * -EDEADLK is the master's blocked-upgrade deny (P-CONVBLK-DENY): the
         * table still shows this node's PR GRANTED — the release of the PR
         * above is in flight, or landed at a master the page has since left
         * — so the EX reads as an upgrade blocked by the other holders, and
         * the engine returns it AT ONCE without spending the retry budget
         * (dlm.c mxfs_dlm_lock_retries, the pass-through arm).  The kernel's
         * ilock layer (P109) answers it by dropping the lower grant through
         * the release pipeline and re-acquiring the target mode fresh — and
         * when it holds NL, as this worker does after its unlock, the entry
         * is a PHANTOM (P109-EDEADLK-NL, D-0904): a plain unlock finds no
         * local entry and sends nothing, so the kernel sends the gen-0
         * unconditional release to the current master
         * (mxfs_dlm_release_orphan_if_unheld, gated on the local table
         * holding no entry of any state) and retries from NL.  This worker
         * does the same, bounded, and counts the laps.  Measured (s59, 8
         * runs each): with no handling 3 runs failed, every failure an EX
         * with rc=-35 at local mode NL, P-CONVBLK-DENY == fails, 0 budget
         * give-ups; with unlock-and-retry alone 5 runs failed, the deny
         * repeating through all 10 laps on the nodes whose release had gone
         * to a master the page had left — a plain unlock cannot clear a
         * phantom.
         */
        {
            int p109 = 0;

            while (rc == -EDEADLK && p109 < 10) {
                p109++;
                w->deadlk_ex++;
                mxfs_dlm_unlock(w->n->dlm, &w->res);
                mxfs_dlm_release_orphan_if_unheld(w->n->dlm, &w->res);
                rc = mxfs_dlm_lock_retries(w->n->dlm, &w->res, MXFS_LOCK_EX, 0, &granted, 10);
            }
            if (p109 > w->p109_max)
                w->p109_max = p109;
        }
        if (rc) { note_fail(w, MXFS_LOCK_EX, rc, held, mxfs_pal_time_ms() - t0); mxfs_pal_sleep_ms(5); continue; }
        mxfs_pal_sleep_ms(1);
        mxfs_dlm_unlock(w->n->dlm, &w->res);
        w->iters++;
    }
    w->done = 1;
}

int main(int argc, char **argv)
{
    struct mxfs_resource_id R;
    struct mxfs_tauth_entry e;
    mxfs_node_id_t ids[NNODES];
    struct worker wk[NNODES];
    int i, rc, joined = 0, total_iters = 0, total_fails = 0, total_deadlk = 0, p109_max = 0;
    uint64_t busy = 0, ghosts = 0, remaster = 0, denies = 0;
    int ramp_ms = argc > 1 ? atoi(argv[1]) : 40;
    int run_ms = argc > 2 ? atoi(argv[2]) : 1500;

    tl_mktemp("formation_test");
    printf("=== formation_test file=%s nodes=%d ramp_ms=%d run_ms=%d ===\n",
           tl_path, NNODES, ramp_ms, run_ms);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    memset(&R, 0, sizeof(R));
    R.type = MXFS_LTYPE_INODE;
    R.ino = 128;                                 /* the root inode */
    memset(wk, 0, sizeof(wk));

    /* the ramp: node i joins, the view grows, its worker starts at once */
    for (i = 0; i < NNODES; i++) {
        struct vnode *n = node_up(i, 1000 + (mxfs_node_id_t)i * 7919, 5000 + (uint64_t)i,
                                  (uint16_t)(i + 1), 1);

        ids[joined++] = n->id;
        membership(ids, joined);
        wk[i].n = n;
        wk[i].res = R;
        wk[i].t = mxfs_pal_thread_create(worker_fn, &wk[i]);
        mxfs_pal_sleep_ms((uint64_t)ramp_ms);
    }
    mxfs_pal_sleep_ms((uint64_t)run_ms);
    for (i = 0; i < NNODES; i++)
        wk[i].stop = 1;
    for (i = 0; i < NNODES; i++) {
        mxfs_pal_thread_join(wk[i].t);
        total_iters += wk[i].iters;
        total_fails += wk[i].fails;
        total_deadlk += wk[i].deadlk_pr + wk[i].deadlk_ex;
        if (wk[i].p109_max > p109_max)
            p109_max = wk[i].p109_max;
        if (wk[i].fails || wk[i].deadlk_ex || wk[i].deadlk_pr)
            printf("  node %u: iters=%d fails=%d last_rc=%d deadlk_pr=%d deadlk_ex=%d p109_max=%d "
                   "first: req=%s held=%s rc=%d iter=%d call_ms=%llu\n",
                   wk[i].n->id, wk[i].iters, wk[i].fails, wk[i].fail_rc,
                   wk[i].deadlk_pr, wk[i].deadlk_ex, wk[i].p109_max,
                   wk[i].first_mode == MXFS_LOCK_PR ? "PR" : "EX",
                   wk[i].first_held == MXFS_LOCK_NL ? "NL" :
                   wk[i].first_held == MXFS_LOCK_PR ? "PR" : "EX",
                   wk[i].first_rc, wk[i].first_iter,
                   (unsigned long long)wk[i].first_ms);
    }
    mxfs_pal_sleep_ms(300);                      /* releases + ACKs settle */
    for (i = 0; i < NNODES; i++) {
        busy += nodes[i].ledger.busy_denies;
        ghosts += nodes[i].dlm->ledger_ghosts;
        remaster += nodes[i].dlm->ledger_remaster;
        denies += nodes[i].dlm->ledger_denies;
    }
    printf("  INFO iters=%d fails=%d busy_denies=%llu ghosts=%llu remaster=%llu ledger_denies=%llu "
           "upgrade_denies=%d p109_max=%d\n",
           total_iters, total_fails, (unsigned long long)busy, (unsigned long long)ghosts,
           (unsigned long long)remaster, (unsigned long long)denies, total_deadlk, p109_max);
    CHECK(total_iters > 0, "0 the workload ran (iters=%d)", total_iters);
    CHECK(total_fails == 0, "1 no lock request failed across the ramp (fails=%d)", total_fails);
    for (i = 0; i < NNODES; i++)
        CHECK(mxfs_dlm_held_mode(nodes[i].dlm, &R) == MXFS_LOCK_NL,
              "1 node %u holds nothing after its worker stopped", nodes[i].id);
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.holders == 0 && e.ex_node == 0,
          "2 platter record of ino=128 clean after quiesce: rc=%d state=%u holders=%#llx ex=%u/%llu",
          rc, e.state, (unsigned long long)e.holders, e.ex_node, (unsigned long long)e.ex_inc);
    CHECK(busy == 0, "3 no P-TAUTH-DOUBLE-GRANT on any master (busy_denies=%llu)",
          (unsigned long long)busy);
    for (i = 0; i < NNODES; i++) {
        uint8_t granted = 0;

        rc = mxfs_dlm_lock_retries(nodes[i].dlm, &R, MXFS_LOCK_EX, 0, &granted, 10);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX, "4 node %u EX on ino=128 after the ramp rc=%d",
              nodes[i].id, rc);
        if (rc == 0)
            mxfs_dlm_unlock(nodes[i].dlm, &R);
    }
    for (i = 0; i < NNODES; i++)
        mxfs_dlm_release_all(nodes[i].dlm);
    for (i = NNODES - 1; i >= 0; i--)
        node_down(&nodes[i]);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== formation_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
