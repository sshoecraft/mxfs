// SPDX-License-Identifier: GPL-2.0
/*
 * bootstrap_race_test — D-TAUTH-BOOTSTRAP-CLAIM-NOT-EXCLUSIVE-ACROSS-FALSE-DEATH-0347
 * instrument step 2: can two nodes that both believe they are the
 * bootstrap node both claim the SAME UNOWNED ledger page?
 *
 * The rig shape: A holds the lowest heartbeat slot but its heartbeat thread
 * stalled past the death timeout (process alive).  A ranks its own slot
 * first, so it stays "bootstrap"; B dropped A from `live` at death
 * detection (before A's fence lands), so B is "bootstrap" too.  Their views
 * differ (A: {A,B}, B: {B}), so each is the page master of P under its own
 * view.  Both request EX on a resource of P.
 *
 * Model: two vnodes, per-node membership, force_bootstrap_all=1.  A's
 * ledger activate is held (activate_hold_once_ms) between its platter read
 * (UNOWNED) and its write, B claims in the window, then A writes.
 *
 * The claim must be exclusive: exactly one node ends with the page MINE
 * and an EX grant; the other must refuse (its activate must see the other
 * image and fail -ESTALE, or its write-readback must catch the race).
 * Asserts:
 *   1  not both nodes granted EX on the same resource
 *   2  not both nodes cache the page as MINE
 *   3  the platter authority is exactly one of them
 * A FAIL on 1/2 proves the double-authority window (the defect).
 */
#define NNODES 2
#include "dlm_mesh.h"

int main(int argc, char **argv)
{
    struct mxfs_resource_id R;
    struct mxfs_tauth_page_auth a;
    struct vnode *A, *B;
    struct lock_job *ja, *jb;
    mxfs_node_id_t view_a[2], view_b[1];
    uint32_t page;
    int rc, hold_ms = argc > 1 ? atoi(argv[1]) : 200;
    int a_mine, b_mine;

    tl_mktemp("bootstrap_race_test");
    printf("=== bootstrap_race_test file=%s hold_ms=%d ===\n", tl_path, hold_ms);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    A = node_up(0, 1000, 5000, 1, 1);
    B = node_up(1, 2000, 5001, 2, 1);
    /* divergent views: A still counts itself and B; B has declared A dead */
    view_a[0] = A->id; view_a[1] = B->id;
    view_b[0] = B->id;
    live_ids[0] = A->id; live_ids[1] = B->id; live_n = 2;
    mxfs_dlm_update_active_nodes(A->dlm, view_a, 2);
    mxfs_dlm_update_active_nodes(B->dlm, view_b, 1);
    force_bootstrap_all = 1;
    mxfs_pal_sleep_ms(50);

    /* a resource A masters under ITS view (B masters everything under its own) */
    R = res_mastered_by(A, A->id, 200000);
    page = tl_page(&R);
    rc = mxfs_tauth_ledger_page_auth(&probe, page, true, &a);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_UNOWNED, "0 page %u UNOWNED before the claims", page);
    CHECK(vbootstrap(A) && vbootstrap(B), "0 both nodes believe they are bootstrap");

    A->ledger.activate_hold_once_ms = (uint32_t)hold_ms;
    ja = lock_async(A, &R, MXFS_LOCK_EX, 10);
    mxfs_pal_sleep_ms((uint64_t)hold_ms / 4);       /* A is inside its hold */
    jb = lock_async(B, &R, MXFS_LOCK_EX, 10);
    lock_wait(ja, 5000);
    lock_wait(jb, 5000);
    printf("  INFO A rc=%d granted=%u wall=%llums | B rc=%d granted=%u wall=%llums\n",
           ja->rc, ja->granted, (unsigned long long)(ja->t1 - ja->t0),
           jb->rc, jb->granted, (unsigned long long)(jb->t1 - jb->t0));
    a_mine = mxfs_tauth_ledger_page_mine(&A->ledger, page);
    b_mine = mxfs_tauth_ledger_page_mine(&B->ledger, page);
    rc = mxfs_tauth_ledger_page_auth(&probe, page, true, &a);
    printf("  INFO page %u: A mine=%d B mine=%d platter rc=%d state=%u auth=%u/%llu seq=%llu "
           "A.activates=%llu B.activates=%llu A.poisons=%llu B.poisons=%llu\n",
           page, a_mine, b_mine, rc, a.state, a.auth_node, (unsigned long long)a.auth_inc,
           (unsigned long long)a.seq, (unsigned long long)A->ledger.activates,
           (unsigned long long)B->ledger.activates, (unsigned long long)A->ledger.poisons,
           (unsigned long long)B->ledger.poisons);
    CHECK(!(ja->rc == 0 && ja->granted == MXFS_LOCK_EX && jb->rc == 0 && jb->granted == MXFS_LOCK_EX),
          "1 not both nodes granted EX on ino=%llu (A rc=%d/%u, B rc=%d/%u)",
          (unsigned long long)R.ino, ja->rc, ja->granted, jb->rc, jb->granted);
    CHECK(!(a_mine && b_mine), "2 not both nodes cache page %u as MINE (A=%d B=%d)", page,
          a_mine, b_mine);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_ACTIVE && (a.auth_node == A->id || a.auth_node == B->id),
          "3 platter authority of page %u is one of them (state=%u auth=%u)", page, a.state,
          a.auth_node);
    CHECK((a_mine ? 1 : 0) + (b_mine ? 1 : 0) == 1 &&
          ((a_mine && a.auth_node == A->id) || (b_mine && a.auth_node == B->id)),
          "3 exactly one node is MINE and it matches the platter (A=%d B=%d platter=%u)",
          a_mine, b_mine, a.auth_node);
    if (ja->rc == 0) mxfs_dlm_unlock(A->dlm, &R);
    if (jb->rc == 0) mxfs_dlm_unlock(B->dlm, &R);
    lock_finish(ja);
    lock_finish(jb);

    mxfs_dlm_release_all(A->dlm);
    mxfs_dlm_release_all(B->dlm);
    node_down(B);
    node_down(A);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== bootstrap_race_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
