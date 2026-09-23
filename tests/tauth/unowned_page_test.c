// SPDX-License-Identifier: GPL-2.0
/*
 * unowned_page_test — D-TCP-ROOT-INODE-LOCK-RETRY-EXHAUSTION-DURING-RAMP-0345
 * instrument step 2, in usermode (sess426).
 *
 * Rig shape (32/tcp, 0.35.3 s427 token stage, tests/evidence/sess425_s427_dmesg):
 * the AG-1/2/3/33 EX requests of one node were answered REMASTER 60/60 by
 * their page masters; the masters logged P-TAUTH-REMASTER-PARKED with
 * page_state=0 (UNKNOWN) and cached_auth=-2 (no image) while all 32 nodes
 * agreed on the view (view=0xaabbb4cff8f0ae5a/32).  No handoff line ever
 * named those pages.
 *
 * Hypothesis H2: a ledger page NOBODY has ever decided on is UNOWNED on the
 * platter; when the view names a NON-bootstrap node its master,
 * dlm_page_acquire's UNOWNED branch returns -EAGAIN without asking anyone
 * (the FREEZE_REQ chain needs an auth_node, and UNOWNED has none), and the
 * bootstrap node only claims pages it decides on itself — so every request
 * on that page parks until the retry budget is gone.
 *
 * Harness: bring NN nodes up one at a time (the ramp), then pick a resource
 * whose page master under the full view is NOT the bootstrap node and whose
 * page no node has touched, and take EX on it from a third node with the
 * kernel's budget (10 retries).  Asserts:
 *   1  the request is granted (rc=0, EX) within the budget
 *   2  the page is ACTIVE(master) on the platter afterwards
 *   3  the same from the master itself (its own local request parks the
 *      same way) and from the bootstrap node (it is NOT the master, so it
 *      must be routed, not bootstrap-claimed)
 * A FAIL on 1 with why[remaster=N] reproduces the rig defect.
 */
#define NNODES 4
#include "dlm_mesh.h"

static int take_ex(struct vnode *n, const struct mxfs_resource_id *r, const char *who)
{
    uint8_t granted = 0;
    uint64_t t0 = mxfs_pal_time_ms();
    int rc = mxfs_dlm_lock_retries(n->dlm, r, MXFS_LOCK_EX, 0, &granted, 10);

    printf("  INFO %s node=%u ino=%llu EX rc=%d granted=%u wall=%llums remaster_rx=%llu\n",
           who, n->id, (unsigned long long)r->ino, rc, granted,
           (unsigned long long)(mxfs_pal_time_ms() - t0),
           (unsigned long long)n->dlm->ledger_remaster);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX, "1 %s (node %u) EX on ino=%llu rc=%d",
          who, n->id, (unsigned long long)r->ino, rc);
    if (rc == 0)
        mxfs_dlm_unlock(n->dlm, r);
    return rc;
}

int main(int argc, char **argv)
{
    struct mxfs_resource_id R;
    struct mxfs_tauth_page_auth a;
    mxfs_node_id_t ids[NNODES];
    struct vnode *boot = NULL, *master = NULL, *other = NULL;
    int i, rc, joined = 0;
    int ramp_ms = argc > 1 ? atoi(argv[1]) : 40;

    tl_mktemp("unowned_page_test");
    printf("=== unowned_page_test file=%s nodes=%d ramp_ms=%d ===\n", tl_path, NNODES, ramp_ms);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    /* the ramp; slot i+1 => node 0 holds the lowest slot = bootstrap */
    for (i = 0; i < NNODES; i++) {
        struct vnode *n = node_up(i, 1000 + (mxfs_node_id_t)i * 7919, 5000 + (uint64_t)i,
                                  (uint16_t)(i + 1), 1);

        ids[joined++] = n->id;
        membership(ids, joined);
        mxfs_pal_sleep_ms((uint64_t)ramp_ms);
    }
    mxfs_pal_sleep_ms(200);
    boot = &nodes[0];
    CHECK(vbootstrap(boot), "0 node %u is the bootstrap node", boot->id);

    /* a never-touched resource mastered by a non-bootstrap node */
    R = res_mastered_by(boot, nodes[2].id, 100000);
    master = &nodes[2];
    other = &nodes[1];
    rc = mxfs_tauth_ledger_page_auth(&probe, tl_page(&R), true, &a);
    printf("  INFO R ino=%llu page=%u master=%u platter: rc=%d state=%u auth=%u/%llu\n",
           (unsigned long long)R.ino, tl_page(&R), master->id, rc, a.state,
           a.auth_node, (unsigned long long)a.auth_inc);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_UNOWNED, "0 page %u UNOWNED before the request",
          tl_page(&R));

    take_ex(other, &R, "other");
    rc = mxfs_tauth_ledger_page_auth(&probe, tl_page(&R), true, &a);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_ACTIVE && a.auth_node == master->id,
          "2 page %u ACTIVE(master %u) after the grant: rc=%d state=%u auth=%u",
          tl_page(&R), master->id, rc, a.state, a.auth_node);

    /* a second untouched page: the master's own request */
    R = res_mastered_by(boot, nodes[3].id, R.ino + 1);
    master = &nodes[3];
    rc = mxfs_tauth_ledger_page_auth(&probe, tl_page(&R), true, &a);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_UNOWNED, "0 page %u UNOWNED before the request",
          tl_page(&R));
    take_ex(master, &R, "master-self");

    /* a third: the bootstrap node asks a non-bootstrap master */
    R = res_mastered_by(boot, nodes[1].id, R.ino + 1);
    rc = mxfs_tauth_ledger_page_auth(&probe, tl_page(&R), true, &a);
    CHECK(rc == 0 && a.state == MXFS_TAUTH_PG_UNOWNED, "0 page %u UNOWNED before the request",
          tl_page(&R));
    take_ex(boot, &R, "bootstrap-as-requester");

    for (i = 0; i < NNODES; i++)
        mxfs_dlm_release_all(nodes[i].dlm);
    for (i = NNODES - 1; i >= 0; i--)
        node_down(&nodes[i]);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== unowned_page_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
