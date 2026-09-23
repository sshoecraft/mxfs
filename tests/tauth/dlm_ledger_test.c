// SPDX-License-Identifier: GPL-2.0
/*
 * dlm_ledger_test — the TCP DLM ENGINE (dlm/dlm.c) on the durable authority
 * ledger (docs/tcp-authority-ledger.md step 3d-3g), usermode: several
 * in-process "nodes", each a real mxfs_dlm_ctx with its own
 * mxfs_tauth_ledger opened on ONE shared temp file (the shared LUN), wired
 * to each other by an in-memory message mesh (per-node inbound queue +
 * receiver thread, the same dispatch v5_peer_msg_cb_tcp does).  The engine
 * under test is byte-identical to the module's.
 *
 * Every case is an assertion; RESULT line per case; non-zero exit on any
 * failure.  The platter is inspected through a separate read-only ledger
 * instance (`probe`) so durability claims are about bytes on the file,
 * never about a node's cache.
 *
 *   1  grant durable-before-deliver: remote EX grant -> record ACTIVE on
 *      the platter with the requester's {node, inc, slot}, grant id echoed
 *      to the holder (mxfs_dlm_grant_id), P-TAUTH counters
 *   2  release + ACK: unlock -> record FREE on the platter, ACK received,
 *      no pending release left
 *   3  contention: holder BASTed, releases, waiter granted; the two
 *      transitions are one release+successor commit
 *   4  local master path: the master's own EX / PR grants and releases
 *   5  blocker import after master loss: the master's DLM is destroyed
 *      (no release), a new incarnation of it re-attaches the same ledger;
 *      the holder's record is imported and blocks the new master's EX
 *      until the holder releases (to the new master, same node id)
 *   6  membership change keeps the holder (D-0287 shape): a third node
 *      joins, the master's table is purged, W's EX is still blocked by
 *      H's ledger record; H's release unblocks it
 *   7  recovery purge retires a dead holder's record; the waiter proceeds
 *   8  refusal is fail-closed: a torn ledger write is retried and the
 *      grant still lands; a ledger that refuses (collision injected on
 *      the platter) denies with -EIO, nothing granted around it
 *   9  lost GRANT message: the requester's retry gets the SAME durable
 *      grant id back (idempotent), no second record
 *  10  activation barrier: a ledger_required DLM without a ledger refuses
 *      every grant
 *  11  clean unmount: release_all waits for the ACKs; the ledger holds no
 *      record of the departed node
 *  12  a bulk takeover DECERTIFIED between pages: the pass runs on the
 *      departure worker now, so it outlives the exclusive-write gate and a
 *      peer can return on a lower slot while it is mid-pass.  The mesh's
 *      bootstrap predicate is budgeted so certification is lost at an exact
 *      page boundary; the pass must answer -EAGAIN, count one
 *      decertification, leave the untouched pages under the dead authority,
 *      and a later certified pass must drain them
 *  13  a REFUSED ACTIVATE and a FAILED IMPORT are not transfers.  Both are
 *      injected page-exactly in ONE pass: the pass must answer -EAGAIN and
 *      count NEITHER page in takeover_pages_done (which is also the progress
 *      a parked request waits on).  They then recover by different paths and
 *      both are driven here by an ordinary lock, because neither may leave a
 *      page that only a second sweep could rescue: the refused page is still
 *      the dead authority's and PREPARED to us, so the requester consumes the
 *      PREPARED image; the un-imported page is already durably ours, so the
 *      requester re-imports it
 */
#define NNODES 4
#include "dlm_mesh.h"

int main(int argc, char **argv)
{
    mxfs_node_id_t ids2[2] = { 11, 22 };
    mxfs_node_id_t ids3[3] = { 11, 22, 33 };
    mxfs_node_id_t ids3b[3] = { 11, 22, 44 };   /* 7b: a purged id never returns */
    struct vnode *A, *B, *C;
    struct mxfs_resource_id R, R2, R3;
    struct mxfs_tauth_entry e;
    uint8_t granted = 0;
    uint64_t auth = 0, seq = 0, lin = 0, auth1, seq1;
    int rc;

    (void)argc; (void)argv;
    tl_mktemp("dlm_ledger_test");
    printf("=== dlm_ledger_test file=%s ===\n", tl_path);
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    A = node_up(0, 11, 1000, 1, 1);
    B = node_up(1, 22, 2000, 2, 1);
    membership(ids2, 2);
    /* R: mastered by A; R2: mastered by B; R3: mastered by A, other page */
    R = res_mastered_by(A, 11, 5000);
    R2 = res_mastered_by(A, 22, 5000);
    /* R3: mastered by A (11) in the 2-node view AND by C (33) once C joins in
     * group 6 (sorted {11,22,33}: page % 3 == 2), so group 6 hands R3's page
     * to C and group 7's successor takeover on A has a page to take.  sess427:
     * explicit — the seeded hash no longer lands R3 on such a page by luck. */
    R3 = res_mastered_by(A, 11, R.ino + 100000);
    while (tl_page(&R3) % 3 != 2)
        R3 = res_mastered_by(A, 11, R3.ino + 1);
    printf("  R=ino %llu (master A) R2=ino %llu (master B) R3=ino %llu (master A)\n",
           (unsigned long long)R.ino, (unsigned long long)R2.ino, (unsigned long long)R3.ino);
    CHECK(mxfs_dlm_resource_master(B->dlm, &R) == 11 && mxfs_dlm_resource_master(B->dlm, &R2) == 22,
          "0 page-aligned mastership agrees on both nodes");

    /* 1 remote EX grant is durable before delivery */
    rc = lock_sync(B, &R, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX, "1 B locks R (master A) EX rc=%d granted=%u", rc, granted);
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 22 && e.ex_inc == 2000 &&
          e.ex_slot == 2 && e.ex_mode == MXFS_LOCK_EX && e.authority_epoch == 1000 && e.auth_node == 11 &&
          e.grant_seq64 == 1,
          "1 platter: ACTIVE ex=%u/%llu slot=%u auth={%llu,%llu} auth_node=%u",
          e.ex_node, (unsigned long long)e.ex_inc, e.ex_slot,
          (unsigned long long)e.authority_epoch, (unsigned long long)e.grant_seq64, e.auth_node);
    CHECK(mxfs_dlm_grant_id(B->dlm, &R, &auth, &seq, &lin) && auth == 1000 && seq == 1 && lin != 0,
          "1 holder's mirror carries grant_id={%llu,%llu} lineage=%#llx",
          (unsigned long long)auth, (unsigned long long)seq, (unsigned long long)lin);
    CHECK(A->dlm->ledger_grants == 1 && A->ledger.commits == 1 && B->ledger.commits == 0,
          "1 one commit at the master (A commits=%llu B commits=%llu)",
          (unsigned long long)A->ledger.commits, (unsigned long long)B->ledger.commits);

    /* 2 release + ACK */
    rc = mxfs_dlm_unlock(B->dlm, &R);
    CHECK(rc == 0, "2 B unlocks R rc=%d", rc);
    {
        uint64_t t0 = mxfs_pal_time_ms();

        while (rel_pending_count(B) && mxfs_pal_time_ms() - t0 < 2000)
            mxfs_pal_sleep_ms(5);
    }
    CHECK(rel_pending_count(B) == 0 && B->dlm->release_acks == 1, "2 release ACKed (acks=%llu)",
          (unsigned long long)B->dlm->release_acks);
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE && e.ex_node == 0 && e.last_grant_seq64 == 1,
          "2 platter: FREE last_grant_seq64=%llu", (unsigned long long)e.last_grant_seq64);
    CHECK(mxfs_dlm_held_mode(B->dlm, &R) == MXFS_LOCK_NL && mxfs_dlm_held_mode(A->dlm, &R) == MXFS_LOCK_NL,
          "2 no table entry left on either node");

    /* 3 contention: B holds EX, A wants EX -> BAST -> B releases -> A granted */
    rc = lock_sync(B, &R, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0, "3 B re-locks R EX rc=%d", rc);
    B->basts = 0;
    B->auto_release = 0;
    {
        struct lock_job *j = lock_async(A, &R, MXFS_LOCK_EX, 10);

        CHECK(wait_until(&B->basts, 1, 2000), "3 B receives the BAST (basts=%d)", B->basts);
        CHECK(!lock_wait(j, 300), "3 A's EX is still blocked while B holds");
        rc = probe_lookup(&R, &e);
        CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 22, "3 platter still shows B");
        mxfs_dlm_unlock(B->dlm, &R);
        CHECK(lock_wait(j, 3000) && j->rc == 0 && j->granted == MXFS_LOCK_EX,
              "3 A granted after B's release rc=%d granted=%u wall=%llums", j->rc, j->granted,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
    }
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 11 && e.ex_inc == 1000 &&
          e.grant_seq64 == 3 && e.last_grant_seq64 == 2,
          "3 platter: A holds seq=%llu (B's seq 2 retired in the same transition)",
          (unsigned long long)e.grant_seq64);

    /* 4 local master: A's own PR after EX, then release */
    rc = mxfs_dlm_unlock(A->dlm, &R);
    rc |= probe_lookup(&R, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_FREE, "4 A's local release -> FREE");
    rc = lock_sync(A, &R, MXFS_LOCK_PR, &granted);
    rc |= lock_sync(B, &R, MXFS_LOCK_PR, &granted);
    rc |= probe_lookup(&R, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.holders == ((1ULL << 1) | (1ULL << 2)) &&
          e.ex_node == 0 && e.shared_mode == MXFS_LOCK_PR,
          "4 A(local)+B(remote) PR holders bits=%#llx", (unsigned long long)e.holders);
    B->auto_release = 1;
    rc = lock_sync(A, &R, MXFS_LOCK_EX, &granted);
    /* the engine's contract (sess12): a blocked INODE upgrade is refused
     * with -EDEADLK and the caller drops its lower grant and re-acquires
     * the target mode through the FIFO — do what the XFS layer does */
    CHECK(rc == -EDEADLK, "4 A's PR->EX upgrade under B's PR = -EDEADLK (rc=%d)", rc);
    mxfs_dlm_unlock(A->dlm, &R);
    settle(A);
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.holders == (1ULL << 2), "4 A's PR release cleared its bit (holders=%#llx)",
          (unsigned long long)e.holders);
    rc = lock_sync(A, &R, MXFS_LOCK_EX, &granted);
    rc |= probe_lookup(&R, &e);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX && e.ex_node == 11 && e.holders == 0,
          "4 A acquires EX after B's BAST-release (holders=%#llx)", (unsigned long long)e.holders);
    B->auto_release = 0;
    mxfs_dlm_unlock(A->dlm, &R);
    settle(A);

    /* 5 blocker import after master loss */
    rc = lock_sync(B, &R, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0, "5 B holds R EX (master A)");
    node_down(A);                                /* A crashes: no release */
    A = node_up(0, 11, 1001, 1, 1);              /* A's next incarnation */
    membership(ids2, 2);
    CHECK(A->dlm->ledger_imports == 0, "5 fresh A has imported nothing yet");
    /* sess423 (step 4): the dead incarnation's pages are ACTIVE(11/1000)
     * on the platter; nobody may serve them until the certified successor
     * (lowest live slot = A') takes them over — what v5 does after the
     * fence certificate, before the lease unregister */
    rc = mxfs_dlm_handoff_takeover(A->dlm, 11, 1000);
    CHECK(rc > 0, "5 successor takeover of the dead incarnation's pages rc=%d", rc);
    {
        struct lock_job *j = lock_async(A, &R, MXFS_LOCK_EX, 10);

        CHECK(!lock_wait(j, 400), "5 A' EX blocked by the imported record");
        CHECK(A->dlm->ledger_imports >= 1 && mxfs_dlm_held_mode(A->dlm, &R) == MXFS_LOCK_NL,
              "5 A' imported %llu blocker(s)", (unsigned long long)A->dlm->ledger_imports);
        CHECK(wait_until(&B->basts, B->basts, 10) && B->basts > 0, "5 B was BASTed by A' (basts=%d)", B->basts);
        mxfs_dlm_unlock(B->dlm, &R);            /* release names the same node id: goes to A' */
        CHECK(lock_wait(j, 3000) && j->rc == 0 && j->granted == MXFS_LOCK_EX,
              "5 A' granted after B's release rc=%d", j->rc);
        lock_finish(j);
    }
    rc = probe_lookup(&R, &e);
    CHECK(rc == 0 && e.ex_node == 11 && e.ex_inc == 1001 && e.authority_epoch == 1001,
          "5 platter: A' holds with its NEW incarnation %llu", (unsigned long long)e.ex_inc);
    mxfs_dlm_unlock(A->dlm, &R);

    /* 6 membership change keeps the holder (D-0287 shape) */
    rc = lock_sync(B, &R3, MXFS_LOCK_EX, &granted);
    CHECK(rc == 0, "6 B holds R3 EX (master A)");
    C = node_up(2, 33, 3000, 3, 1);
    membership(ids3, 3);
    {
        mxfs_node_id_t m = mxfs_dlm_resource_master(A->dlm, &R3);
        struct vnode *M = node_by_id(m);
        struct lock_job *j;

        printf("  R3 master after join: %u\n", m);
        j = lock_async(M == B ? A : M, &R3, MXFS_LOCK_EX, 10);
        CHECK(!lock_wait(j, 400), "6 W's EX on R3 blocked across the membership change (H=B still holds)");
        CHECK(mxfs_dlm_held_mode(B->dlm, &R3) == MXFS_LOCK_EX, "6 H's mirror survived the purge");
        mxfs_dlm_unlock(B->dlm, &R3);
        CHECK(lock_wait(j, 3000) && j->rc == 0, "6 W granted after H's release rc=%d", j->rc);
        mxfs_dlm_unlock(j->n->dlm, &R3);
        lock_finish(j);
    }

    /* 7 recovery purge retires a dead holder */
    {
        mxfs_node_id_t m;
        struct vnode *M, *H = C;
        struct lock_job *j;

        m = mxfs_dlm_resource_master(A->dlm, &R2);
        M = node_by_id(m);
        if (M == H) { R2 = res_mastered_by(A, 22, R2.ino + 1); M = B; }
        rc = lock_sync(H, &R2, MXFS_LOCK_EX, &granted);
        CHECK(rc == 0, "7 C holds R2 EX (master %u)", m);
        node_down(C);                             /* C dies */
        membership(ids2, 2);
        j = lock_async(M == A ? B : A, &R2, MXFS_LOCK_EX, 10);
        CHECK(!lock_wait(j, 400), "7 W blocked by the dead holder's record");
        rc = mxfs_dlm_ledger_purge_owner(A->dlm, 33, 3);
        rc |= mxfs_dlm_ledger_purge_owner(B->dlm, 33, 3) < 0 ? -1 : 0;
        mxfs_dlm_purge_node(A->dlm, 33);
        mxfs_dlm_purge_node(B->dlm, 33);
        CHECK(rc >= 0, "7 recovery purge on both masters rc=%d", rc);
        /* the dead authority's pages (68/416 were handed to C in group 6)
         * move only through the certified successor's takeover — v5 runs
         * it with the purge, after the fence certificate */
        rc = mxfs_dlm_handoff_takeover(A->dlm, 33, 3000);
        CHECK(rc > 0, "7 successor takeover of C's pages rc=%d", rc);
        CHECK(lock_wait(j, 3000) && j->rc == 0, "7 W granted after the purge rc=%d", j->rc);
        rc = probe_lookup(&R2, &e);
        CHECK(rc == 0 && e.ex_node == j->n->id, "7 platter: W holds (ex_node=%u)", e.ex_node);
        mxfs_dlm_unlock(j->n->dlm, &R2);
        lock_finish(j);
    }

    /* 7b (sess425, D-0342) a PARTIAL recovery purge keeps the dead holder's
     * blocker and is re-driven by the master's tick: C returns, holds R2
     * EX, dies again; the master's first purge page-commit fails (-EIO
     * injected) -> rc<0, blockers kept, W stays blocked, purge_pending=1;
     * the tick re-runs the purge (>= 1 s) -> record retired, W granted. */
    {
        mxfs_node_id_t m = mxfs_dlm_resource_master(A->dlm, &R2);
        struct vnode *M = node_by_id(m), *W;
        struct lock_job *j;
        uint64_t t0;

        C = node_up(2, 44, 3002, 3, 1);
        membership(ids3b, 3);
        mxfs_pal_sleep_ms(50);
        /* a resource A masters in BOTH views (3 nodes now, 2 after C dies):
         * the purge under test runs at the master of the post-death view */
        {
            struct mxfs_resource_id r = R2;

            for (r.ino = R2.ino + 1; ; r.ino++) {
                int both;

                if (mxfs_dlm_resource_master(A->dlm, &r) != 11)
                    continue;
                membership(ids2, 2);
                both = (mxfs_dlm_resource_master(A->dlm, &r) == 11);
                membership(ids3b, 3);
                if (both)
                    break;
            }
            R2 = r;
            mxfs_pal_sleep_ms(50);
        }
        m = 11; M = A; W = B;
        rc = lock_sync(C, &R2, MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX, "7b C holds R2 EX (master %u) rc=%d", m, rc);
        node_down(C);
        membership(ids2, 2);
        j = lock_async(W, &R2, MXFS_LOCK_EX, 10);
        CHECK(!lock_wait(j, 400), "7b W blocked by the dead holder's record");
        M->ledger.fail_commit_once_rc = -EIO;     /* the purge's first page write */
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_ledger_purge_owner(M->dlm, 44, 3);
        CHECK(rc < 0, "7b the master's purge is PARTIAL rc=%d", rc);
        mxfs_dlm_purge_node(M->dlm, 44);
        CHECK(M->dlm->purge_pending_count == 1 && M->dlm->ledger_purge_partial >= 1,
              "7b purge pending at the master (pending=%d partial=%llu)",
              M->dlm->purge_pending_count, (unsigned long long)M->dlm->ledger_purge_partial);
        rc = probe_lookup(&R2, &e);
        CHECK(rc == 0 && e.ex_node == 44, "7b platter still names the dead holder (ex_node=%u)",
              e.ex_node);
        CHECK(!lock_wait(j, 300), "7b W still blocked: the blocker was KEPT over the retained bit");
        /* budget: retry interval 1000 ms + one purge pass + W's retry */
        CHECK(lock_wait(j, 3000) && j->rc == 0 && j->granted == MXFS_LOCK_EX,
              "7b W granted after the master re-drove the purge: rc=%d %llums",
              j->rc, (unsigned long long)(j->t1 - t0));
        CHECK(j->done && j->t1 - t0 >= 1000, "7b ... by the tick, not the caller (%llums)",
              (unsigned long long)(j->t1 - t0));
        CHECK(M->dlm->purge_pending_count == 0 && M->dlm->ledger_purge_redrives >= 1,
              "7b purge completed by the re-drive (pending=%d redrives=%llu)",
              M->dlm->purge_pending_count, (unsigned long long)M->dlm->ledger_purge_redrives);
        rc = probe_lookup(&R2, &e);
        CHECK(rc == 0 && e.ex_node == j->n->id, "7b platter: W holds (ex_node=%u)", e.ex_node);
        mxfs_dlm_unlock(j->n->dlm, &R2);
        lock_finish(j);
        /* the other master's purge + C's pages, as v5 does */
        mxfs_dlm_ledger_purge_owner(W->dlm, 44, 3);
        mxfs_dlm_purge_node(W->dlm, 44);
        mxfs_dlm_handoff_takeover(A->dlm, 44, 3002);
        settle(A);
    }

    /* 8 refusal is fail-closed */
    settle(A);
    A->ledger.torn_after_bytes = 1024;
    rc = lock_sync(B, &R, MXFS_LOCK_EX, &granted);
    rc |= probe_lookup(&R, &e);
    /* the platter decides: a tear that covers every changed byte validates
     * (committed on reconcile), any other tear is proven-uncommitted and
     * retried — the grant lands either way, never around the ledger */
    CHECK(rc == 0 && A->ledger.poisons == 1 && A->ledger.reconciled == 1 &&
          A->ledger.commits >= 1 && e.ex_node == 22,
          "8 torn write reconciled, grant durable (poisons=%llu reconciled=%llu uncommitted=%llu)",
          (unsigned long long)A->ledger.poisons, (unsigned long long)A->ledger.reconciled,
          (unsigned long long)A->ledger.uncommitted);
    mxfs_dlm_unlock(B->dlm, &R);
    {
        /* plant a COLLIDING ACTIVE record on R's slot behind A's back */
        struct mxfs_tauth_page *pg = calloc(1, sizeof(*pg));
        struct mxfs_tauth_ledger w;
        uint64_t t0;

        settle(A);
        mxfs_tauth_ledger_open(&w, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 98, 9998, 62);
        mxfs_tauth_page_read(&w.store, tl_page(&R), pg, NULL);
        pg->ent[tl_home(&R)].state = MXFS_TAUTH_ST_ACTIVE;
        pg->ent[tl_home(&R)].ino = R.ino + 7777;
        pg->ent[tl_home(&R)].ex_node = 55;
        /* keep the page's authority: the plant is a foreign RECORD, not a
         * foreign authority (that row is the takeover in group 5) */
        mxfs_tauth_page_write(&w.store, pg, pg->hdr.authority_epoch, 1, 0);
        mxfs_tauth_ledger_close(&w);
        free(pg);
        /* force A to reload the page: a membership bump (same set twice
         * is a no-op, so bounce through 3 members) */
        membership(ids3, 3);
        membership(ids2, 2);
        t0 = mxfs_pal_time_ms();
        rc = mxfs_dlm_lock_retries(B->dlm, &R, MXFS_LOCK_EX, 0, &granted, 2);
        /* sess426 (D-0348): the foreign record on R's home index no longer
         * blocks R — the master records R in another entry of the page */
        CHECK(rc == 0 && granted == MXFS_LOCK_EX && A->ledger.collisions == 0 && A->ledger.probes >= 1,
              "8 foreign record on the home index: R granted elsewhere rc=%d probes=%llu in %llums",
              rc, (unsigned long long)A->ledger.probes, (unsigned long long)(mxfs_pal_time_ms() - t0));
        CHECK(mxfs_dlm_held_mode(B->dlm, &R) == MXFS_LOCK_EX, "8 B holds EX on R");
        if (rc == 0)
            mxfs_dlm_unlock(B->dlm, &R);
    }

    /* 9 lost GRANT: retry gets the same durable grant id */
    R = res_mastered_by(A, 11, R.ino + 200000);
    B->drop_grants = 1;
    {
        struct lock_job *j = lock_async(B, &R, MXFS_LOCK_EX, 5);

        CHECK(lock_wait(j, 4000) && j->rc == 0 && j->t1 - j->t0 >= 900,
              "9 B granted after one lost GRANT rc=%d wall=%llums", j->rc,
              (unsigned long long)(j->t1 - j->t0));
        lock_finish(j);
    }
    rc = probe_lookup(&R, &e);
    mxfs_dlm_grant_id(B->dlm, &R, &auth1, &seq1, &lin);
    CHECK(rc == 0 && e.ex_node == 22 && e.grant_seq64 == 1 && seq1 == 1 && auth1 == e.authority_epoch,
          "9 same grant id on retry: platter seq=%llu holder seq=%llu", (unsigned long long)e.grant_seq64,
          (unsigned long long)seq1);
    mxfs_dlm_unlock(B->dlm, &R);

    /* 10 activation barrier */
    C = node_up(2, 33, 3001, 3, 0);              /* ledger_required, no ledger */
    membership(ids3, 3);
    {
        struct mxfs_resource_id Rc = res_mastered_by(C, 33, 900000);

        rc = mxfs_dlm_lock_retries(C->dlm, &Rc, MXFS_LOCK_EX, 0, &granted, 2);
        CHECK(rc == -EIO, "10 grant refused without a ledger rc=%d", rc);
        rc = mxfs_dlm_lock_retries(A->dlm, &Rc, MXFS_LOCK_EX, 0, &granted, 2);
        CHECK(rc == -EIO, "10 remote request to the ledger-less master denied rc=%d", rc);
    }
    node_down(C);
    membership(ids2, 2);
    /* C's death is recovered (v5: purge after the fence + replay); the
     * PREPAREDs A/B aimed at C are retargeted by the tick */
    mxfs_dlm_ledger_purge_owner(A->dlm, 33, 3);
    mxfs_dlm_ledger_purge_owner(B->dlm, 33, 3);
    mxfs_dlm_purge_node(A->dlm, 33);
    mxfs_dlm_purge_node(B->dlm, 33);
    rc = mxfs_dlm_handoff_takeover(A->dlm, 33, 3001);
    CHECK(rc == 0, "10 the ledger-less incarnation owned no pages (takeover rc=%d)", rc);

    /* 11 clean unmount: release_all waits for ACKs; no record remains */
    rc = lock_sync(B, &R, MXFS_LOCK_EX, &granted);
    rc |= lock_sync(B, &R3, MXFS_LOCK_PR, &granted);
    CHECK(rc == 0, "11 B holds R EX + R3 PR");
    mxfs_dlm_unlock(B->dlm, &R);
    mxfs_dlm_unlock(B->dlm, &R3);
    mxfs_dlm_release_all(B->dlm);
    settle(A);
    CHECK(rel_pending_count(B) == 0 && B->dlm->release_unacked == 0,
          "11 release_all returned with every release ACKed (acks=%llu)",
          (unsigned long long)B->dlm->release_acks);
    rc = probe_lookup(&R, &e);
    rc |= probe_lookup(&R3, &e) ? 1 : (e.state == MXFS_TAUTH_ST_ACTIVE ? 2 : 0);
    CHECK(rc == 0, "11 platter holds no record of B (rc=%d)", rc);
    {
        uint64_t p0 = A->ledger.purged;      /* 7b's recovery purge counted */

        mxfs_dlm_ledger_purge_owner(A->dlm, 22, 2);
        CHECK(A->ledger.purged == p0, "11 clean-departure purge finds nothing to retire (%llu)",
              (unsigned long long)(A->ledger.purged - p0));
    }

    /* 12 (D-0962) a bulk takeover is DECERTIFIED BETWEEN PAGES.  Deferred out
     * of the recovery completion the pass outlives the exclusive-write gate,
     * so the returned peer can claim a lower heartbeat slot while the pass is
     * still running and become the node the cluster certifies to write
     * authority transitions.  Certification was tested once, at entry, which
     * was sufficient only while the gate kept membership still.  The pass must
     * stop between pages, leave the rest under the departed authority, and
     * remain completable — the certified node finds them in its own sweep. */
    {
        mxfs_node_id_t ids3c[3] = { 11, 22, 55 };
        struct mxfs_resource_id cr[6];
        struct mxfs_tauth_page_auth pa;
        uint32_t p, left_before = 0, left_mid = 0, left_after = 0;
        uint64_t decert0 = A->dlm->handoff_decertified;
        uint64_t ino = 3000000;
        int i, n = 0;

        C = node_up(2, 55, 5500, 3, 1);
        membership(ids3c, 3);
        mxfs_pal_sleep_ms(50);
        /* C becomes the authority of several pages by holding EX on
         * resources it masters: an authority record is what a takeover
         * moves, and a lone claim on one page cannot show a pass stopping
         * PART way through one. */
        while (n < 6) {
            struct mxfs_resource_id r = res_mastered_by(C, 55, ino);
            int dup = 0;

            ino = r.ino + 1;
            for (i = 0; i < n; i++)
                if (tl_page(&cr[i]) == tl_page(&r))
                    dup = 1;
            if (dup)
                continue;
            if (lock_sync(C, &r, MXFS_LOCK_EX, &granted) != 0)
                continue;
            cr[n++] = r;
        }
        node_down(C);
        membership(ids2, 2);
        mxfs_pal_sleep_ms(50);
        for (p = 0; p < A->ledger.npages; p++)
            if (mxfs_tauth_ledger_page_auth(&A->ledger, p, true, &pa) == 0 &&
                pa.auth_node == 55 && pa.auth_inc == 5500)
                left_before++;
        CHECK(left_before >= 4, "12 the dead incarnation owns %u pages (want >= 4)", left_before);

        bootstrap_budget = 2;           /* entry passes, the pass loses it */
        rc = mxfs_dlm_handoff_takeover(A->dlm, 55, 5500);
        bootstrap_budget = -1;
        for (p = 0; p < A->ledger.npages; p++)
            if (mxfs_tauth_ledger_page_auth(&A->ledger, p, true, &pa) == 0 &&
                pa.auth_node == 55 && pa.auth_inc == 5500)
                left_mid++;
        CHECK(rc == -EAGAIN && A->dlm->handoff_decertified == decert0 + 1,
              "12 the pass yields when certification is lost mid-pass (rc=%d decert=%llu)",
              rc, (unsigned long long)(A->dlm->handoff_decertified - decert0));
        CHECK(left_mid > 0 && left_mid < left_before,
              "12 it stopped BETWEEN pages: %u of %u pages still under the dead "
              "authority", left_mid, left_before);

        /* and the work it left is not lost: the certified node completes it */
        rc = mxfs_dlm_handoff_takeover(A->dlm, 55, 5500);
        for (p = 0; p < A->ledger.npages; p++)
            if (mxfs_tauth_ledger_page_auth(&A->ledger, p, true, &pa) == 0 &&
                pa.auth_node == 55 && pa.auth_inc == 5500)
                left_after++;
        CHECK(rc > 0 && left_after == 0,
              "12 a later pass by the certified node drains the rest (rc=%d left=%u)",
              rc, left_after);
    }

    /* 13 A REFUSED ACTIVATE AND A FAILED IMPORT ARE NOT TRANSFERS.
     * A page is taken over by prepare + activate + purge + import.
     * The pass used to do the ownership work inside `if (activate == 0)` while
     * counting the page and returning 1 OUTSIDE it, and it never tested the
     * import's rc at all — so a page left PREPARED under the departed
     * authority, or activated but never imported, was reported as transferred.
     * takeover_pages_done is also the progress a parked request waits on, so a
     * pass that moved nothing still looked like progress to every waiter.
     * Both faults are injected here, page-exact and one-shot; reading the code
     * is not evidence that the accounting holds. */
    {
        mxfs_node_id_t ids3d[3] = { 11, 22, 66 }, ids1[1] = { 11 };
        struct mxfs_resource_id dr[6];
        struct mxfs_tauth_page_auth pa;
        uint32_t p, cand = 0, pact, pimp;
        uint64_t done0, ino = 7000000;
        int i, n = 0;
        struct vnode *D;

        D = node_up(2, 66, 6600, 3, 1);
        membership(ids3d, 3);
        mxfs_pal_sleep_ms(50);
        while (n < 6) {
            struct mxfs_resource_id r = res_mastered_by(D, 66, ino);
            int dup = 0;

            ino = r.ino + 1;
            for (i = 0; i < n; i++)
                if (tl_page(&dr[i]) == tl_page(&r))
                    dup = 1;
            if (dup)
                continue;
            if (lock_sync(D, &r, MXFS_LOCK_EX, &granted) != 0)
                continue;
            dr[n++] = r;
        }
        node_down(D);
        /* A ALONE: with one live member A owns every page, so every candidate
         * takes the local activate+purge+import branch and the injected page
         * is certain to reach it.  (B's own records stay on the platter; they
         * are not this authority's and the pass does not touch them.) */
        node_down(B);
        membership(ids1, 1);
        mxfs_pal_sleep_ms(50);
        for (p = 0; p < A->ledger.npages; p++)
            if (mxfs_tauth_ledger_page_auth(&A->ledger, p, true, &pa) == 0 &&
                pa.auth_node == 66 && pa.auth_inc == 6600)
                cand++;
        /* Inject into pages we HOLD A RESOURCE ON, so the recovery each
         * failure needs can be driven by an ordinary lock rather than by
         * another bulk pass — which is the point: neither failure may leave a
         * page that only a second sweep could rescue. */
        pact = tl_page(&dr[0]) + 1;
        pimp = tl_page(&dr[1]) + 1;
        CHECK(cand >= 4 && pact != pimp,
              "13 the dead incarnation owns %u pages; injecting activate on %u, import on %u",
              cand, pact - 1, pimp - 1);

        /* BOTH faults in ONE pass: a refused activate leaves its page PREPARED
         * under the dead authority, and a failed import leaves its page
         * durably ours but unservable.  They are different states, they
         * recover by different paths, and neither is a transfer. */
        done0 = A->dlm->takeover_pages_done;
        A->ledger.fail_activate_once_page = pact;
        A->ledger.fail_activate_once_rc = -EIO;
        A->ledger.fail_scan_active_once_page = pimp;
        A->ledger.fail_scan_active_once_rc = -EIO;
        rc = mxfs_dlm_handoff_takeover(A->dlm, 66, 6600);
        CHECK(A->ledger.fail_activate_once_page == 0 &&
              A->ledger.fail_scan_active_once_page == 0,
              "13 both injected failures fired (knobs consumed)");
        CHECK(rc == -EAGAIN, "13 the pass answers -EAGAIN, not a page count (rc=%d)", rc);
        CHECK(A->dlm->takeover_pages_done == done0 + cand - 2,
              "13 progress counted %llu of %u pages — neither failure is progress",
              (unsigned long long)(A->dlm->takeover_pages_done - done0), cand);

        /* 13a the REFUSED ACTIVATE: not ours, still the dead authority's */
        CHECK(mxfs_tauth_ledger_page_auth(&A->ledger, pact - 1, true, &pa) == 0 &&
              pa.auth_node == 66 && pa.auth_inc == 6600,
              "13a the refused page is STILL under the dead authority (auth=%u/%llu)",
              pa.auth_node, (unsigned long long)pa.auth_inc);
        /* It is PREPARED to us, so a second bulk pass deliberately leaves it
         * alone ("a live target consumes it") — the recovery is the requester
         * consuming the PREPARED image, not another sweep. */
        rc = lock_sync(A, &dr[0], MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX &&
              mxfs_tauth_ledger_page_auth(&A->ledger, pact - 1, true, &pa) == 0 &&
              pa.auth_node == 11,
              "13a a request on that page is served: the PREPARED image is consumed "
              "(rc=%d auth=%u) — a refused activate strands nothing", rc, pa.auth_node);
        mxfs_dlm_unlock(A->dlm, &dr[0]);

        /* 13b the FAILED IMPORT: durably ours, and still not a transfer —
         * unservable until something rebuilds our view of the page */
        CHECK(mxfs_tauth_ledger_page_auth(&A->ledger, pimp - 1, true, &pa) == 0 &&
              pa.auth_node == 11,
              "13b the un-imported page IS durably ours — activate succeeded (auth=%u)",
              pa.auth_node);
        rc = lock_sync(A, &dr[1], MXFS_LOCK_EX, &granted);
        CHECK(rc == 0 && granted == MXFS_LOCK_EX,
              "13b a request on that page re-imports and is served (rc=%d) — a failed "
              "import is retried by the next requester, not left for a sweep", rc);
        mxfs_dlm_unlock(A->dlm, &dr[1]);
    }

    node_down(A);
    mxfs_tauth_ledger_close(&probe);
    mxfs_pal_bdev_close(dev);
    unlink(tl_path);
    printf("=== dlm_ledger_test RESULT %s fails=%d ===\n", tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
