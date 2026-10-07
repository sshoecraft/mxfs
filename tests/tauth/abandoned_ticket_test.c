// SPDX-License-Identifier: GPL-2.0
/*
 * abandoned_ticket_test — a commit ticket left on a page's spare copy by an
 * incarnation that died between its ticket swap and its publish, met by a
 * LATER mount that did not recover that incarnation itself.
 *
 * Measured on the physical DRBD pair on 0.90.91: page 13005 was PREPARED by
 * one incarnation of an earlier era to another, and the target's ticket stood
 * on copy 0 proposing seq 19 over the committed 18.  The store let a writer
 * take a ticket over only from an incarnation THIS mount had purged; the
 * mount that recovered the target was gone, so every commit on the page was
 * refused -EBUSY, the on-demand takeover stalled (P960-STALLED-PAGE
 * ondemand_last{page=13005 rc=-16}) and the survivor's mkdir failed EAGAIN.
 *
 * Each arm runs in its own process on its own temp file:
 *
 *   active    an authority dies mid-commit on its own page; the next mount,
 *             on the slot the authority's tenancy left and never having
 *             recovered it, must take the page over and grant on it
 *   prepared  the measured shape: an authority PREPAREs its page to a
 *             target, the target dies mid-commit consuming it, and nobody
 *             alive recovered either; the next mount must take the page over
 *             and grant on it
 *   live      what the store must go on refusing: the ticket of a writer
 *             that is a live member of the view, then of one that is dead but
 *             not yet recovered (dropped from the view, still the occupant of
 *             its heartbeat slot).  Once this mount purges it, its ticket is
 *             taken over, as it always was
 *
 * The incarnation that dies leaves its ticket with the store's own test knob
 * (ticket_fail_once_rc with ticket_fail_landed): the swap is issued and only
 * its answer is lost, then nothing of the body follows, which is what a death
 * between the swap and the publish leaves on the platter.
 *
 * Each grant attempt prints one SIGNATURE line: whether it was granted, the
 * requester's store counters, the DLM's last on-demand takeover and whether
 * the ticket still stands.  tests/tauth/abandoned_ticket.sh builds this
 * against the engine and against a control copy of dlm/dlm.c whose
 * dlm_store_fenced_cb is the 0.90.91 one, and grades both.
 */
#define NNODES 4
#include "dlm_mesh.h"

/* how long a grant past a dead writer's ticket may take: on the temp file a
 * takeover is a handful of commits (prepare, activate, the page's purge, the
 * grant), each a few ms */
#define ASK_MS 5000

static uint32_t fs_gen;

/* which copy of page `pg` carries a valid ticket of {node, inc}, or -1 */
static int ticket_copy(uint32_t pg, mxfs_node_id_t node, uint64_t inc)
{
    struct mxfs_tauth_ticket t;
    int c;

    for (c = 0; c < 2; c++) {
        raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, pg, c), &t, sizeof(t));
        if (mxfs_tauth_ticket_valid(&t, pg, fs_gen, tl_crc) &&
            t.writer_node == node && t.writer_inc == inc)
            return c;
    }
    return -1;
}

/*
 * The incarnation behind `n` is cut off between its ticket swap and its
 * publish on page `pg`: its own store commits the page's current image again
 * with the swap's answer lost, so the swap is issued, its ticket stands on the
 * spare copy and no body follows.  Returns the copy the ticket stands on, or
 * -1.  A node that dies here must be halted first, so that nothing of its own
 * resumes the ticket.
 */
static int leave_ticket(struct vnode *n, uint32_t pg)
{
    struct mxfs_tauth_page *img = calloc(1, sizeof(*img));
    int copy = -1, rc;

    rc = mxfs_tauth_page_read(&n->ledger.store, pg, img, &copy);
    if (rc) {
        printf("  INFO %u/%llu could not read page %u (rc=%d)\n", n->id,
               (unsigned long long)n->inc, pg, rc);
        free(img);
        return -1;
    }
    n->ledger.store.ticket_fail_once_rc = -EIO;
    n->ledger.store.ticket_fail_landed = true;
    rc = mxfs_tauth_page_write(&n->ledger.store, img, img->hdr.authority_epoch, 1, 0);
    printf("  INFO %u/%llu cut off mid-commit on page %u: proposed seq %llu over %llu, "
           "its write answered %d\n", n->id, (unsigned long long)n->inc, pg,
           (unsigned long long)img->hdr.seq + 1, (unsigned long long)img->hdr.seq, rc);
    free(img);
    return rc == -EIO ? ticket_copy(pg, n->id, n->inc) : -1;
}

static void signature(const char *arm, struct vnode *q, int granted, int rc,
                      uint64_t ms, uint32_t pg, mxfs_node_id_t w, uint64_t winc)
{
    printf("  SIGNATURE arm=%s granted=%d rc=%d ms=%llu ticket_busy=%llu "
           "ticket_takeovers=%llu ondemand_last={page=%u rc=%d} ticket_left=%d\n",
           arm, granted, rc, (unsigned long long)ms,
           (unsigned long long)q->ledger.store.ticket_busy,
           (unsigned long long)q->ledger.store.ticket_takeovers,
           q->dlm->ondemand_last_page, q->dlm->ondemand_last_rc,
           ticket_copy(pg, w, winc) >= 0 ? 1 : 0);
}

/*
 * Q, a mount that never recovered {w, winc}, asks for R on page pg, whose
 * spare copy carries w's ticket.  w is dead by the slot map: its slot has
 * moved on and it is not in Q's view.  Q must take the page over, past the
 * ticket, and grant R.
 */
static void ask_past_dead_ticket(const char *arm, struct vnode *q,
                                 const struct mxfs_resource_id *r, uint32_t pg,
                                 mxfs_node_id_t w, uint64_t winc)
{
    struct mxfs_tauth_page_auth a;
    struct mxfs_tauth_entry e;
    struct lock_job *j;
    int done, ok, prc, lrc;

    j = lock_async(q, r, MXFS_LOCK_EX, 60);
    done = lock_wait(j, ASK_MS);
    ok = done && j->rc == 0 && j->granted == MXFS_LOCK_EX;
    signature(arm, q, ok, done ? j->rc : 1, done ? j->t1 - j->t0 : ASK_MS, pg, w, winc);
    CHECK(ok, "%s: %u/%llu is granted R EX past the ticket of %u/%llu (done=%d rc=%d within %d ms)",
          arm, q->id, (unsigned long long)q->inc, w, (unsigned long long)winc, done,
          done ? j->rc : 0, ASK_MS);
    CHECK(q->ledger.store.ticket_takeovers >= 1 && ticket_copy(pg, w, winc) < 0,
          "%s: the ticket was taken over (takeovers=%llu busy=%llu, still on the platter=%d)",
          arm, (unsigned long long)q->ledger.store.ticket_takeovers,
          (unsigned long long)q->ledger.store.ticket_busy, ticket_copy(pg, w, winc) >= 0);
    prc = mxfs_tauth_ledger_page_auth(&probe, pg, true, &a);
    CHECK(prc == 0 && a.state == MXFS_TAUTH_PG_ACTIVE && a.auth_node == q->id &&
          a.auth_inc == q->inc,
          "%s: page %u on the platter: state=%u auth=%u/%llu (want ACTIVE %u/%llu) rc=%d",
          arm, pg, a.state, a.auth_node, (unsigned long long)a.auth_inc, q->id,
          (unsigned long long)q->inc, prc);
    lrc = probe_lookup(r, &e);
    CHECK(lrc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == q->id &&
          e.ex_inc == q->inc,
          "%s: R on the platter: state=%u ex=%u/%llu (want ACTIVE %u/%llu) rc=%d",
          arm, e.state, e.ex_node, (unsigned long long)e.ex_inc, q->id,
          (unsigned long long)q->inc, lrc);
    /* a request still waiting is left to the process exit: its node is never
     * destroyed under it */
    if (done)
        lock_finish(j);
}

static void arm_active(void)
{
    mxfs_node_id_t era1[1] = { 11 }, era2[1] = { 22 };
    struct vnode *p, *q;
    struct mxfs_resource_id r;
    uint8_t granted = 0;
    uint32_t pg;
    int rc, copy;

    /* P: the authority of an earlier era, alone on slot 0 */
    p = node_up(0, 11, 1100, 0, 1);
    membership(era1, 1);
    r = res_mastered_by(p, 11, 5000);
    pg = tl_page(&r);
    rc = lock_sync(p, &r, MXFS_LOCK_EX, &granted);
    settle(p);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX && mxfs_tauth_ledger_page_mine(&p->ledger, pg),
          "active: P (11/1100) masters page %u and holds R ino=%llu EX (rc=%d)", pg,
          (unsigned long long)r.ino, rc);
    node_halt(p);
    copy = leave_ticket(p, pg);
    CHECK(copy >= 0, "active: P's ticket stands on copy %d of page %u", copy, pg);
    node_down(p);

    /* Q: the next mount, on the slot P's tenancy left; it never recovered P */
    q = node_up(1, 22, 2200, 0, 1);
    membership(era2, 1);
    ask_past_dead_ticket("active", q, &r, pg, 11, 1100);
}

static void arm_prepared(void)
{
    mxfs_node_id_t era1[1] = { 33 }, era2[1] = { 55 };
    struct vnode *a, *t, *q;
    struct mxfs_resource_id r;
    uint64_t seq = 0;
    uint8_t granted = 0;
    uint32_t pg;
    int rc, copy;

    /* A: the authority of an earlier era; T: the member it hands a page to */
    a = node_up(0, 33, 3300, 0, 1);
    membership(era1, 1);
    r = res_mastered_by(a, 33, 7000);
    pg = tl_page(&r);
    rc = lock_sync(a, &r, MXFS_LOCK_EX, &granted);
    rc |= mxfs_dlm_unlock(a->dlm, &r);
    settle(a);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX && mxfs_tauth_ledger_page_mine(&a->ledger, pg),
          "prepared: A (33/3300) masters page %u (R ino=%llu granted and released, rc=%d)",
          pg, (unsigned long long)r.ino, rc);
    t = node_up(1, 44, 4400, 1, 1);
    node_halt(a);
    node_halt(t);
    rc = mxfs_tauth_ledger_prepare(&a->ledger, pg, a->dlm->ledger_gen, 44, 4400, 0, 0,
                                   false, &seq);
    CHECK(rc == 0, "prepared: A PREPAREs page %u to T (44/4400) at seq %llu (rc=%d)", pg,
          (unsigned long long)seq, rc);
    copy = leave_ticket(t, pg);
    CHECK(copy >= 0, "prepared: T's ticket, consuming the PREPARED image, stands on copy %d",
          copy);
    node_down(t);
    node_down(a);

    /* Q: the next mount; it recovered neither */
    q = node_up(2, 55, 5500, 0, 1);
    membership(era2, 1);
    ask_past_dead_ticket("prepared", q, &r, pg, 44, 4400);
}

/* one grant attempt on Q's own page, small budget: refused or granted */
static int try_grant(const char *arm, struct vnode *q, const struct mxfs_resource_id *r,
                     uint32_t pg, mxfs_node_id_t w, uint64_t winc)
{
    uint8_t granted = 0;
    uint64_t t0 = mxfs_pal_time_ms();
    int rc;

    rc = mxfs_dlm_lock_retries(q->dlm, r, MXFS_LOCK_EX, 0, &granted, 3);
    signature(arm, q, rc == 0 && granted == MXFS_LOCK_EX, rc, mxfs_pal_time_ms() - t0, pg,
              w, winc);
    return rc == 0 && granted == MXFS_LOCK_EX;
}

static void arm_live(void)
{
    mxfs_node_id_t both[2] = { 55, 66 }, alone[1] = { 55 };
    struct vnode *q, *s;
    struct mxfs_resource_id r;
    struct mxfs_tauth_entry e;
    uint64_t busy0, take0;
    uint8_t granted = 0;
    uint32_t pg;
    int rc, copy, ok;

    q = node_up(0, 55, 5500, 0, 1);
    s = node_up(1, 66, 6600, 1, 1);
    membership(both, 2);
    r = res_mastered_by(q, 55, 9000);
    pg = tl_page(&r);
    rc = lock_sync(q, &r, MXFS_LOCK_EX, &granted);
    rc |= mxfs_dlm_unlock(q->dlm, &r);
    settle(q);
    CHECK(rc == 0 && granted == MXFS_LOCK_EX && mxfs_tauth_ledger_page_mine(&q->ledger, pg),
          "live: Q (55/5500) masters page %u (R ino=%llu granted and released, rc=%d)", pg,
          (unsigned long long)r.ino, rc);

    /* 1: S, a live member of the view, is mid-commit on Q's page */
    copy = leave_ticket(s, pg);
    CHECK(copy >= 0, "live: S (66/6600), live and in the view, has its ticket on copy %d", copy);
    busy0 = q->ledger.store.ticket_busy;
    take0 = q->ledger.store.ticket_takeovers;
    ok = try_grant("live-member", q, &r, pg, 66, 6600);
    CHECK(!ok && q->ledger.store.ticket_busy > busy0 &&
          q->ledger.store.ticket_takeovers == take0 && ticket_copy(pg, 66, 6600) >= 0,
          "live: a live member's ticket is refused (granted=%d busy +%llu takeovers +%llu)", ok,
          (unsigned long long)(q->ledger.store.ticket_busy - busy0),
          (unsigned long long)(q->ledger.store.ticket_takeovers - take0));

    /* 2: S dies.  Detection drops it from the view; its recovery has not run,
     * so it is still the occupant of slot 1 */
    node_halt(s);
    membership(alone, 1);
    busy0 = q->ledger.store.ticket_busy;
    ok = try_grant("live-unrecovered", q, &r, pg, 66, 6600);
    CHECK(!ok && q->ledger.store.ticket_busy > busy0 &&
          q->ledger.store.ticket_takeovers == take0 && ticket_copy(pg, 66, 6600) >= 0,
          "live: a dead, unrecovered writer's ticket is refused (granted=%d busy +%llu "
          "takeovers +%llu)", ok, (unsigned long long)(q->ledger.store.ticket_busy - busy0),
          (unsigned long long)(q->ledger.store.ticket_takeovers - take0));

    /* 3: this mount recovers S: the purge that follows its fence */
    rc = mxfs_dlm_ledger_purge_owner(q->dlm, 66, 1);
    ok = try_grant("live-purged", q, &r, pg, 66, 6600);
    CHECK(rc >= 0 && ok && q->ledger.store.ticket_takeovers == take0 + 1 &&
          ticket_copy(pg, 66, 6600) < 0,
          "live: once this mount purged S (rc=%d) its ticket is taken over and R granted "
          "(granted=%d takeovers +%llu)", rc, ok,
          (unsigned long long)(q->ledger.store.ticket_takeovers - take0));
    rc = probe_lookup(&r, &e);
    CHECK(rc == 0 && e.state == MXFS_TAUTH_ST_ACTIVE && e.ex_node == 55 && e.ex_inc == 5500,
          "live: R on the platter: state=%u ex=%u/%llu (want ACTIVE 55/5500) rc=%d", e.state,
          e.ex_node, (unsigned long long)e.ex_inc, rc);
}

int main(int argc, char **argv)
{
    const char *arm = argc > 1 ? argv[1] : "";
    int rc;

    if (strcmp(arm, "active") && strcmp(arm, "prepared") && strcmp(arm, "live")) {
        fprintf(stderr, "usage: %s active|prepared|live\n", argv[0]);
        return 2;
    }
    vocc_on = 1;
    tl_mktemp("abandoned_ticket_test");
    printf("=== abandoned_ticket_test arm=%s file=%s ===\n", arm, tl_path);
    format_region(base, uuid);
    fs_gen = mxfs_tauth_fs_gen(uuid);
    dev = mxfs_pal_bdev_open(tl_path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_ledger_open(&probe, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 99, 9999, 63);
    if (rc) { printf("probe open rc=%d\n", rc); return 2; }

    if (!strcmp(arm, "active"))
        arm_active();
    else if (!strcmp(arm, "prepared"))
        arm_prepared();
    else
        arm_live();

    unlink(tl_path);
    printf("=== abandoned_ticket_test arm=%s RESULT %s fails=%d ===\n", arm,
           tl_fails ? "FAIL" : "PASS", tl_fails);
    fflush(stdout);
    /* a refused request may still be waiting inside a node's DLM: no teardown */
    _exit(tl_fails ? 1 : 0);
}
