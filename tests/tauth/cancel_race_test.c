// SPDX-License-Identifier: GPL-2.0
/*
 * cancel_race_test — the release retry tick re-sends a node's unacknowledged
 * lock cancellations while the acknowledgements that free their records land
 * on the receive path.
 *
 * A node that abandons a lock wait tells the master (LOCK_CANCEL) and keeps a
 * record of it until the master's CANCEL_ACK, re-sending it from the release
 * retry tick.  The ACK unlinks and frees the record under rel_lock.  Up to
 * 0.90.90 the tick chose the records to re-send under rel_lock, dropped the
 * lock, and then read each record through its pointer to send it; for a
 * resource remastered onto this node it searched the list for that pointer
 * and freed the record whether it was still listed or not.  An ACK landing
 * between the tick's unlock and its read left the tick reading freed memory,
 * and freeing a record the ACK had already freed.
 *
 * The same tick re-sends unacknowledged lock RELEASES, whose RELEASE_ACK
 * frees its record the same way; until 0.90.83 the release re-send kept
 * pointers past its unlock too.
 *
 * The window is made on every run instead of waited for: node A's transport
 * answers the first message of the phase's kind that the tick re-sends by
 * delivering every planted record's ACK, on the tick's own thread, before the
 * send returns -- an ACK landing while the tick is past its unlock and still
 * in its loop.  All of a phase's records are planted at once under rel_lock,
 * so one tick sees them together.  The cancel phase plants five: three on
 * resources the peer masters (re-sent) and two on resources A masters (the
 * remastered branch), the remote ones first in the list.  The release phase
 * plants four on resources the peer masters.
 *
 * Built with AddressSanitizer by tests/tauth/cancel_race.sh, a read or a free
 * of a freed record aborts the run with the stack that did it.  The script's
 * control arm builds the ticks as they were before those fixes, which must
 * abort here, each phase on its own.
 *
 * Usage: cancel_race_test cancel|release
 *
 * Asserts, per phase:
 *   1  the tick re-sent the planted records: the window was reached
 *   2  every planted record was acknowledged, each exactly once
 *   3  nothing is left pending, and no cancellation was given up
 *   4  a later tick sends nothing more
 */
#define NNODES 2
#include "dlm_mesh.h"

#define NREMOTE 3
#define NLOCAL  2
#define NREL    4

struct planted {
    struct mxfs_resource_id res;
    uint64_t                acq_seq;
    uint32_t                id;         /* cancel_id, or a release's rel_id */
};

static struct planted planted[NREMOTE + NLOCAL + NREL];
static int nplanted;
static volatile int ack_armed;          /* MXFS_MSG_LOCK_CANCEL or _RELEASE, or 0 */
static volatile int acks_delivered;
static volatile int sends;              /* messages of the phase's kind sent */
static mxfs_node_id_t peer_id;

static void ack_planted(struct mxfs_dlm_ctx *ctx, int kind)
{
    int i;

    for (i = 0; i < nplanted; i++) {
        if (kind == MXFS_MSG_LOCK_CANCEL) {
            struct mxfs_dlm_cancel_ack a;

            memset(&a, 0, sizeof(a));
            a.hdr.magic = MXFS_DLM_MAGIC;
            a.hdr.version = MXFS_DLM_VERSION;
            a.hdr.type = MXFS_MSG_LOCK_CANCEL_ACK;
            a.hdr.length = sizeof(a);
            a.hdr.sender = peer_id;
            a.hdr.target = ctx->local_node;
            a.resource = planted[i].res;
            a.acq_seq = planted[i].acq_seq;
            a.cancel_id = planted[i].id;
            a.outcome = MXFS_CANCEL_ABSENT;
            mxfs_dlm_process_cancel_ack(ctx, &a);
        } else {
            struct mxfs_dlm_release_ack a;

            memset(&a, 0, sizeof(a));
            a.hdr.magic = MXFS_DLM_MAGIC;
            a.hdr.version = MXFS_DLM_VERSION;
            a.hdr.type = MXFS_MSG_LOCK_RELEASE_ACK;
            a.hdr.length = sizeof(a);
            a.hdr.sender = peer_id;
            a.hdr.target = ctx->local_node;
            a.resource = planted[i].res;
            a.rel_id = planted[i].id;
            a.status = MXFS_OK;
            mxfs_dlm_process_release_ack(ctx, &a);
        }
        acks_delivered++;
    }
}

/*
 * Node A's transport.  A LOCK_CANCEL or LOCK_RELEASE is never delivered, so
 * the peer never answers one by itself; the first one of the armed kind
 * delivers every planted record's ACK here, before this send returns to the
 * tick.
 */
static int csend(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target, const void *msg,
                 size_t len)
{
    const struct mxfs_dlm_msg_hdr *hdr = msg;
    int kind;

    if (len < sizeof(*hdr) ||
        (hdr->type != MXFS_MSG_LOCK_CANCEL && hdr->type != MXFS_MSG_LOCK_RELEASE))
        return vsend(ctx, target, msg, len);
    sends++;
    kind = ack_armed;
    if (kind == hdr->type) {
        ack_armed = 0;
        ack_planted(ctx, kind);
    }
    return 0;
}

static uint64_t long_ago(void)
{
    uint64_t now = mxfs_pal_time_ms();

    return now > 10000 ? now - 10000 : 0;   /* due for a re-send at the next tick */
}

/* One pending cancellation.  The caller holds rel_lock, as
 * mxfs_dlm_acq_abandon does when it lists one. */
static void plant_cancel_locked(struct vnode *n, const struct mxfs_resource_id *res,
                                uint64_t seq)
{
    struct mxfs_dlm_pending_cancel *pc = mxfs_pal_alloc(sizeof(*pc));

    if (!pc) { printf("alloc failed\n"); exit(2); }
    pc->resource = *res;
    pc->acq_seq = seq;
    pc->cancel_id = ++n->dlm->cancel_id_next;
    pc->mode = MXFS_LOCK_EX;
    pc->sends = 1;
    pc->sent_ms = long_ago();
    planted[nplanted].res = *res;
    planted[nplanted].acq_seq = seq;
    planted[nplanted].id = pc->cancel_id;
    nplanted++;
    pc->next = n->dlm->cancel_pending;
    n->dlm->cancel_pending = pc;
}

/* One pending release.  The caller holds rel_lock, as the unlock path does
 * when it lists one. */
static void plant_release_locked(struct vnode *n, const struct mxfs_resource_id *res,
                                 uint32_t rel_id)
{
    struct mxfs_dlm_pending_release *pr = mxfs_pal_alloc(sizeof(*pr));

    if (!pr) { printf("alloc failed\n"); exit(2); }
    pr->resource = *res;
    pr->rel_id = rel_id;
    pr->grant_gen = 1;
    pr->auth_epoch = 1;
    pr->grant_seq = rel_id;
    pr->mode = MXFS_LOCK_EX;
    pr->sends = 1;
    pr->sent_ms = long_ago();
    pr->first_ms = pr->sent_ms;
    planted[nplanted].res = *res;
    planted[nplanted].id = rel_id;
    nplanted++;
    pr->next = n->dlm->rel_pending;
    n->dlm->rel_pending = pr;
}

static int pending_left(struct vnode *n, int kind)
{
    struct mxfs_dlm_pending_cancel *pc;
    struct mxfs_dlm_pending_release *pr;
    int left = 0;

    mxfs_pal_mutex_lock(n->dlm->rel_lock);
    if (kind == MXFS_MSG_LOCK_CANCEL) {
        for (pc = n->dlm->cancel_pending; pc; pc = pc->next)
            left++;
    } else {
        for (pr = n->dlm->rel_pending; pr; pr = pr->next)
            left++;
    }
    mxfs_pal_mutex_unlock(n->dlm->rel_lock);
    return left;
}

int main(int argc, char **argv)
{
    struct mxfs_resource_id r;
    struct vnode *A, *B;
    mxfs_node_id_t view[2];
    uint64_t from = 300000, t0, acked;
    const char *phase = argc > 1 ? argv[1] : "";
    int kind, i, sends_after, left;

    if (!strcmp(phase, "cancel"))
        kind = MXFS_MSG_LOCK_CANCEL;
    else if (!strcmp(phase, "release"))
        kind = MXFS_MSG_LOCK_RELEASE;
    else {
        printf("usage: %s cancel|release\n", argv[0]);
        return 2;
    }
    printf("=== cancel_race_test %s ===\n", phase);
    A = node_up(0, 1000, 5000, 1, 0);
    B = node_up(1, 2000, 5001, 2, 0);
    view[0] = A->id;
    view[1] = B->id;
    membership(view, 2);
    peer_id = B->id;
    A->dlm->send_cb = csend;
    mxfs_pal_sleep_ms(50);

    /* every record of the phase under one hold, so one tick sees them all;
     * the lists are pushed at their head, so what is planted last comes first */
    ack_armed = kind;
    mxfs_pal_mutex_lock(A->dlm->rel_lock);
    if (kind == MXFS_MSG_LOCK_CANCEL) {
        for (i = 0; i < NLOCAL; i++) {
            r = res_mastered_by(A, A->id, from);
            from = r.ino + 1;
            plant_cancel_locked(A, &r, 100 + i);
        }
        for (i = 0; i < NREMOTE; i++) {
            r = res_mastered_by(A, B->id, from);
            from = r.ino + 1;
            plant_cancel_locked(A, &r, 200 + i);
        }
    } else {
        for (i = 0; i < NREL; i++) {
            r = res_mastered_by(A, B->id, from);
            from = r.ino + 1;
            plant_release_locked(A, &r, 300 + i);
        }
    }
    mxfs_pal_mutex_unlock(A->dlm->rel_lock);

    t0 = mxfs_pal_time_ms();
    while (acks_delivered < nplanted && mxfs_pal_time_ms() - t0 < 3000)
        mxfs_pal_sleep_ms(5);
    mxfs_pal_sleep_ms(100);     /* the tick that delivered them finishes its loop */
    acked = kind == MXFS_MSG_LOCK_CANCEL ? A->dlm->cancel_acked : A->dlm->release_acks;
    printf("  INFO sends=%d acks_delivered=%d acked=%llu cancel_resends=%llu release_resends=%llu "
           "cancel_unacked=%llu\n", sends, acks_delivered, (unsigned long long)acked,
           (unsigned long long)A->dlm->cancel_resends,
           (unsigned long long)A->dlm->release_resends,
           (unsigned long long)A->dlm->cancel_unacked);

    CHECK(sends >= 1 && acks_delivered == nplanted,
          "1 the tick re-sent the planted records (sends=%d, acks delivered %d of %d)",
          sends, acks_delivered, nplanted);
    CHECK(acked == (uint64_t)nplanted,
          "2 every planted record acknowledged exactly once (acked=%llu of %d)",
          (unsigned long long)acked, nplanted);
    left = pending_left(A, kind);
    CHECK(left == 0 && A->dlm->cancel_unacked == 0,
          "3 nothing pending afterwards (left=%d) and no cancellation given up (unacked=%llu)",
          left, (unsigned long long)A->dlm->cancel_unacked);

    sends_after = sends;
    mxfs_pal_sleep_ms(1500);    /* past the re-send interval: a record left would go again */
    CHECK(sends == sends_after,
          "4 a later tick sends nothing more (sends %d -> %d)", sends_after, sends);

    node_down(B);
    node_down(A);
    printf("=== cancel_race_test %s RESULT %s fails=%d ===\n", phase,
           tl_fails ? "FAIL" : "PASS", tl_fails);
    return tl_fails ? 1 : 0;
}
