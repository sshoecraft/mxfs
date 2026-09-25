// SPDX-License-Identifier: GPL-2.0
/*
 * dlm_mesh.h — the usermode DLM-engine harness shared by dlm_ledger_test and
 * formation_test: several in-process "nodes" (a real mxfs_dlm_ctx each, own
 * mxfs_tauth_ledger on ONE shared temp file), an in-memory message mesh
 * (per-node inbound queue + receiver thread, the dispatch v5_peer_msg_cb_tcp
 * does), the mount layer's step-4 callbacks, a tick thread, a read-only
 * platter probe and async lock helpers.  Define NNODES before including.
 */
#ifndef MXFS_TAUTH_DLM_MESH_H
#define MXFS_TAUTH_DLM_MESH_H
#include "tauth_testlib.h"
#include "dlm/dlm.h"
#include "dlm/tauth_ledger.h"
#pragma GCC diagnostic ignored "-Wunused-function"

#ifndef NNODES
#define NNODES 4
#endif

struct vmsg {
    struct vmsg *next;
    size_t len;
    unsigned char buf[512];
};

struct vnode {
    int              used;
    mxfs_node_id_t   id;
    uint64_t         inc;
    uint16_t         slot;
    struct mxfs_dlm_ctx *dlm;
    struct mxfs_tauth_ledger ledger;
    int              ledger_open;
    mxfs_mutex_t    *qlock;
    mxfs_cond_t     *qcond;
    struct vmsg     *head, *tail;
    mxfs_thread_t   *rx;
    mxfs_thread_t   *tick;              /* handoff + release ticks */
    volatile int     stop;
    /* knobs / observations */
    volatile int     drop_grants;       /* drop this many inbound GRANTs */
    volatile int     auto_release;      /* unlock on BAST */
    volatile int     basts;
    struct mxfs_resource_id last_bast_res;
    int              msgs_rx;
};

static struct vnode nodes[NNODES];
static mxfs_node_id_t live_ids[NNODES];   /* the last membership() view */
static int live_n;
static mxfs_bdev_t *dev;
static const uint64_t base = 65536;
static const uint8_t uuid[16] = {7,7,7,7,5,6,7,8,9,10,11,12,13,14,15,16};

static struct vnode *node_by_id(mxfs_node_id_t id)
{
    int i;

    for (i = 0; i < NNODES; i++)
        if (nodes[i].used && nodes[i].id == id)
            return &nodes[i];
    return NULL;
}

/* ─── the mesh ─── */

static int vsend(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target,
                 const void *msg, size_t len)
{
    struct vnode *to = node_by_id(target);
    struct vmsg *m;

    (void)ctx;
    if (!to || to->stop || len > sizeof(m->buf))
        return -ENOTCONN;
    m = calloc(1, sizeof(*m));
    if (!m)
        return -ENOMEM;
    m->len = len;
    memcpy(m->buf, msg, len);
    mxfs_pal_mutex_lock(to->qlock);
    if (to->tail)
        to->tail->next = m;
    else
        to->head = m;
    to->tail = m;
    mxfs_pal_cond_signal(to->qcond);
    mxfs_pal_mutex_unlock(to->qlock);
    return 0;
}

static void vbast(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *res,
                  mxfs_node_id_t owner, uint8_t requested_mode)
{
    struct vnode *me = ctx->cb_data;

    if (owner == me->id) {
        me->basts++;
        me->last_bast_res = *res;
        if (me->auto_release)
            mxfs_dlm_unlock(me->dlm, res);
        return;
    }
    {
        struct mxfs_dlm_bast b;

        memset(&b, 0, sizeof(b));
        b.hdr.magic = MXFS_DLM_MAGIC;
        b.hdr.version = MXFS_DLM_VERSION;
        b.hdr.type = MXFS_MSG_LOCK_BAST;
        b.hdr.length = sizeof(b);
        b.hdr.sender = me->id;
        b.hdr.target = owner;
        b.resource = *res;
        b.requested_mode = requested_mode;
        vsend(ctx, owner, &b, sizeof(b));
    }
}

static void vrx_fn(void *arg)
{
    struct vnode *me = arg;

    for (;;) {
        struct vmsg *m;
        const struct mxfs_dlm_msg_hdr *hdr;

        mxfs_pal_mutex_lock(me->qlock);
        while (!me->head && !me->stop)
            mxfs_pal_cond_timedwait(me->qcond, me->qlock, 50);
        if (me->stop && !me->head) {
            mxfs_pal_mutex_unlock(me->qlock);
            return;
        }
        m = me->head;
        me->head = m->next;
        if (!me->head)
            me->tail = NULL;
        mxfs_pal_mutex_unlock(me->qlock);

        me->msgs_rx++;
        hdr = (const struct mxfs_dlm_msg_hdr *)m->buf;
        if (me->dlm) {
            switch (hdr->type) {
            case MXFS_MSG_LOCK_REQ:
                if (m->len >= sizeof(struct mxfs_dlm_lock_req))
                    mxfs_dlm_process_remote_request(me->dlm, hdr->sender,
                                                    (const struct mxfs_dlm_lock_req *)m->buf);
                break;
            case MXFS_MSG_LOCK_GRANT:
            case MXFS_MSG_LOCK_DENY:
                if (hdr->type == MXFS_MSG_LOCK_GRANT && me->drop_grants > 0) {
                    me->drop_grants--;
                    break;
                }
                if (m->len >= sizeof(struct mxfs_dlm_lock_resp))
                    mxfs_dlm_process_remote_grant(me->dlm,
                                                  (const struct mxfs_dlm_lock_resp *)m->buf);
                break;
            case MXFS_MSG_LOCK_RELEASE:
                if (m->len >= sizeof(struct mxfs_dlm_lock_release))
                    mxfs_dlm_process_remote_release(me->dlm, hdr->sender,
                                                    (const struct mxfs_dlm_lock_release *)m->buf);
                break;
            case MXFS_MSG_LOCK_RELEASE_ACK:
                if (m->len >= sizeof(struct mxfs_dlm_release_ack))
                    mxfs_dlm_process_release_ack(me->dlm,
                                                 (const struct mxfs_dlm_release_ack *)m->buf);
                break;
            case MXFS_MSG_PAGE_HANDOFF:
                if (m->len >= sizeof(struct mxfs_dlm_page_handoff))
                    mxfs_dlm_process_page_handoff(me->dlm, hdr->sender,
                                                  (const struct mxfs_dlm_page_handoff *)m->buf);
                break;
            case MXFS_MSG_LOCK_BAST: {
                const struct mxfs_dlm_bast *b = (const struct mxfs_dlm_bast *)m->buf;

                me->basts++;
                me->last_bast_res = b->resource;
                if (me->auto_release)
                    mxfs_dlm_unlock(me->dlm, &b->resource);
                break;
            }
            default:
                break;
            }
        }
        free(m);
    }
}

/* (step 4): the mount layer's callbacks.  bootstrap = this node
 * holds the lowest heartbeat slot of the current view (the disklock
 * arbitration); node_inc = the disklock table's incarnation for a node. */
/* D-0347 knob: every node believes it is the bootstrap node (a falsely-dead
 * lowest-slot node ranks its own slot first; its successor dropped it) */
static volatile int force_bootstrap_all;

/*
 * D-0962: a bulk takeover rechecks certification BETWEEN pages, because
 * deferred to the departure worker it outlives the exclusive-write gate and a
 * peer can join on a lower slot while it runs.  A budget decertifies the
 * running node at an exact call: the first `bootstrap_budget` answers are the
 * real predicate, every later one is false.  -1 = off.
 */
static volatile int bootstrap_budget = -1;

static bool vbootstrap(void *data)
{
    struct vnode *me = data;
    int i;

    if (bootstrap_budget >= 0) {
        if (bootstrap_budget == 0)
            return false;
        bootstrap_budget--;
    }
    if (force_bootstrap_all)
        return true;
    for (i = 0; i < live_n; i++) {
        struct vnode *n = node_by_id(live_ids[i]);

        if (n && n->slot < me->slot)
            return false;
    }
    return true;
}

/* (D-0345): who the bootstrap node is — lowest slot of the view */
static mxfs_node_id_t vbootstrap_node(void *data, uint64_t *inc_out)
{
    struct vnode *best = NULL;
    int i;

    (void)data;
    for (i = 0; i < live_n; i++) {
        struct vnode *n = node_by_id(live_ids[i]);

        if (n && (!best || n->slot < best->slot))
            best = n;
    }
    if (inc_out)
        *inc_out = best ? best->inc : 0;
    return best ? best->id : 0;
}

/* the disklock heartbeat table: slot -> {node, inc} of the live occupant */
static mxfs_node_id_t vslot_node(void *data, int slot, uint64_t *inc_out)
{
    int i;

    (void)data;
    if (inc_out)
        *inc_out = 0;
    for (i = 0; i < NNODES; i++)
        if (nodes[i].used && nodes[i].slot == slot) {
            if (inc_out)
                *inc_out = nodes[i].inc;
            return nodes[i].id;
        }
    return 0;
}

static uint64_t vnode_inc(void *data, mxfs_node_id_t node)
{
    struct vnode *n = node_by_id(node);

    (void)data;
    return n ? n->inc : 0;
}

static void vtick_fn(void *arg)
{
    struct vnode *me = arg;

    while (!me->stop) {
        if (me->dlm) {
            mxfs_dlm_handoff_tick(me->dlm);
            mxfs_dlm_release_retry_tick(me->dlm);
        }
        mxfs_pal_sleep_ms(20);
    }
}

/* ─── node lifecycle ─── */

static struct vnode *node_up(int idx, mxfs_node_id_t id, uint64_t inc, uint16_t slot,
                             int with_ledger)
{
    struct vnode *n = &nodes[idx];

    memset(n, 0, sizeof(*n));
    n->used = 1;
    n->id = id;
    n->inc = inc;
    n->slot = slot;
    n->qlock = mxfs_pal_mutex_create();
    n->qcond = mxfs_pal_cond_create();
    n->dlm = mxfs_dlm_create(id);
    n->dlm->send_cb = vsend;
    n->dlm->bast_cb = vbast;
    n->dlm->cb_data = n;
    n->dlm->bootstrap_cb = vbootstrap;
    n->dlm->bootstrap_node_cb = vbootstrap_node;
    n->dlm->node_inc_cb = vnode_inc;
    n->dlm->slot_node_cb = vslot_node;
    n->dlm->ledger_required = true;
    if (with_ledger) {
        int rc = mxfs_tauth_ledger_open(&n->ledger, dev, base, MXFS_TAUTH_REGION_BYTES,
                                        uuid, id, inc, slot);
        if (rc) { printf("ledger open node %u rc=%d\n", id, rc); exit(2); }
        n->ledger_open = 1;
        mxfs_dlm_attach_ledger(n->dlm, &n->ledger, inc, slot);
    } else {
        /* (D-0348 step 2): a ledger-less member still routes by
         * the REGION's geometry (it read the header; it just holds no
         * active ledger) — otherwise its view of who masters what
         * diverges from the cluster's. */
        mxfs_dlm_set_ledger_geometry(n->dlm, MXFS_TAUTH_NPAGES, TL_SEED);
    }
    n->rx = mxfs_pal_thread_create(vrx_fn, n);
    n->tick = mxfs_pal_thread_create(vtick_fn, n);
    return n;
}

/* halt = the node's rx + tick threads stop (it no longer receives or
 * retries) but its DLM is still callable — a node whose last act is one
 * outbound message before it dies */
static void node_halt(struct vnode *n)
{
    if (n->stop)
        return;
    n->stop = 1;
    mxfs_pal_cond_broadcast(n->qcond);
    mxfs_pal_thread_join(n->rx);
    mxfs_pal_thread_join(n->tick);
}

/* kill = crash (no releases, queue dropped); the ledger records stay */
static void node_down(struct vnode *n)
{
    struct mxfs_dlm_ctx *dlm = n->dlm;

    node_halt(n);
    n->dlm = NULL;
    mxfs_dlm_destroy(dlm);
    if (n->ledger_open)
        mxfs_tauth_ledger_close(&n->ledger);
    while (n->head) {
        struct vmsg *m = n->head;

        n->head = m->next;
        free(m);
    }
    mxfs_pal_mutex_destroy(n->qlock);
    mxfs_pal_cond_destroy(n->qcond);
    n->used = 0;
}

static void membership(const mxfs_node_id_t *ids, int n)
{
    int i;

    memcpy(live_ids, ids, sizeof(*ids) * (size_t)n);
    live_n = n;
    for (i = 0; i < NNODES; i++)
        if (nodes[i].used && nodes[i].dlm)
            mxfs_dlm_update_active_nodes(nodes[i].dlm, ids, n);
}

/* a resource whose page master (under the current membership of node n)
 * is `want`, scanning inode numbers upward from `from` */
static struct mxfs_resource_id res_mastered_by(struct vnode *n, mxfs_node_id_t want,
                                               uint64_t from)
{
    struct mxfs_resource_id r;
    uint64_t ino;

    memset(&r, 0, sizeof(r));
    r.type = MXFS_LTYPE_INODE;
    for (ino = from; ; ino++) {
        r.ino = ino;
        if (mxfs_dlm_resource_master(n->dlm, &r) == want)
            return r;
    }
}

/* ─── platter probe ─── */

static struct mxfs_tauth_ledger probe;
static int probe_lookup(const struct mxfs_resource_id *res, struct mxfs_tauth_entry *e)
{
    static uint64_t pgen = 100;
    int rc;

    /* a fresh generation forces a re-read from BOTH copies: the platter,
     * never a cached image */
    pgen++;
    mxfs_tauth_ledger_set_owner_gen(&probe, pgen);
    rc = mxfs_tauth_ledger_ensure(&probe, tl_page(res), pgen);
    if (rc)
        return rc;
    return mxfs_tauth_ledger_lookup(&probe, res, pgen, e);
}

/* ─── async lock helper ─── */

struct lock_job {
    struct vnode *n;
    struct mxfs_resource_id res;
    uint8_t mode;
    uint32_t flags;
    int max_retries;
    volatile int done;
    int rc;
    uint8_t granted;
    mxfs_thread_t *t;
    uint64_t t0, t1;
};

static void lock_job_fn(void *arg)
{
    struct lock_job *j = arg;

    j->t0 = mxfs_pal_time_ms();
    j->rc = mxfs_dlm_lock_retries(j->n->dlm, &j->res, j->mode, j->flags, &j->granted,
                                  j->max_retries);
    j->t1 = mxfs_pal_time_ms();
    j->done = 1;
}

static struct lock_job *lock_async(struct vnode *n, const struct mxfs_resource_id *res,
                                   uint8_t mode, int max_retries)
{
    struct lock_job *j = calloc(1, sizeof(*j));

    j->n = n;
    j->res = *res;
    j->mode = mode;
    j->max_retries = max_retries;
    j->t = mxfs_pal_thread_create(lock_job_fn, j);
    return j;
}

static int lock_wait(struct lock_job *j, uint64_t timeout_ms)
{
    uint64_t t0 = mxfs_pal_time_ms();

    while (!j->done && mxfs_pal_time_ms() - t0 < timeout_ms)
        mxfs_pal_sleep_ms(5);
    return j->done;
}

static void lock_finish(struct lock_job *j)
{
    mxfs_pal_thread_join(j->t);
    free(j);
}

static int lock_sync(struct vnode *n, const struct mxfs_resource_id *res, uint8_t mode,
                     uint8_t *granted)
{
    return mxfs_dlm_lock_retries(n->dlm, res, mode, 0, granted, 5);
}

static int rel_pending_count(struct vnode *n)
{
    struct mxfs_dlm_pending_release *pr;
    int c = 0;

    mxfs_pal_mutex_lock(n->dlm->rel_lock);
    for (pr = n->dlm->rel_pending; pr; pr = pr->next)
        c++;
    mxfs_pal_mutex_unlock(n->dlm->rel_lock);
    return c;
}

static int wait_until(volatile int *flag, int want, uint64_t timeout_ms)
{
    uint64_t t0 = mxfs_pal_time_ms();

    while (*flag != want && mxfs_pal_time_ms() - t0 < timeout_ms)
        mxfs_pal_sleep_ms(5);
    return *flag == want;
}

/* quiesce: every node's releases ACKed and inbound queues drained, so a
 * one-shot fault knob armed next hits the intended transition */
static void settle(struct vnode *n)
{
    uint64_t t0 = mxfs_pal_time_ms();
    int i;

    (void)n;
    for (;;) {
        int busy = 0;

        for (i = 0; i < NNODES; i++) {
            if (!nodes[i].used || !nodes[i].dlm)
                continue;
            if (rel_pending_count(&nodes[i]) || nodes[i].head)
                busy = 1;
        }
        if (!busy || mxfs_pal_time_ms() - t0 > 3000)
            break;
        mxfs_pal_sleep_ms(5);
    }
    mxfs_pal_sleep_ms(30);
}


#endif /* MXFS_TAUTH_DLM_MESH_H */
