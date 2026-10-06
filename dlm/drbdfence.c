/*
 * MXFS — Multinode XFS
 * The DRBD attachment's judgments over a witness report (drbdfence.h).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */
#include "drbdfence.h"

static int refuse(char *why, size_t whylen, const char *fmt, const char *a,
                  const char *b)
{
    if (why && whylen)
        snprintf(why, whylen, fmt, a, b);
    return -EPERM;
}

#define NEED(cond, fmt, a, b) do { if (!(cond)) return refuse(why, whylen, fmt, a, b); } while (0)

static int eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

/* What every judgment needs: the configuration this attachment's evidence
 * is built on, and this node a working Primary. */
static int common(const struct mxfs_pal_drbd_report *r, char *why, size_t whylen)
{
    NEED(r->delivered, "no witness report (%s)%s", r->reason, "");
    NEED(eq(r->protocol, "C") && eq(r->protocol_cfg, "C"),
         "replication protocol is '%s' (configured '%s'), not C", r->protocol, r->protocol_cfg);
    NEED(eq(r->two_primaries, "yes"), "allow-two-primaries is '%s'%s", r->two_primaries, "");
    NEED(eq(r->fencing, "resource-and-stonith"),
         "fencing policy is '%s', not resource-and-stonith%s", r->fencing, "");
    NEED(eq(r->fence_handler, MXFS_DRBD_FENCE_HANDLER) && eq(r->handler_installed, "1"),
         "fence-peer handler is '%s' (installed=%s), not this attachment's",
         r->fence_handler, r->handler_installed);
    NEED(eq(r->after_sb, "disconnect,disconnect,disconnect"),
         "after-split-brain policies are '%s'; automatic resolution may discard acknowledged writes%s",
         r->after_sb, "");
    NEED(eq(r->endpoints, "2") && r->local_addr[0] && r->peer_addr[0] && r->peer_host[0],
         "the resource does not name exactly two endpoints (endpoints=%s peer=%s)",
         r->endpoints, r->peer_host);
    NEED(eq(r->fence_self, r->host), "fence configuration names this node '%s', it is '%s'",
         r->fence_self, r->host);
    NEED(eq(r->suspended, "0"), "DRBD I/O is suspended (%s)%s", r->suspended, "");
    NEED(eq(r->role_local, "Primary"), "this node's role is '%s', not Primary%s", r->role_local, "");
    NEED(eq(r->disk_local, "UpToDate"), "this node's disk is '%s', not UpToDate%s", r->disk_local, "");
    return 0;
}

/*
 * The peer is excluded in the episode its receipt names, by a node fence
 * (off and held off) or by the built-in two-node authority (isolated from
 * this host and held StandAlone).  The receipt's kind and the authority's
 * state must agree; a mixed pair proves neither.
 */
static int peer_fenced(const struct mxfs_pal_drbd_report *r, enum mxfs_drbd_exclusion *how,
                       char *why, size_t whylen)
{
    NEED(eq(r->cstate, "WFConnection") || eq(r->cstate, "StandAlone"),
         "the replication link is '%s', not disconnected%s", r->cstate, "");
    NEED(eq(r->disk_peer, "Outdated"), "the peer's disk is '%s', not Outdated%s", r->disk_peer, "");
    NEED(eq(r->receipt_peer, r->peer_host) && r->receipt_episode[0],
         "no fence receipt naming the peer %s (newest names '%s')", r->peer_host, r->receipt_peer);
    NEED(eq(r->auth_inhibit, r->receipt_episode),
         "the peer is inhibited under episode '%s', the receipt names '%s'",
         r->auth_inhibit, r->receipt_episode);
    if (eq(r->receipt_kind, "EXCLUDED")) {
        /* WFConnection would take the old incarnation back the moment the
         * link healed; only StandAlone keeps it out. */
        NEED(eq(r->cstate, "StandAlone"),
             "the peer was excluded but the replication link is '%s', not StandAlone%s",
             r->cstate, "");
        NEED(eq(r->auth_state, "excluded"),
             "the fence authority reports the peer '%s', not excluded%s", r->auth_state, "");
        if (how)
            *how = MXFS_DRBD_EXCLUSION_EXCLUDED;
        return 0;
    }
    NEED(eq(r->receipt_kind, "STONITHED"),
         "the newest fence receipt is '%s', neither STONITHED nor EXCLUDED%s", r->receipt_kind, "");
    NEED(eq(r->auth_state, "shut off"),
         "the fence authority reports the peer '%s', not shut off%s", r->auth_state, "");
    if (how)
        *how = MXFS_DRBD_EXCLUSION_STONITH;
    return 0;
}

int mxfs_drbd_judge_arm(const struct mxfs_pal_drbd_report *r, char *why, size_t whylen)
{
    int rc;

    if (!r)
        return -EINVAL;
    rc = common(r, why, whylen);
    if (rc)
        return rc;
    if (eq(r->cstate, "Connected")) {
        NEED(eq(r->disk_peer, "UpToDate"), "connected, but the peer's disk is '%s'%s",
             r->disk_peer, "");
        /* The node fence must be reachable before anything depends on it,
         * and must not be holding the peer from an earlier episode. */
        NEED(r->auth_state[0], "the fence authority did not answer for the peer %s%s",
             r->peer_host, "");
        NEED(eq(r->auth_inhibit, "none"),
             "connected, but the fence authority holds the peer inhibited (episode %s)%s",
             r->auth_inhibit, "");
        return 0;
    }
    return peer_fenced(r, NULL, why, whylen);
}

int mxfs_drbd_judge_excluded_how(const struct mxfs_pal_drbd_report *r,
                                 enum mxfs_drbd_exclusion *how, char *why, size_t whylen)
{
    int rc;

    if (how)
        *how = MXFS_DRBD_EXCLUSION_NONE;
    if (!r)
        return -EINVAL;
    rc = common(r, why, whylen);
    if (rc)
        return rc;
    return peer_fenced(r, how, why, whylen);
}

int mxfs_drbd_judge_excluded(const struct mxfs_pal_drbd_report *r, char *why, size_t whylen)
{
    return mxfs_drbd_judge_excluded_how(r, NULL, why, whylen);
}

/* Dotted IPv4 to a number; -1 when it is not exactly four octets. */
static long long ipv4(const char *s)
{
    long long v = 0;
    int octets = 0;

    while (*s) {
        long o = 0;
        int digits = 0;

        while (*s >= '0' && *s <= '9' && digits < 4) {
            o = o * 10 + (*s - '0');
            s++;
            digits++;
        }
        if (!digits || o > 255)
            return -1;
        v = (v << 8) | o;
        octets++;
        if (*s == '.' && octets < 4)
            s++;
        else if (*s)
            return -1;
    }
    return octets == 4 ? v : -1;
}

int mxfs_drbd_participant_index(const struct mxfs_pal_drbd_report *r)
{
    long long me, peer;

    if (!r)
        return -EINVAL;
    me = ipv4(r->local_addr);
    peer = ipv4(r->peer_addr);
    if (me < 0 || peer < 0 || me == peer)
        return -EINVAL;
    return me < peer ? 0 : 1;
}
