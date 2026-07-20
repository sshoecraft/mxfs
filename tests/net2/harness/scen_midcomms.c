/*
 * MXFS — NET2 user-mode protocol harness, gate-2 midcomms scenarios.
 *
 * The §13.1 matrix (DLM_PLAN_REVIEW.md §5.1) against the real engine
 * over localhost TCP: loss / dup / reorder / delay per class incl. ACK
 * loss; TCP reset at framing points; per-class backpressure; restart
 * with slot reuse + stale incarnations; epoch change mid-op; window /
 * SACK / serial-arithmetic boundaries; malformed + cross-cluster input;
 * COMM_AMBIGUOUS.  Every scenario ends with the §13 standing-invariant
 * asserts from the evidence counters (vc_assert_invariants).
 *
 * Scenarios run with compressed time (÷10) by default; the pinned
 * real-time subset (real_time_subset flag) reruns at spec defaults via
 * `net2_harness run rt` because compression can mask races.
 *
 * White-box exception: this file includes the engine-internal
 * net2_ctx.h for the serial-arithmetic helpers — the harness is the
 * engine's designated white-box verifier (§7.A "u64 serial arithmetic
 * asserted").
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "harness.h"
#include "dlm/net2_ctx.h"
#include "dlm/net2_wire.h"
#include "include/mxfs/mxfs_dlm.h"

#define COMPRESS(sc)  ((sc)->real_time ? 1u : 10u)
/* Wait budgets scale back up when running at real-time defaults. */
#define MS(sc, v)     ((sc)->real_time ? (v) * 10 : (v))

static int rule_set(struct vcluster *vc, int node, int idx, const char *str)
{
	struct mxfs_net2_fault_rule r;

	if (mxfs_net2_fault_parse_rule(str, &r))
		return -1;
	return mxfs_net2_fault_rule_set(vc->nodes[node].ctx, idx, &r);
}

/* Send `count` reliable/unreliable messages, tags tag0..tag0+count-1.
 * -EAGAIN is the flow-window backpressure contract: the caller retries
 * (exactly what the seam will do at step 7).  Returns how many the
 * engine accepted (rc==0). */
static int send_burst(struct vcluster *vc, int from, int to, uint16_t type,
                      uint32_t tag0, int count, int reliable)
{
	uint64_t deadline = mxfs_pal_time_ms() + 30000;
	int i, ok = 0;

	for (i = 0; i < count; i++) {
		int rc;

		do {
			rc = vc_send(vc, from, to, type,
			             tag0 + (uint32_t)i, reliable, 0);
			if (rc == -EAGAIN)
				mxfs_pal_sleep_ms(2);
		} while (rc == -EAGAIN && mxfs_pal_time_ms() < deadline);
		if (rc == 0)
			ok++;
	}
	return ok;
}

static void get_sess(struct vcluster *vc, int node, int peer,
                     struct mxfs_net2_session_stats *st)
{
	memset(st, 0, sizeof(*st));
	if (vc->nodes[node].up)
		mxfs_net2_get_session_stats(vc->nodes[node].ctx,
		                            vc->nodes[peer].slot, st);
}

static void get_mount(struct vcluster *vc, int node,
                      struct mxfs_net2_stats *st)
{
	memset(st, 0, sizeof(*st));
	if (vc->nodes[node].up)
		mxfs_net2_get_stats(vc->nodes[node].ctx, st);
}

/* ─── mc_basic: clean 2-node delivery, both directions ─── */

static int scen_mc_basic(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	int i;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 50, 1) == 50,
	   "50 sends accepted A->B");
	ck(sc, send_burst(vc, 1, 0, MXFS_MSG_LOCK_GRANT, 101, 50, 1) == 50,
	   "50 sends accepted B->A");

	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 50,
	                     MS(sc, 3000)) == 50, "all delivered at B");
	ck(sc, vc_wait_count(vc, 0, 1, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 50,
	                     MS(sc, 3000)) == 50, "all delivered at A");

	/* Fault-free same-class stream arrives in send order. */
	{
		struct vc_node *b = &vc->nodes[1];
		uint32_t prev = 0;
		int ordered = 1;

		mxfs_pal_mutex_lock(b->log_lock);
		for (i = 0; i < b->log_n; i++) {
			if (b->log[i].src_slot != 0)
				continue;
			if (b->log[i].tag <= prev)
				ordered = 0;
			prev = b->log[i].tag;
		}
		mxfs_pal_mutex_unlock(b->log_lock);
		ck(sc, ordered, "clean same-class stream in order");
	}

	ck(sc, vc_quiesce(vc, MS(sc, 2000)), "quiesced");
	vc_assert_invariants(sc, vc, 0);
	{
		struct mxfs_net2_session_stats st;

		get_sess(vc, 0, 1, &st);
		ck(sc, st.retx == 0, "clean run has no retransmits");
		ck(sc, st.acked == st.msgs_created, "everything acked");
	}
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_loss_data: 25% send-side DATA loss ─── */

static int scen_mc_loss_data(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	ck(sc, rule_set(vc, 0, 0, "s:0:*:drop:250000:*:0") == 0, "rule set");

	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 100, 1) == 100,
	   "100 sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 100,
	                     MS(sc, 8000)) == 100,
	   "all delivered despite 25% loss");
	ck(sc, vc_quiesce(vc, MS(sc, 4000)), "quiesced");
	{
		struct mxfs_net2_session_stats st;

		get_sess(vc, 0, 1, &st);
		ck(sc, st.retx > 0, "loss produced retransmits");
		ck(sc, st.acked == 100, "all 100 acked");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_loss_ack: standalone-ACK loss heals via retx + re-ack ─── */

static int scen_mc_loss_ack(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	/* A drops the next 10 ACK frames it receives — then the stream
	 * PAUSES past RTO, so cumulative-ack self-healing cannot paper
	 * over the loss and the retransmit + re-ACK-on-dup path must
	 * carry recovery. */
	ck(sc, rule_set(vc, 0, 0, "r:1:*:drop:1000000:10:0") == 0,
	   "rule set");

	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 10, 1) == 10,
	   "burst accepted");
	mxfs_pal_sleep_ms(vc->tun.rto_initial_ms * 4);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 11, 10, 1) == 10,
	   "second burst accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 20,
	                     MS(sc, 8000)) >= 20, "all delivered");
	ck(sc, vc_quiesce(vc, MS(sc, 6000)), "quiesced despite ACK loss");
	{
		struct mxfs_net2_session_stats a, b;
		int dups = 0;

		get_sess(vc, 0, 1, &a);
		get_sess(vc, 1, 0, &b);
		ck(sc, a.retx > 0, "ACK loss forced retransmits");
		ck(sc, b.dup_seq_suppressed > 0,
		   "receiver suppressed the resulting dups");
		ck(sc, a.acked == 20, "everything eventually acked");
		ck(sc, vc_unique_from(vc, 1, 0, &dups) == 20 && dups == 0,
		   "exactly-once delivery");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_dup / mc_reorder / mc_delay: wire mangling ─── */

static int scen_mc_dup(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	ck(sc, rule_set(vc, 0, 0, "s:0:*:dup:300000:*:0") == 0, "rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 100, 1) == 100,
	   "100 sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 100,
	                     MS(sc, 6000)) >= 100, "all delivered");
	ck(sc, vc_quiesce(vc, MS(sc, 3000)), "quiesced");
	{
		struct mxfs_net2_session_stats b;
		int dups = 0;

		get_sess(vc, 1, 0, &b);
		ck(sc, b.dup_seq_suppressed > 0, "wire dups suppressed");
		ck(sc, vc_unique_from(vc, 1, 0, &dups) == 100 && dups == 0,
		   "exactly-once delivery under duplication");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

static int scen_mc_reorder(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	ck(sc, rule_set(vc, 0, 0, "s:0:*:reorder:300000:*:0") == 0,
	   "rule set (send reorder)");
	ck(sc, rule_set(vc, 1, 0, "r:0:*:reorder:200000:*:0") == 0,
	   "rule set (recv reorder)");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 100, 1) == 100,
	   "100 sends accepted");
	{
		int dups = 0;
		int got;

		vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 100,
		              MS(sc, 6000));
		got = vc_unique_from(vc, 1, 0, &dups);
		ck(sc, got == 100, "all 100 unique tags delivered");
		ck(sc, dups == 0, "no duplicate deliveries under reorder");
	}
	ck(sc, vc_quiesce(vc, MS(sc, 3000)), "quiesced");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

static int scen_mc_delay(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	char rule[64];

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	/* Hold ~3x RTO so retransmits fire and the late original arrives
	 * as a dup. */
	snprintf(rule, sizeof(rule), "s:0:*:delay:200000:*:%u",
	         vc->tun.rto_initial_ms * 3);
	ck(sc, rule_set(vc, 0, 0, rule) == 0, "rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 50, 1) == 50,
	   "50 sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 50,
	                     MS(sc, 8000)) >= 50, "all delivered");
	ck(sc, vc_quiesce(vc, MS(sc, 4000)), "quiesced");
	{
		struct mxfs_net2_session_stats a;
		int dups = 0;

		get_sess(vc, 0, 1, &a);
		ck(sc, a.retx > 0, "delay forced spurious retransmits");
		ck(sc, vc_unique_from(vc, 1, 0, &dups) == 50 && dups == 0,
		   "exactly-once delivery under delay");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_burst_loss: contiguous loss burst, cum-ack-driven recovery ─── */

static int scen_mc_burst_loss(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;
	/* Drop the first 10 DATA transmissions outright. */
	ck(sc, rule_set(vc, 0, 0, "s:0:*:drop:1000000:10:0") == 0,
	   "rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 50, 1) == 50,
	   "50 sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 50,
	                     MS(sc, 8000)) == 50,
	   "burst loss fully recovered");
	ck(sc, vc_quiesce(vc, MS(sc, 4000)), "quiesced");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_reset_framing: link resets + truncation desync ─── */

static int scen_mc_reset_framing(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	int k;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	/* Phase 1: hard link resets between bursts — the session must
	 * survive every one of them (reliability boundary = session). */
	for (k = 0; k < 5; k++) {
		ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT,
		                  1 + (uint32_t)k * 10, 10, 1) == 10,
		   "burst accepted");
		mxfs_pal_sleep_ms(MS(sc, 20));
		mxfs_net2_link_reset(vc->nodes[0].ctx, vc->nodes[1].slot);
	}
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 51, 10, 1) == 10,
	   "final burst accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 60,
	                     MS(sc, 10000)) == 60,
	   "all 60 delivered across 5 resets");
	ck(sc, vc_quiesce(vc, MS(sc, 5000)), "quiesced");
	{
		struct mxfs_net2_session_stats a;
		int dups = 0;

		get_sess(vc, 0, 1, &a);
		ck(sc, a.resets >= 1, "resets counted");
		ck(sc, a.resumes >= 1, "session resumed across reconnects");
		ck(sc, vc_unique_from(vc, 1, 0, &dups) == 60 && dups == 0,
		   "exactly-once across resets");
	}

	/* Phase 2: truncation mid-stream — the peer desyncs, resets the
	 * link, and the ring redelivers.  (§13.1 TCP failure at framing
	 * points.) */
	ck(sc, rule_set(vc, 0, 0, "s:0:*:trunc:150000:2:0") == 0,
	   "trunc rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 101, 30, 1) == 30,
	   "post-trunc burst accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 90,
	                     MS(sc, 10000)) == 90,
	   "all delivered despite truncation desyncs");
	ck(sc, vc_quiesce(vc, MS(sc, 5000)), "quiesced after trunc");
	{
		struct mxfs_net2_stats mb;

		get_mount(vc, 1, &mb);
		ck(sc, mb.malformed_frames > 0,
		   "desync detected as malformed at receiver");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── backpressure: GRANT gets -EAGAIN, RELEASE freezes, never drops ─── */

static int scen_mc_backpressure_grant(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	int i, accepted = 0, again = 0;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 8) == 0,
	       "cluster up (tx_win=8)") == 0)
		return 1;
	/* A drops ALL ACKs it receives: its window can never advance. */
	ck(sc, rule_set(vc, 0, 0, "r:1:*:drop:1000000:*:0") == 0,
	   "rule set");
	/* Give the link a moment to establish, then fill the window. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 1, 1) == 1,
	   "first send accepted");
	vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 1,
	              MS(sc, 3000));
	for (i = 1; i < 30; i++) {
		int rc = vc_send(vc, 0, 1, MXFS_MSG_LOCK_GRANT,
		                 1 + (uint32_t)i, 1, 0);

		if (rc == 0)
			accepted++;
		else if (rc == -EAGAIN)
			again++;
	}
	ck(sc, accepted == 7, "window admits exactly tx_win sends");
	ck(sc, again > 0, "overflow surfaced as -EAGAIN backpressure");
	{
		struct mxfs_net2_stats ma;

		get_mount(vc, 0, &ma);
		ck(sc, ma.cls[NET2_PRI_GRANT].queue_full > 0,
		   "GRANT queue_full counted");
	}
	/* Heal: clear the rule; retransmit + re-ack drain the window. */
	mxfs_net2_fault_reset(vc->nodes[0].ctx, vc->seed);
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 8,
	                     MS(sc, 8000)) == 8,
	   "accepted sends all delivered after heal");
	ck(sc, vc_quiesce(vc, MS(sc, 5000)), "quiesced");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

static int scen_mc_backpressure_release(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	int i, accepted = 0, nobufs = 0;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 8) == 0,
	       "cluster up (tx_win=8)") == 0)
		return 1;
	ck(sc, rule_set(vc, 0, 0, "r:1:*:drop:1000000:*:0") == 0,
	   "rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_RELEASE, 1, 1, 1) == 1,
	   "first send accepted");
	vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_RELEASE, UINT32_MAX, 1,
	              MS(sc, 3000));
	for (i = 1; i < 30; i++) {
		int rc = vc_send(vc, 0, 1, MXFS_MSG_LOCK_RELEASE,
		                 1 + (uint32_t)i, 1, 0);

		if (rc == 0)
			accepted++;
		else if (rc == -ENOBUFS)
			nobufs++;
	}
	ck(sc, accepted == 7, "window admits exactly tx_win sends");
	ck(sc, nobufs > 0,
	   "coherence overflow is caller-visible (-ENOBUFS), never silent");
	{
		struct mxfs_net2_stats ma;

		get_mount(vc, 0, &ma);
		ck(sc, ma.cls[NET2_PRI_RELEASE].queue_full > 0,
		   "RELEASE queue_full counted");
		ck(sc, ma.comm_ambiguous_events >= 1,
		   "overflow raised COMM_AMBIGUOUS");
		ck(sc, vc->nodes[0].ambiguous_hits >= 1,
		   "freeze-hook stub callback fired");
	}
	mxfs_net2_fault_reset(vc->nodes[0].ctx, vc->seed);
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_RELEASE, UINT32_MAX, 8,
	                     MS(sc, 8000)) == 8,
	   "every ACCEPTED release delivered — nothing silently lost");
	ck(sc, vc_quiesce(vc, MS(sc, 5000)), "quiesced");
	vc_assert_invariants(sc, vc, VC_INV_ALLOW_QFULL);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_restart: destination + sender restart, slot reuse, stale inc ─── */

static int scen_mc_restart(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	uint32_t old_inc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	/* batch1: delivered normally. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 20, 1) == 20,
	   "batch1 accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 20,
	                     MS(sc, 5000)) == 20, "batch1 delivered");

	/* Kill B; batch2 addresses the now-dead incarnation. */
	old_inc = vc->nodes[1].inc;
	vc_node_kill(vc, 1);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 101, 20, 1) == 20,
	   "batch2 buffered toward dead incarnation");

	/* Restart B: same slot, bumped incarnation, new nonce (§5). */
	ck(sc, vc_node_restart(vc, 1) == 0, "B restarted with slot reuse");
	/* batch3 to the NEW incarnation supersedes the old session. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 201, 20, 1) == 20,
	   "batch3 accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 20,
	                     MS(sc, 8000)) == 20,
	   "batch3 delivered to new incarnation");
	ck(sc, vc_count(vc, 1, 0, 0, 101) == 0 &&
	       vc_count(vc, 1, 0, 0, 120) == 0,
	   "no dead-incarnation message reached the new incarnation");
	{
		struct mxfs_net2_stats ma;

		get_mount(vc, 0, &ma);
		ck(sc, ma.retired.aborts >= 20,
		   "batch2 retired with explicit abort dispositions");
	}
	/* A send addressed to the STALE incarnation is refused loudly. */
	ck(sc, vc_send_inc(vc, 0, 1, old_inc, MXFS_MSG_LOCK_GRANT, 999, 1,
	                   0) == -ESTALE,
	   "stale-incarnation send returns -ESTALE");

	/* Sender restart: A bounces; B's session for A supersedes. */
	ck(sc, send_burst(vc, 1, 0, MXFS_MSG_LOCK_GRANT, 301, 10, 1) == 10,
	   "B->A pre-restart accepted");
	vc_wait_count(vc, 0, 1, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 10,
	              MS(sc, 5000));
	ck(sc, vc_node_restart(vc, 0) == 0, "A restarted");
	ck(sc, send_burst(vc, 1, 0, MXFS_MSG_LOCK_GRANT, 401, 10, 1) == 10,
	   "B->A post-restart accepted");
	ck(sc, vc_wait_count(vc, 0, 1, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 10,
	                     MS(sc, 8000)) == 10,
	   "sender-restart traffic delivered");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_epoch_change: E-1 bridge accepted, older dropped ─── */

static int scen_mc_epoch_change(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	uint64_t mask = 0x7;

	if (ck(sc, vc_create(&vc, 3, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	/* Traffic across a view transition: E frames finishing under E+1
	 * (the bridge window) must complete. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 15, 1) == 15,
	   "pre-transition batch accepted");
	vc_view_all(vc, mask, 2);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 16, 15, 1) == 15,
	   "post-transition batch accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 30,
	                     MS(sc, 6000)) == 30,
	   "all delivered across the epoch change (E-1 bridge)");
	{
		struct mxfs_net2_session_stats b;

		get_sess(vc, 1, 0, &b);
		ck(sc, b.stale_epoch_drops == 0,
		   "no bridge-eligible frame was dropped");
	}

	/* Push B two epochs ahead of A: A's frames are now older than
	 * E-1 and must be dropped + counted, never delivered. */
	vc_view_node(vc, 1, mask, 4);
	vc_view_node(vc, 2, mask, 4);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 501, 10, 1) == 10,
	   "stale-epoch batch accepted at sender");
	{
		uint64_t deadline = mxfs_pal_time_ms() +
		                    (uint64_t)MS(sc, 4000);
		struct mxfs_net2_session_stats b;

		do {
			get_sess(vc, 1, 0, &b);
			if (b.stale_epoch_drops >= 10)
				break;
			mxfs_pal_sleep_ms(10);
		} while (mxfs_pal_time_ms() < deadline);
		ck(sc, b.stale_epoch_drops >= 10,
		   "older-than-E-1 frames dropped and counted");
	}
	ck(sc, vc_count(vc, 1, 0, 0, 501) == 0,
	   "no stale-epoch mutation delivered");

	/* A catches up; fresh traffic flows. */
	vc_view_node(vc, 0, mask, 4);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 601, 10, 1) == 10,
	   "caught-up batch accepted");
	ck(sc, vc_wait_count(vc, 1, 0, 0, 601, 1, MS(sc, 6000)) == 1 &&
	       vc_wait_count(vc, 1, 0, 0, 610, 1, MS(sc, 6000)) == 1,
	   "caught-up traffic delivered");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_window_sack: window boundary, SACK healing, serial arith ─── */

static int scen_mc_window_sack(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	int rc9 = -1;

	/* Serial-number arithmetic at the wrap boundary (§7.A assert). */
	ck(sc, net2_seq_before(UINT64_MAX, 1), "wrap: MAX before 1");
	ck(sc, net2_seq_after(1, UINT64_MAX), "wrap: 1 after MAX");
	ck(sc, net2_seq_before(UINT64_MAX - 5, UINT64_MAX), "near wrap lt");
	ck(sc, !net2_seq_before(5, 5), "equal is not before");
	ck(sc, !net2_seq_after(5, 5), "equal is not after");

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 8) == 0,
	       "cluster up (tx_win=8)") == 0)
		return 1;
	/* Warm the link up first so the drop hits a flowing stream. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 900, 1, 1) == 1,
	   "warmup accepted");
	ck(sc, vc_wait_count(vc, 1, 0, 0, 900, 1, MS(sc, 3000)) == 1,
	   "warmup delivered");
	ck(sc, vc_quiesce(vc, MS(sc, 2000)), "warmup quiesced");

	/* Lose exactly the next first transmission: a hole at the window
	 * base, SACKed successors behind it. */
	ck(sc, rule_set(vc, 0, 0, "s:0:*:drop:1000000:1:0") == 0,
	   "rule set");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 8, 1) == 8,
	   "window filled");
	rc9 = vc_send(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 9, 1, 0);
	ck(sc, rc9 == -EAGAIN || rc9 == 0,
	   "9th send window-bounded or already drained");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 8,
	                     MS(sc, 6000)) >= 8, "hole healed by RTO");
	if (rc9 != 0) {
		uint64_t deadline = mxfs_pal_time_ms() +
		                    (uint64_t)MS(sc, 4000);

		do {
			rc9 = vc_send(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 9, 1,
			              0);
			if (rc9 == 0)
				break;
			mxfs_pal_sleep_ms(5);
		} while (mxfs_pal_time_ms() < deadline);
		ck(sc, rc9 == 0, "window reopened after base retired");
	}
	ck(sc, vc_wait_count(vc, 1, 0, 0, 9, 1, MS(sc, 6000)) == 1,
	   "post-window send delivered");
	ck(sc, vc_quiesce(vc, MS(sc, 4000)), "quiesced");
	{
		struct mxfs_net2_session_stats a, b;
		int dups = 0;

		get_sess(vc, 0, 1, &a);
		get_sess(vc, 1, 0, &b);
		ck(sc, a.retx >= 1 && a.retx <= 6,
		   "SACK confined recovery near the single hole");
		ck(sc, vc_unique_from(vc, 1, 0, &dups) >= 9 && dups == 0,
		   "exactly-once through the window boundary");
		(void)b;
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_malformed_cross: garbage + cross-cluster SYN rejected ─── */

static int scen_mc_malformed_cross(struct scenario_ctx *sc)
{
	struct vcluster *vc;
	mxfs_sock_t *raw;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	/* (a) pure garbage at the accept path. */
	raw = mxfs_pal_tcp_connect("127.0.0.1", vc->base_port);
	if (ck(sc, raw != NULL, "raw connect")) {
		uint8_t junk[MXFS_NET2_HDR_SIZE];
		size_t i;

		for (i = 0; i < sizeof(junk); i++)
			junk[i] = (uint8_t)(0xA5 ^ i);
		mxfs_pal_tcp_send(raw, junk, sizeof(junk));
		mxfs_pal_sleep_ms(MS(sc, 50));
		mxfs_pal_tcp_close(raw);
	}
	{
		uint64_t deadline = mxfs_pal_time_ms() +
		                    (uint64_t)MS(sc, 2000);
		struct mxfs_net2_stats ma;

		do {
			get_mount(vc, 0, &ma);
			if (ma.malformed_frames >= 1)
				break;
			mxfs_pal_sleep_ms(10);
		} while (mxfs_pal_time_ms() < deadline);
		ck(sc, ma.malformed_frames >= 1, "garbage counted malformed");
	}

	/* (b) well-formed SYN from a DIFFERENT cluster: fail-closed.
	 * Aimed at node1 (slot 1) claiming src slot 0 — satisfies
	 * lower-slot-initiates so the reject happens on IDENTITY. */
	raw = mxfs_pal_tcp_connect("127.0.0.1",
	                           (uint16_t)(vc->base_port + 1));
	if (ck(sc, raw != NULL, "raw connect 2")) {
		struct mxfs_net2_hdr h;
		uint8_t frame[MXFS_NET2_HDR_SIZE + 128];
		uint8_t tlv[128];
		uint8_t wrong_uuid[16];
		uint8_t le[8];
		int off = 0;

		memset(wrong_uuid, 0xEE, sizeof(wrong_uuid));
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_UUID, wrong_uuid, 16);
		mxfs_net2_put_le32(le, 0x564F4C31);
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_VOLUME_ID, le, 4);
		mxfs_net2_put_le32(le, 7);
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_FS_GEN, le, 4);
		mxfs_net2_put_le64(le, 0x1234);
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_NONCE, le, 8);
		mxfs_net2_put_le32(le, 0);
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_FEATURES, le, 4);
		mxfs_net2_put_le16(le, 1);
		off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
		                        MXFS_NET2_TLV_WIRE_VER, le, 2);

		memset(&h, 0, sizeof(h));
		h.magic = MXFS_NET2_MAGIC;
		h.version = MXFS_NET2_WIRE_VERSION;
		h.frame_class = MXFS_NET2_FC_SYN;
		h.priority = NET2_PRI_FENCE;
		h.payload_len = (uint16_t)off;
		h.cluster_uuid_hash = vc->uuid_hash;  /* hash collides... */
		h.membership_epoch = 1;
		h.src_slot = 0;                       /* lower than B=1 */
		h.dst_slot = vc->nodes[1].slot;
		h.src_incarnation = 77;
		mxfs_net2_hdr_pack(&h, frame);
		memcpy(frame + MXFS_NET2_HDR_SIZE, tlv, (size_t)off);
		mxfs_pal_tcp_send(raw, frame,
		                  MXFS_NET2_HDR_SIZE + (uint32_t)off);
		mxfs_pal_sleep_ms(MS(sc, 50));
		mxfs_pal_tcp_close(raw);
	}
	{
		uint64_t deadline = mxfs_pal_time_ms() +
		                    (uint64_t)MS(sc, 2000);
		struct mxfs_net2_stats mb;

		do {
			get_mount(vc, 1, &mb);
			if (mb.cross_cluster_rejects >= 1)
				break;
			mxfs_pal_sleep_ms(10);
		} while (mxfs_pal_time_ms() < deadline);
		ck(sc, mb.cross_cluster_rejects >= 1,
		   "...but the full UUID does not: SYN rejected");
	}

	/* (c) the cluster still works afterwards. */
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 10, 1) == 10,
	   "post-attack sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 10,
	                     MS(sc, 5000)) == 10,
	   "real traffic unaffected by rejects");
	ck(sc, vc_quiesce(vc, MS(sc, 3000)), "quiesced");
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── mc_ambiguity: unacked age crosses the budget -> loud signal ─── */

static int scen_mc_ambiguity(struct scenario_ctx *sc)
{
	struct vcluster *vc;

	if (ck(sc, vc_create(&vc, 2, sc->seed, COMPRESS(sc), 0) == 0,
	       "cluster up") == 0)
		return 1;

	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 1, 5, 1) == 5,
	   "warmup accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 5,
	                     MS(sc, 5000)) == 5, "warmup delivered");

	vc_node_kill(vc, 1);
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_RELEASE, 101, 5, 1) == 5,
	   "sends toward dead peer accepted (buffered, never dropped)");
	{
		uint64_t deadline = mxfs_pal_time_ms() +
		                    (uint64_t)(vc->tun.ambiguity_ms * 4 +
		                               MS(sc, 2000));
		struct mxfs_net2_stats ma;

		do {
			get_mount(vc, 0, &ma);
			if (ma.comm_ambiguous_events >= 1)
				break;
			mxfs_pal_sleep_ms(10);
		} while (mxfs_pal_time_ms() < deadline);
		ck(sc, ma.comm_ambiguous_events >= 1,
		   "COMM_AMBIGUOUS raised within budget");
		ck(sc, vc->nodes[0].ambiguous_hits >= 1,
		   "freeze-hook stub callback fired");
	}

	/* Peer returns as a NEW incarnation: the ambiguous entries are
	 * retired with abort dispositions and traffic resumes. */
	ck(sc, vc_node_restart(vc, 1) == 0, "peer restarted");
	ck(sc, send_burst(vc, 0, 1, MXFS_MSG_LOCK_GRANT, 201, 5, 1) == 5,
	   "post-restart sends accepted");
	ck(sc, vc_wait_count(vc, 1, 0, MXFS_MSG_LOCK_GRANT, UINT32_MAX, 5,
	                     MS(sc, 8000)) == 5, "post-restart delivered");
	{
		struct mxfs_net2_stats ma;

		get_mount(vc, 0, &ma);
		ck(sc, ma.retired.aborts >= 5,
		   "ambiguous entries retired with abort dispositions");
	}
	vc_assert_invariants(sc, vc, 0);
	if (sc->failed)
		vc_dump_stats(vc);
	vc_destroy(vc);
	return sc->failed ? 1 : 0;
}

/* ─── registry ─── */

const struct scenario net2_scen_midcomms[] = {
	{ "mc_basic",                scen_mc_basic,                1 },
	{ "mc_loss_data",            scen_mc_loss_data,            1 },
	{ "mc_loss_ack",             scen_mc_loss_ack,             0 },
	{ "mc_dup",                  scen_mc_dup,                  0 },
	{ "mc_reorder",              scen_mc_reorder,              0 },
	{ "mc_delay",                scen_mc_delay,                0 },
	{ "mc_burst_loss",           scen_mc_burst_loss,           0 },
	{ "mc_reset_framing",        scen_mc_reset_framing,        1 },
	{ "mc_backpressure_grant",   scen_mc_backpressure_grant,   0 },
	{ "mc_backpressure_release", scen_mc_backpressure_release, 0 },
	{ "mc_restart",              scen_mc_restart,              0 },
	{ "mc_epoch_change",         scen_mc_epoch_change,         0 },
	{ "mc_window_sack",          scen_mc_window_sack,          0 },
	{ "mc_malformed_cross",      scen_mc_malformed_cross,      0 },
	{ "mc_ambiguity",            scen_mc_ambiguity,            0 },
};
const int net2_scen_midcomms_count =
	(int)(sizeof(net2_scen_midcomms) / sizeof(net2_scen_midcomms[0]));
