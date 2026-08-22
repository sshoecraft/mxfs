/*
 * MXFS — Multinode XFS
 * Compare-and-Write (CAW) based DLM
 *
 * Replaces the TCP-based distributed lock manager with a disk-based
 * implementation using SCSI Compare-and-Write (CAW) for atomic lock
 * state transitions on the shared block device.
 *
 * All lock state lives in 512-byte slots on the shared disk. Nodes
 * acquire/release locks via atomic CAW operations — the disk is the
 * master, not any node. This eliminates all TCP peer-to-peer connections
 * for lock coordination and removes the single-point-of-failure master
 * node concept.
 *
 * Lock slots use linear probing from a hash of the resource ID.
 * Each slot stores per-mode holder bitmaps (64-bit, one bit per node)
 * and waiter bitmaps. The 6-mode DLM compatibility matrix (NL/CR/CW/
 * PR/PW/EX) is enforced identically to the TCP DLM.
 *
 * BAST notifications use two complementary paths:
 *   1. UDP multicast — a waiter sends a hint to the multicast group
 *      requesting that holders check their locks. Fast but unreliable.
 *   2. Poll thread — periodically reads held lock slots from disk and
 *      fires the BAST callback if waiters are detected. Reliable but
 *      slower (MXFS_CAW_BAST_POLL_MS interval).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "dlm.h"
#include "dlm_caw.h"
#include "dlm_shared.h"
#include "disklock.h"
#include "discovery.h"

#ifdef __KERNEL__
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
/* mxfs_pal_popcount64 moved to dlm_shared.h (step-3 lift) */

/*
 * v0.3.128 sess30 — caller-level slot-generation verify after CAS.
 * After caw_slot returns CAS-success, FUA-read the slot back and check
 * `slot.generation >= our_new->generation`.  If yes, our write persisted
 * (or peer overwrote with even higher generation, which is also fine —
 * lock state moved forward).  If no, our CAS-success was a lie (kernel
 * SCSI passthrough non-persist, sess26 P49 root cause #2 / sess30
 * Samsung 870 EVO no-FUA finding) — return -EAGAIN to the caw_lock
 * retry loop, which re-reads slot and recomputes desired state.
 *
 * Differs from PAL-level verify:
 *  - Uses generation-field semantics, not byte-level memcmp — correctly
 *    handles "our CAS persisted, peer overwrote" without false-positive.
 *  - Fires only at the caw_slot wrapper boundary, not on every CAW op
 *    submission (PAL verify-poll ran 5 reads × backoff = 0/25 PASS,
 *    sess30 measured).  caw_slot is called per LOGICAL CAS attempt,
 *    not per low-level retry.
 *
 * 0 = no verify (default until validated; same behavior as v0.3.127).
 * 1 = generation verify after every caw_slot success.
 */
static int mxfs_caw_gen_verify;
module_param_named(caw_gen_verify, mxfs_caw_gen_verify, int, 0644);
MODULE_PARM_DESC(caw_gen_verify,
                 "Caller-level CAW generation verify: 0=off (default), "
                 "1=FUA-readback + generation check after each caw_slot "
                 "success; mismatch returns -EAGAIN.");

/*
 * sess380 RULE-4 instrumentation for D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379.
 *
 * sess379 PROVED the serialization is per-LBA (direct READ(16)+FUA to the root
 * inode's slot vs a cold LBA on the same nexus: worst 40,272ms vs 39ms).  What
 * it did NOT establish is WHY that one LBA is 1,000x slower, and there are two
 * very different answers with two very different fixes:
 *
 *   (a) OFFERED LOAD.  The optimistic CAS protocol amplifies: N nodes each
 *       read+CAS the same sector, one wins, N-1 MISCOMPARE and retry with NO
 *       backoff, so total commands on that LBA go as O(N^2).  At 28 departing
 *       nodes x up to 20 release_all retries that is up to 1,120 commands on
 *       one sector in one burst.  Fix = remove/limit the retries and the work.
 *
 *   (b) SERVICE RATE.  The target genuinely takes ~seconds per command on a
 *       sector under CAW (SBC requires COMPARE AND WRITE to be atomic, so it
 *       blocks every overlapping command).  Then even O(N) commands blow the
 *       SCSI timeout and no amount of backoff helps — only not putting a
 *       cluster-shared resource on one sector does.
 *
 * These counters separate them.  Arm caw_watch_slot with the hot slot index
 * (from the P109-CLR-RELEASE-ALL `slot=` field for the resource of interest);
 * every read and every CAW this node issues against exactly that slot is then
 * counted and timed.  Summing the per-node counts over the fleet gives the
 * TOTAL offered load on that LBA, which is the number (a) and (b) disagree on.
 * Writable so a test can zero them between arms.
 *
 * Plain ints, deliberately: the increments are unserialized, so a heavily
 * multi-threaded node can lose a count.  That is acceptable for a measurement
 * whose question is "60 or 1,000", and it keeps the hot path free of an atomic.
 * Every counter is therefore a LOWER BOUND.
 */
/*
 * sess380: the P139-LOCKTOTAL whole-acquire census floor, in ms.  Default 800,
 * which is what it has always been — but see the probe site: at that floor it
 * cannot see a 32-node shared-directory create tail whose p95 is ~424ms, and
 * neither can the per-wait P138 probe, because the acquire is many sub-5ms
 * waits with outer retries between them rather than one long wait.  Lower it
 * (e.g. 50) for a census run; the `retries=` field on each line is what
 * separates claim-race churn from a genuinely long holder.
 */
/*
 * sess380 POLL-CADENCE KNOBS (D-32NODE-SHARED-DIR-CREATE-PACE).
 *
 * MEASURED, counting every SCSI command the whole cluster issued to the ONE
 * CAW slot of a shared directory while 32 nodes did 256 creates into it:
 *
 *     READ(16)+FUA      6,919   = 27.0 per create
 *     COMPARE AND WRITE   424   =  1.7 per create (50% of them MISCOMPARE)
 *     -------------------------------------------------------------------
 *     reads are 93% of ALL traffic on that sector, outnumbering writes 16:1
 *
 * Three hypotheses about that load were tested and REFUTED, each cheaply:
 *   - "the unlock CAS keeps losing to peers registering interest" — the
 *     transition classifier says 0.2% of unlock miscompares are that; 98.3%
 *     are multi-generation.
 *   - "releases wake the whole waiter field" — P382-WAKE says 0.0% take the
 *     wake-the-field branch; 75.7% mint a single successor, mean 1.25 nodes
 *     woken against 4.70 waiters present.
 *   - "the 2ms fastpoll window is the amplifier" — turning it off made reads
 *     WORSE (27.0 -> 32.9 per create), because waits lengthen and the 25ms
 *     cadence then runs longer.
 *
 * What is left is the poll cadence itself. The sleep is a TIMED WAIT ON THE
 * GRANT-NUDGE CONDVAR, so the interval is a pure backstop: a releaser's
 * targeted multicast ends the sleep immediately regardless of how long the
 * timeout is. P297-TKT measures nudge delivery directly and says 96.6% of
 * ticketed waiters wake by nudge, 3.4% by the poll backstop, and ZERO nudges
 * were swallowed. If that holds for non-ticketed waiters too, then almost
 * every one of those 27 reads per create is a backstop firing on a wait the
 * nudge was going to end anyway — pure target-queue pressure on the hottest
 * LBA in the filesystem, and pressure that also serialises against every CAW
 * there, because SBC requires COMPARE AND WRITE to be atomic.
 *
 * These knobs make that testable without a build: raise the backstop cadence
 * and see whether the reads fall while the wall does not move. Defaults are
 * the historical compile-time constants, so 0.15.8 behaves exactly as before
 * until a knob is written.
 */
int mxfs_caw_poll_max_ms = MXFS_CAW_POLL_MAX_MS;
module_param_named(caw_poll_max_ms, mxfs_caw_poll_max_ms, int, 0644);
MODULE_PARM_DESC(caw_poll_max_ms,
                 "ceiling of the exponential grant-poll backstop, in ms "
                 "(default 25). The sleep is on the nudge condvar, so this "
                 "only bounds how long a LOST nudge can cost.");

int mxfs_caw_fastpoll_window_ms = MXFS_CAW_INODE_FASTPOLL_MS;
module_param_named(caw_fastpoll_window_ms, mxfs_caw_fastpoll_window_ms, int, 0644);
MODULE_PARM_DESC(caw_fastpoll_window_ms,
                 "length of the fixed-interval fast-poll window at the start "
                 "of an inode grant wait, in ms (default 64)");

int mxfs_caw_fastpoll_interval_ms = MXFS_CAW_INODE_FASTPOLL_INTERVAL_MS;
module_param_named(caw_fastpoll_interval_ms, mxfs_caw_fastpoll_interval_ms, int, 0644);
MODULE_PARM_DESC(caw_fastpoll_interval_ms,
                 "poll interval inside the fast-poll window, in ms "
                 "(default 2)");

int mxfs_caw_locktotal_ms = 800;
module_param_named(caw_locktotal_ms, mxfs_caw_locktotal_ms, int, 0644);
MODULE_PARM_DESC(caw_locktotal_ms,
                 "P139-LOCKTOTAL whole-acquire census floor in ms; default "
                 "800. Lower it to census the create tail.");

/*
 * sess380 UNLOCK FAST-RETRY (D-32NODE-SHARED-DIR-CREATE-PACE).
 *
 * MEASURED: on a 32-node shared-directory create workload the holder's unlock
 * of the contended directory inode costs 27.9 ms mean (max 77 ms), of which
 * 10.1 ms is this loop's jittered backoff sleep and the rest is the extra slot
 * re-read + re-CAW that each losing retry issues.  Mean 1.96 MISCOMPAREs per
 * unlock.  On the acquire side, 109 of 121 retries lost the WAITER-REGISTER
 * CAS.  So the thing the holder keeps losing to is a peer REGISTERING INTEREST
 * in the very lock the holder is trying to hand over.
 *
 * A waiter setting its own bit and the holder clearing its own holder bit are
 * COMMUTING updates; they collide only because COMPARE AND WRITE compares the
 * whole 512 B image.  Losing to one is not losing a contest — the next attempt
 * starts from a strictly fresher image and recomputes everything.  Sleeping
 * 1-15 ms to "desync" against it is paying the anti-storm insurance premium on
 * a collision that is not a storm.
 *
 * The sess380 RULE-5 review approved this, NARROWED, with conditions that are
 * all implemented here:
 *   - Classify an exact recognized TRANSITION, not a field whitelist.  The
 *     classifier reconstructs byte-for-byte the only image a pure registration
 *     could have produced and memcmps it; anything else is contended.
 *   - A yield_to change is NEVER benign.  It is arbitration state, not
 *     registration metadata, and re-deciding the handoff ticket on it is a
 *     fairness hazard.  (The reconstruction covers this automatically.)
 *   - Bound the fast burst by BOTH a count and an elapsed-time cap, then fall
 *     back to the proven jittered path unchanged and reset the burst.
 *   - Release side ONLY.  The acquire side keeps its existing backoff: there
 *     are 31 waiters and one releaser, so letting them all retry immediately
 *     would trade a sleep for a synchronized retry herd.  Delayed release
 *     extends every waiter's critical path; delayed registration mostly
 *     affects that one waiter.
 *
 * DEFAULT 0 = classify and COUNT only, behaviour byte-identical to before.
 * That is deliberate: the review asked for the classification telemetry to be
 * collected before the optimisation is enabled, so P381-UNLK-CONTEND's
 * benign=/contended= fields can be read off a run with the knob OFF and the
 * A/B is a single flag.
 *
 * WHAT THIS MUST NOT REGRESS: before sess5 the unlock tight-looped on
 * MISCOMPARE with no backoff, lost 100 retries under a 16-node storm, returned
 * -EIO with the lock still HELD on disk, and the resulting endless BAST re-fire
 * spawned 1000+ blocked workers and wedged the host at load 870.  The bounded
 * burst plus the unchanged fallback is what keeps that impossible; the
 * liveness risk here is starvation of the releaser, not a lost update.
 */
int mxfs_caw_unlock_fastretry;
module_param_named(caw_unlock_fastretry, mxfs_caw_unlock_fastretry, int, 0644);
MODULE_PARM_DESC(caw_unlock_fastretry,
                 "skip the unlock-CAS backoff when the miscompare was caused "
                 "purely by a peer registering interest; 0=classify+count only "
                 "(default), 1=act on it");

int mxfs_caw_unlock_fastretry_max = 4;
module_param_named(caw_unlock_fastretry_max, mxfs_caw_unlock_fastretry_max, int, 0644);
MODULE_PARM_DESC(caw_unlock_fastretry_max,
                 "max consecutive no-sleep unlock retries before falling back "
                 "to the jittered backoff");

int mxfs_caw_unlock_fastretry_ms = 8;
module_param_named(caw_unlock_fastretry_ms, mxfs_caw_unlock_fastretry_ms, int, 0644);
MODULE_PARM_DESC(caw_unlock_fastretry_ms,
                 "elapsed-time cap in ms on a no-sleep unlock burst; derived "
                 "from the measured ~6ms CAW round trip, so a burst cannot "
                 "outlive roughly one round trip's worth of slack");

int mxfs_caw_watch_slot = -1;
module_param_named(caw_watch_slot, mxfs_caw_watch_slot, int, 0644);
MODULE_PARM_DESC(caw_watch_slot,
                 "CAW slot index to instrument for per-LBA offered load; "
                 "-1 = off (default).");

int mxfs_caw_watch_reads;
module_param_named(caw_watch_reads, mxfs_caw_watch_reads, int, 0644);
MODULE_PARM_DESC(caw_watch_reads,
                 "count of single-slot READ(16)+FUA commands this node issued "
                 "to caw_watch_slot");

int mxfs_caw_watch_read_totms;
module_param_named(caw_watch_read_totms, mxfs_caw_watch_read_totms, int, 0644);
MODULE_PARM_DESC(caw_watch_read_totms,
                 "summed wall ms of the caw_watch_slot reads");

int mxfs_caw_watch_read_maxms;
module_param_named(caw_watch_read_maxms, mxfs_caw_watch_read_maxms, int, 0644);
MODULE_PARM_DESC(caw_watch_read_maxms,
                 "worst single caw_watch_slot read, in ms");

int mxfs_caw_watch_spans;
module_param_named(caw_watch_spans, mxfs_caw_watch_spans, int, 0644);
MODULE_PARM_DESC(caw_watch_spans,
                 "count of multi-slot span reads whose window COVERED "
                 "caw_watch_slot (these also land on the hot LBA)");

int mxfs_caw_watch_caws;
module_param_named(caw_watch_caws, mxfs_caw_watch_caws, int, 0644);
MODULE_PARM_DESC(caw_watch_caws,
                 "count of COMPARE AND WRITE commands this node issued to "
                 "caw_watch_slot");

int mxfs_caw_watch_caw_totms;
module_param_named(caw_watch_caw_totms, mxfs_caw_watch_caw_totms, int, 0644);
MODULE_PARM_DESC(caw_watch_caw_totms,
                 "summed wall ms of the caw_watch_slot CAWs");

int mxfs_caw_watch_caw_maxms;
module_param_named(caw_watch_caw_maxms, mxfs_caw_watch_caw_maxms, int, 0644);
MODULE_PARM_DESC(caw_watch_caw_maxms,
                 "worst single caw_watch_slot CAW, in ms");

int mxfs_caw_watch_miscmp;
module_param_named(caw_watch_miscmp, mxfs_caw_watch_miscmp, int, 0644);
MODULE_PARM_DESC(caw_watch_miscmp,
                 "of caw_watch_caws, how many MISCOMPAREd (-EAGAIN) — the "
                 "wasted half of the optimistic-CAS amplification");

int mxfs_caw_watch_err;
module_param_named(caw_watch_err, mxfs_caw_watch_err, int, 0644);
MODULE_PARM_DESC(caw_watch_err,
                 "of the caw_watch_slot commands, how many returned an error "
                 "that was neither success nor MISCOMPARE");

/*
 * sess2(ccloop 26c41354) FAIR HANDOFF — anti-starvation for the 16-node
 * inode-EX contention.  DEFAULT 0.  When 1: on an INODE-lock release with EX
 * waiters, the releaser sets yield_to to ONE round-robin-chosen next EX waiter
 * (first waiter after the releaser's node bit, wrapping) instead of ALL
 * waiters; and in caw_wait_for_grant a fresh EX waiter that is NOT the chosen
 * one defers its self-promote until its turn.  This replaces the self-promote
 * free-for-all (every waiter races to CAS the instant the lock frees, so an
 * unlucky node's poll cadence never wins) with a bounded O(N) rotation —
 * killing the 16-node victim-node data loss (a starved writer misses the
 * coherency barrier; P131-WAITLONG / SESS50-STARVE).  Deadlock-safe: a dead
 * chosen node is skipped by the existing 5s yield_to stale-clear.  Upgraders
 * (conversion priority, sess130) are exempt; AG locks are untouched.
 */
/* sess6 (ccloop 72513a13): DEFAULT ON.  A/B at 32/cawd, fresh cluster,
 * 32-node one-shot create storm in ONE shared dir: fair=0 free-for-all
 * left 16/32 nodes' creates HUNG >90s (victim-node starvation is fatal at
 * this scale, not just slow); fair=1 completed all 32 in <=2.5s
 * (p50=942ms).  The earlier "fair=1 catastrophic" reading (p90=46s) was
 * measured on a POISONED cluster whose killed runs had leaked stale
 * waiter bits — the 5s stale-ticket clears dominated; on clean state the
 * rotation is sound. */
/*
 * sess37 (GPT-ruled design) DIRECT GRANT HANDOFF.  Fresh 32-node anatomy on
 * 0.11.313: 86.6% of 81.9s total grant wait was "grantable-but-unclaimed" —
 * readers dozing behind an EX ticket while the chosen winner is slow to
 * claim (nudge + poll + its own claim-CAW storm: miscompares mean 7.65 per
 * grant, p95 27).  Every ms of winner claim latency multiplies by N-1
 * deferring readers.  With direct handoff the RELEASE CAW itself transfers
 * ownership: when the releaser is the last holder and fair-handoff picks EX
 * waiter W, the same CAS sets W's holders_ex bit, clears W's waiter bits,
 * zeroes the ticket, and does the epoch/streak bookkeeping FOR W; W's poll
 * then ADOPTS the grant on sight (no claim CAW at all).  The ticket-guard
 * window and the winner's claim storm both collapse to zero.  Soundness
 * (ownership incarnation): adoption requires W's own registration proof
 * (waiter bit committed at generation G_reg) plus generation > G_reg plus
 * waiter bit CLEARED — a stale same-node holder bit cannot satisfy that
 * (pre-registration state routes through P-SELF-STALE-EDEADLK recovery as
 * before), and an abandoned acquire reconciles its own landed grant in
 * caw_drop_own_waiter (P6H-ABORT-RECONCILE).  0 = legacy ticket handoff.
 */
int mxfs_caw_direct_handoff = 1;
module_param_named(caw_direct_handoff, mxfs_caw_direct_handoff, int, 0644);
MODULE_PARM_DESC(caw_direct_handoff,
	"release CAW hands the lock straight to the fair-handoff EX winner "
	"(no ticket window, no winner claim CAW); 0=legacy ticket, 1=on (default)");

int mxfs_caw_fair_handoff = 1;
module_param_named(caw_fair_handoff, mxfs_caw_fair_handoff, int, 0644);
MODULE_PARM_DESC(caw_fair_handoff,
                 "round-robin inode-EX lock handoff (anti-starvation) instead "
                 "of the self-promote free-for-all; 0=off, 1=on (default)");

/*
 * ccloop c7ee71c6 sess24 — SHARED-CLASS TICKET BYPASS.
 *
 * The fair-handoff ticket (yield_to) exists for exactly one purpose, stated in
 * its own comment at the release site: stop a stream of self-promoting waiters
 * from starving an EX waiter.  But caw_wait_for_grant's acquire-side check
 * honours the ticket for ANY requested mode, and the release path sets
 * `yield_to = cur_slot->waiters` — a snapshot BATCH ticket — whenever the slot
 * has no EX waiter.  A node that becomes a waiter after that snapshot is not in
 * the ticket, so it defers... to a ticket that is protecting nobody.
 *
 * Measured cost on the live 32-node cluster (tests/caw_grant_wait_anatomy.sh,
 * 256 creates into per-node PRIVATE subdirectories of one shared parent, so the
 * only contended resource is the parent dir's inode read lock):
 *
 *     contended inode grants (>5ms)      195
 *     total cluster grant wait          86.8 s
 *     of which already-grantable (ffw)   82.7 s  = 95.3%
 *     waits with ffw>0                  194 / 195  (99%)
 *     ticket deferrals                  2633
 *     inode absorbing all of it         ONE, mode=3 (MXFS_LOCK_PR), 194 grants
 *
 * mode=PR is compatible with PR: all 32 nodes could hold it simultaneously,
 * is_compatible() said so on the FIRST poll, and they still queued behind each
 * other 30-70 deferrals deep (25ms poll ceiling ⇒ the 2.0s tail measured).
 * This is the dominant O(N) term behind D-DIR-REUSE-COHERENCY-32-FLAKY and
 * D-CRASH-CONSISTENCY-32-BUDGET: per-create p50 stays 5-12ms at every node
 * count while the MEAN grows 5.2ms → 191.8ms from 1 → 32 nodes, entirely in
 * this tail.
 *
 * So: when the ticket guards no EX waiter and our request is shared-class
 * (PR/CR) and already compatible, do not defer.  The conversion path at
 * caw_lock already draws this exact distinction (its `yt_pr_only`); this brings
 * the acquire path in line.  Anti-starvation is preserved: the bypass is
 * disabled the moment any EX waiter exists on the slot, whether the ticket
 * names it or not.
 *
 * DEFAULT 0 = OFF: MEASURED TO NEVER ENGAGE.  P203-PR-NODEFER fired 0 times
 * with reason "no-ex-waiter" across the whole 32-node census while P204-YT-DEFER
 * fired 910 times, i.e. every deferral this workload takes is to a ticket that
 * DOES guard a real EX waiter (wex=0x28440804, six of them).  The bypass is
 * provably correct -- a compatible shared-class requester with no EX waiter
 * anywhere on the slot has nothing to yield to -- but correctness is not
 * evidence of value, and this project already has one default-OFF param
 * (mxfs.dir_lookup_freshness_gate) set that way for exactly this reason:
 * measured never to engage.  Same precedent applied here rather than shipping an
 * unexercised path default-on.
 */
int mxfs_caw_pr_batch_nodefer;
module_param_named(caw_pr_batch_nodefer, mxfs_caw_pr_batch_nodefer, int, 0644);
MODULE_PARM_DESC(caw_pr_batch_nodefer,
                 "shared-class (PR/CR) requesters do not defer to a "
                 "fair-handoff ticket that guards no EX waiter; "
                 "0=off (default, measured never to engage), 1=on");

/*
 * ccloop c7ee71c6 sess24 — BOUNDED SHARED-CLASS PATIENCE.
 *
 * The nodefer bypass above was written on the hypothesis that the tickets these
 * PR waiters defer to guard no EX waiter.  P204-YT-DEFER REFUTED that: the slot
 * masks at the defer site read
 *
 *     ino=131 req_mode=3(PR) yt=4 w=fb4dffff wex=28440804 hpr=4820000 hex=0
 *
 * i.e. 28 waiters of which 6 want EX, 3 nodes hold PR, and NO node holds EX.
 * So the ticket does guard real EX waiters and the bypass correctly declines
 * (P203 fired 0 times, P204 910 times).  The bypass stays -- it is correct and
 * cheap -- but it is not the fix.
 *
 * What the same capture DOES show is the actual mechanism.  A PR requester is
 * COMPATIBLE the whole time (hex=0, and ffw_ms==elapsed_ms on 99% of waits), and
 * it defers purely on policy: strict writer preference, unbounded.  The bound
 * that was supposed to limit it is MXFS_CAW_YIELD_TIMEOUT_MS (5s) applied to
 * yt_age -- but yt_age is the wrong clock.  The release path re-arms
 * yield_set_ms whenever the ticket VALUE changes, and the ticket rotates through
 * the EX waiters, so every EX handoff resets the clock.  The capture shows it
 * plainly: age_ms=0..8 while the SAME waiter's ytd climbs to 86.  A reader can
 * therefore be deferred without limit while EX waiters keep arriving -- measured
 * as 132 grants on one inode absorbing 43.2s, mean 328ms, tail 1.47s.
 *
 * The right clock is the requester's OWN wait, which is monotonic and is exactly
 * the fairness quantity.  So: a shared-class requester defers to an EX ticket
 * only while its own wait is under this bound; past it, it admits itself.  It is
 * already compatible, so admission changes no lock semantics -- only scheduling.
 * Writer starvation stays bounded because an admitted reader completes and
 * releases; readers no longer queue behind an unbounded EX rotation.
 *
 * DEFAULT 0 = OFF, AND HERE IS WHY — the bound was MEASURED AND REFUTED as a
 * throughput fix.  It does exactly what it was designed to do to the tail, on
 * the 32-node private-subdir microbenchmark (tests/caw_pr_nodefer_ab.sh, 3
 * passes, arms alternated within one cluster state, 768 creates per arm):
 *
 *     metric              unbounded    bound 50ms     delta
 *     mean create ms          147.9         111.6    -24.5%
 *     p95  create ms         1154           437      -62.1%
 *     max  create ms         2366           565      -76.1%
 *     p50  create ms            9            13      +44.4%   <-- the catch
 *     total grant wait      197.3s        193.5s      -2.0%   <-- conserved
 *
 * The tail collapses, but the MEDIAN gets worse, and total grant wait is
 * essentially conserved: the policy redistributes the wait, it does not remove
 * it (already-grantable share stays ~95%).  On the criterion this was meant to
 * help -- dir_reuse_coherency at 32 nodes, whose score is reuse ROUNDS completed
 * inside a fixed 100s box -- the median penalty dominates:
 *
 *     caw_pr_defer_max_ms=0   ->  10 rounds, 10 rounds
 *     caw_pr_defer_max_ms=50  ->   9 rounds,  9 rounds
 *
 * A barrier-gated round workload pays for the median on every one of its many
 * operations and only occasionally meets the tail, so trading median for tail is
 * a net loss here.  Shipping it on would be a regression, so it ships OFF.
 *
 * The knob and probes stay: P203-PR-NODEFER / P204-YT-DEFER are how the ticket
 * clock bug was found at all, and a workload that is genuinely tail-sensitive
 * (rather than throughput-bound) may well want this on.  Set to ~50 to enable.
 *
 * WHAT IS STILL UNEXPLAINED, for whoever picks this up: ~95% of all grant wait
 * is spent AFTER the slot first read compatible (ffw_ms == elapsed_ms on 99% of
 * waits), and that fraction did NOT improve under either arm.  The fairness
 * policy is therefore NOT where the bulk of the wait lives.  The next suspect is
 * CAW CAS throughput on a single slot sector: admitting yourself to a shared PR
 * grant requires a successful COMPARE AND WRITE on the one 512B slot every peer
 * is also CAS-ing, and the -EAGAIN retry path in caw_wait_for_grant does not
 * count its attempts -- so instrument CAS attempts/failures per grant before
 * touching policy again.
 */
int mxfs_caw_pr_defer_max_ms;
module_param_named(caw_pr_defer_max_ms, mxfs_caw_pr_defer_max_ms, int, 0644);
MODULE_PARM_DESC(caw_pr_defer_max_ms,
                 "max ms a compatible shared-class (PR/CR) requester defers to "
                 "an EX fair-handoff ticket before admitting itself; "
                 "0=unbounded (pre-sess24 behaviour), default 50");

/*
 * ccloop c7ee71c6 sess24 — FAIR-HANDOFF EPISODE CLOCK (a real bug; RULE-5 GPT
 * consult confirmed the shape of the fix).
 *
 * yield_to carries a 5s staleness bound (MXFS_CAW_YIELD_TIMEOUT_MS) whose stated
 * job is to break an EX-starvation deadlock if the chosen waiter dies.  The
 * acquire path only defers while yt_age < that bound, so it is ALSO the only
 * limit on how long any waiter can be deferred.
 *
 * IT CAN NEVER FIRE.  The release path re-arms yield_set_ms whenever the ticket
 * VALUE changes, and the ticket deliberately rotates round-robin through the EX
 * waiters (caw_pick_next_ex_waiter), so every EX handoff resets the clock to
 * zero.  Measured directly with P204-YT-DEFER on a 32-node run: ticket
 * age_ms=0..8 while the SAME waiter's own deferral count climbed to 86.  A bound
 * that cannot be reached is not a bound.
 *
 * The clock must measure the STARVATION EPISODE, not the age of the current
 * ticket value: arm it when an episode BEGINS (no ticket outstanding in the
 * previous state) and carry it forward unchanged while the episode continues,
 * however many times the chosen waiter rotates.  Then the 5s valve genuinely
 * bounds deferral and the existing stale-clear path can do the job it was
 * written for.
 *
 * This is deliberately NOT the refuted patience patch above.  That one let aged
 * readers barge, which weakened writer handoff and cost round throughput.  This
 * changes no admission decision at all; it only stops a timestamp from being
 * falsified, so the safety valve the design already specifies can fire.
 */
int mxfs_caw_yield_episode_clock = 1;
module_param_named(caw_yield_episode_clock, mxfs_caw_yield_episode_clock, int, 0644);
MODULE_PARM_DESC(caw_yield_episode_clock,
                 "fair-handoff staleness clock measures the starvation EPISODE "
                 "instead of being reset by every ticket rotation (which made the "
                 "5s bound unreachable); 0=off (pre-sess24), 1=on (default)");

/*
 * sess2(ccloop 26c41354) UNLOCK ANTI-STORM — the CAW UNLOCK retry loop
 * (mxfs_dlm_caw_unlock) tight-loops on -EAGAIN with NO backoff, unlike the
 * acquire path (sess39 desync).  Under a 16-node hot-inode CAS storm (all
 * nodes create+unlink in ONE shared dir, e.g. dir_reuse) the unlock can never
 * win 100 tight retries -> returns -EIO -> the lock stays HELD -> BAST re-fires
 * forever -> the mxfs-ino-bast workqueue spawns 1000+ blocked workers -> load
 * 870 WEDGE (PROVEN this session).  DEFAULT 0.  When 1: on an INODE-lock unlock
 * CAS miscompare, sleep a node-phased + retry-escalating jitter (1..~15ms) to
 * desync the storm so the unlock wins; and if the retry budget is exhausted,
 * keep retrying (wall-clock bounded by MXFS_CAW_WAIT_TIMEOUT_MS) instead of
 * -EIO, because a FAILED unlock wedges the cluster and an unlock MUST complete.
 * AG locks unaffected.
 */
int mxfs_caw_unlock_backoff = 1;	/* sess5 (ccloop 72513a13): DEFAULT ON.
				 * Measured with it off: dir 8388739's holder
				 * completed its in-core release (P70-BP
				 * EXIT=full on every node) yet its slot bit
				 * stayed set — the unlock CAS lost 100 tight
				 * retries against the 8-node waiter-bit churn
				 * and gave up (-EIO swallowed), orphaning the
				 * bit; all 8 nodes' mkdirs then convoyed
				 * 300s+ on a lock NOBODY held in-core (cc
				 * NO_TERMINAL, board cascade).  An unlock
				 * MUST complete; the jittered no-EIO retry is
				 * the designed cure and AG locks are
				 * unaffected. */
module_param_named(caw_unlock_backoff, mxfs_caw_unlock_backoff, int, 0644);
MODULE_PARM_DESC(caw_unlock_backoff,
                 "jittered backoff + no-EIO retry on inode-unlock CAS "
                 "miscompare (anti CAS-storm wedge); 0=off (default), 1=on");

/*
 * v0.10.39: runtime gate for the inode-acquire fresh-handoff fast poll
 * (MXFS_CAW_INODE_FASTPOLL_MS window at 2ms).  Default ON — it removes up
 * to 25ms of exponential-backoff quantization from a BAST-driven handoff
 * (measured 45→30ms per unlink).  A/B lever: under a 31-waiter dir-EX
 * convoy the window adds ~32 slot reads per waiter per wait, suspected of
 * slowing the hot slot's CAS traffic at the target.
 */
/*
 * sess134 (GPT sess133 ruling B2): the ONE final grace after a blocking
 * teardown phase has already blown MXFS_CAW_QUIESCE_MS.  Configurable because
 * the right value depends on the storage stack; clamped on read to
 * [MIN,MAX] because the ruling forbids an infinite setting on a shared-write
 * clustered mount — "wait forever" is the failure mode this exists to remove.
 */
int mxfs_caw_failstop_grace_ms = MXFS_CAW_FAILSTOP_GRACE_MS;
module_param_named(caw_failstop_grace_ms, mxfs_caw_failstop_grace_ms, int, 0644);
MODULE_PARM_DESC(caw_failstop_grace_ms,
                 "final grace, in ms, after a teardown phase blows its quiesce "
                 "budget; on expiry this node performs a non-returning local "
                 "fail-stop rather than free a mount its threads still touch. "
                 "Clamped to [5000,300000] — it cannot be made infinite.");

int mxfs_caw_inode_fastpoll = 1;
module_param_named(caw_inode_fastpoll, mxfs_caw_inode_fastpoll, int, 0644);
MODULE_PARM_DESC(caw_inode_fastpoll,
                 "fast fixed-interval poll during the first 64ms of an "
                 "inode lock wait; 1=on (default), 0=exponential backoff "
                 "from the first sleep");

/*
 * ccloop cc87fed3 sess7/sess8: dlm_scaling@32 op-rate collapse fix -- clear a
 * freed inode's CAW slot dir_epoch/last_ex_slot so a REUSED ino doesn't
 * inherit a stale cross-node-handoff signal from its predecessor incarnation.
 * sess8: implemented as the is_free parameter to mxfs_dlm_caw_unlock_gen,
 * piggybacking the clear onto the tombstone CAS the unlock already performs
 * (zero extra I/O) -- see that function's own comment for why a separate
 * post-hoc find+read+CAS (the sess7 attempt) both silently never fired AND,
 * once fixed to actually fire, measurably regressed the test by adding a
 * synchronous extra round-trip to the free hot path.  Default ON: the write
 * is guarded to only ever touch an idle tombstone for the EXACT resource
 * being freed (never a live lock, never a probe-chain neighbor), so it
 * cannot corrupt in-flight lock state even if the hypothesis is wrong --
 * worst case is a wasted field clear inside a CAS that was happening anyway.
 * A/B lever for regression isolation if a future session needs to rule this
 * fix out as a suspect.
 */
int mxfs_caw_epoch_free_reset = 1;
module_param_named(caw_epoch_free_reset, mxfs_caw_epoch_free_reset, int, 0644);
MODULE_PARM_DESC(caw_epoch_free_reset,
                 "clear CAW slot dir_epoch/last_ex_slot at inode free so a "
                 "reused ino doesn't inherit a stale handoff signal; 1=on "
                 "(default), 0=off (pre-sess7 behavior, for A/B)");

/*
 * sess154 (D-RELEASEALL-LREQ-RETIRE-MISSING, 0.11.455): deterministic fault
 * injection for the teardown tenure-retire machinery.  The GPT ruling on the
 * P248 fix requires POSITIVE observation of every branch — an all-quiet fleet
 * run cannot distinguish "the retire worked" from "nothing ever reached it",
 * because the in-line release_all retry (fix B) may eliminate the natural
 * owed traffic that would exercise the retire (fix A).  Each knob is a
 * consumable count: writing N arms the next N hits of its site, each hit
 * decrements, 0 disarms.  TEST ONLY — all default 0 and stay 0 in production.
 */
static int mxfs_caw_inject_ra_casfail;
module_param_named(caw_inject_ra_casfail, mxfs_caw_inject_ra_casfail, int, 0644);
MODULE_PARM_DESC(caw_inject_ra_casfail,
                 "TEST ONLY: fail the next N release_all slot CAS attempts "
                 "with -ESHUTDOWN before issuing I/O (consumable; 0=off)");

static int mxfs_caw_inject_owed_enoent;
module_param_named(caw_inject_owed_enoent, mxfs_caw_inject_owed_enoent, int, 0644);
MODULE_PARM_DESC(caw_inject_owed_enoent,
                 "TEST ONLY: turn the next N successful owed-dispatch slot "
                 "resolutions into terminal -ENOENT (consumable; 0=off)");

static int mxfs_caw_inject_dow_casfail;
module_param_named(caw_inject_dow_casfail, mxfs_caw_inject_dow_casfail, int, 0644);
MODULE_PARM_DESC(caw_inject_dow_casfail,
                 "TEST ONLY: fail the next N drop_own_waiter CAS attempts "
                 "with -EIO before issuing I/O (consumable; 0=off)");

static int mxfs_caw_inject_pubfreeze_bump;
module_param_named(caw_inject_pubfreeze_bump, mxfs_caw_inject_pubfreeze_bump,
                   int, 0644);
MODULE_PARM_DESC(caw_inject_pubfreeze_bump,
                 "TEST ONLY: bump the context publication generation once the "
                 "teardown drain arms, so the phase-4 freeze snapshot no "
                 "longer matches and the retire tripwire must refuse "
                 "(consumable; 0=off)");

/*
 * sess374 (sess363 ruling, Hazards section 7): the CAW-side half of the
 * closure fault matrix.  Same consumable-count discipline as the knobs above.
 */
static int mxfs_caw_inject_closure_cas;
module_param_named(caw_inject_closure_cas, mxfs_caw_inject_closure_cas,
                   int, 0644);
MODULE_PARM_DESC(caw_inject_closure_cas,
                 "TEST ONLY: force the next N closure-strip slot CAS attempts "
                 "to miscompare (-EAGAIN) without issuing I/O, so retry "
                 "exhaustion and its partial reporting are observed "
                 "(consumable; 0=off)");

static int mxfs_caw_inject_closure_gate;
module_param_named(caw_inject_closure_gate, mxfs_caw_inject_closure_gate,
                   int, 0644);
MODULE_PARM_DESC(caw_inject_closure_gate,
                 "TEST ONLY: fail the next N per-CAS closure gate evaluations "
                 "with -ESTALE, so a mid-scan authority loss is observed at a "
                 "CAS boundary (consumable; 0=off)");

static int mxfs_caw_inject_closure_gate_skip;
module_param_named(caw_inject_closure_gate_skip,
                   mxfs_caw_inject_closure_gate_skip, int, 0644);
MODULE_PARM_DESC(caw_inject_closure_gate_skip,
                 "TEST ONLY: let the next N per-CAS closure gate evaluations "
                 "through BEFORE caw_inject_closure_gate starts failing them, "
                 "so the stop lands with successful strips already behind it "
                 "and 'completed CASes stand' is observable (consumable; "
                 "0=off)");

/*
 * sess375 (sess363 ruling Hazards section 7, tombstone/slot-reuse race).
 * These perturb TIMING ONLY — they never write a forged image.  Widening the
 * window at one of the two boundaries lets REAL concurrent code (a survivor's
 * demand scrub emptying the slot, then a fresh acquire re-binding it to a
 * different resource) land inside a strip attempt, which is the only way the
 * reuse hazard is reachable: while the victim's bits are still present nobody
 * else may tombstone the slot.
 *   where=1  between the batched candidacy HINT and the authoritative re-read
 *   where=2  between classify+gate and the destructive CAS
 */
static int mxfs_caw_inject_closure_pause_n;
module_param_named(caw_inject_closure_pause_n, mxfs_caw_inject_closure_pause_n,
                   int, 0644);
MODULE_PARM_DESC(caw_inject_closure_pause_n,
                 "TEST ONLY: pause the next N closure-strip attempts at the "
                 "boundary named by caw_inject_closure_pause_where "
                 "(consumable; 0=off)");

static int mxfs_caw_inject_closure_pause_ms = 1500;
module_param_named(caw_inject_closure_pause_ms,
                   mxfs_caw_inject_closure_pause_ms, int, 0644);
MODULE_PARM_DESC(caw_inject_closure_pause_ms,
                 "TEST ONLY: how long each caw_inject_closure_pause_n pause "
                 "lasts, in ms");

static int mxfs_caw_inject_closure_pause_slot = -1;
module_param_named(caw_inject_closure_pause_slot,
                   mxfs_caw_inject_closure_pause_slot, int, 0644);
MODULE_PARM_DESC(caw_inject_closure_pause_slot,
                 "TEST ONLY: pause ONLY at this slot index (-1 = any slot). "
                 "Needed because the pause has to sit on one CHOSEN slot for a "
                 "long time without stretching the whole scan by that much per "
                 "candidate");

/*
 * sess376: WHICH caller of caw_closure_strip_one the pause applies to.  The
 * pause countdown is a single global, and BOTH the publisher's purge scan and
 * a blocked waiter's demand scrub pass through the same site, so an unfiltered
 * injection stalls whichever thread arrives first.  That is exactly what
 * misread as "the demand scrub never fired" in sess375: the scrub fired
 * immediately and then slept inside the injected pause.
 *   0 = any caller (previous behavior), 1 = publisher purge scan only,
 *   2 = survivor demand scrub only.
 */
static int mxfs_caw_inject_closure_pause_who;
module_param_named(caw_inject_closure_pause_who,
                   mxfs_caw_inject_closure_pause_who, int, 0644);
MODULE_PARM_DESC(caw_inject_closure_pause_who,
                 "restrict the closure-strip pause to one caller: "
                 "0=any, 1=publisher purge scan, 2=demand scrub");

static int mxfs_caw_inject_closure_pause_where;
module_param_named(caw_inject_closure_pause_where,
                   mxfs_caw_inject_closure_pause_where, int, 0644);
MODULE_PARM_DESC(caw_inject_closure_pause_where,
                 "TEST ONLY: 1 = pause between the batch hint and the "
                 "authoritative re-read, 2 = pause between classify+gate and "
                 "the CAS");

static int mxfs_caw_inject_wait_expire;
module_param_named(caw_inject_wait_expire, mxfs_caw_inject_wait_expire,
                   int, 0644);
MODULE_PARM_DESC(caw_inject_wait_expire,
                 "TEST ONLY: treat the next N contended CAW acquire waits "
                 "(own waiter bit registered) as expired, forcing the "
                 "timeout give-up path (consumable; 0=off)");

static int mxfs_caw_inject_gep_wrap;
module_param_named(caw_inject_gep_wrap, mxfs_caw_inject_gep_wrap, int, 0644);
MODULE_PARM_DESC(caw_inject_gep_wrap,
                 "TEST ONLY: next N tenure-token mints treat the prior "
                 "ex_grant_epoch as ~0 (wrap), asserting the zero-skip "
                 "policy (consumable; 0=off)");

static int mxfs_caw_drain_budget_ms;
module_param_named(caw_drain_budget_ms, mxfs_caw_drain_budget_ms, int, 0644);
MODULE_PARM_DESC(caw_drain_budget_ms,
                 "override the teardown owed-drain budget in ms; "
                 "<=0 = default (MXFS_CAW_OWED_DRAIN_MS)");

/* Consume one armed injection: true and decrement while the knob is >0. */
static inline bool caw_inject_take(int *knob)
{
	if (*knob > 0) {
		(*knob)--;
		return true;
	}
	return false;
}
/*
 * sess40: gate the per-op P13-INSTR GRANT-WAIT/POLL diagnostics behind
 * mxfs.instr.  They fire on EVERY contended inode-DLM acquire (and the
 * POLL variant once per slot-state change inside the wait spin); under
 * 4-node shared-dir contention that is thousands of printk/sec on the
 * lock hot path, which made cache_coherency ~100x slower and timed out
 * the criterion (the same class of slowdown sess36 gated for the xfs
 * overlay).  Pure logging, no side effects.  mxfs_instr_enabled lives in
 * the xfs overlay (xfs_mxfs_dlm.c) and is linked into mxfs.ko alongside
 * this file; user-mode dlm builds (no overlay) compile it out.
 */
extern int mxfs_instr_enabled;
#define caw_instr_on() (unlikely(mxfs_instr_enabled))
#else
#define mxfs_caw_gen_verify 0
#define caw_instr_on() (0)
#define mxfs_caw_failstop_grace_ms MXFS_CAW_FAILSTOP_GRACE_MS
/*
 * sess154: injection is kernel-only.  The function-like macro drops its
 * argument, so the knob symbols are never referenced in user-mode builds
 * and must not be defined here.
 */
#define caw_inject_take(k) (false)
#define mxfs_caw_drain_budget_ms 0
/* sess380: the per-LBA watch is kernel-only; -1 makes caw_watch_armed()
 * constant-false so the whole instrumentation folds away in user builds. */
#define mxfs_caw_watch_slot (-1)
#define mxfs_caw_locktotal_ms 800
#define mxfs_caw_poll_max_ms MXFS_CAW_POLL_MAX_MS
#define mxfs_caw_fastpoll_window_ms MXFS_CAW_INODE_FASTPOLL_MS
#define mxfs_caw_fastpoll_interval_ms MXFS_CAW_INODE_FASTPOLL_INTERVAL_MS
#define mxfs_caw_unlock_fastretry 0
#define mxfs_caw_unlock_fastretry_max 4
#define mxfs_caw_unlock_fastretry_ms 8
#endif

/*
 * sess380 — see the caw_watch_slot block above.  Split into an "armed?" test
 * and a "note the result" sink so the hot path pays only one integer compare
 * when the watch is off (the default), and takes no clock reads at all.
 */
static inline bool caw_watch_armed(uint32_t slot_index)
{
	return unlikely(mxfs_caw_watch_slot >= 0) &&
	       (uint32_t)mxfs_caw_watch_slot == slot_index;
}

static inline bool caw_watch_span_armed(uint32_t start_idx, uint32_t nslots)
{
	return unlikely(mxfs_caw_watch_slot >= 0) &&
	       (uint32_t)mxfs_caw_watch_slot >= start_idx &&
	       (uint32_t)mxfs_caw_watch_slot < start_idx + nslots;
}

#ifdef __KERNEL__
static void caw_watch_note(bool is_caw, uint64_t ms, int rc)
{
	int msi = ms > INT_MAX ? INT_MAX : (int)ms;

	if (is_caw) {
		mxfs_caw_watch_caws++;
		mxfs_caw_watch_caw_totms += msi;
		if (msi > mxfs_caw_watch_caw_maxms)
			mxfs_caw_watch_caw_maxms = msi;
		if (rc == -EAGAIN)
			mxfs_caw_watch_miscmp++;
		else if (rc != 0)
			mxfs_caw_watch_err++;
	} else {
		mxfs_caw_watch_reads++;
		mxfs_caw_watch_read_totms += msi;
		if (msi > mxfs_caw_watch_read_maxms)
			mxfs_caw_watch_read_maxms = msi;
		if (rc != 0)
			mxfs_caw_watch_err++;
	}
}

static void caw_watch_span_note(void)
{
	mxfs_caw_watch_spans++;
}
#else
static void caw_watch_note(bool is_caw, uint64_t ms, int rc)
{
	(void)is_caw; (void)ms; (void)rc;
}

static void caw_watch_span_note(void) { }
#endif

/*
 * sess134: the clamp the ruling requires.  A grace of 0, a negative, or an
 * absurd value must not become "wait forever" — the unbounded wait is the
 * defect this deadline exists to remove, and a tunable that can reintroduce it
 * is the same defect with an extra step.
 */
static uint32_t caw_failstop_grace_ms(void)
{
	int v = mxfs_caw_failstop_grace_ms;

	if (v < MXFS_CAW_FAILSTOP_GRACE_MIN_MS)
		v = MXFS_CAW_FAILSTOP_GRACE_MIN_MS;
	if (v > MXFS_CAW_FAILSTOP_GRACE_MAX_MS)
		v = MXFS_CAW_FAILSTOP_GRACE_MAX_MS;
	return (uint32_t)v;
}

/* Compatibility matrix + FNV-1a hash + const holder readers +
 * is_compatible + recompute_granted_mode: lifted to dlm_shared.c
 * (§11 step 3) — one copy shared with dlm.c and the NET2 lock plane. */

static const char * const lock_mode_names[] = {
	"NL", "CR", "CW", "PR", "PW", "EX"
};

static inline const char *mode_name(uint8_t mode)
{
	if (mode < MXFS_LOCK_MODE_COUNT)
		return lock_mode_names[mode];
	return "??";
}

/* ─── Holder bitmap pointer by mode ─── */

static uint64_t *holders_for_mode(struct mxfs_caw_lock_slot *slot, uint8_t mode)
{
	switch (mode) {
	case MXFS_LOCK_EX: return &slot->holders_ex;
	case MXFS_LOCK_PW: return &slot->holders_pw;
	case MXFS_LOCK_PR: return &slot->holders_pr;
	case MXFS_LOCK_CW: return &slot->holders_cw;
	case MXFS_LOCK_CR: return &slot->holders_cr;
	default: return NULL; /* NL has no holders */
	}
}

/* ─── Compatibility check (self-excluding variant; the plain
 *     is_compatible lives in dlm_shared.c) ─── */

static bool compatible_excluding_self(const struct mxfs_caw_lock_slot *slot,
				       uint8_t mode, uint64_t node_bit)
{
	int m;

	for (m = MXFS_LOCK_CR; m <= MXFS_LOCK_EX; m++) {
		uint64_t others = holders_for_mode_const(slot, (uint8_t)m) &
				  ~node_bit;
		if (others != 0 && !lock_compat[m][mode])
			return false;
	}
	return true;
}

/* ─── Determine which mode a given node holds ─── */

static uint8_t node_held_mode(const struct mxfs_caw_lock_slot *slot,
			       uint64_t node_bit)
{
	if (slot->holders_ex & node_bit) return MXFS_LOCK_EX;
	if (slot->holders_pw & node_bit) return MXFS_LOCK_PW;
	if (slot->holders_pr & node_bit) return MXFS_LOCK_PR;
	if (slot->holders_cw & node_bit) return MXFS_LOCK_CW;
	if (slot->holders_cr & node_bit) return MXFS_LOCK_CR;
	return MXFS_LOCK_NL;
}

/* ─── Check if slot has any holders at all ─── */

static bool slot_has_holders(const struct mxfs_caw_lock_slot *slot)
{
	return slot->holders_ex || slot->holders_pw || slot->holders_pr ||
	       slot->holders_cw || slot->holders_cr;
}

/* ─── Consume a sticky revoke request (D-AGLOCK-...-LIVELOCK-488) ─── */

/*
 * The revoke bit is DEMAND against the resource, not against a particular
 * holder, so it may only be cleared once that demand is actually satisfiable:
 * i.e. once the reference image shows NO holders left.  Two call shapes, both
 * folded into the CAS that publishes new_slot so the clear is atomic with the
 * transition that justifies it:
 *
 *   grant:   ref = cur_slot  — "was this slot unowned when I took it?"  A
 *            fresh acquisition of an unowned slot normalizes a bit that some
 *            contender set and then went away; a compat-ADD onto a slot that
 *            still has holders leaves the demand standing, because it is not
 *            this new co-holder that the contender was blocked behind.
 *   release: ref = new_slot  — "did my clear drop the last holder?"  Called
 *            BEFORE the direct-handoff arms re-add a waiter as holder, so a
 *            handoff still consumes the bit (the demander is being granted,
 *            and any OTHER contender re-asserts within one demand cadence).
 *
 * A holder must NEVER clear the bit and keep caching: that is precisely the
 * clear-and-ignore that reinstates the livelock.
 */
static inline void caw_revoke_consume(struct mxfs_caw_lock_slot *new_slot,
				      const struct mxfs_caw_lock_slot *ref)
{
	if (new_slot->revoke && !slot_has_holders(ref))
		new_slot->revoke = 0;
}

/* ─── Recompute waiter_mode from waiter bitmap ─── */

static uint8_t recompute_waiter_mode(const struct mxfs_caw_lock_slot *slot)
{
	/*
	 * sess50 (run14d): derive waiter_mode from the waiter bitmaps so it
	 * can be DOWNGRADED when the exclusive waiter departs.  The old code
	 * preserved the existing waiter_mode whenever any waiter bit was set,
	 * so a leaked-or-departed EX waiter left waiter_mode stuck at EX while
	 * PR waiters kept `waiters` nonzero -> defer_for_waiter deferred every
	 * fresh PR reader forever (16-node posix_semantics wedge: ino=8388738
	 * frozen at waiter_mode=5 h_ex=0 with no live EX requester anywhere).
	 * waiters_ex tracks exclusive-class (EX/PW) waiters precisely; AND with
	 * `waiters` defensively ignores any stale exclusive bit whose node bit
	 * has already cleared from `waiters`.
	 */
	if (slot->waiters == 0)
		return MXFS_LOCK_NL;
	if (slot->waiters_ex & slot->waiters)
		return MXFS_LOCK_EX;
	return MXFS_LOCK_PR;
}

/*
 * sess380 — see the mxfs_caw_unlock_fastretry block comment.
 *
 * Did the ONE successful write that beat our unlock CAS consist of nothing but
 * a peer REGISTERING INTEREST?
 *
 * The test is not a field whitelist (the RULE-5 review rejected that shape:
 * a whitelist silently blesses every field the author did not think of, and
 * this slot has a dozen of them).  Instead it RECONSTRUCTS, byte for byte, the
 * only image a pure registration could have produced from `prev`, and requires
 * `now` to equal it exactly.  Anything else at all — a holder bit moving, a
 * yield_to ticket being minted or rotated, a revoke, a tombstone, a slot
 * recycled to a different resource, a field this function has never heard of —
 * fails the memcmp and is classified CONTENDED, which keeps the proven
 * jittered backoff.
 *
 * `scratch` is caller-owned so this stays off the stack; the slot is 512 B.
 */
/*
 * sess380: why a miscompare was NOT a pure registration.  MEASURED arm A
 * (classify-only, 32 nodes, create ladder): 458 of 460 miscompares were
 * CONTENDED and only 2 were benign registrations -- so the fast-retry idea is
 * refuted and the interesting question became "then what IS beating the
 * unlock?".  These codes answer it without another build cycle.
 */
#define CAW_UNLKD_BENIGN	0	/* pure foreign registration */
#define CAW_UNLKD_IDENTITY	1	/* magic/tombstone/slot recycled */
#define CAW_UNLKD_MULTIGEN	2	/* generation moved by != 1 */
#define CAW_UNLKD_SELFBITS	3	/* OUR own waiter/ticket bits moved */
#define CAW_UNLKD_REMOVED	4	/* waiter bits were CLEARED, not added */
#define CAW_UNLKD_NOREG		5	/* nobody registered — some other write */
#define CAW_UNLKD_HOLDERS	6	/* a holder bitmap changed */
#define CAW_UNLKD_YIELDTO	7	/* the fair-handoff ticket moved */
#define CAW_UNLKD_CONTROL	8	/* granted_mode/revoke/open_holders/other */
#define CAW_UNLKD_MAX		9

static int caw_unlk_delta_classify(const struct mxfs_caw_lock_slot *prev,
				   const struct mxfs_caw_lock_slot *now,
				   struct mxfs_caw_lock_slot *scratch,
				   uint64_t self_bit);

static bool caw_unlk_delta_is_registration(const struct mxfs_caw_lock_slot *prev,
					   const struct mxfs_caw_lock_slot *now,
					   struct mxfs_caw_lock_slot *scratch,
					   uint64_t self_bit)
{
	return caw_unlk_delta_classify(prev, now, scratch, self_bit) ==
	       CAW_UNLKD_BENIGN;
}

static int caw_unlk_delta_classify(const struct mxfs_caw_lock_slot *prev,
				   const struct mxfs_caw_lock_slot *now,
				   struct mxfs_caw_lock_slot *scratch,
				   uint64_t self_bit)
{
	uint64_t added_w, added_wex;

	if (!prev || !now || !scratch)
		return CAW_UNLKD_IDENTITY;
	if (now->magic != MXFS_CAW_MAGIC || prev->magic != MXFS_CAW_MAGIC)
		return CAW_UNLKD_IDENTITY;
	/*
	 * EXACTLY one generation advance.  Without this, several intervening
	 * writes whose net effect happens to look like a registration would
	 * pass — still atomically correct, but a false read of "the field is
	 * quiet", which is precisely the liveness signal this classifier is
	 * used for.
	 */
	if (memcmp(&prev->resource, &now->resource, sizeof(prev->resource)) != 0)
		return CAW_UNLKD_IDENTITY;
	if ((uint32_t)(now->generation - prev->generation) != 1)
		return CAW_UNLKD_MULTIGEN;
	/* Our own interest must not have moved; only a peer's may appear. */
	if (((prev->waiters ^ now->waiters) & self_bit) ||
	    ((prev->waiters_ex ^ now->waiters_ex) & self_bit))
		return CAW_UNLKD_SELFBITS;
	/*
	 * Report the loudest fact first: a holder bitmap or the fair-handoff
	 * ticket moving is what the fix design needs to know about, and it is
	 * more informative than "some waiter bit was cleared".
	 */
	if (prev->holders_ex != now->holders_ex ||
	    prev->holders_pw != now->holders_pw ||
	    prev->holders_pr != now->holders_pr ||
	    prev->holders_cw != now->holders_cw ||
	    prev->holders_cr != now->holders_cr)
		return CAW_UNLKD_HOLDERS;
	if (prev->yield_to != now->yield_to)
		return CAW_UNLKD_YIELDTO;
	/* Registration ADDS bits.  A removal is a cancel/purge, not this. */
	if ((prev->waiters & ~now->waiters) ||
	    (prev->waiters_ex & ~now->waiters_ex))
		return CAW_UNLKD_REMOVED;
	added_w = now->waiters & ~prev->waiters;
	added_wex = now->waiters_ex & ~prev->waiters_ex;
	if (!added_w && !added_wex)
		return CAW_UNLKD_NOREG;
	if (added_wex & ~now->waiters)
		return CAW_UNLKD_CONTROL;

	*scratch = *prev;
	scratch->waiters = now->waiters;
	scratch->waiters_ex = now->waiters_ex;
	scratch->waiter_mode = recompute_waiter_mode(scratch);
	scratch->generation = now->generation;
	scratch->last_modified_ms = now->last_modified_ms;
	if (memcmp(scratch, now, sizeof(*scratch)) != 0)
		return CAW_UNLKD_CONTROL;
	return CAW_UNLKD_BENIGN;
}

/*
 * v0.10.39: note a grant's mode class in the slot's EX streak counter —
 * inside the same CAS image, so it is exactly as atomic as the grant.
 * The fair-handoff releaser yields one turn to the whole shared class at
 * MXFS_CAW_EX_STREAK_YIELD (PR-reader anti-starvation).
 */
static void caw_grant_streak_note(struct mxfs_caw_lock_slot *slot,
				  uint8_t mode)
{
	if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW)
		slot->ex_grant_streak++;
	else
		slot->ex_grant_streak = 0;
}

/* ─── Slot I/O ─── */

static uint64_t slot_offset(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	return ctx->lock_region_offset +
	       (uint64_t)slot_index * MXFS_CAW_SLOT_SIZE;
}

/*
 * v0.3.30: detect and repair corrupted CAW slots.
 *
 * Background: on VM/LIO/iSCSI setups mkfs's zero_region pwrite-with-O_SYNC is
 * not always durable — the disklock region can retain bytes from a previous
 * filesystem.  Once a CAW slot is claim-empty'd (memset(0) + magic + resource
 * etc), the FIRST write zeros the full 512 bytes via SCSI CAW.  But sess19
 * observed the slot reverting to garbage in unused fields after some minutes
 * (mechanism unconfirmed — possibly LIO write-back-cache flush replaying
 * old content, possibly a path that writes a partially-initialized buffer).
 *
 * Symptom: holders_cw / holders_cr / waiters / granted_mode / waiter_mode /
 * yield_to fields contain ASCII text from prior disk content.  is_compatible()
 * iterates all modes including CW/CR; a non-zero holders_cw bitmap makes
 * EX-acquire wait forever ("no one is holding CW so EX should be compatible"
 * — but holders_cw=0x5028... has many bits set and is_compatible says NO).
 *
 * Detection: granted_mode and waiter_mode are u8 with valid range 0..5
 * (NL..EX).  Anything > MXFS_LOCK_EX is unambiguously corrupt.
 *
 * Repair: CAS the slot, keeping magic/gen/resource and the clean
 * holders_ex/pw/pr fields, zeroing everything else and recomputing derived
 * values.  Bound retries — if we lose the CAS, someone else modified the
 * slot, re-read.  If repair fails after retries, return the read content
 * anyway so callers can make progress (the next CAW operation may overwrite
 * the garbage).
 */
static bool slot_appears_corrupt(const struct mxfs_caw_lock_slot *s)
{
	if (s->magic != MXFS_CAW_MAGIC)
		return false; /* tombstone or empty — not "corrupt" */
	if (s->granted_mode > MXFS_LOCK_EX)
		return true;
	if (s->waiter_mode > MXFS_LOCK_EX)
		return true;
	/* v0.3.83 EX/PW single-holder popcount validity — the check (and
	 * its stale-disk-garbage history) lives in dlm_shared.c. */
	if (!caw_slot_holders_popcount_ok(s))
		return true;
	/*
	 * granted_mode must agree with the highest-occupied holder bitmap.
	 * Disagreement indicates stale fields from prior FS where granted
	 * was preserved but holder bits were re-zeroed (or vice-versa).
	 */
	if (s->granted_mode != recompute_granted_mode(s))
		return true;
	return false;
}

static int caw_repair_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
			    const struct mxfs_caw_lock_slot *corrupt,
			    struct mxfs_caw_lock_slot *repaired_out)
{
	struct mxfs_caw_lock_slot repaired;
	int rc;

	mxfs_pal_log(MXFS_LOG_WARN,
		"mxfs: P-H22-REPAIR slot=%u corrupt_hex=%llx hpw=%llx hpr=%llx "
		"hcw=%llx hcr=%llx gm=%u",
		slot_index,
		(unsigned long long)corrupt->holders_ex,
		(unsigned long long)corrupt->holders_pw,
		(unsigned long long)corrupt->holders_pr,
		(unsigned long long)corrupt->holders_cw,
		(unsigned long long)corrupt->holders_cr,
		corrupt->granted_mode);

	memset(&repaired, 0, sizeof(repaired));
	repaired.magic = corrupt->magic;
	repaired.generation = corrupt->generation + 1;
	repaired.resource = corrupt->resource;
	/* v0.6.0: a repaired slot has UNKNOWN EX history — advance the epoch
	 * (even a garbage base value works: the XFS gate adopts on CHANGE) and
	 * drop the last-EX record so every holder reloads rather than trusting
	 * a base stamped under the pre-corruption history. */
	repaired.dir_epoch = corrupt->dir_epoch + 1;
	repaired.last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
	/*
	 * v0.3.83: repair holder bitmaps when invalid.  Sess19 observed
	 * h_ex/h_pw/h_pr clean while h_cw/h_cr/etc were garbage and trusted
	 * the former.  Sess23 captured the opposite: h_ex/h_pw garbage too
	 * (e0041d00e1000413, popcount=16 — invalid for EX-exclusive).  Detect
	 * by popcount and zero garbage fields instead of preserving them.
	 */
	if (mxfs_pal_popcount64(corrupt->holders_ex) <= 1)
		repaired.holders_ex = corrupt->holders_ex;
	if (mxfs_pal_popcount64(corrupt->holders_pw) <= 1)
		repaired.holders_pw = corrupt->holders_pw;
	/* h_pr / h_cw / h_cr can have multiple legitimate bits.  Without
	 * a known cluster topology at this layer, conservatively preserve
	 * them only when h_ex was clean (suggesting fields are coherent).
	 * Otherwise zero them — let real holders re-acquire.
	 */
	if (mxfs_pal_popcount64(corrupt->holders_ex) <= 1 &&
	    mxfs_pal_popcount64(corrupt->holders_pw) <= 1) {
		repaired.holders_pr = corrupt->holders_pr;
	}
	/* sess46 (iclus open-tracking, GPT retention invariant): open_holders
	 * survives repair UNCONDITIONALLY.  It is a protection bitmap, not a
	 * lock-consistency field — no popcount constraint applies, a garbage
	 * value only DEFERS peers' reaps (fail-safe direction, converged by
	 * owner clears and fence strips), while dropping a real bit lets a
	 * peer free a file another node holds open (data loss). */
	repaired.open_holders = corrupt->open_holders;
	/* holders_cw / holders_cr / waiters / yield_to / yield_set_ms /
	 * waiter_mode / last_modified_ms — zero out (memset already did this) */
	repaired.granted_mode = recompute_granted_mode(&repaired);
	repaired.waiter_mode = MXFS_LOCK_NL;
	repaired.last_modified_ms = mxfs_pal_time_ms();

	mxfs_pal_log(MXFS_LOG_WARN,
		"mxfs: CAW slot %u corrupt — attempting repair "
		"(corrupt: gm=%u wm=%u w=%llx yt=%llx h_cw=%llx h_cr=%llx; "
		"repaired: gm=%u h_ex=%llx h_pw=%llx h_pr=%llx)",
		slot_index, corrupt->granted_mode, corrupt->waiter_mode,
		(unsigned long long)corrupt->waiters,
		(unsigned long long)corrupt->yield_to,
		(unsigned long long)corrupt->holders_cw,
		(unsigned long long)corrupt->holders_cr,
		repaired.granted_mode,
		(unsigned long long)repaired.holders_ex,
		(unsigned long long)repaired.holders_pw,
		(unsigned long long)repaired.holders_pr);

	rc = mxfs_pal_bdev_compare_and_write(ctx->dev,
					      slot_offset(ctx, slot_index),
					      corrupt, &repaired);
	if (rc == 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: CAW slot %u repaired successfully",
			slot_index);
		*repaired_out = repaired;
	}
	return rc;
}

static int read_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
		      struct mxfs_caw_lock_slot *out)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: read_slot %u I/O error %d, "
				     "retry %d/%d (backoff %u ms)",
				     slot_index, rc, attempt,
				     MXFS_CAW_IO_MAX_RETRIES, backoff);
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}

		if (caw_watch_armed(slot_index)) {
			uint64_t t0 = mxfs_pal_time_ms();

			rc = mxfs_pal_bdev_read_prio(ctx->dev,
						     slot_offset(ctx, slot_index),
						     out, MXFS_CAW_SLOT_SIZE);
			caw_watch_note(false, mxfs_pal_time_ms() - t0, rc);
			/*
			 * sess380 P383-SLOTREAD.  Reads are 93% of ALL SCSI
			 * traffic on a contended directory's slot (23-27 per
			 * create against 1.8 CAWs), and four hypotheses about
			 * where they come from have now been refuted by
			 * measurement: wake-the-field (0% of releases), the
			 * 2ms fastpoll window (removing it is WORSE), the
			 * exponential backstop (lengthening it is WORSE), and
			 * unlock-CAS retries (only 7% of traffic is CAWs at
			 * all).  Stop inferring: name the caller.  Armed only
			 * when caw_watch_slot points at this exact slot, so
			 * this costs nothing on any other resource.
			 */
			pr_warn("mxfs: P383-SLOTREAD slot=%u rc=%d caller=%pS\n",
				slot_index, rc, __builtin_return_address(0));
		} else {
			rc = mxfs_pal_bdev_read_prio(ctx->dev,
						     slot_offset(ctx, slot_index),
						     out, MXFS_CAW_SLOT_SIZE);
		}
		if (rc == 0) {
			/* v0.3.30: detect & repair corrupted slots */
			if (slot_appears_corrupt(out)) {
				int rep_rc = caw_repair_slot(ctx, slot_index,
							      out, out);
				if (rep_rc == 0)
					return 0;
				if (rep_rc == -EAGAIN) {
					/* lost CAS; re-read fresh */
					continue;
				}
				/* repair I/O error: log and return original
				 * content anyway — caller can still try */
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: CAW slot %u repair failed rc=%d",
					slot_index, rep_rc);
			}
			return 0;
		}
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: read_slot %u failed after %d retries: %d",
		     slot_index, MXFS_CAW_IO_MAX_RETRIES + 1, rc);
	return rc;
}

/*
 * ccloop 72513a13 sess3 (RULE-4 PROVEN): probe-chain walks dominated per-op
 * latency — 9.2 FUA slot reads per file CREATE (kprobe count over a 20-create
 * burst), because every open-addressing probe was its own synchronous 512B
 * SCSI READ(16)+FUA (~0.3-0.5ms each) and tombstone churn keeps chains long.
 * Read the chain in SPANS: one READ(16) of up to MXFS_CAW_PROBE_SPAN
 * contiguous slots replaces up to that many probe commands.  Same bytes, same
 * walk order; a corrupt-looking slot in the span is re-read + repaired through
 * read_slot (the existing screening path).  The claim-race protocol is
 * untouched: inserts still CAW against live content and the post-claim
 * skip_idx re-walk still runs.
 */
#define MXFS_CAW_PROBE_SPAN	16

/*
 * sess40 (D-CAW-SPAN-READ-SHORT): the multi-slot probe read is PROVEN to
 * return data that disagrees with a per-slot read of the same LBA taken
 * microseconds later — P94-SPAN-DISAGREE captured it 41-91 times per node
 * per 32-way run, ALWAYS at span_base+1 (the second slot of the window) and
 * ALWAYS with the same value 0x6fa01f04 on every node, while read_slot at
 * that same index returned a valid LIVE/TOMBSTONE slot.  A constant value
 * across 32 independent machines is not media content; the multi-sector read
 * is not filling the buffer past its first sector.
 *
 * 0.11.337 made the classify and CAS paths re-read before trusting an
 * unrecognised image, which is what stopped the cluster-cascading shutdowns.
 * But that guard only fires when the bad bytes fail to look like a valid
 * magic — bytes that happen to decode as LIVE or TOMBSTONE would be trusted
 * silently.  Until the read path itself is fixed, default to NOT using the
 * span optimisation: probes then issue per-slot reads, which is what they
 * did before the span existed and what every other slot consumer already
 * does.  Probes terminate within a few slots in the common case, so the
 * cost is small and bounded; correctness is not.
 * 1 = re-enable spanning (A/B control / post-fix validation).
 */
/*
 * MEASURED TRADE-OFF (sess40): defaulting this OFF costs dir_reuse_coherency
 * a round (7 vs >=8 bar, 115s/120s) because probes then issue per-slot reads,
 * while the 0.11.337 re-read guard already contained the observed harm — the
 * full 32-node board is green with spanning ON.  So spanning stays ON and
 * P94-SPAN-DISAGREE stays armed as a standing detector; 0 is the control arm
 * and the safe fallback if the disagreement is ever seen to slip past the
 * guard (i.e. bad bytes that decode as a valid magic).
 * NOTE: mxfs_pal_alloc uses kzalloc at this size, so the disagreeing bytes
 * are NOT uninitialised memory — they are real device content, identical on
 * all 32 nodes, which points at a wrong-location / misaligned transfer for
 * the tail of the window rather than a short read.
 */
unsigned int mxfs_caw_probe_span_enable = 1;

static int read_slot_span(struct mxfs_dlm_caw_ctx *ctx, uint32_t start_idx,
			  uint32_t nslots, struct mxfs_caw_lock_slot *buf)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc = 0;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}
		if (caw_watch_span_armed(start_idx, nslots))
			caw_watch_span_note();
		rc = mxfs_pal_bdev_read_prio(ctx->dev,
					     slot_offset(ctx, start_idx),
					     buf,
					     nslots * MXFS_CAW_SLOT_SIZE);
		if (rc == 0)
			return 0;
	}
	return rc;
}

static int caw_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
		     const struct mxfs_caw_lock_slot *compare,
		     const struct mxfs_caw_lock_slot *write)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: caw_slot %u I/O error %d, "
				     "retry %d/%d (backoff %u ms)",
				     slot_index, rc, attempt,
				     MXFS_CAW_IO_MAX_RETRIES, backoff);
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}

		if (caw_watch_armed(slot_index)) {
			uint64_t t0 = mxfs_pal_time_ms();

			rc = mxfs_pal_bdev_compare_and_write(ctx->dev,
							     slot_offset(ctx, slot_index),
							     compare, write);
			caw_watch_note(true, mxfs_pal_time_ms() - t0, rc);
		} else {
			rc = mxfs_pal_bdev_compare_and_write(ctx->dev,
							     slot_offset(ctx, slot_index),
							     compare, write);
		}
		/* Success — optionally verify slot persistence via FUA-read. */
		if (rc == 0 && mxfs_caw_gen_verify) {
			struct mxfs_caw_lock_slot verify_slot;
			int vrc = mxfs_pal_bdev_read_prio(ctx->dev,
							  slot_offset(ctx, slot_index),
							  &verify_slot,
							  sizeof(verify_slot));
			if (vrc != 0) {
				/*
				 * sess119 (sess118 ruling item 3): the CAW itself
				 * ALREADY SUCCEEDED — only the persistence check
				 * failed to read back.  Retrying the CAS here was
				 * wrong twice over: the compare image is stale
				 * (our write landed), so the retry miscompares
				 * and this function returns -EAGAIN, which every
				 * caller reads as "definitely nothing changed"
				 * for a write that definitely DID change the
				 * slot.  Return the read error instead — an
				 * AMBIGUOUS result, which is what this outcome
				 * actually is.
				 */
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P250-CAW-VERIFY-IO slot=%u vrc=%d gen=%u — CAW succeeded but the persistence read failed; reporting ambiguous",
					slot_index, vrc, write->generation);
				return vrc;
			}
			/* slot.generation >= write->generation means our write
			 * landed (or was overwritten by a later writer with even
			 * higher generation — lock state moved forward, which is
			 * fine for the caller's intent of "I made my change").
			 * Lower generation means our write didn't persist. */
			if (verify_slot.generation < write->generation) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P72-INSTR caw gen-verify mismatch "
					"slot=%u expected_gen>=%u got_gen=%u — "
					"non-persist (sess30 root cause)",
					slot_index, write->generation,
					verify_slot.generation);
				rc = -EAGAIN;
			}
		}
		/*
		 * sess135 (ccloop 14d31183) P135-SLOTWR — RULE-4 instrumentation
		 * for the P108 "on-disk slot lost" producer.  A live holder's
		 * bit vanished from the hot shared-dir inode slot within 6ms of
		 * an EX grant (test12 t=58.830→58.836), forcing a reload that
		 * tears the dir (dabuf-map HOLE family).  Every slot mutation
		 * goes through this CAS, so logging every SUCCESSFUL write for
		 * low-numbered inode resources gives the slot's complete
		 * cross-node history, totally ordered by write->generation.
		 * `stripped` = holder bits present in the compare image but
		 * absent from the written image, excluding our own bit —
		 * legitimate only in dead-node purge and slot repair; any other
		 * caller stripping a foreign holder bit is the P108 producer.
		 */
		if (rc == 0) {
			const struct mxfs_resource_id *p135_res =
				write->magic == MXFS_CAW_MAGIC ?
				&write->resource : &compare->resource;

			/* daf50d34 sess2: drop the ino<=256 gate — the mkdir-storm
			 * parents are high inos and BOTH storm forensics were blind
			 * exactly here (no claim-side write history, no foreign-strip
			 * attribution).  caw_instr_on() still gates the volume. */
			if (caw_instr_on() &&
			    p135_res->type == MXFS_LTYPE_INODE) {
				uint64_t p135_cheld =
					compare->magic == MXFS_CAW_MAGIC ?
					(compare->holders_ex |
					 compare->holders_pw |
					 compare->holders_pr) : 0;
				uint64_t p135_wheld =
					write->magic == MXFS_CAW_MAGIC ?
					(write->holders_ex |
					 write->holders_pw |
					 write->holders_pr) : 0;
				uint64_t p135_strip =
					p135_cheld & ~p135_wheld &
					~ctx->node_bit;

				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P135-SLOTWR ino=%llu slot=%u "
				    "gen=%u->%u wmagic=%x "
				    "hex=%llx->%llx hpr=%llx->%llx "
				    "w=%llx->%llx gm=%u->%u yt=%llx "
				    "self=%llx stripped=%llx caller=%pS",
				    (unsigned long long)p135_res->ino,
				    slot_index,
				    compare->generation, write->generation,
				    write->magic,
				    (unsigned long long)compare->holders_ex,
				    (unsigned long long)write->holders_ex,
				    (unsigned long long)compare->holders_pr,
				    (unsigned long long)write->holders_pr,
				    (unsigned long long)compare->waiters,
				    (unsigned long long)write->waiters,
				    compare->granted_mode,
				    write->granted_mode,
				    (unsigned long long)write->yield_to,
				    (unsigned long long)ctx->node_bit,
				    (unsigned long long)p135_strip,
				    __builtin_return_address(0));
				if (p135_strip)
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: P135-FOREIGN-STRIP ino=%llu "
					    "slot=%u stripped=%llx caller=%pS "
					    "(P108 slot-loss producer)",
					    (unsigned long long)p135_res->ino,
					    slot_index,
					    (unsigned long long)p135_strip,
					    __builtin_return_address(0));
			}
		}
		/* Success or MISCOMPARE — return immediately */
		if (rc == 0 || rc == -EAGAIN)
			return rc;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: caw_slot %u failed after %d retries: %d",
		     slot_index, MXFS_CAW_IO_MAX_RETRIES + 1, rc);
	return rc;
}

/*
 * sess119 (sess118 RULE-5 ruling item 3 — AMBIGUOUS CAW RESULT).
 *
 * Classify a caw_slot() return for the ONE question a destructive clear has to
 * answer before it closes its clear window: "could this node's bit have been
 * stripped on disk?"
 *
 * There are exactly two answers, and the default must be the pessimistic one:
 *
 *   rc == 0        the CAW completed and the write landed.  CHANGED.
 *   rc == -EAGAIN  the target compared the image and MISCOMPARED, so by the
 *                  definition of COMPARE AND WRITE no data was written.  This
 *                  is the ONLY definite no-change outcome.  (The gen-verify
 *                  arm also yields -EAGAIN, and it too establishes that our
 *                  generation is not in the slot — see caw_slot.)
 *   anything else  I/O error after retries, transport failure, -ESHUTDOWN.
 *                  The command MAY have reached the target and completed; we
 *                  simply did not collect the status.  MAY HAVE CHANGED.
 *
 * Reporting the third class as "no change" is what the ruling calls a
 * destructive change happening invisibly to validation: a concurrent
 * publication compares clr_seq across the window, sees it unmoved, and
 * publishes a grant on a holder bit that is gone from the disk.  A false
 * "changed" only costs that publication a re-read.
 */
static inline bool caw_may_have_written(int rc)
{
	return rc != -EAGAIN;
}

/* ─── Slot-index hint cache (v0.5.3, see dlm_caw.h) ─── */

static void slot_hint_store(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t slot_idx)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_SLOTHINT_SIZE;

	if (!ctx->slot_hints)
		return;
	mxfs_pal_mutex_lock(ctx->slot_hint_lock);
	ctx->slot_hints[h].resource = *resource;
	ctx->slot_hints[h].slot_idx = slot_idx;
	ctx->slot_hints[h].valid = true;
	mxfs_pal_mutex_unlock(ctx->slot_hint_lock);
}

static bool slot_hint_get(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint32_t *slot_idx_out)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_SLOTHINT_SIZE;
	bool hit = false;

	if (!ctx->slot_hints)
		return false;
	mxfs_pal_mutex_lock(ctx->slot_hint_lock);
	if (ctx->slot_hints[h].valid &&
	    memcmp(&ctx->slot_hints[h].resource, resource,
		   sizeof(*resource)) == 0) {
		*slot_idx_out = ctx->slot_hints[h].slot_idx;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->slot_hint_lock);
	return hit;
}

/* ─── v0.6.0 cross-node EX-handoff epoch (see dir_epoch in dlm_caw.h) ─── */

/*
 * sess108 (RULE-5 ruling, blocker 7): mint the next write-authority token for
 * this resource.  A DURABLE PER-RESOURCE 64-BIT SEQUENCE, carried in the slot
 * and advanced only by a CAS that grants an EX-class tenure.
 *
 * It replaces `s->generation` (sess48), which was NOT a 64-bit epoch: the slot
 * generation is a uint32 zero-extended into a uint64 field, so (a) a token
 * REPEATS after 2^32 slot CASes — and generation advances on EVERY CAS, waiter
 * registration included, so a hot resource wraps far sooner than a count of
 * tenures suggests — and (b) at the wrap it mints exactly 0, the value the
 * protocol defines as "no authority", making a live legitimate tenure report
 * none.  Nothing requires the token to equal the CAS generation; it only has to
 * uniquely name the tenure, and the C&W that publishes it serialises it.
 *
 * Zero is skipped forever: it is reserved for "this slot has never granted a
 * write tenure" and for the fail-closed reads.
 */
static uint64_t caw_next_grant_epoch(uint64_t prev)
{
	uint64_t next = prev + 1;

	return next ? next : 1;
}

/*
 * Apply the handoff-epoch policy to the slot image we are about to CAS in as
 * part of granting `mode` TO `grantee_slot`.  Returns true when the previous
 * EX-class holder was a DIFFERENT node — i.e. anything the grantee cached under
 * an earlier grant of this resource may be stale.  Call on every grant image
 * (any mode); only EX-class grants take over last_ex_slot.
 *
 * sess108: the grantee is now an EXPLICIT parameter, never `ctx->node_slot`.
 * The direct-handoff arm of the unlock CAS (sess37) grants EX to a DIFFERENT
 * node — it hand-rolled the dir_epoch/last_ex_slot bookkeeping and silently
 * omitted the mint, so every directly-handed-off tenure inherited the RELEASING
 * node's token (measured: 1502 handoffs on one node in one board lap; sess106).
 * A third-party grant path that cannot name its grantee will repeat that bug,
 * so the signature makes it impossible to express.
 *
 * sess169 (D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID, RULE-5 ruled): the token
 * mint is EDGE-TRIGGERED, not per-grant.  ex_grant_epoch names a write
 * TENURE — the maximal continuous interval of one node holding a
 * write-capable mode — so it changes exactly when such an interval STARTS:
 * when the granted mode is write-capable and the grantee held no
 * write-capable mode in `cur`, the pre-CAS compare image.  A mid-tenure mode
 * change (PW->EX upgrade, EX->PW downgrade-leg of a convert) PRESERVES the
 * token: journal records stamped earlier in the same tenure must keep
 * matching the published authority, or the foreign-replay equality gate
 * would refuse legitimately durable records.  The discriminator is the
 * grantee's holder bits in `cur` — NEVER last_ex_slot, which the tombstone
 * carry keeps pointing at this node across idle gaps (a release->reacquire
 * is a NEW tenure and must mint).
 *
 * `cur` must be the exact image handed to the CAS as its compare buffer.
 * Passing it (rather than a caller-computed prior mode) makes the edge
 * undeniable at every site — same philosophy as the explicit grantee.
 * The mint's sequence base is `s->ex_grant_epoch` (the image the site built:
 * the claim path resets it for a different-resource recycle via
 * caw_claim_inherit_epoch, and that policy must be respected); the preserve
 * arm copies from `cur` explicitly rather than trusting image inheritance.
 */
static bool caw_grant_epoch_update(struct mxfs_caw_lock_slot *s,
				   const struct mxfs_caw_lock_slot *cur,
				   uint8_t grantee_slot, uint8_t mode)
{
	bool handoff = (s->last_ex_slot != MXFS_CAW_EX_SLOT_NONE &&
			s->last_ex_slot != grantee_slot);

	if (mxfs_mode_can_write(mode)) {
		uint8_t prior = (grantee_slot < MXFS_MAX_NODES) ?
			node_held_mode(cur, 1ULL << grantee_slot) :
			MXFS_LOCK_NL;

		if (handoff)
			s->dir_epoch++;
		s->last_ex_slot = grantee_slot;
		if (!mxfs_mode_can_write(prior)) {
			uint64_t prev = s->ex_grant_epoch;

			if (caw_inject_take(&mxfs_caw_inject_gep_wrap)) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "dlm_caw: P274-GEPWRAP-INJECT rt=%u rk=%llu prev=%llu forced=~0",
					     s->resource.type,
					     (unsigned long long)(s->resource.type == MXFS_LTYPE_AG ?
						(uint64_t)s->resource.ag_number : s->resource.ino),
					     (unsigned long long)prev);
				prev = ~0ULL;
			}
			s->ex_grant_epoch = caw_next_grant_epoch(prev);
		} else if (cur->ex_grant_epoch == 0) {
			/*
			 * The grantee already holds write authority but the
			 * compare image carries NO token.  Continuity is
			 * broken (legacy peer, recycled identity, or a lost
			 * publication) and minting here would CONCEAL it —
			 * the fresh token would validate records this tenure
			 * never had authority to write.  Fail closed: keep
			 * zero (consumers already treat zero as no-proof) and
			 * say so loudly.
			 */
			s->ex_grant_epoch = 0;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "dlm_caw: P274-GEP-CONT-ZERO rt=%u rk=%llu grantee=%u prior=%u mode=%u",
				     s->resource.type,
				     (unsigned long long)(s->resource.type == MXFS_LTYPE_AG ?
					(uint64_t)s->resource.ag_number : s->resource.ino),
				     grantee_slot, prior, mode);
		} else {
			/* Mid-tenure mode change: copy the token from the
			 * compare image, deliberately not trusting whatever
			 * the site left in `s`. */
			s->ex_grant_epoch = cur->ex_grant_epoch;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: P274-GEP-PRESERVE rt=%u rk=%llu grantee=%u prior=%u mode=%u gep=%llu",
				     s->resource.type,
				     (unsigned long long)(s->resource.type == MXFS_LTYPE_AG ?
					(uint64_t)s->resource.ag_number : s->resource.ino),
				     grantee_slot, prior, mode,
				     (unsigned long long)cur->ex_grant_epoch);
		}
	}
	return handoff;
}

/*
 * sess97 step 5.3(b) — capture the provenance of one grant from the exact
 * slot image that carries it (see struct mxfs_grant_result).
 *
 * `held` is the mode THIS NODE holds in THAT image — the mode a granting CAS
 * just installed, or the mode an already-held probe observed.  Never the
 * requested mode: an acquire may request PR while already holding EX, and the
 * epoch belongs to the EX tenure, not to the request.
 *
 * A zero ex_grant_epoch is never valid.  Since sess108 the tombstone/claim path
 * CARRIES the sequence, so a same-resource idle gap no longer restarts the
 * namespace and every EX/PW grant mints — which leaves exactly three ways to
 * observe zero here, all of them fail-closed cases and none of them benign:
 * a legacy slot granted by a pre-sess108 node (mixed version), a slot whose
 * resource identity was recycled through a DIFFERENT resource, or a genuine
 * publication gap.  Fail closed: no epoch, no proof.
 */
static void caw_grant_result_fill(struct mxfs_grant_result *gres,
				  const struct mxfs_resource_id *resource,
				  const struct mxfs_caw_lock_slot *s,
				  uint8_t held, bool reaffirm)
{
	if (!gres)
		return;

	gres->resource = (resource->type == MXFS_LTYPE_AG) ?
			 (uint64_t)resource->ag_number : resource->ino;
	gres->generation = s->generation;
	gres->kind = resource->type;
	gres->mode = held;
	gres->reaffirm = reaffirm ? 1 : 0;
	/* sess176: binding identity from the SAME image as the epoch.  Copied
	 * unconditionally — it describes the binding, not the tenure; the
	 * status classification below governs whether the pair proves write
	 * authority. */
	gres->resource_lineage = s->resource_lineage;

	/*
	 * sess105: classify HERE, where `held` and `ex_grant_epoch` come from
	 * ONE coherent slot image.  A single `valid=0` downstream cannot
	 * distinguish "we held a read grant" (benign) from "we held a writing
	 * grant with no epoch" (a real publication/restart gap) — and the
	 * sess104 measurement drowned in exactly that conflation.
	 */
	if (!mxfs_mode_can_write(held)) {
		gres->grant_epoch = 0;
		gres->status = MXFS_GAUTH_NONWRITE_MODE;
	} else if (s->ex_grant_epoch == 0) {
		gres->grant_epoch = 0;
		gres->status = MXFS_GAUTH_WRITE_ZERO_EPOCH;
	} else {
		gres->grant_epoch = s->ex_grant_epoch;
		gres->status = MXFS_GAUTH_WRITE_EPOCH;
	}
}

/*
 * Turn a fully-released slot image into a tombstone IN PLACE.  Keeps
 * generation (CAS lineage) — and, v0.6.0, the resource identity plus the
 * EX-handoff epoch fields: a tombstone is the only carrier of dir_epoch
 * across an idle gap (all holders released, then the resource is claimed
 * again later).  Zeroing them made the first cross-node grant after every
 * idle gap look handoff-free (epoch restarts at 0, last_ex_slot=NONE), so
 * the adopt gate never fired and stale cached dirs survived.  The claim
 * path inherits these fields when it recycles a tombstone whose resource
 * matches; a different resource ignores them (fresh init).
 *
 * sess108: ex_grant_epoch joins that carry set, and it is REQUIRED, not an
 * optimisation.  The write-authority token is now a per-resource +1 sequence
 * (caw_next_grant_epoch); a tombstone that zeroed it would RESTART the sequence
 * at 1 on the next same-resource claim, so a durable image stamped with epoch 1
 * from before the idle gap would false-match the first tenure after it — the
 * exact confusion the "zero epoch is never valid" rule exists to prevent.  With
 * the carry the namespace only ever advances, and zero recurs never.
 */
static void caw_tombstone_slot(struct mxfs_caw_lock_slot *s)
{
	uint32_t saved_gen = s->generation;
	struct mxfs_resource_id saved_res = s->resource;
	uint32_t saved_epoch = s->dir_epoch;
	uint8_t saved_lex = s->last_ex_slot;
	uint64_t saved_open = s->open_holders;
	uint64_t saved_gep = s->ex_grant_epoch;
	uint64_t saved_lineage = s->resource_lineage;

	memset(s, 0, sizeof(*s));
	s->magic = MXFS_CAW_TOMBSTONE_MAGIC;
	s->generation = saved_gen;
	s->resource = saved_res;
	s->dir_epoch = saved_epoch;
	s->last_ex_slot = saved_lex;
	s->ex_grant_epoch = saved_gep;
	/* sess176: the lineage identifies the BINDING, and a tombstone is the
	 * binding surviving an idle gap — carry it with the resource identity
	 * (sess175 ruling: preserve in tombstone + frozen manifest). */
	s->resource_lineage = saved_lineage;
	/* sess40: open-unlinked protection must survive grant-idle gaps —
	 * the tombstone carries open_holders with the resource identity. */
	s->open_holders = saved_open;
	s->last_modified_ms = mxfs_pal_time_ms();
}

/*
 * Claim-path counterpart: `fresh` is the memset-zero image being built for
 * a claim of `resource` at an insertion point whose CURRENT on-disk content
 * is `prev` (tombstone, ghost, or truly empty — whatever the CAS compare
 * buffer read).  Inherit the epoch lineage when the insertion point is a
 * tombstone of the SAME resource.
 */
static void caw_claim_inherit_epoch(struct mxfs_caw_lock_slot *fresh,
				    const struct mxfs_caw_lock_slot *prev,
				    const struct mxfs_resource_id *resource)
{
	if (prev->magic == MXFS_CAW_TOMBSTONE_MAGIC &&
	    memcmp(&prev->resource, resource, sizeof(*resource)) == 0) {
		fresh->dir_epoch = prev->dir_epoch;
		fresh->last_ex_slot = prev->last_ex_slot;
		/* sess108: carry the write-authority sequence too, so a
		 * same-resource re-claim CONTINUES the namespace instead of
		 * restarting it at 1 (see caw_tombstone_slot). */
		fresh->ex_grant_epoch = prev->ex_grant_epoch;
		/* sess176: same-resource recycle CONTINUES the binding, so the
		 * lineage rides with it.  A zero here (legacy tombstone from a
		 * pre-lineage build) is left zero — the claim site upgrades it
		 * with a fresh mint, which cannot invalidate anything: records
		 * stamped under a zero-lineage tenure are lineage-less and
		 * already outside the enforceable set. */
		fresh->resource_lineage = prev->resource_lineage;
		/* sess46: complete the sess40 tombstone-carry contract — the
		 * tombstone preserves open_holders but this inherit never
		 * restored them, so a same-resource re-claim silently dropped
		 * idle-gap open bits.  Unreachable-with-bits today (every
		 * tombstone site gates on open_holders==0) but load-bearing
		 * once bit-only records exist (iclus open publication). */
		fresh->open_holders = prev->open_holders;
	}
}

/*
 * sess176 (lineage discriminator, sess175 RULE-5 ruling): mint the random
 * nonzero 64-bit lineage id for a FRESH resource binding.  Same fail-closed
 * draw discipline as disklock.c's hb_draw_incarnation:
 * mxfs_pal_get_random_bytes returns void and cannot report failure — its
 * only failure mode is the user-space backend zero-filling the buffer, so a
 * bounded draw-until-nonzero loop IS the detector (16 all-zero draws from a
 * working RNG has probability 2^-1024).  NEVER fall back to a clock,
 * node id, or generation: weak entropy collides exactly where the
 * discriminator must not (VM snapshot restore, rapid reboot, recycled
 * slots).  Returns 0 on failure; the caller MUST FAIL THE CLAIM (ruling:
 * no lineage, no fresh binding).
 */
#define MXFS_CAW_LINEAGE_DRAWS 16

static uint64_t caw_mint_lineage(void)
{
	uint64_t l = 0;
	int i;

	for (i = 0; i < MXFS_CAW_LINEAGE_DRAWS; i++) {
		mxfs_pal_get_random_bytes(&l, sizeof(l));
		if (l != 0)
			return l;
	}
	return 0;
}

/* Record the grant-time epoch/handoff observation for `resource`. */
static void caw_grant_meta_store(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint32_t dir_epoch, bool handoff,
				 uint64_t dir_block0_fsb, uint32_t dir_block0_gen)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;

	if (!ctx->grant_meta)
		return;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	/* v0.6.2: `releasing` belongs to the unlock that set it — preserve it
	 * across a same-resource store; a collision overwrite drops the old
	 * resource's mark (the unlock's clear no-ops on mismatch; the abort
	 * check below still fires via grant_seq). */
	if (!(ctx->grant_meta[h].valid &&
	      memcmp(&ctx->grant_meta[h].resource, resource,
		     sizeof(*resource)) == 0))
		ctx->grant_meta[h].releasing = false;
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].dir_epoch = dir_epoch;
	ctx->grant_meta[h].handoff = handoff;
	ctx->grant_meta[h].dir_block0_fsb = dir_block0_fsb;
	ctx->grant_meta[h].dir_block0_gen = dir_block0_gen;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

/*
 * sess37 direct-handoff adopt support: report the dir_epoch this node
 * recorded at its LAST grant of `resource` (any mode).  The adopter compares
 * it against the slot's current dir_epoch to decide whether a foreign
 * EX-class tenure intervened since our last coherent load — the exact
 * question dir_epoch exists to answer.  Returns false when no valid meta is
 * cached (first contact => adopter must assume handoff=true, the safe side).
 */
static bool caw_grant_meta_get_epoch(struct mxfs_dlm_caw_ctx *ctx,
				     const struct mxfs_resource_id *resource,
				     uint32_t *epoch_out)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	bool valid = false;

	if (!ctx->grant_meta)
		return false;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0) {
		*epoch_out = ctx->grant_meta[h].dir_epoch;
		valid = true;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return valid;
}

/*
 * v0.6.3 — atomic form of the already-held shortcut's gate + meta store.
 * The v0.6.2 two-section sequence (caw_release_active check, then a separate
 * caw_grant_meta_store) left a window: the shortcut checks `releasing`
 * (false — the unlock hasn't marked yet), the unlock then marks + snapshots
 * grant_seq and passes its retry-0 check, the shortcut's store lands, and the
 * unlock's CAS clears the very bit the shortcut just vouched for.  Because
 * the shortcut grant is MEMORY-ONLY (no slot write), nothing perturbs the
 * unlock's CAS compare buffer — the clear commits and the phantom is born
 * (4/caw run 20260705T205922Z: 68× P106-STALE-EX, 0 anchor fires).  Done in
 * ONE grant_meta_lock section, the store either lands BEFORE the unlock's
 * mark+snapshot (so its entry/loop seq checks abort) or observes `releasing`
 * and refuses (caller waits the release out and re-probes).  Returns true
 * when the grant was recorded, false when a release is in flight.
 */
/* v0.6.3 phantom-genesis instrumentation: the DIVERG guards clear OUR OWN
 * holder bit outside the bast pipeline — a silent phantom-EX genesis when the
 * caller's in-core mode stays cached.  Capped always-on for INODE resources
 * (divergence is an anomaly; a flood is itself diagnostic). */
static int caw_diverg_logged;

static bool caw_grant_meta_store_unless_releasing(struct mxfs_dlm_caw_ctx *ctx,
					const struct mxfs_resource_id *resource,
					uint32_t dir_epoch, bool handoff,
					uint64_t dir_block0_fsb, uint32_t dir_block0_gen)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	bool ours;

	if (!ctx->grant_meta)
		return true;	/* no table — degrade to unconditional store semantics */
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	ours = ctx->grant_meta[h].valid &&
	       memcmp(&ctx->grant_meta[h].resource, resource,
		      sizeof(*resource)) == 0;
	if (ours && ctx->grant_meta[h].releasing) {
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		return false;
	}
	/*
	 * sess4 (ccloop 46efd8b6): NEVER claim a bucket out from under a
	 * FOREIGN resource's in-flight release.  grant_meta is a no-chain
	 * hash table; the old claim path wiped the collided entry INCLUDING
	 * its `releasing` mark and its grant_seq — evaporating both v0.6.2
	 * unlock protections mid-CAS (run 065143Z: 339 anchor-less releases
	 * on one 32-node run).  Report busy instead; the caller's existing
	 * false-handling (P-SHORTCUT-RELWAIT 1ms re-probe) waits the
	 * colliding release out.
	 */
	if (!ours && ctx->grant_meta[h].valid &&
	    ctx->grant_meta[h].releasing) {
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		return false;
	}
	if (!ours)
		ctx->grant_meta[h].releasing = false;
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].dir_epoch = dir_epoch;
	ctx->grant_meta[h].handoff = handoff;
	ctx->grant_meta[h].dir_block0_fsb = dir_block0_fsb;
	ctx->grant_meta[h].dir_block0_gen = dir_block0_gen;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return true;
}

/*
 * v0.6.4 — pre-CAS grant intent.  The v0.6.2/3 unlock abort keys off
 * grant_seq, but every slow-path grant bumped it only AFTER the slot CAS —
 * and between them sit caw_check_exclusion + caw_verify_grant_persisted, a
 * full SCSI read: the fresh bit is live on disk for MILLISECONDS with
 * grant_seq un-bumped.  An unlock whose find_slot read lands in that window
 * sees the bit, passes its entry/in-loop/last-instant seq checks (nothing
 * advanced yet), and CAS-clears the brand-new tenure — no regrant-abort,
 * phantom cached EX born (proven: 4/caw iter-12 test2 ino=133 P106-EXGRANT
 * expop=1 @.538467 → P106-STALE-EX held=0 @.539723, abort count 0, no
 * DIVERG/DUP-SLOT).  Bumping IMMEDIATELY BEFORE every bit-adding CAS attempt
 * restores the implication "unlock read our fresh bit ⇒ unlock's next seq
 * check sees a bump" — the abort fires.  A bump for an attempt that then
 * -EAGAINs is harmless: seq aborts err toward LEAVING the bit set, and the
 * stranded-release path (BAST re-arm) self-heals that direction.  Preserves
 * epoch fields; claims the entry only when foreign/invalid.
 */
static void caw_grant_seq_prebump(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	int spin;

	if (!ctx->grant_meta)
		return;
	/*
	 * sess4 (ccloop 46efd8b6): a colliding FOREIGN resource mid-release
	 * owns this bucket; claiming it would wipe its `releasing` mark and
	 * grant_seq — the v0.6.2 protections — mid-CAS.  Wait it out
	 * (bounded; a release CAS is ms-scale) before claiming.  On timeout
	 * fall through to the old lossy claim — bounded degradation beats a
	 * wedge.
	 */
	for (spin = 0; spin < 500; spin++) {
		bool foreign_rel;

		mxfs_pal_mutex_lock(ctx->grant_meta_lock);
		foreign_rel = ctx->grant_meta[h].valid &&
			      ctx->grant_meta[h].releasing &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) != 0;
		if (!foreign_rel) {
			if (!(ctx->grant_meta[h].valid &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) == 0)) {
				memset(&ctx->grant_meta[h], 0,
				       sizeof(ctx->grant_meta[h]));
				ctx->grant_meta[h].resource = *resource;
				ctx->grant_meta[h].valid = true;
			}
			ctx->grant_meta[h].grant_seq =
				++ctx->grant_seq_counter;
			mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
			return;
		}
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		mxfs_pal_sleep_ms(1);
	}
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	memset(&ctx->grant_meta[h], 0, sizeof(ctx->grant_meta[h]));
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

/*
 * v0.6.2 — closure of the unlock-vs-regrant race behind P106-STALE-EX
 * (phantom cached EX → two nodes concurrently RMW one dir block → durable
 * dirent loss; genesis proven: P106-EXREL retry at :264909 vs P106-EXGRANT
 * at :265003, the release CAS then cleared the fresh re-grant).  Two local
 * serialization primitives on the existing grant-meta table:
 *
 *  - `releasing`: set for the lifetime of our unlock's CAS loop.  The
 *    acquire path's ALREADY-HELD shortcut must not trust our on-disk bit
 *    while our own unlock is concurrently clearing it (the bit's presence
 *    is a torn read of a release in flight) — it waits the release out
 *    (bounded) and retries the probe.
 *  - `grant_seq`: bumped by every grant-meta store.  The unlock loop
 *    snapshots it at entry and ABORTS (leaving the slot alone) when it
 *    advances — a local acquire re-granted this resource, so the bit now
 *    belongs to the NEW tenure.  The in-core release that follows in the
 *    caller is then an inverse-phantom (in-core NL, disk held), which the
 *    P135-ORPHAN-RELEASE machinery already self-heals on the next BAST.
 */
static uint64_t caw_grant_meta_seq(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	uint64_t seq = 0;

	if (!ctx->grant_meta)
		return 0;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0)
		seq = ctx->grant_meta[h].grant_seq;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return seq;
}

static void caw_release_mark(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource, bool on)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	int spin;

	if (!ctx->grant_meta)
		return;
	/* sess4 (ccloop 46efd8b6): as in caw_grant_seq_prebump — never claim
	 * a bucket from a colliding FOREIGN resource mid-release (wiping its
	 * releasing mark + grant_seq kills the v0.6.2 protections).  Two
	 * concurrent unlocks colliding on one bucket serialize here. */
	for (spin = 0; on && spin < 500; spin++) {
		bool foreign_rel;

		mxfs_pal_mutex_lock(ctx->grant_meta_lock);
		foreign_rel = ctx->grant_meta[h].valid &&
			      ctx->grant_meta[h].releasing &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) != 0;
		if (!foreign_rel)
			goto locked_apply;
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		mxfs_pal_sleep_ms(1);
	}
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
locked_apply:
	if (on) {
		/* claim the entry if it isn't ours (invalid or collision —
		 * the epoch fields of a colliding victim are lossy by design) */
		if (!(ctx->grant_meta[h].valid &&
		      memcmp(&ctx->grant_meta[h].resource, resource,
			     sizeof(*resource)) == 0)) {
			memset(&ctx->grant_meta[h], 0,
			       sizeof(ctx->grant_meta[h]));
			ctx->grant_meta[h].resource = *resource;
			ctx->grant_meta[h].valid = true;
		}
		ctx->grant_meta[h].releasing = true;
	} else if (ctx->grant_meta[h].valid &&
		   memcmp(&ctx->grant_meta[h].resource, resource,
			  sizeof(*resource)) == 0) {
		ctx->grant_meta[h].releasing = false;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

static bool caw_grant_meta_get(struct mxfs_dlm_caw_ctx *ctx,
			       const struct mxfs_resource_id *resource,
			       uint32_t *epoch_out, bool *handoff_out)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	bool hit = false;

	if (!ctx->grant_meta)
		return false;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0) {
		if (epoch_out)
			*epoch_out = ctx->grant_meta[h].dir_epoch;
		if (handoff_out)
			*handoff_out = ctx->grant_meta[h].handoff;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return hit;
}

uint32_t mxfs_dlm_caw_grant_dir_epoch(struct mxfs_dlm_caw_ctx *ctx,
				      const struct mxfs_resource_id *resource)
{
	uint32_t epoch = 0;

	if (!ctx || !resource)
		return 0;
	caw_grant_meta_get(ctx, resource, &epoch, NULL);
	return epoch;
}

/* ccloop(3e02e7dd) sess3: canonical dir block0 query — see the
 * dir_block0_fsb comment in struct mxfs_caw_lock_slot. */
bool mxfs_dlm_caw_grant_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   uint32_t want_gen, uint64_t *fsb_out)
{
	uint32_t h;
	bool hit = false;

	if (fsb_out)
		*fsb_out = 0;
	if (!ctx || !resource || !ctx->grant_meta)
		return false;
	h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0 &&
	    ctx->grant_meta[h].dir_block0_gen == want_gen &&
	    ctx->grant_meta[h].dir_block0_fsb != 0) {
		if (fsb_out)
			*fsb_out = ctx->grant_meta[h].dir_block0_fsb;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return hit;
}

bool mxfs_dlm_caw_grant_handoff(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				uint32_t *gen_out)
{
	uint32_t epoch = 0;
	bool handoff = false;

	if (gen_out)
		*gen_out = 0;
	if (!ctx || !resource)
		return false;
	if (!caw_grant_meta_get(ctx, resource, &epoch, &handoff))
		return false;
	if (gen_out)
		*gen_out = epoch;
	return handoff;
}

uint32_t mxfs_dlm_caw_grant_seq32(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	uint64_t seq;

	if (!ctx || !resource)
		return 0;
	seq = caw_grant_meta_seq(ctx, resource);
	if (!seq)
		return 0;
	/* fold to the caller's u32 token; never collapse a live tenure to
	 * the "no tenure" sentinel 0 */
	return (uint32_t)seq ?: 1;
}

/*
 * interactive session 2026-07-13: backed by ctx->orphan_clock, NOT
 * grant_meta — a dedicated table with its own mxfs_pal_spinlock_t (never
 * sleeps), because callers (mxfs_dlm_bast_process via
 * mxfs_v5_dlm_inode_orphan_clock_get/set) run with the caller's own
 * xfs_inode spinlock held.  Sharing grant_meta's mutex would risk
 * scheduling-while-atomic.  Collision handling is a simple claim-on-mismatch
 * (unlike grant_meta's wait-out-foreign-release dance) since these are
 * timing hints, not CAS-protected coherency state — the worst case of a
 * lost sample is one extra ~3s cycle before a force-timeout re-arms, not a
 * correctness bug.
 */
uint64_t mxfs_dlm_caw_orphan_clock_get(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       bool starve)
{
	uint32_t h;
	uint64_t val = 0;

	if (!ctx || !resource || !ctx->orphan_clock)
		return 0;
	h = resource_hash_raw(resource) % MXFS_CAW_ORPHANCLOCK_SIZE;
	mxfs_pal_spinlock_lock(ctx->orphan_clock_lock);
	if (ctx->orphan_clock[h].valid &&
	    memcmp(&ctx->orphan_clock[h].resource, resource,
		   sizeof(*resource)) == 0)
		val = starve ? ctx->orphan_clock[h].bast_starve_since_ns
			     : ctx->orphan_clock[h].orphan_since_ns;
	mxfs_pal_spinlock_unlock(ctx->orphan_clock_lock);
	return val;
}

void mxfs_dlm_caw_orphan_clock_set(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   bool starve, uint64_t val)
{
	uint32_t h;

	if (!ctx || !resource || !ctx->orphan_clock)
		return;
	h = resource_hash_raw(resource) % MXFS_CAW_ORPHANCLOCK_SIZE;
	mxfs_pal_spinlock_lock(ctx->orphan_clock_lock);
	if (!(ctx->orphan_clock[h].valid &&
	      memcmp(&ctx->orphan_clock[h].resource, resource,
		     sizeof(*resource)) == 0)) {
		/* claim the bucket (invalid, or a foreign resource — rare
		 * per MXFS_CAW_ORPHANCLOCK_SIZE's sizing, harmless either
		 * way: the evicted resource's clock just restarts) */
		memset(&ctx->orphan_clock[h], 0,
		       sizeof(ctx->orphan_clock[h]));
		ctx->orphan_clock[h].resource = *resource;
		ctx->orphan_clock[h].valid = true;
	}
	if (starve)
		ctx->orphan_clock[h].bast_starve_since_ns = val;
	else
		ctx->orphan_clock[h].orphan_since_ns = val;
	mxfs_pal_spinlock_unlock(ctx->orphan_clock_lock);
}

/* ─── sess112: LOCAL REQUEST REGISTRY (per node, per resource) ─── */

/*
 * See the long comment on ctx->lreq in dlm_caw.h for WHY this exists.  In one
 * line: the slot encodes this node as a single bit, but several local threads
 * can legitimately be behind that bit at once, so the give-up reconcile needs
 * an in-core statement of "what else on this node is relying on these bits"
 * before it is allowed to clear any of them.
 *
 * The entry carries three independent counts, and each answers a different
 * clearing question:
 *
 *   attempts  — live local acquire/convert attempts.  While >1, no reconcile
 *               may clear `waiters`: some other local thread registered it and
 *               is still waiting to be granted through it.
 *   writers   — the write-capable subset of `attempts`.  `waiters_ex` may be
 *               cleared as soon as the last write-capable attempt leaves EVEN
 *               IF readers remain; that DOWNGRADE is the point, because an
 *               over-high waiter_mode is exactly the measured 16-node
 *               reader-starvation wedge (peers' defer_for_waiter defers every
 *               fresh PR behind a phantom EX request).
 *   tenure[m] — committed local tenures at mode m.  While >0, the holder bit
 *               for m is load-bearing and clearing it would leave a local
 *               writer with no on-disk authority.  Published while the
 *               acquiring attempt is STILL JOINED (lreq_finish does the
 *               publish and the leave in one critical section), so there is no
 *               window in which a grant is committed but invisible here.
 *
 * The observe-to-track window that killed the first design (a reconciler
 * deciding while an adopter has validated but not yet recorded itself) cannot
 * open, because an adopter is by construction a JOINED ATTEMPT for the whole
 * of its validate-and-publish sequence: `attempts` is already >1 before it
 * reads the image it adopts on.  The reconciler does not need to see the
 * adoption, only that somebody else is still in the room.
 *
 * Nothing is lost by refusing: whatever this attempt declined to clear is
 * recorded as OWED on the entry, and the LAST local attempt to leave the
 * resource runs the deferred cleanup with a freshly evaluated plan.  That also
 * covers the symmetric case where two abandoning attempts each see the other
 * live and both refuse.
 */

/* Bits set in owed_holder_mask are indexed by mxfs_lock_mode. */
struct mxfs_caw_lreq {
	struct mxfs_caw_lreq	*next;
	struct mxfs_resource_id	 resource;
	uint32_t		 attempts;
	uint32_t		 writers;
	uint32_t		 tenure[MXFS_LOCK_MODE_COUNT];
	/*
	 * ─── sess122: the OWED RECORD (GPT sess121 ruling, blocker 2) ───
	 *
	 * An obligation to clear one of THIS node's bits on THIS resource.  It
	 * is published BEFORE the I/O that would discharge it and retracted only
	 * on proof, so it is a state machine with a guaranteed collector (the
	 * owed worker), not the best-effort "last leaver runs it" the sess112
	 * shape had.
	 *
	 * THE TARGET IS THE RESOURCE, NOT A SLOT.  That is the load-bearing
	 * simplification: the worker re-resolves the resource to its live slot
	 * canonically on every pass, so there is no stored location that a
	 * second obligation can overwrite (ruling item 6) and no tombstone→
	 * recycle ABA to reason about (ruling item B).  `owed_slot_hint` is
	 * DIAGNOSTIC ONLY — it never selects the slot that gets written.
	 *
	 * owed_gen is bumped by EVERY publish/merge.  A retraction that finds it
	 * changed since its window opened refuses: that is precisely the race in
	 * which thread A would erase an obligation thread B published after A
	 * had already read the image it is about to prove clear.
	 */
	uint32_t		 pin;		/* deferred cleanup in flight */
	uint32_t		 owed_holder_mask;
	bool			 owed_waiters;
	bool			 owed_waiters_ex;
	bool			 owed_busy;	/* the worker owns it right now */
	/*
	 * sess129 (GPT sess126 ruling, blocker 4): owed-ready queue links.  See
	 * ctx->owed_q_head in dlm_caw.h for the invariant they maintain and why
	 * it is load-bearing for memory safety.  DOUBLY linked because a
	 * retraction dequeues an arbitrary entry and must not walk to find it —
	 * retractions run on unlock paths under lreq_lock, and an O(queue) walk
	 * there is charged to an XFS thread.
	 */
	struct mxfs_caw_lreq	*oq_next;
	struct mxfs_caw_lreq	*oq_prev;
	bool			 oq_queued;
	uint64_t		 owed_gen;
	uint32_t		 owed_slot_hint;
	uint32_t		 owed_fails;
	uint64_t		 owed_next_ms;	/* backoff floor */
	/*
	 * sess130 (GPT sess126 ruling, blocker 3): the EPISODE clock, and the
	 * exact claim it supports.
	 *
	 * owed_since_ms is stamped on the not-pending → pending transition in
	 * lreq_owed_merge and cleared by lreq_owed_retract in the same place it
	 * already resets owed_fails.  So it measures ONE thing, and the log line
	 * says that thing and no more:
	 *
	 *   "this resource has had continuously outstanding cleanup for X"
	 *
	 * NOT "these bits are X old".  GPT sess130 named the attribution
	 * problem: obligation A ages, B is merged onto the same entry, A is
	 * retracted, the entry never goes non-pending, and B inherits A's age.
	 * Per-constituent ages would fix the attribution and are strictly more
	 * state; the episode measure is the CONSERVATIVE one for the decision
	 * being made here — a resource whose cleanup has never once come clean
	 * is stuck whichever individual bit is currently outstanding — so it is
	 * what escalation triggers on, and the wording is chosen to be true.
	 *
	 * owed_last_rc is the last real failure cause the worker saw (CAW
	 * contention, I/O error, -ENOMEM, plan-suppressed), for the one
	 * actionable line the ruling requires.
	 */
	uint64_t		 owed_since_ms;	/* episode start, 0 = not owing */
	int			 owed_last_rc;
	/*
	 * sess117 CLEAR-WINDOW LINEARIZATION (sess115 ruling, blocker 1's
	 * surviving half + blocker 2 "adoption must be PROVISIONAL").
	 *
	 * clr_active — destructive clear windows open on this resource right
	 *              now.  Nonzero means SOME local thread is in the middle
	 *              of a CAS sequence that may strip this node's bits.
	 * clr_seq    — destructive clears that actually COMMITTED.  Monotone.
	 * pub_seq    — tenure publications (lreq_finish raising tenure[]).
	 *              Monotone.
	 *
	 * The two sequence counters exist because edge-triggered exclusion is
	 * not enough on either side.  A publication that samples "no clear is
	 * running" and then publishes has not proven anything: a clear could
	 * have begun AND committed entirely inside that gap.  Comparing the
	 * committed count across the gap closes it.  Symmetrically, a release
	 * that blanket-retires tenure[] must not eat a tenure published after
	 * the release began — pub_seq across the release window says whether
	 * one was.
	 */
	uint32_t		 clr_active;
	uint64_t		 clr_seq;
	uint64_t		 pub_seq;
};

/*
 * A publication site's view of the clear state, captured at the instant it
 * read the slot image it intends to publish on, and re-validated immediately
 * before that publication becomes usable by XFS.
 *
 * `armed` false means the registry is absent (single-node teardown or a
 * legacy caller): validation is then vacuously true and behaviour is exactly
 * what shipped before this mechanism existed.
 */
struct mxfs_caw_clr_snap {
	uint64_t	seq;
	bool		quiet;
	bool		armed;
};

/* What an abandoning attempt is permitted to clear in its cleanup CAS. */
struct mxfs_caw_clear_plan {
	bool	waiters;
	bool	waiters_ex;
	bool	holder;
	/*
	 * sess122: the holder clear was refused because a COMMITTED LOCAL TENURE
	 * holds this exact mode.  That bit is authorised, not dirt, and its
	 * owner's unlock clears it — so the obligation must DISCHARGE rather
	 * than stay owed.  Without this exception the worker would retry forever
	 * on a bit that can never become clearable while the tenure lives, which
	 * is a livelock, not a safety property.
	 *
	 * sess157: MID-RUN ONLY.  In the frozen teardown world
	 * (lreq_world_frozen) the owner's unlock will never run — lreq_plan
	 * then permits a real clear instead, and lreq_owed_retract refuses a
	 * moot verdict on a tenured mode (P270).  See
	 * D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK.
	 */
	bool	holder_moot;
};

/*
 * sess122: one obligation, as published by whoever created it.  `slot_hint` is
 * diagnostic (UINT32_MAX = none); the worker resolves the resource canonically.
 */
struct mxfs_caw_owed_intent {
	uint32_t	holder_mask;	/* bits indexed by mxfs_lock_mode */
	bool		waiters;
	bool		waiters_ex;
	uint32_t	slot_hint;
};

static uint32_t lreq_bucket(const struct mxfs_resource_id *resource)
{
	return resource_hash_raw(resource) % MXFS_CAW_LREQ_BUCKETS;
}

/* Caller holds ctx->lreq_lock. */
static struct mxfs_caw_lreq *lreq_find(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lreq *e;

	for (e = ctx->lreq[lreq_bucket(resource)]; e; e = e->next)
		if (memcmp(&e->resource, resource, sizeof(*resource)) == 0)
			return e;
	return NULL;
}

/* Does this entry still owe any cleanup?  Caller holds ctx->lreq_lock. */
static bool lreq_owed_pending(const struct mxfs_caw_lreq *e)
{
	return e->owed_waiters || e->owed_waiters_ex || e->owed_holder_mask != 0;
}

/*
 * ─── sess129 (GPT sess126 ruling, blocker 4): the OWED-READY QUEUE ───
 *
 * Caller holds ctx->lreq_lock for all four helpers.  ctx->owed_q_head in
 * dlm_caw.h carries the invariant and the argument for why it is a memory
 * safety property; these are just the mechanics.
 */

static void lreq_oq_remove(struct mxfs_dlm_caw_ctx *ctx,
			   struct mxfs_caw_lreq *e)
{
	if (!e->oq_queued)
		return;
	if (e->oq_prev)
		e->oq_prev->oq_next = e->oq_next;
	else
		ctx->owed_q_head = e->oq_next;
	if (e->oq_next)
		e->oq_next->oq_prev = e->oq_prev;
	else
		ctx->owed_q_tail = e->oq_prev;
	e->oq_next = NULL;
	e->oq_prev = NULL;
	e->oq_queued = false;
	if (ctx->owed_q_n)
		ctx->owed_q_n--;
}

static void lreq_oq_push_tail(struct mxfs_dlm_caw_ctx *ctx,
			      struct mxfs_caw_lreq *e)
{
	if (e->oq_queued)
		return;
	e->oq_next = NULL;
	e->oq_prev = ctx->owed_q_tail;
	if (ctx->owed_q_tail)
		ctx->owed_q_tail->oq_next = e;
	else
		ctx->owed_q_head = e;
	ctx->owed_q_tail = e;
	e->oq_queued = true;
	ctx->owed_q_n++;
}

/*
 * Move `e` to the back of the queue without changing whether it is owed.  The
 * sweep uses this for an entry it examined but declined (a clear window is
 * open on the resource, or it is still inside its backoff floor), which is what
 * bounds a sweep to examining each entry at most once and is therefore the
 * whole anti-starvation property.
 */
static void lreq_oq_rotate(struct mxfs_dlm_caw_ctx *ctx,
			   struct mxfs_caw_lreq *e)
{
	lreq_oq_remove(ctx, e);
	lreq_oq_push_tail(ctx, e);
}

/*
 * Re-establish the invariant for `e`.  EVERY write to the owed bits and every
 * write to owed_busy is followed by a call to this, so the queue cannot drift
 * out of step with the record it schedules, and there is exactly one place to
 * audit if it ever does.
 */
static void lreq_oq_sync(struct mxfs_dlm_caw_ctx *ctx,
			 struct mxfs_caw_lreq *e)
{
	if (lreq_owed_pending(e) && !e->owed_busy)
		lreq_oq_push_tail(ctx, e);
	else
		lreq_oq_remove(ctx, e);
}

/*
 * Publish (or merge into) an obligation.  Caller holds ctx->lreq_lock.
 *
 * The generation bump is unconditional, including for a merge that adds
 * nothing.  It is not a change counter — it is the token a retraction validates
 * against, and any publication at all, informative or not, means some other
 * thread's view of this record is now older than the record.  Bumping only on a
 * real change would let a no-op merge slip a stale retraction through.
 *
 * Clearing the backoff floor is part of publication: a NEW obligation must be
 * attempted promptly even if the entry is deep into exponential backoff from an
 * older one.
 */
static void lreq_owed_merge(struct mxfs_dlm_caw_ctx *ctx,
			    struct mxfs_caw_lreq *e,
			    const struct mxfs_caw_owed_intent *in)
{
	bool added;

	if (!in)
		return;
	added = ((in->holder_mask & ~e->owed_holder_mask) != 0) ||
		(in->waiters && !e->owed_waiters) ||
		(in->waiters_ex && !e->owed_waiters_ex);

	/* sess130 (blocker 3): start the episode clock on the not-pending →
	 * pending edge ONLY.  A merge onto an entry that already owes something
	 * extends the same episode and must not restart it — restarting is
	 * exactly how continuous publication would suppress the wall-clock
	 * escalation forever, which is the surviving half of ruling blocker 7. */
	if (!lreq_owed_pending(e))
		e->owed_since_ms = mxfs_pal_time_ms();

	e->owed_holder_mask |= in->holder_mask;
	if (in->waiters)
		e->owed_waiters = true;
	if (in->waiters_ex)
		e->owed_waiters_ex = true;
	if (in->slot_hint != UINT32_MAX)
		e->owed_slot_hint = in->slot_hint;
	e->owed_gen++;
	e->owed_next_ms = 0;
	/*
	 * sess129 (blocker 4): the not-owed → owed transition is one of the four
	 * queue edges.  A merge onto an entry the collector has already CLAIMED
	 * must NOT enqueue — owed_busy is the other half of the invariant, and
	 * caw_owed_release will put it back when it hands the claim over.
	 */
	lreq_oq_sync(ctx, e);
	/* sess127 (blocker 6): the wake edge, recorded under the lock the worker
	 * parks on.  The broadcast that follows this call is outside the lock and
	 * can therefore be lost; this cannot. */
	ctx->lreq_owed_work_seq++;
	if (added)
		ctx->lreq_owed_pub++;
}

/*
 * ─── sess120: the destructive-clear entry reserve (GPT sess118 ruling item 5)
 *
 * See ctx->lreq_reserve in dlm_caw.h for WHY a destructive clear may not call
 * the allocator.  These three helpers are the whole mechanism.
 */

/* Caller holds ctx->lreq_lock.  Take a zeroed entry, or NULL if dry. */
static struct mxfs_caw_lreq *lreq_reserve_take(struct mxfs_dlm_caw_ctx *ctx)
{
	struct mxfs_caw_lreq *e = ctx->lreq_reserve;

	if (!e)
		return NULL;
	ctx->lreq_reserve = e->next;
	if (ctx->lreq_reserve_n)
		ctx->lreq_reserve_n--;
	memset(e, 0, sizeof(*e));
	return e;
}

/*
 * Caller holds ctx->lreq_lock.  Hand `e` back.  Returns true if the reserve
 * took it (so the caller must NOT free it); false if the reserve is already at
 * target and the caller owns the memory.
 */
static bool lreq_reserve_give(struct mxfs_dlm_caw_ctx *ctx,
			      struct mxfs_caw_lreq *e)
{
	if (ctx->lreq_reserve_n >= MXFS_CAW_LREQ_RESERVE)
		return false;
	e->next = ctx->lreq_reserve;
	ctx->lreq_reserve = e;
	ctx->lreq_reserve_n++;
	return true;
}

/*
 * Restock the reserve.  MUST be called only from an allocation-safe context —
 * mount, or an ACQUIRE path, which already allocates here and is not the path
 * whose failure mode is a cluster stall.  Never from a destructive clear.
 * Allocates outside the lock; best-effort, so failure is silent (the reserve
 * simply stays low and a clear that finds it dry fails closed and is counted).
 */
static void lreq_reserve_fill(struct mxfs_dlm_caw_ctx *ctx, uint32_t target)
{
	if (!ctx || !ctx->lreq || !ctx->lreq_lock)
		return;
	if (target > MXFS_CAW_LREQ_RESERVE)
		target = MXFS_CAW_LREQ_RESERVE;

	for (;;) {
		struct mxfs_caw_lreq *fresh;
		bool need;

		mxfs_pal_mutex_lock(ctx->lreq_lock);
		need = (ctx->lreq_reserve_n < target);
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
		if (!need)
			return;

		fresh = mxfs_pal_alloc(sizeof(*fresh));
		if (!fresh)
			return;
		memset(fresh, 0, sizeof(*fresh));

		mxfs_pal_mutex_lock(ctx->lreq_lock);
		need = lreq_reserve_give(ctx, fresh);
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
		if (!need) {
			mxfs_pal_free(fresh);
			return;		/* someone else filled it */
		}
	}
}

/*
 * Caller holds ctx->lreq_lock.  Unlink an entry that no longer says anything:
 * no live attempt, no live tenure, no deferred cleanup owed and no deferred
 * cleanup running.  Keeping a quiescent entry would be harmless for correctness
 * but would turn the table into an unbounded leak across a mount.
 *
 * sess120: the unlinked entry goes back to the destructive-clear reserve rather
 * than to the allocator whenever the reserve is below target.  That is what
 * makes the reserve self-sustaining: an entry a clear window created returns
 * the instant that window closes, so the steady-state draw is zero.
 */
static void lreq_gc(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e)
{
	struct mxfs_caw_lreq **pp;
	int m;

	/*
	 * sess129 (blocker 4): oq_queued is REDUNDANT under the owed-ready queue
	 * invariant — queued implies pending, which is already a refusal — and it
	 * is listed anyway on purpose.  It is the only barrier between a future
	 * weakening of that invariant and a use-after-free through the queue, and
	 * the failure it converts to is a leaked registry entry, which the P248
	 * teardown report already names.
	 */
	if (e->attempts || e->pin || e->clr_active || e->owed_busy ||
	    e->oq_queued || lreq_owed_pending(e))
		return;
	for (m = 0; m < MXFS_LOCK_MODE_COUNT; m++)
		if (e->tenure[m])
			return;

	for (pp = &ctx->lreq[lreq_bucket(&e->resource)]; *pp;
	     pp = &(*pp)->next) {
		if (*pp == e) {
			*pp = e->next;
			if (!lreq_reserve_give(ctx, e))
				mxfs_pal_free(e);
			return;
		}
	}
}

/*
 * Register one local attempt on `resource` wanting `mode`.  Returns the
 * entry, which stays valid until the matching lreq_finish (lreq_gc refuses to
 * free an entry with a live attempt).
 *
 * Returns NULL ONLY when the registry cannot represent the attempt.  The
 * caller MUST refuse the acquisition in that case: proceeding would mean a
 * later reconcile reads "no other local attempt is live" from a table that
 * simply failed to record one, which is the unsound view this whole mechanism
 * exists to prevent (GPT sess111 ruling item 6 — never "overflowed and
 * continue").  Refusing costs an -ENOMEM to a caller that retries; continuing
 * costs an unfenced writer.
 */
static struct mxfs_caw_lreq *lreq_join(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       uint8_t mode)
{
	struct mxfs_caw_lreq *e, *fresh;

	if (!ctx->lreq || !ctx->lreq_lock)
		return NULL;

	/* Allocated OUTSIDE the lock and freed unused if we lost the race —
	 * the table's mutex is never held across an allocation. */
	fresh = mxfs_pal_alloc(sizeof(*fresh));
	if (!fresh)
		return NULL;
	memset(fresh, 0, sizeof(*fresh));
	fresh->resource = *resource;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (!e) {
		uint32_t b = lreq_bucket(resource);

		fresh->next = ctx->lreq[b];
		ctx->lreq[b] = fresh;
		e = fresh;
		fresh = NULL;
	}
	e->attempts++;
	if (mxfs_mode_can_write(mode))
		e->writers++;
	/* sess120: we lost the race and hold a spare.  Donate it to the
	 * destructive-clear reserve instead of freeing it — this is the cheapest
	 * restock there is, and it happens exactly when the resource is
	 * contended, which is when a clear is most likely to need one. */
	if (fresh && lreq_reserve_give(ctx, fresh))
		fresh = NULL;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	mxfs_pal_free(fresh);

	/*
	 * sess120: top the reserve up from HERE, an acquire path.  This is the
	 * allocation-safe context the reserve exists to move the allocation
	 * into: an acquire that fails on -ENOMEM costs one caller a retry,
	 * whereas an unlock that fails leaves the lock held and stalls every
	 * waiting peer.  Cheap — the common case reads one counter under the
	 * mutex and returns.
	 */
	lreq_reserve_fill(ctx, MXFS_CAW_LREQ_RESERVE);
	return e;
}

/*
 * sess157 (D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK, GPT sess157 ruling):
 * the world is FROZEN once stop() has closed admission (phase 1), every
 * publication-capable producer is quiesced and joined (phases 2+3), the
 * release_all traversal has FINISHED (phase 4 sets release_all_done at its
 * single full-walk exit), and no attempt has finished since the phase-4
 * snapshot.  From that point no owner's unlock can ever run again, so a
 * committed tenure stops being a reason to moot its holder bit — the tenure
 * IS the record of the on-disk bit the teardown drain exists to clear.
 *
 * Caller holds ctx->lreq_lock (every term is written under it).
 * lreq_finish_gen is a u64 bumped once per finished attempt; it cannot wrap
 * within a mount lifetime, so the equality cannot ABA.  The mid-run failure
 * latch (caw_owed_fail_latch) and the mount.c pre-stop release_all can raise
 * the two flags outside stop(), but any committed tenure implies at least one
 * finished publication, so lreq_finish_gen >= 1 while stop_finish_gen is
 * still 0 — the gen term keeps that window unfrozen.
 */
static bool lreq_world_frozen(const struct mxfs_dlm_caw_ctx *ctx)
{
	return ctx->ops_closed && ctx->release_all_done &&
	       ctx->lreq_finish_gen == ctx->stop_finish_gen;
}

/*
 * Decide what THIS abandoning attempt may clear.  The attempt is still joined,
 * so `attempts` includes us and `others` is the number of local threads that
 * would be harmed by an over-broad clear.
 *
 * sess122 (GPT sess121 ruling item 2): THIS FUNCTION IS PURE.  It used to
 * record what it refused as OWED, which made a plan evaluation — something the
 * CAS loop does on EVERY iteration, purely to decide what to write — also a
 * publication.  That conflated deciding with owing: a refusal recorded on an
 * iteration whose CAS then succeeded left a phantom obligation, and a refusal
 * NOT recorded because the caller never reached an iteration left a real one
 * unpublished.  Publication now happens exactly once, up front, atomically with
 * the clear window (lreq_clr_begin), and retraction happens exactly once, on
 * proof.  A plan is only ever an answer to "what may this CAS touch?".
 */
static void lreq_plan(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e,
		      uint8_t giveup_mode, bool self_joined,
		      struct mxfs_caw_clear_plan *plan)
{
	uint32_t others, other_writers;

	/* No registry (single-node teardown, or a legacy caller): the historic
	 * behaviour — clear everything this attempt could own. */
	plan->waiters = true;
	plan->waiters_ex = true;
	plan->holder = (giveup_mode != MXFS_LOCK_NL);
	plan->holder_moot = false;
	if (!e || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	/*
	 * sess117: `others` is "local attempts that are NOT this caller".  The
	 * deferred (owed) pass runs AFTER its attempt already left, so it must
	 * NOT subtract itself — doing so read one live attempt as zero and let
	 * the deferred clear strip a bit that attempt was still relying on.
	 */
	if (self_joined)
		others = e->attempts ? e->attempts - 1 : 0;
	else
		others = e->attempts;
	other_writers = e->writers;
	if (self_joined && mxfs_mode_can_write(giveup_mode) && other_writers)
		other_writers--;

	plan->waiters = (others == 0);
	plan->waiters_ex = (other_writers == 0);

	if (plan->holder && giveup_mode < MXFS_LOCK_MODE_COUNT) {
		if (e->tenure[giveup_mode]) {
			if (!lreq_world_frozen(ctx)) {
				/*
				 * A COMMITTED local tenure holds this exact
				 * mode.  The bit is not ours to drop and it
				 * never becomes owed — it is legitimately set
				 * and its owner's unlock will clear it.  This
				 * is the corruption-class save.  MID-RUN ONLY
				 * (sess157): in the frozen world the owner is
				 * the departing node itself and its unlock
				 * will never run.
				 */
				plan->holder = false;
				plan->holder_moot = true;
				ctx->lreq_guard_hits++;
			} else if (others) {
				/*
				 * sess157: the frozen world promises zero live
				 * attempts, yet one exists.  Fail closed:
				 * DEFER, never moot — the obligation stays
				 * owed, the drain retries, and P254 reports it
				 * if it survives.  Mooting here would retract
				 * the obligation as discharged without any CAS
				 * — the exact defect class
				 * D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK.
				 */
				ctx->lreq_frozen_defer++;
				pr_warn_ratelimited("mxfs: P269-FROZEN-TENURE-ATTEMPTS type=%c id=%llu mode=%u attempts=%u tenure=%u gen=%llu/%llu — live local attempt contradicts the frozen-teardown premise on a tenured mode; holder clear deferred (fail closed), obligation stands\n",
					e->resource.type == MXFS_LTYPE_INODE ? 'I' :
					e->resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
					(unsigned long long)(e->resource.type ==
						MXFS_LTYPE_INODE ? e->resource.ino :
						(uint64_t)e->resource.ag_number),
					giveup_mode, e->attempts,
					e->tenure[giveup_mode],
					(unsigned long long)ctx->lreq_finish_gen,
					(unsigned long long)ctx->stop_finish_gen);
				plan->holder = false;
			}
			/*
			 * else — frozen world, no live attempt (sess157,
			 * D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK): PERMIT
			 * the clear.  plan->holder stays true so the teardown
			 * drain CASes the bit off the LUN; a bit the image
			 * already shows absent (e.g. a PR bit consumed by a
			 * PR→EX up-convert) proves case (b) with no I/O.  The
			 * moot exception's termination argument does not apply
			 * here: the bit is genuinely clearable, so the
			 * obligation terminates by discharge or by drain
			 * budget expiry (P254 residue, departure not clean).
			 */
		} else if (others) {
			/*
			 * No committed tenure yet, but another local attempt is
			 * live and may be mid-adoption on this very grant.  Do
			 * not race it; the obligation published for this clear
			 * keeps it alive and the owed worker collects it once
			 * that attempt has resolved one way or the other.
			 */
			plan->holder = false;
			ctx->lreq_defer_hits++;
		}
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

/*
 * ─── sess122: RETRACTION (GPT sess121 ruling items 4 + 5) ───
 *
 * Discharge only what this pass PROVED, and only if no newer intent arrived.
 *
 * `proven` means the pass ended holding proof that every bit the plan PERMITTED
 * is now clear on disk.  There are exactly three ways to hold that proof and no
 * others:
 *
 *   (a) a CAS that landed after clearing every permitted-and-set bit — the
 *       permitted bits that were NOT set were already clear in the image the
 *       CAS compared against, so all of them are covered;
 *   (b) an image in which no permitted bit was set at all;
 *   (c) `terminal` — the resource has no live slot, so no bit of ours can be
 *       set anywhere.  This is the terminal transition ruling item D demands,
 *       and canonical resolution of the resource (rather than a remembered slot
 *       index) is what makes it reachable.
 *
 * Bits the plan REFUSED are never discharged — with the single `holder_moot`
 * exception documented on struct mxfs_caw_clear_plan, which is required for
 * termination rather than being a relaxation of it.  A waiter refusal
 * (`others != 0`) needs no exception: it terminates naturally when the last
 * local attempt leaves and a later pass finds the plan permissive.
 *
 * sess157 (D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK): the moot exception is
 * MID-RUN ONLY.  Once the world is frozen (lreq_world_frozen) a tenured mode
 * is planned as a real clear, and a moot verdict arriving at retraction in
 * the frozen world is refused (P270) — accepting it would erase the
 * obligation without a CAS and leak the holder bit on the LUN behind a
 * claimed-clean departure.
 *
 * Caller must NOT hold ctx->lreq_lock.
 */
static void lreq_owed_retract(struct mxfs_dlm_caw_ctx *ctx,
			      struct mxfs_caw_lreq *e, uint64_t gen0,
			      const struct mxfs_caw_clear_plan *plan,
			      uint8_t giveup_mode, bool proven, bool terminal)
{
	if (!e || !ctx || !ctx->lreq_lock)
		return;
	if (!proven && !terminal && !(plan && plan->holder_moot))
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	if (e->owed_gen != gen0) {
		/*
		 * Somebody published a NEW obligation on this resource while
		 * this pass was running.  Our proof is about the state we
		 * observed, which is older than that publication, so retracting
		 * now would erase an obligation nobody has discharged.
		 */
		ctx->lreq_owed_genrace++;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
		return;
	}

	if (terminal) {
		e->owed_holder_mask = 0;
		e->owed_waiters = false;
		e->owed_waiters_ex = false;
	} else {
		if (plan && plan->holder_moot &&
		    giveup_mode < MXFS_LOCK_MODE_COUNT) {
			if (e->tenure[giveup_mode] &&
			    lreq_world_frozen(ctx)) {
				/*
				 * sess157 (GPT ruling, retraction-time
				 * provenance guard): a moot verdict reached
				 * retraction in the frozen world while the
				 * mode is still tenured — the plan predates
				 * the phase-4 freeze, or a moot path survived
				 * the lreq_plan gate.  Refuse the strip: the
				 * obligation stands and the drain re-plans it
				 * under the frozen predicate, which permits a
				 * real CAS.  Waiter retracts below are proof-
				 * gated separately and stay valid.
				 */
				ctx->lreq_owed_moot_refused++;
				pr_warn_ratelimited("mxfs: P270-MOOT-RETRACT-REFUSED type=%c id=%llu mode=%u tenure=%u — moot verdict tried to retract a tenured holder obligation in the frozen world (stale pre-freeze plan or unhandled moot path); refused, obligation stands\n",
					e->resource.type == MXFS_LTYPE_INODE ? 'I' :
					e->resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
					(unsigned long long)(e->resource.type ==
						MXFS_LTYPE_INODE ? e->resource.ino :
						(uint64_t)e->resource.ag_number),
					giveup_mode,
					e->tenure[giveup_mode]);
			} else {
				e->owed_holder_mask &= ~(1u << giveup_mode);
				ctx->lreq_owed_moot++;
			}
		}
		if (proven && plan) {
			if (plan->waiters)
				e->owed_waiters = false;
			if (plan->waiters_ex)
				e->owed_waiters_ex = false;
			if (plan->holder &&
			    giveup_mode < MXFS_LOCK_MODE_COUNT) {
				e->owed_holder_mask &= ~(1u << giveup_mode);
				/*
				 * sess157: the POSITIVE per-mode observation
				 * for the teardown drain — this holder mode
				 * was discharged on PROOF (CAS landed or image
				 * showed it absent), not mooted.  Frozen-world
				 * only, so mid-run churn stays silent.
				 */
				if (lreq_world_frozen(ctx))
					pr_warn_ratelimited("mxfs: P271-OWED-DISCHARGE type=%c id=%llu mode=%u tenure=%u — teardown drain discharged this holder mode on proof (CAS landed or bit already absent)\n",
						e->resource.type == MXFS_LTYPE_INODE ? 'I' :
						e->resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
						(unsigned long long)(e->resource.type ==
							MXFS_LTYPE_INODE ? e->resource.ino :
							(uint64_t)e->resource.ag_number),
						giveup_mode,
						e->tenure[giveup_mode]);
			}
		}
	}
	if (!lreq_owed_pending(e)) {
		e->owed_fails = 0;
		e->owed_next_ms = 0;
		/* sess130 (blocker 3): the episode ENDED — cleanup on this resource
		 * came clean.  Clearing the clock here, in the one place that already
		 * owns the per-episode reset, is what makes owed_since_ms mean
		 * "continuously outstanding" and not "first ever seen". */
		e->owed_since_ms = 0;
		e->owed_last_rc = 0;
		ctx->lreq_owed_done++;
	}
	/* sess129 (blocker 4): the owed → not-owed transition.  It runs on both
	 * the collector's own retractions (where the entry is claimed, hence not
	 * queued, and this is a no-op) and on give-up paths retracting an entry
	 * the collector has never touched — that one IS queued, and leaving it
	 * there would hand the sweep an entry with nothing left to do. */
	lreq_oq_sync(ctx, e);
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

/*
 * ─── sess117: the clear window ───
 *
 * WHY (sess115 RULE-5 ruling): "a destructive disk transition may occur only
 * after the authoritative resource state has stopped new dependent activity
 * and established that all previously admitted dependent activity is
 * quiescent, or after a DLM-level protocol has provided an equivalent
 * resource-wide exclusion."  For the TRANSIENT half of that — one local CAW
 * attempt versus another local CAW attempt — this is that protocol.
 *
 * The reduction that makes it small: enumerate every way a local grant becomes
 * BELIEVED-HELD, and ask what already linearizes it against a destructive
 * clear CAS.
 *
 *   slow-path grant CAS    — ALREADY LINEARIZED.  It writes the slot, so a
 *                            concurrent clear CAS miscompares and re-reads;
 *                            and the grantee is a joined attempt for the whole
 *                            window, so `others >= 1` protects it until
 *                            lreq_finish publishes the tenure.
 *   already-held shortcut  — NOT linearized.  Memory-only: it writes nothing,
 *                            so there is no CAS for a clear to lose against.
 *   direct-handoff adopt   — NOT linearized.  The PEER's CAS set our bit; we
 *                            write nothing at all.
 *   lreq_release_all       — NOT linearized.  A blanket tenure retire can eat
 *                            a tenure published after the release began.
 *
 * So the exposed surface is exactly three memory-only publications plus the
 * release, and a snapshot-and-validate is sufficient for all four.  That is
 * why this is not the heavyweight blocking op-state protocol (CANCELLING /
 * RELEASING / ADOPTING with admission blocking): the ruling's requirement for
 * adoption is that it "stays provisional and retries after", and a publication
 * that validates its snapshot before becoming usable IS provisional.
 *
 * It also closes an aliasing hole in the defence that shipped before it:
 * caw_grant_meta_store_unless_releasing keys off grant_meta, a NO-CHAIN hash,
 * so a colliding FOREIGN resource can evict the `releasing` mark that protects
 * the shortcut.  The lreq table is chained and keyed by the resource itself,
 * so it cannot alias.
 *
 * The snapshot cannot be defeated by entry recycling: every publication site
 * runs inside mxfs_dlm_caw_lock/_convert AFTER lreq_join, and lreq_gc refuses
 * to free an entry with a live attempt, so the same entry is observed at
 * snapshot and at validation.
 */

/*
 * Open a destructive-clear window on `resource`.
 *
 * find-OR-CREATE is load-bearing, not a convenience: without it a lreq_join
 * racing in mid-window would find no entry, snapshot a freshly created one
 * with clr_active == 0, and publish straight through the clear.
 *
 * sess120 (GPT sess118 ruling item 5) — this is FIND-FIRST and ALLOCATION-FREE.
 * Two changes from the sess117 shape, both required:
 *
 *   1. The lookup happens before any allocation, so the overwhelmingly common
 *      case — a clear on a resource this node holds a grant on — never touches
 *      the allocator at all.  It cannot: lreq_finish publishes tenure[] and
 *      lreq_gc refuses to free an entry with nonzero tenure, so the entry is
 *      already there for every unlock of a held lock and for both DIVERG arms.
 *   2. The genuinely-absent case draws from the pre-allocated reserve rather
 *      than calling mxfs_pal_alloc, whose GFP_KERNEL reclaim can re-enter XFS
 *      writeback and deadlock against the very resource being released.
 *
 * Returns MXFS_CAW_CLR_ARMED with *out pinned; MXFS_CAW_CLR_NOREG (with *out
 * NULL) when there is no registry at all, which is the pre-registry legacy
 * behaviour and is unchanged; or -ENOMEM, which the caller MUST treat as FAIL
 * CLOSED — a destructive clear that proceeds without registry coverage is
 * exactly the unlinearized clear this whole mechanism exists to prevent.
 *
 * sess124 (GPT sess121 ruling item 1): opening the window is ALSO the
 * publication point for the obligation the clear is about to take on.  `intent`
 * (NULL for a window that owes nothing) is merged and `*gen0` returns the
 * post-merge generation, all inside the SAME lreq_lock section that claims the
 * window.  One section matters because the entry may be CREATED here: a caller
 * whose own entry pointer is NULL (a claim-exhaustion give-up that never
 * registered, a legacy path) still gets its obligation recorded, on the very
 * entry find-or-create just made, and can never lose it in the gap between
 * "created" and "published".
 */
#define MXFS_CAW_CLR_NOREG	0	/* no registry — legacy, proceed */
#define MXFS_CAW_CLR_ARMED	1	/* window open, *out pinned */

static int lreq_clr_begin(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  const struct mxfs_caw_owed_intent *intent,
			  uint64_t *pub_seq0, uint64_t *gen0,
			  struct mxfs_caw_lreq **out)
{
	struct mxfs_caw_lreq *e;

	*out = NULL;
	if (pub_seq0)
		*pub_seq0 = 0;
	if (gen0)
		*gen0 = 0;
	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return MXFS_CAW_CLR_NOREG;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (!e) {
		e = lreq_reserve_take(ctx);
		if (e) {
			uint32_t b = lreq_bucket(resource);

			e->resource = *resource;
			e->next = ctx->lreq[b];
			ctx->lreq[b] = e;
		}
	}
	if (e) {
		lreq_owed_merge(ctx, e, intent);
		e->clr_active++;
		e->pin++;
		if (pub_seq0)
			*pub_seq0 = e->pub_seq;
		if (gen0)
			*gen0 = e->owed_gen;
	} else {
		ctx->lreq_reserve_dry++;
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	/* Wake the owed worker for a NEW obligation.  Outside the lock: the
	 * worker's park re-acquires it, and a broadcast under it would just
	 * make the wakee spin on a mutex we still hold. */
	if (e && intent && ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);

	*out = e;
	return e ? MXFS_CAW_CLR_ARMED : -ENOMEM;
}

/*
 * lreq_clr_begin with a bounded wait for the reserve to be restocked.
 *
 * The reserve is refilled by other threads closing their own clear windows
 * (lreq_gc hands entries back) and by acquire paths, so a transient dry spell
 * resolves in memory-operation time.  A persistent one does not, and then the
 * caller's fail-closed disposition is the right answer.  `deadline_ms` is the
 * caller's EXISTING deadline when it has one (an unlock's), so this can never
 * extend a lock budget; 0 means use the short default.
 */
static int lreq_clr_begin_wait(struct mxfs_dlm_caw_ctx *ctx,
			       const struct mxfs_resource_id *resource,
			       const struct mxfs_caw_owed_intent *intent,
			       uint64_t *pub_seq0, uint64_t *gen0,
			       struct mxfs_caw_lreq **out,
			       uint64_t deadline_ms)
{
	uint64_t giveup;
	int rc;

	rc = lreq_clr_begin(ctx, resource, intent, pub_seq0, gen0, out);
	if (rc != -ENOMEM)
		return rc;

	giveup = mxfs_pal_time_ms() + MXFS_CAW_LREQ_RESERVE_WAIT_MS;
	if (deadline_ms && deadline_ms < giveup)
		giveup = deadline_ms;

	while (mxfs_pal_time_ms() < giveup) {
		if (!ctx->running)
			break;		/* shutdown-compatible (ruling (iii)) */
		mxfs_pal_sleep_ms(MXFS_CAW_LREQ_RESERVE_STEP_MS);
		rc = lreq_clr_begin(ctx, resource, intent, pub_seq0, gen0, out);
		if (rc != -ENOMEM)
			return rc;
	}
	return -ENOMEM;
}

/*
 * ─── sess127: the COLLECTOR's clear window (GPT sess126 ruling, blocker 5) ───
 *
 * Open a destructive-clear window on an entry whose obligation the caller
 * ALREADY OWNS.  Same exclusion as lreq_clr_begin — clr_active is raised, so a
 * concurrent memory-only publication sees that its image may be invalidated —
 * but WITHOUT the publication half.
 *
 * WHY THE PUBLICATION HALF IS WRONG HERE.  lreq_clr_begin merges the caller's
 * intent and bumps owed_gen unconditionally, which is right for a give-up: it
 * is writing down a NEW obligation before doing the I/O that could discharge
 * it.  The owed worker is in the opposite position — the obligation is already
 * recorded and it is here to collect it — so a merge adds nothing, and the gen
 * bump is actively harmful: owed_gen is the token every retraction validates
 * against, so bumping it once per mode makes a CONCURRENT retraction by some
 * other local thread (one that genuinely proved its bits clear) refuse and
 * re-owe work that was already done.  The collector must be transparent to that
 * protocol, not a participant in it.
 *
 * `e` must already be held live by the caller — the worker's sweep claim raises
 * pin and owed_busy before dispatch — so there is nothing to find, nothing to
 * create, and no way for this to fail.  That is also why it needs no reserve:
 * the allocation-free requirement (ctx->lreq_reserve) is satisfied vacuously.
 */
static void lreq_clr_begin_existing(struct mxfs_dlm_caw_ctx *ctx,
				    struct mxfs_caw_lreq *e, uint64_t *gen0)
{
	if (gen0)
		*gen0 = 0;
	if (!ctx || !ctx->lreq_lock || !e)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e->clr_active++;
	e->pin++;
	if (gen0)
		*gen0 = e->owed_gen;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

/*
 * Close a destructive-clear window.  `committed` MUST be true if any CAS in
 * the window actually landed a clear of one of this node's bits — that is what
 * a concurrent publication validates against.
 */
static void lreq_clr_end(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e,
			 bool committed)
{
	if (!e || !ctx || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	if (committed)
		e->clr_seq++;
	if (e->clr_active)
		e->clr_active--;
	if (e->pin)
		e->pin--;
	/* sess127 (blocker 6): the sweep SKIPS an entry with a window open on it,
	 * so closing one is a wake edge — the entry may be dispatchable now and
	 * nothing else will say so. */
	ctx->lreq_owed_work_seq++;
	lreq_gc(ctx, e);
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	if (ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);
}

/*
 * Capture the clear state for a slot image the caller intends to publish on.
 * Must be paired with lreq_clr_still_good BEFORE the grant becomes usable by
 * XFS.
 *
 * ORDERING (sess118 correction to the sess116 design note, which said "after
 * the read"): the snapshot MUST be taken BEFORE the read, never after.  Taken
 * after, a clear that both BEGINS and COMMITS inside the read→snap gap is
 * invisible — clr_active is back to 0 and clr_seq is already at its new value,
 * so the later validation compares equal and the publication proceeds on an
 * image whose holder bit has since been stripped.  Taken before, that clear is
 * caught either as clr_active != 0 (quiet == false) or as a clr_seq that moved.
 *
 * The converse — a clear that committed BEFORE the snapshot — needs no
 * detection: its CAS happened-before our read, so the image we read is already
 * the post-clear one and the shortcut simply does not fire.
 */
static void lreq_clr_snap(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  struct mxfs_caw_clr_snap *s)
{
	struct mxfs_caw_lreq *e;

	s->seq = 0;
	s->quiet = true;
	s->armed = false;
	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return;

	s->armed = true;
	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (e) {
		s->seq = e->clr_seq;
		s->quiet = (e->clr_active == 0);
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

/*
 * Is the snapshot still good?  True means: no destructive clear was running
 * when the image was read, none is running now, and none committed in between
 * — so the holder bit this publication is about to rely on was not stripped
 * underneath it.  False means the publication must be abandoned and the
 * acquire retried from a fresh image.
 */
static bool lreq_clr_still_good(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				const struct mxfs_caw_clr_snap *s)
{
	struct mxfs_caw_lreq *e;
	bool ok;

	if (!s->armed)
		return true;		/* no registry — legacy behaviour */
	if (!s->quiet)
		return false;		/* a clear was already running */
	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return true;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	/*
	 * sess118 ruling item 4 (registry ABA): a MISSING entry is a validation
	 * FAILURE, not a pass.  clr_seq is monotone only over one entry's
	 * lifetime, so "entry absent ⇒ nothing cleared" is only sound if
	 * disappearance is provably impossible — and while that is believed
	 * true here (every publication site holds a joined attempt, and lreq_gc
	 * refuses to free an entry with attempts != 0), a belief is not an
	 * audit.  Failing closed makes the property enforced instead of
	 * assumed, and costs only a re-read on a path that cannot occur.
	 */
	ok = e && e->clr_active == 0 && e->clr_seq == s->seq;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return ok;
}

/*
 * sess120 (GPT sess118 ruling item (i): "no destructive path bypasses
 * begin/end").  Wrap ONE destructive CAS in a clear window.
 *
 * The sess119 audit classified every `&= ~ctx->node_bit` site in this file and
 * found three that strip this node's AUTHORITY with no window at all — both
 * divergence arms of mxfs_dlm_caw_lock and the downgrade arm of
 * mxfs_dlm_caw_convert.  All three are memory-invisible to a concurrent
 * already-held or adopt publication in exactly the way the three already
 * windowed sites are, so all three need this.
 *
 * Why the window only has to span the CAS and not the read that produced
 * `cur`: what a publication validates is that no clear was running at its
 * snapshot, none is running at its validation, and none COMMITTED in between.
 * A window opened at any point before the destructive CAS and closed after it
 * satisfies all three tests for any publication whose snapshot→validate
 * interval overlaps the CAS.  Opening it back at the acquire loop's slot read
 * instead would make an ordinary retrying acquire look like a clear in
 * progress and bounce every concurrent publication on the resource.
 *
 * Fail-closed disposition is -EAGAIN, which every caller already routes into
 * its own bounded retry: an acquire that cannot clear its provably-stale bit
 * must keep retrying and eventually fail, never return success on it.
 *
 * sess124: `owed_mode` names the holder bit this CAS is trying to strip, or
 * MXFS_LOCK_NL for a clear that owes nothing.  Why the two divergence arms owe
 * and the downgrade arm does not:
 *
 *   diverg-lo / diverg-hi — strip a provably-stale holder bit for our_mode.
 *       If the CAS never lands, NOTHING else collects it: the give-up path
 *       reconciles the REQUESTED mode, not the mode we were found diverged at,
 *       so the bit is invisible to every other collector in the file.  The
 *       acquire does retry, but it may also fail out, and then the stale bit
 *       is a cluster-wide liveness leak of exactly the kind this campaign
 *       exists to close.
 *   convert-downgrade     — strips the OLD, HIGHER mode while setting the new
 *       lower one.  An abandoned downgrade leaves the higher mode held, which
 *       is the safe direction (over-strong local authority, no peer admitted
 *       past it), so owing it would only invite the worker to strip authority
 *       a live local tenure is using.
 */
static int caw_slot_clearing(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource,
			     uint32_t slot_idx,
			     const struct mxfs_caw_lock_slot *cur,
			     struct mxfs_caw_lock_slot *new,
			     const char *site, uint8_t owed_mode)
{
	struct mxfs_caw_owed_intent intent;
	struct mxfs_caw_owed_intent *ip = NULL;
	struct mxfs_caw_clear_plan plan;
	struct mxfs_caw_lreq *clr = NULL;
	uint64_t gen0 = 0;
	int rc;

	if (owed_mode != MXFS_LOCK_NL && owed_mode < MXFS_LOCK_MODE_COUNT) {
		intent.holder_mask = 1u << owed_mode;
		intent.waiters = false;
		intent.waiters_ex = false;
		intent.slot_hint = slot_idx;
		ip = &intent;
	}

	if (lreq_clr_begin_wait(ctx, resource, ip, NULL, &gen0, &clr, 0) < 0) {
		ctx->lreq_nomem++;
		pr_warn_ratelimited("mxfs: P251-LREQ-DRY %s type=%u ino=%llu slot=%u dry=%llu — destructive clear REFUSED (retryable)\n",
				    site, resource->type,
				    (unsigned long long)resource->ino, slot_idx,
				    (unsigned long long)ctx->lreq_reserve_dry);
		return -EAGAIN;
	}
	rc = caw_slot(ctx, slot_idx, cur, new);

	/*
	 * Retract on proof only.  The permitted set here is exactly the one
	 * holder bit, and the proof is a CAS that landed — an -EAGAIN
	 * miscompare or an I/O error proves nothing, so the obligation stands
	 * and the worker re-resolves the resource and tries again.
	 */
	if (ip) {
		plan.waiters = false;
		plan.waiters_ex = false;
		plan.holder = true;
		plan.holder_moot = false;
		lreq_owed_retract(ctx, clr, gen0, &plan, owed_mode,
				  rc == 0, false);
	}
	lreq_clr_end(ctx, clr, caw_may_have_written(rc));
	return rc;
}

/* ─── Find slot for resource (hash + linear probe) ─── */

/*
 * sess128 (GPT sess126 ruling, blocker 1): `deadline` is an ABSOLUTE
 * mxfs_pal_time_ms() value, or 0 for "unbounded" — which is what every acquire/
 * release caller passes, because their bound is the caller's own lock timeout
 * and a probe walk cut short there would be a correctness regression, not a
 * courtesy (a truncated walk cannot distinguish "absent" from "not reached").
 * Only the owed collector, whose whole contract is that giving up is safe
 * because the obligation stands, passes one.  -ETIMEDOUT is deliberately NOT
 * -ENOENT: caw_owed_resolve's terminal proof requires a COMPLETE walk.
 */
static int find_slot_skip(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource,
		      uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out,
		      uint32_t *empty_out, uint32_t skip_idx,
		      uint32_t *last_read_out, uint64_t deadline)
{
	uint32_t base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	struct mxfs_caw_lock_slot *span;
	uint32_t span_base = UINT32_MAX, span_n = 0;
	uint32_t i;
	int rc;

	*empty_out = UINT32_MAX;
	if (last_read_out)
		*last_read_out = UINT32_MAX;

	/* NULL span → the per-slot read path below still works unchanged */
	span = mxfs_caw_probe_span_enable ?
		mxfs_pal_alloc(MXFS_CAW_PROBE_SPAN * MXFS_CAW_SLOT_SIZE) : NULL;

	/*
	 * v0.5.3 hint fast path: one content-validated read of the
	 * last-known slot instead of the chain walk.  A hit requires the
	 * hinted slot to STILL hold a live entry for exactly this
	 * resource — peers cannot move a live entry to a different slot,
	 * they can only release it (tombstone) or, after a release, the
	 * resource may get re-claimed elsewhere in the chain; both cases
	 * fail the content check and fall through to the full walk.
	 * Skipped when the caller excludes a slot (skip_idx) — that path
	 * needs the true chain scan semantics.
	 */
	if (skip_idx == UINT32_MAX) {
		uint32_t hint;

		if (deadline && mxfs_pal_time_ms() >= deadline) {
			if (span)
				mxfs_pal_free(span);
			return -ETIMEDOUT;
		}
		if (slot_hint_get(ctx, resource, &hint)) {
			rc = read_slot(ctx, hint, data_out);
			if (rc == 0 &&
			    data_out->magic == MXFS_CAW_MAGIC &&
			    memcmp(&data_out->resource, resource,
				   sizeof(*resource)) == 0) {
				if (last_read_out)
					*last_read_out = hint;
				*slot_out = hint;
				if (span)
					mxfs_pal_free(span);
				return 0;
			}
			/* stale hint — full walk below refreshes it */
		}
	}

	/*
	 * Open-addressing linear probe.  Deletes write a tombstone (magic =
	 * MXFS_CAW_TOMBSTONE_MAGIC) so that the probe chain remains
	 * traversable past freed slots.  Only a truly-empty slot (magic == 0
	 * — never used) terminates the probe.  An earlier zero-on-delete
	 * design corrupted lookups: a freed slot looked identical to a
	 * never-used slot, so probes terminated early and missed live
	 * entries past the gap, allowing the same resource to be claimed in
	 * two different slots concurrently — i.e. two nodes briefly holding
	 * the same lock EX (bug B in state.md session 8).
	 */
	for (i = 0; i < MXFS_CAW_MAX_SLOTS; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;

		/*
		 * sess128: before every slot read, span refill included.  A full
		 * walk is 65536 slots; at one span read per MXFS_CAW_PROBE_SPAN
		 * that is still hundreds of I/Os, which is precisely why the
		 * teardown drain could outrun its budget inside a single
		 * resolve.
		 */
		if (deadline && mxfs_pal_time_ms() >= deadline) {
			if (span)
				mxfs_pal_free(span);
			return -ETIMEDOUT;
		}

		if (span && (span_base == UINT32_MAX || idx < span_base ||
			     idx >= span_base + span_n)) {
			/* refill: never wrap inside one span read */
			uint32_t n = MXFS_CAW_MAX_SLOTS - idx;

			if (n > MXFS_CAW_PROBE_SPAN)
				n = MXFS_CAW_PROBE_SPAN;
			if (read_slot_span(ctx, idx, n, span) == 0) {
				span_base = idx;
				span_n = n;
			} else {
				/* span I/O trouble — this walk degrades to
				 * the per-slot path (its own retries) */
				mxfs_pal_free(span);
				span = NULL;
				span_base = UINT32_MAX;
				span_n = 0;
			}
		}

		if (span && idx >= span_base && idx < span_base + span_n) {
			*data_out = span[idx - span_base];
			if (slot_appears_corrupt(data_out)) {
				/* re-read + repair via the existing path */
				rc = read_slot(ctx, idx, data_out);
				if (rc) {
					mxfs_pal_free(span);
					return rc;
				}
			}
		} else {
			rc = read_slot(ctx, idx, data_out);
			if (rc) {
				if (span)
					mxfs_pal_free(span);
				return rc;
			}
		}
		if (last_read_out)
			*last_read_out = idx;

		if (data_out->magic == MXFS_CAW_MAGIC) {
			if (memcmp(&data_out->resource, resource,
				   sizeof(*resource)) == 0) {
				*slot_out = idx;
				slot_hint_store(ctx, resource, idx);
				if (span)
					mxfs_pal_free(span);
				return 0; /* Found */
			}
			/*
			 * sess131: a live entry whose resource belongs to a
			 * DIFFERENT volume is a pre-mkfs ghost record (an
			 * old-generation node wrote it after the mkfs zero
			 * pass).  Nothing in this generation will ever look
			 * it up or release it — treat it like a tombstone:
			 * recyclable insertion point, probe continues.  The
			 * insert path CAWs against the slot's actual content
			 * (Bug 93), so recycling stays race-safe even if the
			 * ghost is still writing.
			 */
			if (data_out->resource.volume != resource->volume) {
				if (*empty_out == UINT32_MAX && idx != skip_idx)
					*empty_out = idx;
				continue;
			}
			continue; /* live entry for different resource */
		}

		if (data_out->magic == MXFS_CAW_TOMBSTONE_MAGIC) {
			/* Recyclable: prefer the first tombstone seen as
			 * insertion point, but keep probing — the resource
			 * may live further down the chain. */
			if (*empty_out == UINT32_MAX && idx != skip_idx)
				*empty_out = idx;
			continue;
		}

		/*
		 * sess40 (same root as the claim-compare fix above): only a
		 * ZERO magic is "truly empty / never used".  Any OTHER
		 * unrecognised magic is UNKNOWN — a stale-disk sector or a
		 * bad/torn read — and must not be trusted, because trusting
		 * it here TERMINATES THE PROBE and makes every live entry
		 * further down the chain invisible (observed: a resource
		 * whose live slot sat one index past the terminating slot,
		 * so find_slot returned -ENOENT forever while a peer held
		 * the lock).  Re-read it per-slot first; the span buffer is
		 * not authoritative and slot_appears_corrupt deliberately
		 * ignores non-LIVE magics, so nothing else would re-read it.
		 */
		if (data_out->magic != 0) {
			struct mxfs_caw_lock_slot *rr =
				mxfs_pal_alloc(sizeof(*rr));
			uint32_t span_magic = data_out->magic;
			bool from_span = (span && idx >= span_base &&
					  idx < span_base + span_n);

			if (rr) {
				int rrc = read_slot(ctx, idx, rr);

				if (rrc == 0) {
					*data_out = *rr;
					if (last_read_out)
						*last_read_out = idx;
				}
				mxfs_pal_free(rr);
			}
			/*
			 * sess40 forensic: a SPAN-sourced image whose magic is
			 * unrecognised while a per-slot read of the same LBA
			 * returns a perfectly valid slot means the multi-slot
			 * read path is serving data that disagrees with the
			 * single-sector read path.  Measured 55-100 times per
			 * node per 32-way run.  The classify/CAS paths are now
			 * robust to it (always re-read), but the disagreement
			 * itself is tracked as its own defect.
			 */
			if (from_span && span_magic != data_out->magic) {
				static int p94_n;

				if (p94_n++ < 100) {
					const uint8_t *sb8 = (const uint8_t *)
						&span[idx - span_base];
					const uint8_t *fr8 = (const uint8_t *)
						data_out;

					/* First 16 bytes of both images: if the
					 * span bytes are a SHIFTED view of a
					 * real slot (magic appearing at a
					 * non-zero offset), the transfer is
					 * misaligned for the window tail and
					 * that names the mechanism outright. */
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P94-SPAN-DISAGREE idx=%u span_magic=%x fresh_magic=%x span_base=%u span_n=%u span16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x fresh16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					    idx, span_magic, data_out->magic,
					    span_base, span_n,
					    sb8[0],sb8[1],sb8[2],sb8[3],sb8[4],sb8[5],sb8[6],sb8[7],
					    sb8[8],sb8[9],sb8[10],sb8[11],sb8[12],sb8[13],sb8[14],sb8[15],
					    fr8[0],fr8[1],fr8[2],fr8[3],fr8[4],fr8[5],fr8[6],fr8[7],
					    fr8[8],fr8[9],fr8[10],fr8[11],fr8[12],fr8[13],fr8[14],fr8[15]);
				}
			}
			if (data_out->magic == MXFS_CAW_MAGIC) {
				if (memcmp(&data_out->resource, resource,
					   sizeof(*resource)) == 0) {
					*slot_out = idx;
					slot_hint_store(ctx, resource, idx);
					if (span)
						mxfs_pal_free(span);
					return 0;	/* found after re-read */
				}
				continue;	/* live, different resource */
			}
			if (data_out->magic != 0) {
				/* Still unrecognised on a fresh read: a real
				 * garbage sector.  Recyclable (a claim CASes
				 * against this fresh image and heals it), but
				 * NOT a chain terminator. */
				static int p93_n;

				if (p93_n++ < 100)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P93-SLOT-GARBAGE idx=%u magic=%x — unrecognised on fresh read; recyclable but not terminating the probe",
					    idx, data_out->magic);
				if (*empty_out == UINT32_MAX &&
				    idx != skip_idx)
					*empty_out = idx;
				continue;
			}
			/* fresh read says zero — fall through to terminate */
		}

		/* Truly empty (never used).  Probe chain ends here:
		 * nothing past this point can be a live entry for the
		 * resource — find_slot's invariant is that any live entry
		 * is reachable from its hash base via an unbroken chain of
		 * live-or-tombstone slots. */
		if (*empty_out == UINT32_MAX && idx != skip_idx)
			*empty_out = idx;
		break;
	}

	if (span)
		mxfs_pal_free(span);
	return -ENOENT; /* Not found, empty_out has insertion point */
}

static int find_slot(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource,
		      uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out,
		      uint32_t *empty_out)
{
	return find_slot_skip(ctx, resource, slot_out, data_out, empty_out,
			      UINT32_MAX, NULL, 0);
}

/* Same walk under an absolute deadline — see find_slot_skip.  The owed
 * collector is the only caller; everything else must have a complete walk. */
static int find_slot_deadline(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint32_t *slot_out,
			      struct mxfs_caw_lock_slot *data_out,
			      uint32_t *empty_out, uint64_t deadline)
{
	return find_slot_skip(ctx, resource, slot_out, data_out, empty_out,
			      UINT32_MAX, NULL, deadline);
}

/*
 * sess19 (ccloop 4eef1f39): read the current on-disk generation (ABA counter)
 * for a resource's lock slot.  Used as a SHARED cross-node epoch for AG
 * free-space coherency — see pag_dlm_disk_gen_seen in xfs_ag.h.  The caller
 * (AG fresh-acquire path) holds EX when it calls this, so the value is stable
 * (no peer can modify the slot while we hold it).  Returns 0 + *out_gen on
 * success, -ENOENT if the slot does not exist (resource never locked), or a
 * negative I/O error.
 */
int mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint64_t *out_gen)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx, empty_idx;
	int rc;

	if (!ctx || !resource || !out_gen)
		return -EINVAL;

	slot = kmalloc(sizeof(*slot), GFP_NOFS);
	if (!slot)
		return -ENOMEM;

	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc == 0)
		*out_gen = (uint64_t)slot->generation;
	kfree(slot);
	return rc;
}

/*
 * sess48's mxfs_dlm_caw_read_ex_grant_epoch() lived here and was DELETED in
 * sess110 (step 5.3 ruling blocker 5) along with its only caller.  Reading
 * ex_grant_epoch out of band — in a second slot I/O after an acquire already
 * returned — produces an epoch with NO proven relationship to the grant the
 * caller holds: release+regrant in the window (our own bast drain, or a peer
 * borrowing and returning the resource) makes the read return a nonzero,
 * current, and wrong token, which then gets stamped into durable log records
 * as write authority.  Authority epochs come out of the granting CAS only,
 * via struct mxfs_grant_result.  Do not reintroduce this primitive.
 */

/*
 * sess165 (foreign-replay step 5, shadow evaluator) — the CONSUMER-side
 * counterpart the comment above must not be read as banning.  See the
 * contract comment in dlm_caw.h: this reads a FENCED victim's frozen
 * held-at-death manifest for log-replay evaluation, is stable because the
 * victim cannot CAS and recovery purges only after IMAGES_REPLAYED, and its
 * result must never reach a producer-side path.  Deliberately takes the
 * victim slot EXPLICITLY — it answers "does the VICTIM hold EX here", never
 * "who holds EX", so a caller cannot repurpose it to fish an epoch for its
 * own writes (the sess110 misuse shape).
 */
int mxfs_dlm_caw_victim_manifest_read(struct mxfs_dlm_caw_ctx *ctx,
                                      const struct mxfs_resource_id *resource,
                                      uint32_t victim_slot,
                                      bool *out_holds_ex,
                                      uint64_t *out_ex_grant_epoch,
                                      uint64_t *out_lineage)
{
    struct mxfs_caw_lock_slot *slot;
    uint32_t slot_idx, empty_idx;
    int rc;

    if (!ctx || !resource || !out_holds_ex || !out_ex_grant_epoch ||
        !out_lineage || victim_slot >= 64)
        return -EINVAL;

    slot = kmalloc(sizeof(*slot), GFP_NOFS);
    if (!slot)
        return -ENOMEM;

    rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
    if (rc == 0) {
        *out_holds_ex = !!((slot->holders_ex | slot->holders_pw) &
                           (1ULL << victim_slot));
        *out_ex_grant_epoch = slot->ex_grant_epoch;
        /* same slot image as the fields above — sess175 Q-C, no reread */
        *out_lineage = slot->resource_lineage;
    }
    kfree(slot);
    return rc;
}

/*
 * ccloop(3e02e7dd) sess3: WRITE-ONCE publish of the canonical dir block0 for
 * incarnation `gen` — see the dir_block0_fsb comment in struct
 * mxfs_caw_lock_slot.  Caller holds EX on the inode (the sf->block converter,
 * right after allocating the new block0); the resource's lock-grant state
 * cannot change under us, but the block0 field is published via its own
 * small CAS rather than piggybacked on the acquire CAS, since the fsb is
 * not known until partway through the conversion transaction.  A no-op if a
 * value is already published for this exact gen (first publisher wins); a
 * stored gen from a DIFFERENT incarnation (stale leftover, or unset) is
 * always safely overwritten since only one incarnation is ever live.
 */
void mxfs_dlm_caw_set_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint64_t fsb, uint32_t gen)
{
	struct mxfs_caw_lock_slot *cur, *new;
	uint32_t slot_idx, empty_idx;
	int retry, rc;

	if (!ctx || !resource || ctx->single_node || !fsb)
		return;

	cur = kmalloc(sizeof(*cur), GFP_NOFS);
	new = kmalloc(sizeof(*new), GFP_NOFS);
	if (!cur || !new)
		goto out;

	for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
		rc = find_slot(ctx, resource, &slot_idx, cur, &empty_idx);
		if (rc)
			break;	/* no live slot for a resource we hold EX on —
				 * should not happen; nothing to publish into */
		if (cur->dir_block0_gen == gen && cur->dir_block0_fsb != 0)
			break;	/* already published for this incarnation */
		*new = *cur;
		new->dir_block0_fsb = fsb;
		new->dir_block0_gen = gen;
		new->generation++;
		rc = caw_slot(ctx, slot_idx, cur, new);
		if (rc == -EAGAIN)
			continue;
		if (rc == 0)
			pr_warn_ratelimited(
			    "mxfs: P-BLOCK0-PUBLISH ino=%llu fsb=%llu gen=%u — canonical dir block0 published\n",
			    (unsigned long long)resource->ino,
			    (unsigned long long)fsb, gen);
		break;
	}
out:
	kfree(cur);
	kfree(new);
}

/*
 * sess47: CLAIM-RACE detector (RULE-4 diagnostic for the bnobt stale-pristine
 * clobber).  Scan the ENTIRE probe chain (hash base -> first truly-empty slot,
 * tombstones DON'T terminate) and count LIVE slots whose resource matches
 * `resource`.  The find_slot invariant is exactly-one; >1 means two nodes each
 * claimed a DIFFERENT empty slot for the same resource (each slot internally
 * exclusive, so per-slot exclusion checks P87/CAW-EXCL stay silent) => two
 * nodes hold the resource EX via different slots => one never BASTs the other
 * => stale cached AG buffer written back => corruption.  Gemini-confirmed:
 * must scan the WHOLE chain (the duplicate can be EARLIER OR LATER than ours).
 *
 * Returns the number of live slots found for the resource and, if >1, fills
 * dup_slots[0..min(n,DUPMAX)-1] with their indices.  Bounded scan (caps at
 * MXFS_CAW_CLAIMRACE_SCAN_MAX probes) so a pathological chain can't stall the
 * acquire; logs if the cap is hit.  One probe-chain scan per FRESH claim only
 * (not the hot cached/found path), so the steady-state cost is low.
 */
#define MXFS_CAW_CLAIMRACE_SCAN_MAX 4096
static int caw_count_resource_slots(struct mxfs_dlm_caw_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    uint32_t *dup_slots, int dupmax,
				    uint64_t *holders_ex_or)
{
	struct mxfs_caw_lock_slot *s;
	uint32_t base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	uint32_t i;
	int n = 0;
	bool capped = false;

	if (holders_ex_or)
		*holders_ex_or = 0;
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -1;

	for (i = 0; i < MXFS_CAW_MAX_SLOTS; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;

		if (i >= MXFS_CAW_CLAIMRACE_SCAN_MAX) {
			capped = true;
			break;
		}
		if (read_slot(ctx, idx, s) != 0)
			continue;
		if (s->magic == MXFS_CAW_MAGIC) {
			if (memcmp(&s->resource, resource,
				   sizeof(*resource)) == 0) {
				if (n < dupmax)
					dup_slots[n] = idx;
				if (holders_ex_or)
					*holders_ex_or |= s->holders_ex;
				n++;
			}
			continue;
		}
		if (s->magic == MXFS_CAW_TOMBSTONE_MAGIC)
			continue;
		/* truly-empty: probe chain ends here */
		break;
	}
	if (capped)
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: CAW-CLAIMRACE-SCAN capped at %d probes "
			"(type=%u ag=%u ino=%llu) — chain longer than scan cap",
			MXFS_CAW_CLAIMRACE_SCAN_MAX, resource->type,
			resource->ag_number,
			(unsigned long long)resource->ino);
	mxfs_pal_free(s);
	return n;
}

/* ─── Local held lock tracking ─── */

/*
 * Record slot_index as a lock this mount actively holds.
 *
 * sess53: returns false if the table was full, i.e. the grant could NOT
 * be recorded.  Callers used to ignore that (it only warned), which is
 * safe for the lock itself — the authority is the on-disk bit, not this
 * table — but NOT safe for the settle purge, whose entire discriminator
 * is "is this bit tracked?".  An unrecorded grant looks exactly like a
 * dead incarnation's leftover.  So overflow is also latched in
 * ctx->held_overflow, which permanently disables SKIP_TRACKED purging
 * for this mount (see the field comment in dlm_caw.h).
 */
static bool track_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);

	/* Avoid duplicates */
	for (i = 0; i < ctx->held.count; i++) {
		if (ctx->held.slots[i] == slot_index) {
			mxfs_pal_mutex_unlock(ctx->held.lock);
			return true;
		}
	}

	if (ctx->held.count < ctx->max_held) {
		ctx->held.slots[ctx->held.count++] = slot_index;
		mxfs_pal_mutex_unlock(ctx->held.lock);
		return true;
	}

	ctx->held_overflow = true;
	mxfs_pal_mutex_unlock(ctx->held.lock);

	mxfs_pal_log(MXFS_LOG_ERR,
		     "mxfs: P226-HELD-OVERFLOW disk lock table full (%d "
		     "entries), slot=%u granted but NOT tracked — settle "
		     "purge disabled for this mount",
		     ctx->max_held, slot_index);
	return false;
}

/*
 * sess52 (D-FOREIGN-REPLAY step 4a): is this slot index one WE are
 * actively holding?  "Tracked" is the discriminator the post-recovery
 * settle uses to tell a live hold (adopted or freshly granted) from a
 * dead incarnation's leftover bit.  In steady state ctx->held mirrors
 * our on-disk holder bits exactly — every grant tracks, every release
 * untracks — so the two disagree only across a mount boundary, which is
 * precisely the case being resolved.
 */
static bool is_tracked_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	bool found = false;
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);
	for (i = 0; i < ctx->held.count; i++) {
		if (ctx->held.slots[i] == slot_index) {
			found = true;
			break;
		}
	}
	mxfs_pal_mutex_unlock(ctx->held.lock);

	return found;
}

/*
 * sess53 (D-FOREIGN-REPLAY step 4a) — ADOPT A RETAINED HOLDER BIT.
 *
 * Called from the two mxfs_dlm_caw_lock fast paths, i.e. the paths that
 * observe our own bit already set on disk and return success WITHOUT
 * writing anything.  During the mount adopt window that silence is a
 * hazard: the bit may be one step 4 deliberately retained from our
 * previous incarnation (the authority manifest xlog_recover replays
 * under), and the post-recovery settle is concurrently purging exactly
 * the bits that are not tracked.  A pure read-and-return therefore
 * races:
 *
 *      acquire reads retained EX  ->  settle sees untracked, clears EX
 *                                 ->  acquire tracks, returns success
 *
 * and the node is left holding a local fiction with no on-disk bit.
 * Snapshotting before the purge does not fix this; only making both
 * sides write the same slot does.
 *
 * So adoption performs a real CAS.  It changes nothing semantically —
 * the bit was already ours — but it forces adopt and settle to contend:
 *   - adopt wins   => settle's CAS fails, it re-reads, the slot is now
 *                     tracked, it skips.  Correct.
 *   - settle wins  => adopt's CAS fails with -EAGAIN, the acquire loop
 *                     retries from the top, sees our bit gone and takes
 *                     the normal full-acquire path (fresh grant, new
 *                     epoch).  Correct — replay has finished by settle
 *                     time, so the discarded old epoch costs nothing.
 *
 * ex_grant_epoch is deliberately NOT restamped: adoption inherits the
 * previous incarnation's authority rather than minting new authority
 * (GPT sess52 ruling item 8).  Restamping here would forge a grant that
 * never happened and defeat the whole point of the token.
 *
 * Returns 0 to proceed with the fast path (adopted, or nothing to do),
 * -EAGAIN to retry the acquire loop, or another negative errno on I/O
 * failure.
 */
static int caw_adopt_retained(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint32_t slot_idx,
			      const struct mxfs_caw_lock_slot *cur_slot,
			      struct mxfs_caw_lock_slot *new_slot,
			      uint8_t our_mode)
{
	static int adopt_logged;
	int rc;

	/* Steady state: not in the window, or already ours in this
	 * incarnation.  Hot path — one bool test and a short list scan. */
	if (!ctx->mount_adopt_window)
		return 0;
	if (is_tracked_held(ctx, slot_idx))
		return 0;

	*new_slot = *cur_slot;
	new_slot->generation++;
	new_slot->last_modified_ms = mxfs_pal_time_ms();

	rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
	if (rc)
		return rc;

	track_held(ctx, slot_idx);

	if (adopt_logged < 64) {
		adopt_logged++;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P225-ADOPT-RETAINED type=%u ag=%u "
			     "ino=%llu slot=%u our_mode=%u gen=%llu "
			     "ex_epoch=%llu (inherited, not restamped)",
			     resource->type, resource->ag_number,
			     (unsigned long long)resource->ino,
			     slot_idx, our_mode,
			     (unsigned long long)new_slot->generation,
			     (unsigned long long)new_slot->ex_grant_epoch);
	}

	return 0;
}

static void untrack_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);

	for (i = 0; i < ctx->held.count; i++) {
		if (ctx->held.slots[i] == slot_index) {
			ctx->held.slots[i] =
				ctx->held.slots[--ctx->held.count];
			break;
		}
	}

	mxfs_pal_mutex_unlock(ctx->held.lock);
}

/* ─── UDP BAST multicast send ─── */

static void caw_send_bast_mcast(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource,
				  uint8_t requested_mode)
{
	struct mxfs_caw_bast_notify msg;

	if (!ctx->bast_mcast_sock)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.magic = MXFS_BAST_MAGIC;
	msg.version = 1;
	msg.resource = *resource;
	msg.requester = ctx->local_node;
	msg.requested_mode = requested_mode;
	memcpy(msg.volume_uuid, ctx->volume_uuid, 16);

	/* Fire and forget — best effort hint */
	mxfs_pal_udp_sendto(ctx->bast_mcast_sock, &msg, sizeof(msg),
			     MXFS_DISCOVERY_MCAST, MXFS_CAW_BAST_PORT);
}

/* ccloop 72513a13 sess3: GRANT NUDGE send — fired after a successful slot
 * CAW that a blocked peer is waiting on (release, tombstone, handoff or a
 * self-grant that leaves other waiters grantable).  Wakes their poll sleep
 * immediately; the disk poll remains the lossless backstop.
 *
 * sess35 NUDGE v2 (see dlm_caw.h): wake_mask = the node bits that can act
 * on this slot change.  Receivers outside the mask skip their re-read and
 * keep sleeping, collapsing the ~28-reader herd per release (the measured
 * 21.6ms/handoff of the 32-node create convoy) to one read + one CAS. */
static void caw_send_grant_mcast(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint64_t wake_mask)
{
	struct mxfs_caw_bast_notify msg;

	if (!ctx->bast_mcast_sock)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.magic = MXFS_GRANT_MAGIC;
	msg.version = 2;
	msg.resource = *resource;
	msg.requester = ctx->local_node;
	msg.requested_mode = 0;
	memcpy(msg.volume_uuid, ctx->volume_uuid, 16);
	msg.wake_mask = wake_mask;

	mxfs_pal_udp_sendto(ctx->bast_mcast_sock, &msg, sizeof(msg),
			     MXFS_DISCOVERY_MCAST, MXFS_CAW_BAST_PORT);
}

/* Snapshot the nudge sequence BEFORE the caller's slot read; the paired
 * caw_nudge_wait() then cannot sleep through a nudge that raced in
 * between (it re-checks the seq under the lock before waiting). */
static uint64_t caw_nudge_prepare(struct mxfs_dlm_caw_ctx *ctx)
{
	uint64_t seq;

	if (!ctx->nudge_lock)
		return 0;
	mxfs_pal_mutex_lock(ctx->nudge_lock);
	seq = ctx->nudge_seq;
	mxfs_pal_mutex_unlock(ctx->nudge_lock);
	return seq;
}

/*
 * sess35 NUDGE v2: does any nudge in (from_seq, nudge_seq] want THIS waiter
 * awake?  Called under nudge_lock.  Conservative in every uncertain case
 * (missed/overwritten entries, v1 senders): returns true, which just costs
 * one slot read — the pre-v2 behavior.
 */
static bool caw_nudge_ring_wants_wake(struct mxfs_dlm_caw_ctx *ctx,
				      uint64_t from_seq,
				      const struct mxfs_resource_id *res)
{
	uint64_t s;

	if (ctx->nudge_seq <= from_seq)
		return false;
	if (ctx->nudge_seq - from_seq > MXFS_CAW_NUDGE_RING)
		return true;	/* fell off the ring: fall back to a read */
	for (s = from_seq + 1; s <= ctx->nudge_seq; s++) {
		struct mxfs_caw_nudge_rec *r =
			&ctx->nudge_ring[s % MXFS_CAW_NUDGE_RING];

		if (r->seq != s)
			return true;	/* unexpected: conservative wake */
		if (r->version < 2)
			return true;	/* v1 nudge carries no target info */
		if (memcmp(&r->resource, res, sizeof(*res)) != 0)
			continue;	/* different resource: irrelevant */
		if (r->wake_mask == 0 || (r->wake_mask & ctx->node_bit))
			return true;	/* our turn (or untargeted wake-all) */
		/* targeted at someone else: keep sleeping; the poll
		 * interval bounds the wait (stale tickets, lost nudges,
		 * PR patience clocks all ride that backstop). */
	}
	return false;
}

/* P297 (sess296, D-503 ruling step 1): returns true iff the wait ended
 * because a relevant nudge arrived (wake attribution for the handoff
 * timeline); false = poll-interval backstop (or no nudge machinery). */
static bool caw_nudge_wait(struct mxfs_dlm_caw_ctx *ctx, uint64_t seen_seq,
			   uint32_t ms, const struct mxfs_resource_id *res)
{
	uint64_t deadline;
	bool nudged = true;

	if (!ctx->nudge_lock || !ctx->nudge_cond) {
		mxfs_pal_sleep_ms(ms);
		return false;
	}
	deadline = mxfs_pal_time_ms() + ms;
	mxfs_pal_mutex_lock(ctx->nudge_lock);
	while (!caw_nudge_ring_wants_wake(ctx, seen_seq, res)) {
		uint64_t prev = ctx->nudge_seq;
		uint64_t now = mxfs_pal_time_ms();
		uint64_t t0;

		/* everything up to prev is judged irrelevant — consume it */
		seen_seq = prev;
		if (now >= deadline) {
			nudged = false;
			break;		/* poll backstop: do the slot read */
		}
		t0 = now;
		mxfs_pal_cond_timedwait(ctx->nudge_cond, ctx->nudge_lock,
					(uint32_t)(deadline - now));
		if (ctx->nudge_seq == prev) {
			if (mxfs_pal_time_ms() - t0 < 1) {
				/* Interruptible wait returned immediately
				 * with no nudge (pending signal).  Burn the
				 * remaining interval the way the old
				 * uninterruptible sleep_ms did so the
				 * acquire loop cannot busy-spin slot reads
				 * until timeout. */
				uint64_t left = deadline - mxfs_pal_time_ms();

				mxfs_pal_mutex_unlock(ctx->nudge_lock);
				if ((int64_t)left > 0)
					mxfs_pal_sleep_ms((uint32_t)left);
				return false;
			}
			nudged = false;
			break;		/* timed out: poll backstop read */
		}
	}
	mxfs_pal_mutex_unlock(ctx->nudge_lock);
	return nudged;
}

/* P297: locked one-shot query — did any nudge in (from_seq, now] want THIS
 * waiter awake?  Used to detect a nudge that raced into the window between
 * the caller's slot read and the sleep's own caw_nudge_prepare(): such a
 * nudge is invisible to caw_nudge_wait (it consumes only seq > its snapshot)
 * and the waiter oversleeps the full poll interval.  Detection only — the
 * D-503 ruling orders the measurement before the fix. */
static bool caw_nudge_check(struct mxfs_dlm_caw_ctx *ctx, uint64_t from_seq,
			    const struct mxfs_resource_id *res)
{
	bool w;

	if (!ctx->nudge_lock)
		return false;
	mxfs_pal_mutex_lock(ctx->nudge_lock);
	w = caw_nudge_ring_wants_wake(ctx, from_seq, res);
	mxfs_pal_mutex_unlock(ctx->nudge_lock);
	return w;
}

/* sess39: forward decl — defined just before mxfs_dlm_caw_lock. */
static void caw_check_exclusion(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				const struct mxfs_caw_lock_slot *slot,
				uint8_t mode);
static void caw_verify_grant_persisted(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       uint32_t slot_idx, uint8_t mode);

/*
 * sess48 (ccloop 14d31183) PROVEN ROOT FIX — phantom EX-waiter leak.
 *
 * When a waiter GIVES UP (grant timeout, retry exhaustion) it MUST drop its
 * own bit from slot->waiters.  Otherwise a stale EX-waiter bit makes every
 * peer's defer_for_waiter (mxfs_dlm_caw_lock) defer fresh PR/SHARED acquires
 * FOREVER — proven this session: a 16-node barrier-directory wedge where the
 * slot froze at waiter_mode=EX h_ex=0 h_pr=multi, every blocked thread across
 * all 16 nodes was a SHARED reader (find/ls readdir), and NO thread anywhere
 * in the cluster was actually requesting EX.  The two EX "waiters" were
 * orphaned bits; defer_for_waiter then starved all readers → cluster phase
 * >600s → posix_semantics_multi16 FAIL.
 *
 * The OLD cleanup (in caw_wait_for_grant timeout) was a bounded 10-iteration
 * CAS loop.  Under the 16-node CAS storm on a hot shared-dir slot all 10
 * compare-and-write attempts lose the race to peers' concurrent writes, so the
 * bit is left set permanently; once the contention burst ends the slot
 * generation freezes with the orphan bit still there and nothing ever clears
 * it.  Retry with backoff until a FRESH read confirms our bit is clear (or the
 * slot is gone).  The common case exits immediately (bit already clear or CAS
 * wins on the first try).
 *
 * sess128 (GPT sess126 ruling, blocker 1): the retry policy is a WALL-CLOCK
 * BUDGET, never again an attempt count — see the budget block in dlm_caw.h.
 * `deadline` is absolute; 0 means "derive one", which is what every caller but
 * the collector passes, because the right budget depends on something only this
 * function knows: whether an obligation actually got recorded for the bits (in
 * which case the worker owns persistence and this thread may leave quickly) or
 * whether there is no registry at all (in which case this thread is the only
 * collector the bit will ever get).  Expiry returns -ETIMEDOUT, which the
 * collector reads as "stop this dispatch", not as contention.
 */
static int caw_drop_own_waiter(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_idx,
			       const struct mxfs_resource_id *resource,
			       struct mxfs_caw_lreq *e, bool self_joined,
			       uint8_t giveup_mode, bool collector,
			       uint64_t deadline)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	struct mxfs_caw_clear_plan plan;
	struct mxfs_caw_lreq *clr = NULL;
	struct mxfs_caw_lreq *owed;
	struct mxfs_caw_owed_intent intent;
	bool committed = false;
	bool proven = false;
	bool terminal = false;
	uint64_t gen0 = 0;
	int attempt;
	int rc = 0;
	uint32_t backoff = 1;

	/*
	 * sess122 (GPT sess121 ruling item 1): PUBLISH THE OBLIGATION FIRST,
	 * before any of the I/O that could discharge it, and publish the MAXIMAL
	 * one — everything this give-up could possibly leave behind.  Retraction
	 * below gives back only what the pass proves clear.
	 *
	 * The ordering is the whole point.  Under the sess112 shape the record
	 * was written when a plan REFUSED something, i.e. after the decision and
	 * often after the I/O, so every way the caller could leave early — the
	 * "nothing permitted" return, an allocation failure, a read error, a
	 * hard CAS error — left a bit on disk that nothing had written down.  A
	 * record published up front cannot be lost by any exit path, and an
	 * over-broad record costs only a worker pass that finds the bit already
	 * clear and discharges it.
	 *
	 * sess127 (GPT sess126 ruling, blocker 5): `collector` inverts that.  The
	 * owed worker is not taking on an obligation, it is DISCHARGING one it
	 * already owns, so it publishes nothing at all — see
	 * lreq_clr_begin_existing for why re-publishing is not merely redundant
	 * but breaks concurrent retractions.  (The sess124 shape had the worker
	 * pass down the intent it was collecting, which kept the record from
	 * re-inflating to maximal but still bumped owed_gen once per mode.)
	 */
	if (!collector) {
		intent.holder_mask = (giveup_mode != MXFS_LOCK_NL &&
				      giveup_mode < MXFS_LOCK_MODE_COUNT) ?
					(1u << giveup_mode) : 0;
		intent.waiters = true;
		intent.waiters_ex = true;
		intent.slot_hint = slot_idx;
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));

	/*
	 * sess117: declare the clear window BEFORE the first slot read, so a
	 * concurrent memory-only publication (already-held shortcut, adopt) can
	 * see that its image may be about to be invalidated.  If the registry
	 * is present but the window cannot be opened, REFUSE the clear and owe
	 * it: an unlinearized destructive clear is exactly the corruption this
	 * mechanism exists to prevent, and the owed record loses nothing.
	 *
	 * sess124: this is ALSO where the obligation is published, and it is
	 * opened BEFORE the plan is evaluated rather than after.  Both changes
	 * are required, for the same reason: publication has to precede every
	 * exit that can leave a bit behind, and the plan's "nothing permitted"
	 * exit is one of them.  Opening the window here also lets find-or-create
	 * cover the case `e == NULL` — a claim-exhaustion give-up that never
	 * registered on this resource still gets its obligation recorded, on the
	 * entry this call creates.  The cost is that the window is open across
	 * one extra mutex round-trip, which can bounce a concurrent publication
	 * into a retry; that is a microsecond of liveness against a permanent
	 * on-disk leak.
	 */
	if (collector) {
		/*
		 * sess127: the collector's entry is already live and pinned by
		 * the sweep claim, so the window cannot fail to open and the
		 * reserve is never touched.  `e` IS the entry the obligation
		 * lives on.
		 */
		lreq_clr_begin_existing(ctx, e, &gen0);
		clr = e;
	} else if (ctx->lreq && ctx->lreq_lock) {
		if (lreq_clr_begin_wait(ctx, resource, &intent, NULL, &gen0,
					&clr, 0) < 0) {
			ctx->lreq_nomem++;
			pr_warn_ratelimited("mxfs: P251-LREQ-DRY clear-window slot=%u mode=%u dry=%llu — give-up cleanup refused and owed (cannot linearize against local publication)\n",
					    slot_idx, giveup_mode,
					    (unsigned long long)ctx->lreq_reserve_dry);
			/* The reserve is dry, so there is no entry to record
			 * the obligation ON.  Counted (P251 / lreq_reserve_dry)
			 * and retryable — the caller's acquire loop comes back
			 * round, and by then a closing window has restocked. */
			mxfs_pal_free(cur_slot);
			mxfs_pal_free(new_slot);
			return -EAGAIN;
		}
	}

	/*
	 * The entry the obligation lives on.  `clr` when the window armed —
	 * that is the entry find-or-create just published into, and when the
	 * caller also passed `e` they are necessarily the same object (entries
	 * are unique per resource and `e` is held live by an attempt or a pin).
	 * `e` otherwise, which is the no-registry legacy case where both are
	 * NULL and every registry operation below is a no-op.
	 */
	owed = clr ? clr : e;

	/*
	 * sess128 (blocker 1): derive the budget now that we know whether the
	 * obligation is RECORDED.  `owed` plus a live registry means the worker
	 * will come back for whatever this pass fails to prove clear, so this
	 * thread leaves quickly.  With neither, nothing else will ever try —
	 * there is no record, no collector, and no second chance — so the long
	 * budget is the only thing standing between a lost CAS race and a
	 * permanent EX-waiter leak.
	 */
	if (!deadline)
		deadline = mxfs_pal_time_ms() +
			   ((owed && ctx->lreq && ctx->lreq_lock) ?
			    MXFS_CAW_DROP_OWED_MS : MXFS_CAW_DROP_UNOWED_MS);

	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		lreq_clr_end(ctx, clr, false);
		return -ENOMEM;		/* obligation stands; worker retries */
	}

	/*
	 * sess112: ASK THE REGISTRY FIRST.  ctx->node_bit alone cannot say
	 * whether these bits are ours to drop — several local threads share it
	 * (see the registry comment in dlm_caw.h).  The plan is fail-closed:
	 * anything it refuses stays owed and is re-collected by the owed worker,
	 * so a refusal never becomes a permanent leak.
	 *
	 * sess117: this first evaluation only answers "is there any work at
	 * all?".  The plan the CAS uses is re-derived on every iteration below,
	 * because the loop drops all locks across a slot read and a CAS: a
	 * tenure published in that gap was invisible to a once-evaluated plan,
	 * and the clear then stripped the very bit that tenure depends on.
	 */
	lreq_plan(ctx, e, giveup_mode, self_joined, &plan);
	if (!plan.waiters && !plan.waiters_ex && !plan.holder) {
		/* Nothing we are permitted to touch.  The obligation stays
		 * published for the worker — except a moot holder bit, which
		 * discharges here (see struct mxfs_caw_clear_plan). */
		lreq_owed_retract(ctx, owed, gen0, &plan, giveup_mode, false,
				  false);
		lreq_clr_end(ctx, clr, false);
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return 0;
	}

	for (attempt = 0; ; attempt++) {
		uint64_t *ghp;
		bool do_w, do_wx, do_h;

		/*
		 * sess128 (blocker 1): the budget check sits BEFORE the slot
		 * read, so an expired deadline costs no I/O at all.  It is also
		 * the loop's only exit-by-exhaustion — there is no attempt cap
		 * any more, because a count says nothing about elapsed time and
		 * an attempt here is two I/Os plus a sleep.
		 */
		if (mxfs_pal_time_ms() >= deadline) {
			rc = -ETIMEDOUT;
			break;
		}

		rc = read_slot(ctx, slot_idx, cur_slot);
		if (rc)
			break;	/* slot read error — give up */
		if (cur_slot->magic != MXFS_CAW_MAGIC) {
			/* sess122: a tombstone took the whole slot record with
			 * it, bitmaps included, so every bit of ours that lived
			 * here is provably gone.  TERMINAL — discharge all. */
			rc = 0;
			terminal = true;
			break;
		}
		/*
		 * sess112: the slot index reaching here is a REMEMBERED one —
		 * the last slot this acquire probed, captured up to a full
		 * acquire timeout ago, and the claim-exhaustion caller may
		 * never have registered on it at all.  A slot that was
		 * tombstoned and re-claimed in the meantime carries a
		 * DIFFERENT resource, and our node bit in it would then be a
		 * live registration for that other resource.  Clearing it
		 * would silently cancel an unrelated lock.  Identity is
		 * checked by content, never assumed from the index.
		 */
		if (memcmp(&cur_slot->resource, resource,
			   sizeof(*resource)) != 0) {
			/*
			 * Slot recycled — these bits are not ours.  TERMINAL
			 * too, and the ABA argument is the one that makes it
			 * sound (GPT sess121 ruling item B): a recycle passed
			 * through a tombstone, which erased our bits; a fresh
			 * slot for this resource can only carry our bit if a
			 * NEW local attempt set it, and that attempt is exactly
			 * what makes lreq_plan refuse.  The gen guard in
			 * lreq_owed_retract catches the obligation such an
			 * attempt would publish on its own way out.
			 */
			rc = 0;
			terminal = true;
			break;
		}
		/*
		 * sess37 ABORT RECONCILE (GPT ruling, direct-handoff design):
		 * a give-up must also look for a GRANT that landed for the
		 * very acquire it is abandoning — either a releaser's direct
		 * handoff CAS that raced this cleanup, or this acquire's own
		 * promote CAW whose completion was ambiguous (reported
		 * miscompare but actually landed: the sess34 SIGKILL wedge
		 * shape, wire EX with no in-core tenure, 350s cluster
		 * starvation).  giveup_mode names the mode the abandoned
		 * acquire wanted; clear our bit there in the SAME CAS as the
		 * waiter-bit clear.  Callers that legitimately hold another
		 * mode (upgrader keeping PR while its EX wait timed out) are
		 * unaffected — only the abandoned mode's bit is touched.
		 */
		ghp = (giveup_mode != MXFS_LOCK_NL) ?
			holders_for_mode(cur_slot, giveup_mode) : NULL;

		/*
		 * sess117: re-derive the plan HERE — against the image we are
		 * about to CAS on, as late as possible before the CAS.  The
		 * clear window is open, so no memory-only publication (shortcut
		 * / adopt) can slip into the plan→CAS gap; a slow-path grant
		 * that does write the slot makes the CAS miscompare, and its
		 * grantee is still a joined attempt (or has already raised
		 * tenure[]) when we come back round, so this re-derivation sees
		 * it and refuses.
		 */
		lreq_plan(ctx, e, giveup_mode, self_joined, &plan);

		/* Only bits the plan permits AND that are actually set count
		 * as work; everything else is left exactly as found. */
		do_w  = plan.waiters && (cur_slot->waiters & ctx->node_bit);
		do_wx = plan.waiters_ex && (cur_slot->waiters_ex & ctx->node_bit);
		do_h  = plan.holder && ghp && (*ghp & ctx->node_bit);

		if (!do_w && !do_wx && !do_h) {
			/* sess122 proof (b): no permitted bit is set in this
			 * image, so the plan's whole permitted set is clear. */
			rc = 0;
			proven = true;
			break;
		}

		if (do_h)
			pr_warn_ratelimited("mxfs: P6H-ABORT-RECONCILE slot=%u mode=%u gen=%llu — grant landed for an abandoned acquire (handoff race or ambiguous CAW); releasing in the abort's own cleanup CAS\n",
				slot_idx, giveup_mode,
				(unsigned long long)cur_slot->generation);

		*new_slot = *cur_slot;
		if (do_w)
			new_slot->waiters &= ~ctx->node_bit;
		if (do_wx)
			new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50: drop our exclusive-waiter bit too */
		/* sess299: a sticky reservation (ruling item 8) dies ONLY on
		 * deregister/cancel/fence/purge — this is the cancel leg, so
		 * retire any ticket naming us in the same CAS that drops our
		 * waiter registration, rather than leaving a dead reservation
		 * for the waiter-side invalidity clear to age out. */
		if ((do_w || do_wx) && (new_slot->yield_to & ctx->node_bit))
			new_slot->yield_to &= ~ctx->node_bit;
		if (do_h) {
			uint64_t *nhp = holders_for_mode(new_slot, giveup_mode);

			if (nhp)
				*nhp &= ~ctx->node_bit;
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
		}
		new_slot->waiter_mode = recompute_waiter_mode(new_slot);
		new_slot->generation++;
		new_slot->last_modified_ms = mxfs_pal_time_ms();

		if (caw_inject_take(&mxfs_caw_inject_dow_casfail))
			rc = -EIO;	/* sess154 K5: transient discharge fail */
		else
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		/*
		 * sess117: a destructive clear COMMITTED.  Any local publication
		 * that snapshotted before this must now refuse and retry from a
		 * fresh image.
		 *
		 * sess119 (ruling item 3): "committed" means MAY-HAVE-CHANGED,
		 * not DEFINITELY-CHANGED.  An I/O error is not evidence that the
		 * CAW failed to reach the target, so it too closes the window as
		 * committed — otherwise a clear that actually landed is invisible
		 * to every publication validating across this window.
		 */
		if (caw_may_have_written(rc))
			committed = true;
		if (rc == 0) {
			/* sess122 proof (a): the CAS landed on an image in
			 * which every permitted bit was either clear already or
			 * cleared by this write. */
			proven = true;
			break;			/* cleared */
		}
		if (rc != -EAGAIN)
			break;			/* hard error — give up */

		/*
		 * Lost the CAS race against a concurrent slot write — back off
		 * and re-read.  We keep trying: leaving our bit set is a
		 * cluster-wide liveness bug, not a best-effort nicety.
		 *
		 * sess128: the nap is CLAMPED to what is left of the budget.  An
		 * unclamped 8ms sleep on a 200ms budget overshoots by up to 4%
		 * per attempt, and on the teardown drain's shared deadline the
		 * overshoot is what the deadline exists to prevent.
		 */
		{
			uint64_t now = mxfs_pal_time_ms();
			uint64_t left = now < deadline ? deadline - now : 0;
			uint32_t nap = backoff;

			if (nap > left)
				nap = (uint32_t)left;
			if (nap)
				mxfs_pal_sleep_ms(nap);
		}
		if (backoff < 8)
			backoff *= 2;
	}

	/*
	 * sess112 (D-RECONCILE-EXHAUSTION-SILENT): this used to return void.
	 * A cleanup that ran out of attempts left a live EX-waiter bit behind
	 * and the caller walked back into normal service knowing nothing — and
	 * a leaked EX-waiter bit is precisely what wedged 16 nodes for >600s
	 * (every peer's defer_for_waiter deferring fresh readers behind a
	 * request nobody was making any more).  Failure is now OBSERVABLE and
	 * OWED: the bit is re-queued on the registry entry so the last local
	 * attempt to leave this resource tries again with a fresh plan.
	 *
	 * sess122: the requeue is no longer done HERE — the obligation was
	 * published before the first read and has simply never been retracted,
	 * which is strictly stronger (it also covers the exits above that never
	 * reach this point).  What remains here is the observability half.
	 */
	if (rc) {
		ctx->lreq_exhausted++;
		pr_warn_ratelimited("mxfs: P245-RECONCILE-EXHAUST type=%c id=%llu slot=%u mode=%u attempts=%d rc=%d w=%d wx=%d h=%d — give-up cleanup never confirmed clear (rc=-110 is the sess128 wall-clock budget, not an attempt cap); obligation stands\n",
			resource->type == MXFS_LTYPE_INODE ? 'I' :
			resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
			(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
				resource->ino : (uint64_t)resource->ag_number),
			slot_idx, giveup_mode, attempt, rc,
			plan.waiters, plan.waiters_ex, plan.holder);
	}

	/*
	 * sess122: give back exactly what was proved, gen-guarded.  Runs BEFORE
	 * the window closes so a publication released by that close cannot
	 * observe a half-retracted entry — the same ordering the sess117 owed
	 * re-record had, for the same reason.
	 */
	lreq_owed_retract(ctx, owed, gen0, &plan, giveup_mode, proven, terminal);

	lreq_clr_end(ctx, clr, committed);

	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/*
 * ══════════════════════════════════════════════════════════════════════════
 *  sess125: THE OWED-CLEANUP WORKER  (GPT sess121 ruling on blocker 2)
 * ══════════════════════════════════════════════════════════════════════════
 *
 * The collector half of the obligation state machine.  Publication (sess122-124)
 * guarantees that every destructive clear writes down what it might leave
 * behind BEFORE the I/O that would discharge it; this is what guarantees the
 * record is eventually acted on.
 *
 * WHAT IT REPLACES, AND WHY THAT HAD TO GO.  Until now the only collector was
 * an inline pass at the bottom of lreq_finish, run by whichever local attempt
 * happened to be the last one out.  Three independent failures:
 *
 *   1. NO COLLECTOR IN THE COMMON CASE.  An obligation published by a resource
 *      whose local attempts have all already left is collected by the NEXT
 *      attempt on that resource — which on a cold resource is never.  A leaked
 *      EX-waiter bit then makes every peer's defer_for_waiter stall fresh
 *      readers behind a request nobody is making: the measured 16-node >600s
 *      wedge this whole line of work exists to kill.
 *   2. IT RAN ON A LOCK-ACQUIRE THREAD.  The collection is a destructive CAS
 *      loop against a contended slot; charging it to whichever unlucky thread
 *      finished last put unbounded disk latency inside an XFS operation.
 *   3. IT COULD NOT RETRY.  One pass, then the attempt was gone.  A pass that
 *      loses every CAS achieved nothing and nothing came back.
 *
 * The worker fixes all three by construction: it is woken by every event that
 * can make an obligation runnable, it owns its own thread, and it retries with
 * exponential backoff INDEFINITELY.  It never abandons a record — escalation
 * means shouting (P253) and, at teardown, refusing to exit quietly (P254).
 */

/*
 * Resolve a resource to the slot that currently holds it.
 *
 * 0            — *slot_idx is the live slot.
 * -ENOENT      — THE TERMINAL PROOF.  find_slot walks the probe chain from the
 *                resource's hash base and only a never-used slot terminates it
 *                (tombstones and foreign live entries do not), so -ENOENT means
 *                no slot anywhere holds this resource.  Our bits live only in a
 *                slot whose resource field matches, so there is nowhere left
 *                for one to be set: the obligation is discharged, not deferred.
 * -ETIMEDOUT   — sess128: the walk ran out of budget.  Proves NOTHING, and in
 *                particular is not the terminal proof: a truncated walk cannot
 *                distinguish "absent" from "not reached".  Kept distinct from
 *                -ENOENT for exactly that reason.
 * other < 0    — I/O error.  Proves nothing; the obligation stands.
 *
 * find_slot_skip dereferences BOTH out-params unconditionally, so `data` and
 * `empty` must be real storage — passing NULL for the ones we do not care about
 * would fault.
 */
static int caw_owed_resolve(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t *slot_idx, uint64_t deadline)
{
	struct mxfs_caw_lock_slot *data;
	uint32_t empty = UINT32_MAX;
	int rc;

	*slot_idx = UINT32_MAX;
	data = mxfs_pal_alloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	rc = find_slot_deadline(ctx, resource, slot_idx, data, &empty, deadline);
	mxfs_pal_free(data);
	return rc;
}

/*
 * Run one collection pass over `e`.  The caller (caw_owed_sweep) has already
 * claimed the entry — owed_busy is set and pin is raised — so the pointer stays
 * valid across every unlocked section here and no second sweep can select it.
 *
 * The record is re-read under the lock rather than trusted from the claim,
 * because a publication may have merged into it since.
 *
 * sess127 (GPT sess126 ruling, blocker 5): the pass publishes NOTHING.  It used
 * to hand the flags it had just read back down as an intent, which kept the
 * record from re-inflating to the maximal give-up intent but still merged (and
 * so bumped owed_gen) once per mode; see lreq_clr_begin_existing for why that
 * breaks concurrent retractions.  The record is now re-read AFTER EACH MODE
 * instead, which is what the intent hand-down was standing in for and is
 * strictly better: a mode discharged by a concurrent local clear is not
 * re-attempted, and a dispatch whose obligation went terminal on the first mode
 * stops immediately rather than doing I/O for every remaining bit of a snapshot
 * that no longer describes anything.
 *
 * sess128 (GPT sess126 ruling, blocker 1): `deadline` is an ABSOLUTE wall-clock
 * budget for this whole pass, checked before the resolve and again before each
 * mode, and handed down into both the resolve walk and every CAS loop.  In the
 * running worker it is a per-entry budget; during teardown it is the drain's
 * single shared deadline, which is what turns DRAIN_MS from a value checked
 * between sweeps into one that actually bounds a sweep.
 *
 * Returns TRUE if the pass did (or tried to do) real work, FALSE if it declined
 * because the budget was already gone.  The caller uses that to decide whether
 * the entry earned a failure count and a backoff — charging a retry to an entry
 * that was never attempted would walk it toward escalation for free.
 */
static bool caw_owed_dispatch(struct mxfs_dlm_caw_ctx *ctx,
			      struct mxfs_caw_lreq *e, uint64_t deadline)
{
	struct mxfs_resource_id resource;
	uint32_t mask, slot_idx = UINT32_MAX;
	uint32_t hint;
	uint64_t gen0;
	bool w, wx;
	int m, rc;

	if (mxfs_pal_time_ms() >= deadline)
		return false;		/* out of budget before any I/O */

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	resource = e->resource;
	mask = e->owed_holder_mask;
	w    = e->owed_waiters;
	wx   = e->owed_waiters_ex;
	hint = e->owed_slot_hint;
	gen0 = e->owed_gen;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	if (!mask && !w && !wx)
		return true;		/* discharged while we were claiming it */

	ctx->lreq_owed_disp++;

	/*
	 * CANONICAL RESOLUTION, EVERY PASS.  The obligation names a RESOURCE,
	 * never a slot (see struct mxfs_caw_lreq): a stored index could be
	 * overwritten by a second obligation and would have to reason about
	 * tombstone→recycle ABA.  owed_slot_hint is diagnostic only and is
	 * deliberately not used to select what gets written.
	 */
	rc = caw_owed_resolve(ctx, &resource, &slot_idx, deadline);
	/* sess154 K2: force the terminal path — the resource resolved, but the
	 * test wants the retract-everything disposition exercised on demand. */
	if (rc == 0 && caw_inject_take(&mxfs_caw_inject_owed_enoent))
		rc = -ENOENT;
	if (rc == -ENOENT) {
		/*
		 * Terminal.  Retract EVERYTHING, gen-guarded — an obligation
		 * published after our snapshot describes bits that may live in
		 * a slot claimed since we resolved, so it must survive.
		 */
		lreq_owed_retract(ctx, e, gen0, NULL, MXFS_LOCK_NL, false, true);
		return true;
	}
	if (rc) {
		pr_warn_ratelimited("mxfs: P252-OWED-RESOLVE type=%c id=%llu hint=%u rc=%d — cannot resolve an owed resource to its slot (rc=-110 is the sess128 budget expiring mid-walk, NOT an I/O error and NOT proof of absence); obligation stands\n",
			resource.type == MXFS_LTYPE_INODE ? 'I' :
			resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
			(unsigned long long)(resource.type == MXFS_LTYPE_INODE ?
				resource.ino : (uint64_t)resource.ag_number),
			hint, rc);
		return true;		/* proves nothing — retry with backoff */
	}

	/*
	 * One pass per owed HOLDER mode; each carries the waiter clears with it
	 * (caw_drop_own_waiter clears waiters, waiters_ex and the one holder bit
	 * in a single CAS).  Intersecting with the SNAPSHOT mask is what bounds
	 * this: a mode is attempted at most once per dispatch even if a
	 * concurrent publication re-adds it, so a hot resource cannot hold the
	 * worker slot.  The FRESH mask is re-read each time round so a mode
	 * already discharged since the snapshot costs no I/O at all.
	 *
	 * self_joined = false: the worker never joined an attempt, so it must
	 * not subtract itself from the live-attempt count — doing so would read
	 * one live local attempt as zero and authorise stripping a bit that
	 * attempt is still relying on (the sess117 correction, same shape).
	 */
	if (mask) {
		for (m = MXFS_LOCK_CR; m < MXFS_LOCK_MODE_COUNT; m++) {
			uint32_t fresh;

			if (!(mask & (1u << m)))
				continue;

			/* sess127 (blocker 5): re-read under the lock before
			 * every mode.  Three things can have changed since the
			 * snapshot — a concurrent local clear proved a mode
			 * clear, the previous mode's pass went terminal and
			 * retracted everything, or a publication added bits we
			 * deliberately do not chase this pass. */
			mxfs_pal_mutex_lock(ctx->lreq_lock);
			fresh = e->owed_holder_mask;
			w = e->owed_waiters;
			wx = e->owed_waiters_ex;
			mxfs_pal_mutex_unlock(ctx->lreq_lock);

			if (!fresh && !w && !wx)
				break;		/* nothing owed any more */
			if (!(fresh & (1u << m)))
				continue;	/* this mode discharged already */

			/* sess128 (blocker 1): and again before each mode —
			 * the previous mode's CAS loop can have consumed the
			 * whole remaining budget by itself. */
			if (mxfs_pal_time_ms() >= deadline)
				break;

			rc = caw_drop_own_waiter(ctx, slot_idx, &resource, e,
						 false, (uint8_t)m, true,
						 deadline);
			ctx->lreq_owed_runs++;
			/*
			 * -EAGAIN (reserve dry) is contention: the next mode
			 * may still make progress, and the obligation stands
			 * either way.  Anything else is either a hard I/O or
			 * memory failure that every remaining mode would hit
			 * too, or (sess128) -ETIMEDOUT, which says the budget
			 * for this whole pass is gone.  Both mean stop burning
			 * the LUN and let the backoff space the retry out.
			 */
			if (rc && rc != -EAGAIN)
				break;
		}
	} else {
		caw_drop_own_waiter(ctx, slot_idx, &resource, e, false,
				    MXFS_LOCK_NL, true, deadline);
		ctx->lreq_owed_runs++;
	}
	return true;
}

/*
 * Release a claimed entry.  If anything is still owed, arm the backoff and
 * escalate when the entry has failed often enough to mean something is wrong
 * rather than merely contended.
 *
 * lreq_gc CAN FREE `e` — every field the log needs is captured into locals
 * before that call, and `e` is not touched after it.
 *
 * sess127 (GPT sess126 ruling, blocker 6): returns the wall-clock time this
 * entry next becomes eligible, or 0 if it owes nothing any more.  The worker's
 * park interval is derived from these — the release happens AFTER the sweep's
 * locked walk, so an entry re-armed here is invisible to that walk and would
 * otherwise be slept past.
 *
 * sess128 (GPT sess126 ruling, blocker 1): `attempted` is false when the sweep
 * claimed the entry but the deadline expired before anything was tried.  Such
 * an entry gets its claim handed straight back — no failure count, no backoff —
 * because charging a retry to work that never ran walks a perfectly healthy
 * obligation toward the P253 escalation bar for free, and the drain, which is
 * where this happens, is the one path that reclaims nothing at all.
 */
static uint64_t caw_owed_release(struct mxfs_dlm_caw_ctx *ctx,
				 struct mxfs_caw_lreq *e, bool attempted)
{
	struct mxfs_resource_id resource;
	uint32_t fails = 0, mask = 0, shift;
	uint64_t backoff, next_ms = 0;
	bool w = false, wx = false, pending, stuck = false;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e->owed_busy = false;
	if (e->pin)
		e->pin--;

	pending = lreq_owed_pending(e);
	resource = e->resource;
	/*
	 * ─── sess154: THE TEARDOWN TENURE RETIRE (P248 fix A, GPT sess153
	 *     ruling) ───
	 *
	 * D-RELEASEALL-LREQ-RETIRE-MISSING: when release_all's CAS loses and
	 * the slot becomes an OBLIGATION, the obligation's later completion
	 * clears the node's bits on disk — but nothing retired the registry
	 * entry's tenure[], so the entry survived to the destroy census as a
	 * P248 "leak" even though the disk state it described was gone.
	 *
	 * Retire here, on an EXPLICIT disposition only:
	 *   attempted          — work actually ran (a deadline handback must
	 *                        not retire; the obligation still stands);
	 *   !pending           — the obligation is DISCHARGED, not requeued;
	 *   ops_closed &&      — co-held only from stop() phase 4 onward (the
	 *   release_all_done     mount.c pre-stop release_all cannot arm this:
	 *                        ops_closed is false there, and stop()'s
	 *                        election re-clears release_all_done), i.e.
	 *                        every attempt has departed, every publisher
	 *                        is joined, and no new tenure can ever land.
	 *
	 * TRIPWIRES FAIL CLOSED (keep tenure; the entry then survives to the
	 * P248 destroy report, which is exactly the evidence wanted):
	 *   attempts != 0      — a live attempt contradicts the frozen-world
	 *                        premise outright;
	 *   finish_gen mismatch — a tenure publication landed anywhere in the
	 *                        context after the phase-4 freeze snapshot.
	 * Never warn-and-proceed: a wrong retire erases the only local record
	 * of a tenure whose disk bits may still exist.
	 */
	if (attempted && !pending && ctx->ops_closed && ctx->release_all_done) {
		if (e->attempts != 0 ||
		    ctx->lreq_finish_gen != ctx->stop_finish_gen) {
			pr_err_ratelimited("mxfs: P266-RETIRE-REFUSED type=%c id=%llu attempts=%u gen=%llu/%llu — teardown completion coincides with a live attempt or a post-freeze publication; tenure kept (fail closed)\n",
				resource.type == MXFS_LTYPE_INODE ? 'I' :
				resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
				(unsigned long long)(resource.type ==
					MXFS_LTYPE_INODE ? resource.ino :
					(uint64_t)resource.ag_number),
				e->attempts,
				(unsigned long long)ctx->lreq_finish_gen,
				(unsigned long long)ctx->stop_finish_gen);
		} else {
			int m;
			bool any = false;

			for (m = 0; m < MXFS_LOCK_MODE_COUNT; m++)
				if (e->tenure[m])
					any = true;
			if (any) {
				ctx->lreq_teardown_retired++;
				pr_warn_ratelimited("mxfs: P263-OWED-TEARDOWN-RETIRE type=%c id=%llu tenure=%u/%u/%u/%u/%u/%u pub_seq=%llu — teardown obligation completed with no attempt or publication possible; local tenure record retired\n",
					resource.type == MXFS_LTYPE_INODE ? 'I' :
					resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
					(unsigned long long)(resource.type ==
						MXFS_LTYPE_INODE ? resource.ino :
						(uint64_t)resource.ag_number),
					e->tenure[0], e->tenure[1],
					e->tenure[2], e->tenure[3],
					e->tenure[4], e->tenure[5],
					(unsigned long long)e->pub_seq);
				memset(e->tenure, 0, sizeof(e->tenure));
			}
		}
	}
	if (pending && !attempted) {
		/* Untouched: still owed, still eligible whenever it already
		 * was.  1 (rather than 0) so a caller deriving a park interval
		 * reads "there is work" and not "nothing is owed". */
		next_ms = e->owed_next_ms ? e->owed_next_ms : 1;
	} else if (pending) {
		e->owed_fails++;
		shift = e->owed_fails > 7 ? 7 : e->owed_fails;
		backoff = (uint64_t)MXFS_CAW_OWED_BACKOFF_MS << shift;
		if (backoff > MXFS_CAW_OWED_BACKOFF_MAX_MS)
			backoff = MXFS_CAW_OWED_BACKOFF_MAX_MS;
		e->owed_next_ms = mxfs_pal_time_ms() + backoff;
		next_ms = e->owed_next_ms;

		fails = e->owed_fails;
		mask = e->owed_holder_mask;
		w = e->owed_waiters;
		wx = e->owed_waiters_ex;
		/* Count the OBLIGATION once, at the instant it crosses the bar —
		 * not once per log line, which would make the counter a measure
		 * of how long the mount ran. */
		if (fails == MXFS_CAW_OWED_ESCALATE)
			ctx->lreq_owed_stuck++;
		stuck = (fails >= MXFS_CAW_OWED_ESCALATE);
	}
	/* sess129 (blocker 4): the claim goes back on the queue — at the TAIL, so
	 * an entry that keeps failing cannot re-occupy the head and starve the
	 * ones behind it.  Must precede lreq_gc, whose oq_queued refusal then
	 * correctly declines to free a re-enqueued entry. */
	lreq_oq_sync(ctx, e);
	lreq_gc(ctx, e);		/* may FREE e — nothing below touches it */
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	if (stuck)
		pr_warn_ratelimited("mxfs: P253-OWED-STUCK type=%c id=%llu fails=%u mask=%x w=%d wx=%d — this node's bits on a resource have resisted %u collection passes; peers may be deferring behind them\n",
			resource.type == MXFS_LTYPE_INODE ? 'I' :
			resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
			(unsigned long long)(resource.type == MXFS_LTYPE_INODE ?
				resource.ino : (uint64_t)resource.ag_number),
			fails, mask, w, wx, fails);
	return next_ms;
}

/* How many entries still owe something?  Teardown reporting only. */
/*
 * Caller holds lreq_lock.  This is the AUTHORITATIVE form (GPT sess130 ruling
 * item 9): teardown's final residue census must read registry state inside the
 * same critical section it makes its clean/dirty decision in, or the answer is
 * a sample.  Queue emptiness is NOT a substitute — an entry can be off the
 * ready queue and still owe (owed_busy), which is precisely the state a
 * dispatch in flight leaves it in.
 */
static uint32_t caw_owed_count_locked(struct mxfs_dlm_caw_ctx *ctx)
{
	uint32_t b, n = 0;

	if (!ctx->lreq || !ctx->lreq_lock)
		return 0;

	for (b = 0; b < MXFS_CAW_LREQ_BUCKETS; b++) {
		struct mxfs_caw_lreq *e;

		for (e = ctx->lreq[b]; e; e = e->next)
			if (lreq_owed_pending(e))
				n++;
	}
	return n;
}

static uint32_t caw_owed_count(struct mxfs_dlm_caw_ctx *ctx)
{
	uint32_t n;

	if (!ctx->lreq || !ctx->lreq_lock)
		return 0;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	n = caw_owed_count_locked(ctx);
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return n;
}

/*
 * One sweep.  Returns the number of entries dispatched.
 *
 * CLAIM-THEN-DISPATCH, never walk-and-dispatch.  The queue cannot be walked
 * across an unlocked dispatch (lreq_gc frees entries), and re-taking the lock
 * after each one to find the next would re-examine everything already declined.
 * So the claim set is taken in ONE locked pass — owed_busy + pin raised on each,
 * which is exactly what makes lreq_gc refuse to free them — and the pointers
 * stay valid until caw_owed_release hands them back.
 *
 * `drain` ignores the per-entry backoff floor.  It is used only by the teardown
 * loop, which has its own overall budget and would otherwise sit out a 500ms
 * backoff it has no reason to honour.
 *
 * ─── sess128 (GPT sess126 ruling, blocker 1): THE DEADLINE ───
 *
 * `deadline` is an absolute wall-clock ms value, or 0 for the running worker,
 * which instead gives EACH entry its own MXFS_CAW_OWED_PASS_MS budget.  A
 * nonzero deadline is the teardown drain's, shared by every entry in the sweep
 * and re-checked before each dispatch, and it also cuts the claim set to
 * MXFS_CAW_OWED_DRAIN_CLAIM: the ruling's "process ONE bounded op per deadline
 * check — don't claim 16 with 2s left".  An entry claimed and then declined for
 * want of budget is released as NOT attempted, so it keeps its failure count.
 *
 * ─── sess127 (GPT sess126 ruling, blocker 6): the SCHEDULING out-params ───
 *
 * `seq0` returns ctx->lreq_owed_work_seq as read INSIDE the same locked walk
 * that chose the claim set.  The worker refuses to park if it has moved since,
 * which is what makes a broadcast issued outside the lock non-lossy.  Sampling
 * it in a separate lock acquisition would reopen the very gap it closes.
 *
 * `next_due` returns the earliest wall-clock time at which some entry becomes
 * eligible, so the park is a real schedule instead of a fixed poll:
 *
 *   0            nothing is owed anywhere — park the full idle interval.
 *   <= now       work is ready RIGHT NOW (the dispatch cap cut the walk short,
 *                so there is a backlog this sweep did not reach).
 *   > now        the earliest backoff floor.
 *
 * Entries skipped for `clr_active` are deliberately NOT counted as due: another
 * thread owns those bits and lreq_clr_end bumps the work sequence when it lets
 * go, so they are covered by the seq predicate rather than by a timer that
 * would spin for the whole duration of somebody else's CAS loop.
 *
 * ─── sess129 (GPT sess126 ruling, blocker 4): THE QUEUE ───
 *
 * The claim set is taken off ctx->owed_q_head (see dlm_caw.h), NOT by walking
 * the hash table from a rotating bucket cursor.  The cursor could not be fair:
 * it stored a BUCKET, so a sweep that stopped part-way along a chain resumed at
 * that chain's head and re-claimed the same entry on every pass — permanent
 * starvation of everything behind it in the bucket, and with the drain's
 * one-entry cap that was the ordinary case rather than an edge one.
 *
 * The walk is bounded by the queue length AT SWEEP START, and an entry examined
 * and declined is rotated to the TAIL.  Those two together are the whole
 * anti-starvation argument: each sweep examines each entry at most once, and an
 * entry that could not be claimed this time is behind everything that has not
 * been examined yet, so it cannot monopolise the next sweep either.
 */
static uint32_t caw_owed_sweep(struct mxfs_dlm_caw_ctx *ctx, bool drain,
			       uint64_t *seq0, uint64_t *next_due,
			       uint64_t deadline)
{
	struct mxfs_caw_lreq *claim[MXFS_CAW_OWED_DISPATCH_MAX];
	uint32_t n = 0, k, examined, qlen, cap;
	uint64_t now, due = 0;
	bool capped = false;

	if (seq0)
		*seq0 = 0;
	if (next_due)
		*next_due = 0;
	if (!ctx || !ctx->lreq || !ctx->lreq_lock)
		return 0;

	cap = deadline ? MXFS_CAW_OWED_DRAIN_CLAIM : MXFS_CAW_OWED_DISPATCH_MAX;
	now = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	if (seq0)
		*seq0 = ctx->lreq_owed_work_seq;
	qlen = ctx->owed_q_n;
	for (examined = 0; examined < qlen; examined++) {
		struct mxfs_caw_lreq *e = ctx->owed_q_head;

		if (!e)
			break;			/* queue emptied under us */
		if (n >= cap) {
			/* Everything from here on is UNEXAMINED and stays at the
			 * head, so the next sweep resumes exactly here. */
			capped = true;
			break;
		}
		/*
		 * A clear window is open on this resource right now, so some
		 * other local thread is already mid-CAS on exactly these bits.
		 * Let it finish: it will retract what it proves, and closing the
		 * window broadcasts lreq_cond, which brings us straight back.
		 */
		if (e->clr_active) {
			lreq_oq_rotate(ctx, e);
			continue;
		}
		if (!drain && now < e->owed_next_ms) {
			/* Still in backoff — but it IS work, and the clock alone
			 * will make it eligible, so the park must not outlast
			 * it. */
			if (!due || e->owed_next_ms < due)
				due = e->owed_next_ms;
			lreq_oq_rotate(ctx, e);
			continue;
		}
		/* CLAIM.  Dequeue and raise owed_busy together — they are the
		 * two halves of the queue invariant — and raise pin, which is
		 * what makes lreq_gc refuse to free the entry while the dispatch
		 * below runs unlocked. */
		lreq_oq_remove(ctx, e);
		e->owed_busy = true;
		e->pin++;
		claim[n++] = e;
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	/*
	 * The walk stopped at the claim cap, so entries beyond it were never
	 * examined and this sweep cannot say when they come due.  Report READY,
	 * which costs one extra sweep — that sweep examines them and computes a
	 * real floor — and never sleeps past work.
	 */
	if (capped)
		due = 1;

	for (k = 0; k < n; k++) {
		uint64_t again, budget;
		bool attempted;

		/*
		 * sess128: the drain's shared deadline, or a fresh per-entry
		 * budget for the running worker.  Either way every dispatch
		 * below this point has an absolute one to check against, so no
		 * CAS loop and no probe walk can outlast the sweep.
		 */
		budget = deadline ? deadline :
			 mxfs_pal_time_ms() + MXFS_CAW_OWED_PASS_MS;
		attempted = caw_owed_dispatch(ctx, claim[k], budget);
		/* Re-armed backoff floors are set AFTER the locked walk above,
		 * so they can only be folded in here. */
		again = caw_owed_release(ctx, claim[k], attempted);
		if (again && (!due || again < due))
			due = again;
	}

	if (next_due)
		*next_due = due;
	return n;
}

/*
 * The worker thread.
 *
 * PARKING.  It is normally woken explicitly — lreq_clr_begin on a new
 * obligation, lreq_clr_end when a window closes, lreq_finish when the last
 * local attempt leaves (which is what makes a deferred plan permissive), and
 * teardown.
 *
 * sess127 (GPT sess126 ruling, blocker 6): the park is now PREDICATED and
 * SCHEDULED, not an unconditional fixed-interval wait.
 *
 *   PREDICATED — every broadcast is issued outside lreq_lock, so a publication
 *   landing between this thread's decision to park and the park itself signals
 *   an empty condvar and is lost.  ctx->lreq_owed_work_seq is bumped inside the
 *   lock by every such event; the sweep reads it inside the same locked walk
 *   that chose its claim set, and a park is refused outright if it has moved.
 *   The worst case is therefore one extra sweep, never a missed obligation.
 *
 *   SCHEDULED — the interval is the earliest per-entry backoff floor rather
 *   than a constant, capped at IDLE_MS as the missed-wakeup safety net.  The
 *   old shape woke at a fixed BUSY_MS/IDLE_MS cadence that had no relationship
 *   to when anything actually became eligible: it both spun (20ms polls against
 *   a 500ms backoff) and slept past work (a 4ms backoff behind a 1000ms park).
 *
 * TEARDOWN.  After !running it drains with backoff floors ignored, budgeted by
 * MXFS_CAW_OWED_DRAIN_MS so a genuinely dead LUN cannot hang the unmount.  A
 * residue is REPORTED, never silently dropped: the bits stay on disk until
 * membership withdrawal makes them reclaimable by peers, and an operator
 * needs to know that happened.
 *
 * sess128 (GPT sess126 ruling, blocker 1): DRAIN_MS is now an ABSOLUTE deadline
 * handed down through sweep → dispatch → resolve/drop_own_waiter → find_slot,
 * and the drain claims ONE entry per sweep so it is re-checked between every
 * bounded operation.  Before this it was tested only BETWEEN sweeps, and a
 * single sweep — 16 entries x 4 modes x a 1000-attempt CAS loop — ran to
 * something on the order of 512s against a 2000ms budget.
 *
 * It is a BUDGET, not a hard bound, and the P254 line says so: the deadline
 * stops this thread STARTING work, but a slot I/O already handed to the block
 * layer is not cancellable and a dead LUN's own timeout is tens of seconds.
 * What the drain does guarantee is that it will not begin an operation it has
 * no budget for.
 */
static void caw_owed_worker_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;
	uint64_t deadline;
	uint32_t left, budget_ms;

	while (ctx->running) {
		uint64_t seq0 = 0, due = 0, now, wait;

		caw_owed_sweep(ctx, false, &seq0, &due, 0);

		mxfs_pal_mutex_lock(ctx->lreq_lock);
		/*
		 * Both halves of the predicate are re-tested under the lock the
		 * wakers bump the sequence under, so neither a stop nor a
		 * publication that landed during the sweep can be parked through.
		 */
		if (ctx->running && seq0 == ctx->lreq_owed_work_seq) {
			now = mxfs_pal_time_ms();
			if (!due)
				wait = MXFS_CAW_OWED_IDLE_MS;
			else if (due <= now)
				wait = MXFS_CAW_OWED_BUSY_MS;
			else if (due - now > MXFS_CAW_OWED_IDLE_MS)
				wait = MXFS_CAW_OWED_IDLE_MS;
			else
				wait = due - now;
			mxfs_pal_cond_timedwait(ctx->lreq_cond, ctx->lreq_lock,
						wait);
		}
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	}

	/*
	 * sess131 (GPT sess130 ruling): the drain does not start when the main
	 * loop ends.  It starts when TEARDOWN says so — after the admission gate
	 * has closed, the in-flight operations have left, and the exclusive
	 * release_all has run and published everything it could not clear.
	 * Draining before that point collected an obligation set that release_all
	 * had not yet contributed to, and the residue check that followed was
	 * therefore a census of the wrong thing.
	 *
	 * ─── sess132 (GPT sess132 ruling, part 1c): THE WAIT IS UNCONDITIONAL ───
	 *
	 * sess131 bounded this wait at QUIESCE_MS + DRAIN_MS and drained anyway on
	 * expiry, "which is exactly the pre-sess131 behaviour and strictly safer
	 * than not draining."  Both halves of that were wrong, and the safety net
	 * reintroduced the exact defect the restructure exists to remove.
	 *
	 * Because phase 2's quiesce is deliberately unbounded, the expiry could
	 * fire while ops_active != 0, while the BAST producers were still running,
	 * and BEFORE phase 4 had executed.  The drain would then run, find the
	 * pre-release obligation set, exit, and END THE WORKER — after which phase
	 * 4's release_all publishes everything it could not clear into a registry
	 * WITH NO COLLECTOR LEFT.  That is uncollectable-by-construction residue,
	 * which is the whole bug.  Declaring the census "not authoritative" did not
	 * repair it: stop() still proceeded as though it had joined the designated
	 * teardown worker.
	 *
	 * And there was no deadlock to protect against.  While phase 2 is stuck,
	 * stop() has not reached its thread_join yet, so a worker parked here
	 * forever costs nothing and blocks nobody.  The join and the arm are issued
	 * by the same thread in that order; if the arm never happens, the join
	 * never happens either.
	 */
	if (ctx->lreq_lock) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		while (!ctx->drain_armed)
			mxfs_pal_cond_timedwait(ctx->lreq_cond, ctx->lreq_lock,
						MXFS_CAW_QUIESCE_POLL_MS);
		/* sess154 K4: simulate a publication landing after the
		 * phase-4 freeze — the retire tripwire must then refuse every
		 * completion in this drain, fail closed, and the entries must
		 * survive to the P248 destroy report. */
		if (caw_inject_take(&mxfs_caw_inject_pubfreeze_bump))
			ctx->lreq_finish_gen++;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	}

	/* sess154 K3: operator/test override of the drain budget. */
	budget_ms = mxfs_caw_drain_budget_ms > 0 ?
		(uint32_t)mxfs_caw_drain_budget_ms : MXFS_CAW_OWED_DRAIN_MS;
	deadline = mxfs_pal_time_ms() + budget_ms;
	for (;;) {
		uint64_t now;
		uint32_t nap, did;

		if (mxfs_pal_time_ms() >= deadline)
			break;
		/*
		 * ONE entry per sweep (MXFS_CAW_OWED_DRAIN_CLAIM), each dispatch
		 * carrying the shared deadline.
		 */
		did = caw_owed_sweep(ctx, true, NULL, NULL, deadline);
		if (!caw_owed_count(ctx))
			break;
		now = mxfs_pal_time_ms();
		if (now >= deadline)
			break;
		/*
		 * Pace ONLY when the sweep could claim nothing — everything
		 * pending is then clr_active, owned by another thread's CAS
		 * loop, and waiting that out is what the rest of the budget is
		 * for.  Pacing a sweep that DID claim would cap the drain at
		 * (DRAIN_MS / STEP_MS) entries no matter how fast they went.
		 */
		if (did)
			continue;
		nap = MXFS_CAW_OWED_DRAIN_STEP_MS;
		if (nap > deadline - now)
			nap = (uint32_t)(deadline - now);
		if (nap)
			mxfs_pal_sleep_ms(nap);
	}

	left = caw_owed_count(ctx);
	if (left) {
		ctx->lreq_owed_left = left;
		pr_warn("mxfs: P254-OWED-TEARDOWN left=%u drain_ms=%u disp=%llu stuck=%llu — obligations to clear this node's slot bits survived the teardown drain (drain_ms budgets the work STARTED, not in-flight block-layer I/O); they are reclaimed by peers only when this node's membership is withdrawn\n",
			left, budget_ms,
			(unsigned long long)ctx->lreq_owed_disp,
			(unsigned long long)ctx->lreq_owed_stuck);
	}
	/* sess154 (P248 fix A): the POSITIVE observation the verification
	 * requires — retires that actually ran this teardown, printed whether
	 * or not anything was left over. */
	if (ctx->lreq_teardown_retired)
		pr_warn("mxfs: P267-RETIRE-SUM node=%u retired=%llu — teardown obligations whose completion retired the local tenure record\n",
			ctx->local_node,
			(unsigned long long)ctx->lreq_teardown_retired);
}

/*
 * sess112: end one local attempt on `resource`.
 *
 * `held_mode` is the mode actually granted (MXFS_LOCK_NL when the attempt
 * failed).  Publication of the tenure and departure of the attempt happen in
 * ONE critical section, so no reconcile can ever observe the gap between "this
 * thread has a durable grant" and "the registry knows about it" — that gap was
 * the observe-to-track window the first design died on.
 *
 * sess125: THIS NO LONGER COLLECTS ANYTHING.  Two things used to happen here
 * and both are now the owed worker's job (caw_owed_worker_fn above):
 *
 *   THE CLRWAIT PARK — the last attempt out held its departure up while a clear
 *   window was open, because the clearer recorded what it refused only AFTER
 *   the fact and leaving first could orphan it.  Publication now precedes the
 *   I/O, so there is nothing left to orphan and nothing to wait for; the park
 *   was pure latency on a lock-release path (and P249 was its own timeout).
 *
 *   THE INLINE OWED RUN — the last attempt out ran the deferred clears itself.
 *   That was the sess116 corruption path: it cleared the record under the lock
 *   and then ran the passes unlocked, so a failure lost the obligation outright,
 *   and it charged an unbounded contended CAS loop to an XFS thread.  Worse, on
 *   a resource whose attempts had ALL already left there was no "last attempt"
 *   to run it at all, which is the leak the worker exists to close.
 *
 * What remains is bookkeeping plus one wake edge: the departure of a local
 * attempt is precisely what can turn a refused plan (others != 0) permissive,
 * so it is a real reason to prod the worker.
 */
static void lreq_finish(struct mxfs_dlm_caw_ctx *ctx,
			const struct mxfs_resource_id *resource,
			struct mxfs_caw_lreq *e, uint8_t req_mode,
			uint8_t held_mode)
{
	bool owed;

	(void)resource;
	if (!e || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	if (held_mode != MXFS_LOCK_NL && held_mode < MXFS_LOCK_MODE_COUNT) {
		/*
		 * sess118 ruling item 6: SATURATE, never wrap.  tenure[] is not
		 * a reference count — there is no per-acquire release in the
		 * cached-grant model, so nothing ever decrements it and a
		 * shortcut-heavy workload increments without bound.  A wrap to
		 * zero would read as "no local tenure holds this mode" and
		 * authorise exactly the clear this guard exists to refuse.
		 */
		if (e->tenure[held_mode] != UINT32_MAX)
			e->tenure[held_mode]++;
		/* sess117: a tenure publication.  lreq_release_all compares
		 * this across a release window so a blanket tenure retire
		 * cannot eat a tenure published after that release began. */
		e->pub_seq++;
		/* sess154 (P248 fix A tripwire): the CONTEXT-WIDE publication
		 * generation.  stop() snapshots it in phase 4 immediately
		 * before release_all; a teardown retire whose entry completed
		 * after ANY later publication — on any entry, including one
		 * that landed between release_all and the completion — must
		 * refuse, because the freeze the retire's soundness argument
		 * rests on ("phases 2+3 joined every publisher") no longer
		 * describes reality. */
		ctx->lreq_finish_gen++;
	}
	if (e->attempts)
		e->attempts--;
	if (mxfs_mode_can_write(req_mode) && e->writers)
		e->writers--;

	/* Read BEFORE lreq_gc — which refuses to free an entry that still owes
	 * anything, but may free this one, so `e` is dead after it. */
	owed = lreq_owed_pending(e);
	/* sess127 (blocker 6): a departure can turn a refused plan permissive, so
	 * it is a wake edge and must be recorded under the lock. */
	if (owed)
		ctx->lreq_owed_work_seq++;
	lreq_gc(ctx, e);
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	if (owed && ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);
}

/*
 * ─── sess131 (GPT sess126 ruling blocker 2; sess130 design): THE ADMISSION
 *     GATE ───
 *
 * WHAT IT PROVES.  Once teardown has observed `ops_active == 0` while holding
 * lreq_lock with `ops_closed` already set, no further obligation can be
 * published, because every operation that can publish one publishes it under
 * lreq_lock and only then decrements ops_active under that same lock.  Both
 * events are ordered by one mutex, so a zero observed after the close is a
 * census of the producers, not a sample of them.  The pre-existing
 * `running = false` proved nothing of the sort: no producer ever read it.
 *
 * HOW IT IS APPLIED.  Every gated entry point is a thin wrapper over a static
 * `*_body`, so `caw_op_leave` is structurally the last thing the call does —
 * there is no exit path that can skip it and no audit of `return` statements
 * to keep correct as the bodies change.  A leaked count would wedge teardown
 * forever, so the property is worth buying structurally.
 *
 * WHAT IS GATED (verified sess131, not inherited):
 *   lock, convert, unlock_gen, force_release_self, open_set, open_clear,
 *   flush_held_to_disk, purge_dead_nodes_ex
 * — i.e. exactly the public entry points that write a slot on disk or touch
 * the local request registry.  `unlock`, `purge_node` and `purge_dead_nodes`
 * are pure delegations and inherit their target's gate; gating them too would
 * nest.  For the same reason caw_convert_body's NL delegation calls
 * caw_unlock_gen_body directly: it is already inside the gate, and an
 * already-admitted operation must never be refused halfway through.
 *
 * WHAT IS NOT GATED, DELIBERATELY: dump_slot, read_generation, ex_count, held,
 * granted_mode, open_holders, open_probe, footprint_scan, self_held_scan,
 * grant_dir_epoch, grant_dir_block0, grant_seq32, grant_handoff,
 * orphan_clock_get.  None writes a slot, none publishes, none can race
 * release_all.  (sess130's note listed grant_handoff as a writer; it is not —
 * caw_grant_meta_get only reads ctx->grant_meta under grant_meta_lock.)
 * Their lifetime against ctx teardown is the caller's problem and is
 * unchanged by this mechanism.
 *
 * A ctx with no lreq_lock has no gate and admits everything, which is exactly
 * its pre-gate behaviour.
 */
/*
 * ─── sess131 (GPT sess130 ruling blocker 3): THE FAILURE LATCH ───
 *
 * The DLM's OWN record that this mount cannot account for its bits on disk.
 * It is deliberately not the callback: ruling item 5 is that the callback must
 * not be the safety latch, because it may be unregistered, racing, or have its
 * work cancelled, and a clean departure must be impossible in every one of
 * those cases.  So the state is recorded SYNCHRONOUSLY under lreq_lock and the
 * callback is a notification of a decision already made.
 *
 * Setting it also closes admission and revokes `departed_clean`: a mount that
 * cannot prove its slot bits are gone must not be allowed to acquire more, and
 * must not tell peers it left cleanly (which would authorise them to reclaim
 * without the fence/replay protocol that makes reclaim safe).
 *
 * Caller holds ctx->lreq_lock.  Returns true exactly once — on the transition —
 * so the caller can invoke the notification exactly once.
 */
static bool caw_owed_fail_latch(struct mxfs_dlm_caw_ctx *ctx)
{
	if (ctx->owed_failed)
		return false;
	ctx->owed_failed = true;
	ctx->owed_failed_ms = mxfs_pal_time_ms();
	ctx->ops_closed = true;
	ctx->departed_clean = false;
	return true;
}

/*
 * Deliver the latched failure upward.  Call with NO lock held.
 *
 * The pointer is re-read under the lock rather than passed in, so a teardown
 * that cleared it after the worker join cannot be called into.
 */
static void caw_owed_fail_notify(struct mxfs_dlm_caw_ctx *ctx)
{
	void (*fn)(void *) = NULL;
	void *data = NULL;

	if (!ctx || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	fn = ctx->owed_stuck_fn;
	data = ctx->owed_stuck_data;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	if (fn)
		fn(data);
}

/*
 * ─── sess134 (GPT sess133 ruling B3): THE ASYNCHRONOUS ESCALATION ───
 *
 * The quiesce loop RECORDS AND QUEUES; it never invokes the upper handler.
 *
 * Calling a contractually queue-only handler synchronously would be enough
 * today and wrong tomorrow: it makes this layer's teardown liveness depend on
 * upper-layer behaviour, and it lets a future handler change introduce blocking
 * — or a re-entrant stop() — directly inside the loop that is trying to
 * establish quiescence.  So the handler runs from a deferred context and the
 * deadline below does NOT depend on it running at all.
 *
 * LIFETIME.  The work item holds a bare ctx pointer, and that is safe for
 * exactly one reason: any path that queues it has already set unsafe_to_free,
 * so destroy() will leak the context rather than free it — and if the grace
 * expires instead, the node fail-stops and nothing is freed ever again.  Do not
 * queue this from a path that leaves the context freeable.
 */
static void caw_teardown_escalate_work(void *arg)
{
	caw_owed_fail_notify((struct mxfs_dlm_caw_ctx *)arg);
}

/*
 * Latch a blown teardown budget.  CALL WITH lreq_lock HELD.
 *
 * Returns true if this is the first observation, i.e. the caller should queue
 * the escalation once it has dropped the lock.  Repeat observations are no-ops
 * by construction — the expiry is sticky and the deferral is one-shot.
 */
static bool caw_teardown_expire_locked(struct mxfs_dlm_caw_ctx *ctx)
{
	bool first;

	/*
	 * unsafe_to_free BEFORE anything else: it is what makes the deferred
	 * work item's bare ctx pointer safe, and it must be true even if the
	 * stuck phase later completes and teardown runs to the end.
	 */
	ctx->unsafe_to_free = true;
	if (!ctx->teardown_expired) {
		ctx->teardown_expired = true;
		ctx->teardown_expired_ms = mxfs_pal_time_ms();
	}
	(void)caw_owed_fail_latch(ctx);

	first = !ctx->teardown_defer_sent;
	if (first)
		ctx->teardown_defer_sent = true;
	return first;
}

/* Queue the escalation.  Call with NO lock held, only when the latch above
 * returned true. */
static void caw_teardown_escalate_queue(struct mxfs_dlm_caw_ctx *ctx)
{
	int rc = mxfs_pal_defer(caw_teardown_escalate_work, ctx);

	if (rc < 0)
		pr_err("mxfs: P261-ESCALATE-UNDELIVERED node=%u rc=%d — the DLM could not queue its force-shutdown request; the refusal to depart clean and the fail-stop deadline still stand, but the filesystem above will not be told to stop writing\n",
		       ctx->local_node, rc);
}

/*
 * ─── sess134 (GPT sess133 ruling B1): THE BOUNDED TEARDOWN JOIN ───
 *
 * Every teardown join whose target can touch storage or mount-owned state gets
 * this shape, and NOT a plain blocking join.  `esc_at_ms` is the absolute
 * MXFS_CAW_QUIESCE_MS escalation point for this teardown; whatever budget is
 * left runs out first, then the escalation is queued, then ONE grace, then the
 * node fail-stops.
 *
 * mxfs_pal_thread_join_timeout is the split form the ruling demands: the stop
 * request is already published (phase 1), and it waits on the thread's EXIT
 * COMPLETION, reaping only once exit is known.  A timeout leaves the thread
 * untouched — never a blind kthread_stop on a thread still inside an I/O.
 */
static void caw_join_bounded(struct mxfs_dlm_caw_ctx *ctx,
			     mxfs_thread_t **slot, const char *what,
			     uint64_t esc_at_ms)
{
	uint64_t now;
	uint32_t grace;
	bool first = false;
	int rc;

	if (!slot || !*slot)
		return;

	now = mxfs_pal_time_ms();
	if (now < esc_at_ms) {
		rc = mxfs_pal_thread_join_timeout(*slot,
						  (uint32_t)(esc_at_ms - now));
		if (rc == 0) {
			*slot = NULL;
			return;
		}
	}

	if (ctx->lreq_lock) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		first = caw_teardown_expire_locked(ctx);
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	} else {
		ctx->unsafe_to_free = true;
		ctx->teardown_expired = true;
	}

	grace = caw_failstop_grace_ms();
	pr_err("mxfs: P262-TEARDOWN-JOIN-STUCK node=%u thread=%s — it has not exited within the teardown budget; requesting force-shutdown and starting the final %ums grace before this node fail-stops\n",
	       ctx->local_node, what, grace);
	if (first)
		caw_teardown_escalate_queue(ctx);

	/*
	 * Non-returning on expiry.  Returning would skip the remaining teardown
	 * phases and hand this thread's live pointer into the XFS mount back to
	 * a VFS that is about to free it.
	 *
	 * The call is deliberately NOT the last statement in the function.
	 * objtool validates control flow against a hardcoded noreturn list and
	 * cannot learn about a function defined in another translation unit, so
	 * a function ENDING on this call is reported as falling through into its
	 * neighbour; letting both paths merge on the success tail below keeps a
	 * real `ret` at the end and costs nothing.
	 */
	if (mxfs_pal_thread_join_timeout(*slot, grace) != 0)
		mxfs_pal_failstop("mxfs: CAW teardown: node %u thread %s never exited (quiesce budget + %ums grace); it still holds references into a mount that is being freed and can still write the shared LUN — fail-stopping this node rather than corrupting the cluster",
				  ctx->local_node, what, grace);

	*slot = NULL;
	pr_err("mxfs: P262-TEARDOWN-JOIN-LATE node=%u thread=%s — it exited inside the grace; teardown continues but the clean-departure refusal stands\n",
	       ctx->local_node, what);
}

static bool caw_op_enter(struct mxfs_dlm_caw_ctx *ctx)
{
	bool ok;

	if (!ctx)
		return false;
	if (!ctx->lreq_lock)
		return true;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	/*
	 * sess134 (ruling A1): admission is a LIFECYCLE decision, so it reads
	 * the lifecycle.  Admitted before teardown owns the context and before a
	 * failed start has torn its threads down — NOT in START_FAILED, where
	 * `ops_closed` alone used to keep admitting into a context with no BAST
	 * poller and no owed-cleanup collector.
	 *
	 * NEW is admitted deliberately: the mount-time own-slot reclaim
	 * (mxfs_dlm_caw_purge_dead_nodes_ex, v5_mount step 4) runs between
	 * create() and start() and is a legitimate pre-start operation.
	 */
	ok = (ctx->lc == MXFS_CAW_LC_NEW ||
	      ctx->lc == MXFS_CAW_LC_STARTING ||
	      ctx->lc == MXFS_CAW_LC_RUNNING) && !ctx->ops_closed;
	if (ok)
		ctx->ops_active++;
	else
		ctx->ops_refused++;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return ok;
}

static void caw_op_leave(struct mxfs_dlm_caw_ctx *ctx)
{
	bool drained = false;

	if (!ctx || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	if (ctx->ops_active) {
		ctx->ops_active--;
	} else {
		/*
		 * Unbalanced leave.  Clamping keeps teardown from underflowing
		 * to UINT32_MAX and waiting forever, but the imbalance itself
		 * breaks the census, so it is an error and says so.
		 */
		pr_err_ratelimited("mxfs: P255-CAW-OPS-UNBALANCED node=%u — caw_op_leave with ops_active==0; the teardown quiescence census is unreliable on this mount\n",
				   ctx->local_node);
	}
	drained = (ctx->ops_closed && ctx->ops_active == 0);
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	/*
	 * The last operation out is what teardown is waiting for.  Broadcast
	 * OUTSIDE the lock: the waiter needs lreq_lock to re-test its
	 * predicate, so signalling under it just makes it wake into contention.
	 */
	if (drained && ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);
}

/*
 * sess112: the local tenure(s) on `resource` are gone — the unlock CAS cleared
 * our bit in EVERY mode bitmap, or a force-release/teardown did.  Drop the
 * whole tenure vector so a later give-up on this resource is once again free
 * to reconcile stale bits.
 *
 * Deliberately called only where the clear is CONFIRMED.  Dropping tenure
 * early would re-open the wrongful-clear window; dropping it late merely makes
 * a reconcile refuse a bit that the last leaver then collects.
 */
static void lreq_release_all(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource,
			     uint64_t pub_seq0)
{
	struct mxfs_caw_lreq *e;

	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (e) {
		/*
		 * sess117 (sess115 ruling blocker 1): a BLANKET retire is only
		 * valid for the tenures that existed when this release began.
		 * pub_seq counts tenure publications; if one landed inside the
		 * release window it is a REAL grant belonging to a different
		 * local thread, and retiring it would tell the next give-up
		 * reconcile that the holder bit is free to strip.
		 *
		 * Keeping it instead is fail-closed in the harmless direction:
		 * a stale-high tenure only makes later plans REFUSE, and every
		 * refusal is recorded as owed and collected by the last leaver.
		 */
		if (e->pub_seq == pub_seq0) {
			memset(e->tenure, 0, sizeof(e->tenure));
		} else {
			ctx->lreq_rel_kept++;
			pr_warn_ratelimited("mxfs: P248-LREQ-REL-KEPT type=%c id=%llu pub0=%llu pub=%llu — tenure published inside the release window; not retiring it\n",
				resource->type == MXFS_LTYPE_INODE ? 'I' :
				resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
				(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
					resource->ino : (uint64_t)resource->ag_number),
				(unsigned long long)pub_seq0,
				(unsigned long long)e->pub_seq);
		}
		lreq_gc(ctx, e);
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

/*
 * sess151 (D-RELEASEALL-LREQ-RETIRE-MISSING): release_all's read of the
 * pub_seq anchor lreq_release_all guards on.  A bare peek — no clear window
 * (lreq_clr_begin) — is the ruled shape for the unmount path: release_all
 * runs after XFS quiesce, so there is no competing destructive clear to
 * serialize against, and the peek and lreq_release_all's compare are in the
 * same serialization domain (both under ctx->lreq_lock).  0 doubles as the
 * no-entry anchor: the only bump site is lreq_finish's e->pub_seq++, so a
 * published entry always reads >= 1, and retiring against anchor 0 can only
 * no-op an idle entry.
 */
static uint64_t lreq_pub_seq_peek(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lreq *e;
	uint64_t seq = 0;

	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return 0;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (e)
		seq = e->pub_seq;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return seq;
}

/*
 * sess2(ccloop 26c41354) FAIR HANDOFF — pick ONE round-robin next EX waiter.
 * Returns the bit of the first EX waiter strictly after the releaser's own
 * node bit (cyclic over 64 positions), so successive releases rotate through
 * all EX waiters and no node is starved by the self-promote free-for-all in
 * caw_wait_for_grant (16-node victim-node data loss; P131-WAITLONG).  Returns
 * 0 if there are no EX waiters.
 */
/*
 * sess24: episode-preserving stamp for the fair-handoff ticket.  Returns the
 * yield_set_ms the new slot image should carry.  See
 * mxfs_caw_yield_episode_clock for why re-stamping on every rotation is a bug.
 */
static uint64_t caw_yield_stamp(const struct mxfs_caw_lock_slot *cur,
				uint64_t new_yield_to)
{
	bool episode_live;

	if (!mxfs_caw_yield_episode_clock)
		return (new_yield_to != cur->yield_to) ?
			mxfs_pal_time_real_ms() : cur->yield_set_ms;

	/* An episode is already running iff a ticket was outstanding AND it was
	 * stamped.  Rotating WHICH waiter holds it does not start a new one. */
	episode_live = (cur->yield_to != 0 && cur->yield_set_ms != 0);
	if (new_yield_to == 0)
		return 0;			/* episode over */
	if (episode_live)
		return cur->yield_set_ms;	/* carry the episode forward */
	return mxfs_pal_time_real_ms();		/* episode begins now */
}

static uint64_t caw_pick_next_ex_waiter(uint64_t ex_waiters, uint64_t self_bit)
{
	int self_pos = 0, i;

	if (!ex_waiters)
		return 0;
	if (self_bit) {
		while (self_pos < 63 && !((self_bit >> self_pos) & 1ULL))
			self_pos++;
	}
	for (i = 1; i <= 64; i++) {
		int pos = (self_pos + i) & 63;
		uint64_t b = 1ULL << pos;

		if (ex_waiters & b)
			return b;
	}
	return 0;
}

/*
 * sess299 (D-32NODE-SHARED-DIR-CREATE-PACE, RULE-5 sess298 ruling): the
 * standing EX reservation.  A single-bit yield_to naming a live REGISTERED
 * EX-class waiter is a RESERVATION, not a hint: ordinary releasers must
 * carry it forward unchanged, PR drains and streak-yield batches may delay
 * but never overwrite it, and the direct-handoff arm consumes exactly this
 * ticket.  The sess298 census proved the old behavior — every intermediate
 * releaser re-running nomination relative to its OWN slot — re-pointed the
 * ticket away from a slow waiter 2.5x per wait (only 44% of slow waiters
 * ever saw themselves named; max 23.8s), which was the whole p99 tail.
 *
 * Returns the reservation bit, or 0 when yield_to holds no valid standing
 * EX reservation (empty, multi-bit PR batch, or nominee no longer a
 * registered EX waiter — deregister/cancel/lease-purge clear waiter bits,
 * which is the ONLY way a reservation dies).
 */
static uint64_t caw_standing_ex_resv(const struct mxfs_caw_lock_slot *s)
{
	uint64_t yt = s->yield_to;

	if (!yt || (yt & (yt - 1)))
		return 0;
	if (!(yt & s->waiters & s->waiters_ex))
		return 0;
	return yt;
}

/*
 * sess299: round-robin base for a FRESH nomination — the last committed
 * EX-class grantee's bit, so every releaser computes the SAME next nominee
 * from the same slot image (state-relative), instead of one relative to its
 * own slot (releaser-relative, memoryless — the proven D-503 root).
 * last_ex_slot advances only in caw_grant_epoch_update, i.e. only on a
 * committed EX-class grant — never at nomination, never on a PR batch.
 */
static uint64_t caw_last_ex_bit(const struct mxfs_caw_lock_slot *s)
{
	return (s->last_ex_slot < MXFS_MAX_NODES) ?
		(1ULL << s->last_ex_slot) : 0;
}

/*
 * sess108 (RULE-5 ruling, ordering item): validate the nominated waiter BEFORE
 * a direct EX handoff installs it as holder.  The handoff mints a durable write
 * tenure for another node in one CAS, so the nomination must be provably a
 * single eligible EX-class waiter — not "whatever bits happen to be in
 * yield_to".  `new` carries the nomination; `cur` is the on-disk image the CAS
 * compares against, and is where waiter eligibility must be read from.
 *
 * A rejected nomination is not an error: we simply leave the ticket in place
 * and the waiter claims it itself (the pre-sess37 path).  Correct, just slower.
 */
static bool caw_handoff_nominee_ok(const struct mxfs_caw_lock_slot *cur,
				   const struct mxfs_caw_lock_slot *new_slot)
{
	uint64_t wbit = new_slot->yield_to;
	int w_slotno;

	if (!wbit || (wbit & (wbit - 1)))		/* exactly one bit */
		return false;
	w_slotno = __builtin_ctzll(wbit);
	if (w_slotno >= MXFS_MAX_NODES)
		return false;
	if ((uint8_t)w_slotno == MXFS_CAW_EX_SLOT_NONE)
		return false;
	/* Must be a registered EX-class waiter in the image we are CAS-ing
	 * against — never a bare ticket for a node that never queued. */
	if (!(cur->waiters & cur->waiters_ex & wbit))
		return false;
	return true;
}

/*
 * sess285 (D-DLMFAIRNESS-32CAW-HOTDIR-EX-STARVATION-501) RULE-4 probe: one
 * uniform line per successful exclusive-class INODE grant, emitted from
 * EVERY grant path (promote/adopt/cold/claim/convert, plus the releaser's
 * direct-handoff mint and its un-minted nomination).  Aggregating all
 * nodes' dmesg by realms gives the complete per-ino grant sequence —
 * winner slot, path taken, inter-grant spacing — which decides H1 (biased
 * yield_to nomination re-favoring a subset) against the alternative
 * (fair rotation whose per-handoff cadence is simply too slow for the
 * budget).  Not caw_instr_on()-gated for the same reason as P203: a zero
 * reading must be falsifiable.  Hard 20000-line cap per module load.
 */
static void caw_exwin_log(const struct mxfs_resource_id *resource,
			  const char *path, uint32_t mode, int slotno,
			  uint64_t waited_ms, uint64_t yt, uint64_t wex)
{
	static int p291_n;

	if (resource->type != MXFS_LTYPE_INODE ||
	    !mxfs_mode_can_write((uint8_t)mode))
		return;
	if (p291_n++ >= 20000)
		return;
	pr_warn("mxfs: P291-EXWIN ino=%llu path=%s mode=%u slot=%d waited_ms=%llu yt=%llx wex=%llx realms=%llu\n",
		(unsigned long long)resource->ino, path, mode, slotno,
		(unsigned long long)waited_ms,
		(unsigned long long)yt, (unsigned long long)wex,
		(unsigned long long)mxfs_pal_time_real_ms());
}

/*
 * v0.10.36: one poll step of the acquire wait.  Inside the inode
 * fresh-handoff window (first MXFS_CAW_INODE_FASTPOLL_MS of the wait) poll
 * at a fast fixed interval — a BAST-driven handoff completes in ~10-25ms
 * and the exponential backoff parked the waiter up to 25ms past the slot
 * going free (measured 42-46ms/unlink, 32-node dir_reuse rm).  Beyond the
 * window, exponential backoff exactly as before.
 */
/* P297 wake-attribution flags (sess296, D-503 ruling step 1). */
#define MXFS_CAW_WAKE_NUDGE	1	/* sleep ended by a relevant nudge */
#define MXFS_CAW_WAKE_MISS	2	/* a nudge for us landed in the slot-read→
					 * prepare window: the sleep below cannot
					 * see it and oversleeps the interval */

static int caw_acquire_poll_sleep(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   uint64_t start, uint32_t *poll_ms,
				   uint32_t hopeless_ms, uint64_t pre_read_seq)
{
	extern int mxfs_caw_inode_fastpoll;
	/* ccloop 72513a13 sess3: sleep interruptibly on the GRANT-NUDGE
	 * cond so a releaser's multicast wakes us NOW instead of after the
	 * poll interval (kprobe-proven 4.6s/6.0s of an 8-node create phase
	 * was this sleep).  A nudge racing in between the caller's slot
	 * read and this prepare is missed and costs one interval — bounded
	 * by the poll backstop; accepted for a minimal-risk diff.
	 * P297 measures exactly how often that miss happens and what it
	 * costs (`pre_read_seq` = the caller's pre-read nudge snapshot). */
	uint64_t seq = caw_nudge_prepare(ctx);
	int fl = 0;

	if (caw_nudge_check(ctx, pre_read_seq, resource) &&
	    !caw_nudge_check(ctx, seq, resource))
		fl |= MXFS_CAW_WAKE_MISS;

	/* sess35 NUDGE v2: the caller's slot read proved no grant can land
	 * until another node's release (foreign EX holder / foreign ticket).
	 * Fast cadence buys nothing but target-queue pressure — sleep long;
	 * the targeted nudge ends the sleep the moment we can act, and the
	 * verification read at this cadence still drives the stale-ticket
	 * and patience clocks. */
	if (hopeless_ms) {
		if (caw_nudge_wait(ctx, seq, hopeless_ms, resource))
			fl |= MXFS_CAW_WAKE_NUDGE;
		return fl;
	}
	if (mxfs_caw_inode_fastpoll &&
	    resource->type == MXFS_LTYPE_INODE &&
	    mxfs_pal_time_ms() - start <
		(uint64_t)max(0, mxfs_caw_fastpoll_window_ms)) {
		if (caw_nudge_wait(ctx, seq,
				   (uint32_t)max(1, mxfs_caw_fastpoll_interval_ms),
				   resource))
			fl |= MXFS_CAW_WAKE_NUDGE;
		return fl;
	}
	if (caw_nudge_wait(ctx, seq, *poll_ms, resource))
		fl |= MXFS_CAW_WAKE_NUDGE;
	if (*poll_ms < (uint32_t)max(1, mxfs_caw_poll_max_ms)) {
		*poll_ms *= 2;
		if (*poll_ms > (uint32_t)max(1, mxfs_caw_poll_max_ms))
			*poll_ms = (uint32_t)max(1, mxfs_caw_poll_max_ms);
	}
	return fl;
}

/* ─── Wait for lock grant (poll disk until compatible or timeout) ─── */

/*
 * `reg_epoch` is the slot's ex_grant_epoch as it stood in the image our waiter
 * registration CAS-ed in (sess109, ruling blocker 3).  It is the ONLY thing
 * that lets the adopt arm tell a grant that was MINTED for us from a holder bit
 * a releaser set without minting: the epoch is a per-resource +1 sequence, so a
 * write-capable tenure granted after our registration must carry an epoch
 * STRICTLY GREATER than the one we registered against.  A pre-sess108 releaser
 * (mixed version) sets the holder bit and leaves ex_grant_epoch at the RELEASING
 * node's value — equal to reg_epoch when no other tenure intervened — and that
 * is precisely the "confidently wrong token" the ruling forbids adopting.
 */
/* sess374: demand-triggered out-of-closure scrub — defined with the closure
 * purge family below, called from the two demand chokepoints above it. */
static uint64_t caw_victim_state_mask(const struct mxfs_caw_lock_slot *s,
				      uint64_t mask);
static int caw_closure_scrub_slot(struct mxfs_dlm_caw_ctx *ctx,
				  uint32_t slot_idx,
				  const struct mxfs_resource_id *res,
				  uint64_t cand_mask,
				  const char *site,
				  uint64_t el_ms);

static int caw_wait_for_grant(struct mxfs_dlm_caw_ctx *ctx,
			       uint32_t slot_idx,
			       const struct mxfs_resource_id *resource,
			       uint8_t mode,
			       uint64_t reg_gen,
			       uint64_t reg_epoch,
			       struct mxfs_caw_lreq *lreq,
			       struct mxfs_grant_result *gres,
			       uint64_t deadline_ms)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint64_t start = mxfs_pal_time_ms();
	uint32_t poll_ms = MXFS_CAW_POLL_INITIAL_MS;
	/* v0.5.3: the registration-time UDP BAST hint is sent ONCE; if that
	 * packet is lost the holder only discovers the waiter via its disk
	 * poll.  Re-send the hint every MXFS_CAW_BAST_RESEND_MS while still
	 * blocked — network-only, no extra disk I/O — so the holder-side
	 * idle disk poll can be relaxed (MXFS_CAW_BAST_POLL_RELAX_MS)
	 * without widening the lost-packet recovery window. */
	uint64_t last_bast_ms = mxfs_pal_time_ms();
	int bast_resends = 0;
	int rc;
	uint32_t prev_magic = 0;
	uint64_t prev_gen = 0;
	uint64_t prev_hex = 0;
	uint64_t prev_hpr = 0;
	uint8_t prev_granted = 0;
	bool first_iter = true;
	bool wait_handoff = false;	/* v0.6.0 EX-handoff epoch observation */
	uint64_t last_stuck_dump_ms = 0;	/* v0.10.43 P-ACQ-STUCK throttle */
	uint64_t last_scrub_ms = 0;	/* sess374 out-of-closure scrub throttle */
	bool quar_skip_lap = false;	/* sess374: one lap owed to ADOPT after a
					 * cancel raced a direct handoff */
	/* sess280 part D: last/max poll-read service time (see read site). */
	uint64_t acq_read_t0 = 0, acq_read_ms = 0, acq_read_max_ms = 0;
	/* P297 (sess296, D-503 ruling step 1) — nominee-side handoff timeline.
	 * pre_read_seq: nudge snapshot taken BEFORE each slot read, so a nudge
	 * landing during the read/processing window (invisible to the sleep's
	 * own prepare) is detectable.  last_wake attributes the wake that
	 * preceded the current read: 0=first read (no sleep yet), 1=nudge,
	 * 2=poll-interval backstop, 3=oversleep past a swallowed nudge. */
	uint64_t pre_read_seq = 0, sleep_t0 = 0, last_sleep_ms = 0;
	int last_wake = 0, p297_miss = 0;
	bool p297_tkt_logged = false;
	/*
	 * sess118: clear-window snapshot for the direct-handoff ADOPT arm.
	 * Re-armed BEFORE every read_slot in the wait loop, because that read
	 * produces the image the adoption publishes on.  This arm is the one
	 * with no prior defence of any kind: it does not go through
	 * caw_grant_meta_store_unless_releasing, and the CAS that set our
	 * holder bit was the PEER's, so there is no local write for a
	 * concurrent clear to lose against.
	 */
	struct mxfs_caw_clr_snap wsnap = { 0, true, false };

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}

	if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P13-INSTR GRANT-WAIT-START ino=%llu slot=%u "
			"want_mode=%u t_ms=%llu",
			(unsigned long long)resource->ino, slot_idx, mode,
			(unsigned long long)start);
	}

	bool slot_seen = false;
	uint64_t ext_last_log_ms = 0;
	/* sess8 (ccloop 72513a13) T1 dead-time anatomy: stamp the FIRST
	 * re-read where the slot was already grantable for `mode`, and count
	 * fair-handoff ticket deferrals taken while grantable.  At grant,
	 * P138-WAIT reports ffw_ms (grantable->grant claim-side latency) and
	 * ytd so the 113ms-p50 inter-tenure gap attributes to (machinery |
	 * ticket-defer | late-arrival) from dmesg alone. */
	uint64_t first_compat_ms = 0;
	int yt_defer = 0;
	/*
	 * ccloop c7ee71c6 sess24 (RULE-5 GPT consult) — CAW ATTEMPT CENSUS.
	 *
	 * The measured "95% of grant wait is spent after the slot first read
	 * COMPATIBLE" does NOT by itself implicate CAS contention: mode-compatible
	 * is not admission-eligible.  A requester the fair-handoff ticket excludes
	 * sleeps while fully compatible, and that policy time lands in the very
	 * same bucket.  The discriminating measurement is how many CAW submissions
	 * each LOGICAL grant costs, classified:
	 *
	 *   long wait, 0-1 attempts         -> admission POLICY is the cost
	 *   long wait, tens of miscompares  -> single-sector CAS contention
	 *   few attempts, slow service_ms   -> block/target/multipath path
	 *
	 * caw_slot() retries only true I/O errors internally; a compare miscompare
	 * returns -EAGAIN straight back and is retried by THIS loop, so counting
	 * here lets no retry path escape the count.
	 */
	int caw_try = 0, caw_miss = 0, caw_err = 0, slot_reads = 0;
	/* sess376: how many times THIS wait actually entered the demand-scrub
	 * chokepoint, reported in P-ACQ-STUCK next to the live candidate mask.
	 * "hook never entered" and "hook entered, oracle refused" are otherwise
	 * indistinguishable from dmesg — the ambiguity D-...-375 was filed on. */
	int scrub_hits = 0;
	uint64_t caw_svc_ms = 0, caw_t0;
	/* sess38 P139 TAIL CENSUS (unconditional, >800ms waits only): the
	 * dir_reuse round wall is set by ONE rotating multi-second outlier
	 * (measured 4.7s EX wait on an otherwise-instant wave).  These
	 * counters discriminate the tail's mechanism from a single line:
	 *   bit_lost      reads where our WAITER BIT was ABSENT after we
	 *                 registered (queue position consumed by churn)
	 *   chosen_seen   reads where yield_to named US (ticket held but
	 *                 grant not completed -> claim/adopt latency)
	 *   foreign_yt    reads where a ticket named someone else (bounded-
	 *                 bypass violation if it dwarfs 31)
	 *   free_defer    reads with NO holders yet we did not claim
	 *   doze250       long-doze sleeps taken (each risks a lost nudge)
	 */
	int p139_bit_lost = 0, p139_chosen = 0, p139_foreign = 0;
	int p139_free_defer = 0, p139_doze250 = 0;
	/* P298 (sess298, D-503): the slow handoffs all end in ADOPT, and the
	 * adopt exit skips the P138/P139 census entirely, so the 1.8s median
	 * sighting->adopt window has NO sub-step attribution.  Classify every
	 * read by what blocked promotion in that image and split wall time
	 * into slept/read/CAS-service, emitted at the ADOPT exit for >800ms
	 * waits:
	 *   bk_wr    reads with a foreign WRITE-class holder (EX|PW) up —
	 *            another tenure ran ahead of the nominated waiter
	 *   bk_shr   reads with only foreign SHARED holders (PR|CW|CR) up —
	 *            a reader class held the slot (bounded-patience cut-ins)
	 *   tkt_lost reads AFTER our first ticket sighting where yield_to
	 *            was nonzero and no longer named us (renominated away) */
	int p298_bk_wr = 0, p298_bk_shr = 0, p298_tkt_lost = 0;
	uint64_t sleep_tot_ms = 0;

	for (;;) {
		uint64_t wait_el = mxfs_pal_time_ms() - start;

		/*
		 * sess158 K6: force the timeout give-up path for a wait whose
		 * own waiter bit is provably registered on the slot.  The
		 * give-up publishes a maximal owed obligation via
		 * caw_drop_own_waiter, which is the only deterministic mid-run
		 * obligation source at 2 nodes (divergence strips and natural
		 * give-ups are effectively unreachable there).  Gated on
		 * slot_seen so cur_slot is a real image from a prior
		 * iteration; exits through the identical cleanup the real
		 * timeout uses.
		 */
		if (slot_seen &&
		    ((cur_slot->waiters | cur_slot->waiters_ex) &
		     ctx->node_bit) &&
		    caw_inject_take(&mxfs_caw_inject_wait_expire)) {
			pr_warn("mxfs: P272-INJECT-WAIT-EXPIRE type=%u ino=%llu mode=%u el_ms=%llu\n",
				resource->type,
				(unsigned long long)resource->ino, mode,
				(unsigned long long)wait_el);
			break;
		}

		if (wait_el >= MXFS_CAW_WAIT_TIMEOUT_MS) {
			/* ccloop 72513a13 sess2 LIVENESS EXTENSION (see
			 * MXFS_CAW_WAIT_HARDCAP_MS in dlm_caw.h): past the
			 * base timeout, keep waiting ONLY while every
			 * blocking holder is provably heartbeating.  Dead
			 * holders get purged by lease expiry (slot bits
			 * cleared -> we promote); a no-holder stall (CAS
			 * storm / waiter-gating) and a live-but-wedged
			 * holder past the hard cap still time out. */
			uint64_t blockers = 0;

			if (slot_seen)
				blockers = (cur_slot->holders_ex |
					    cur_slot->holders_pw |
					    cur_slot->holders_pr |
					    cur_slot->holders_cw |
					    cur_slot->holders_cr) &
					   ~ctx->node_bit;
			if (wait_el >= MXFS_CAW_WAIT_HARDCAP_MS ||
			    !blockers || !ctx->holders_alive_fn ||
			    !ctx->holders_alive_fn(ctx->holders_alive_data,
						   blockers))
				break;
			if (mxfs_pal_time_ms() - ext_last_log_ms > 10000) {
				ext_last_log_ms = mxfs_pal_time_ms();
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P-WAIT-EXTEND type=%u ino=%llu ag=%u want=%u el_ms=%llu blockers=%llx — holders alive; extending past base timeout",
				    resource->type,
				    (unsigned long long)resource->ino,
				    resource->ag_number, mode,
				    (unsigned long long)wait_el,
				    (unsigned long long)blockers);
			}
		}

		if (!ctx->running) {
			rc = -ESHUTDOWN;
			goto out;
		}

		slot_reads++;
		/* sess118: arm before the read the adopt arm publishes on. */
		lreq_clr_snap(ctx, resource, &wsnap);
		/* P297: nudge snapshot BEFORE the read — see the locals. */
		pre_read_seq = caw_nudge_prepare(ctx);
		/* sess280 (sess276 ruling, part D): time every wait-loop poll
		 * read.  The D-482 frozen-grant stalls showed gen pinned for
		 * >120s and nothing said whether those were reads that never
		 * completed or fast reads returning stale data — read_ms in
		 * P-ACQ-STUCK answers that from dmesg alone. */
		acq_read_t0 = mxfs_pal_time_ms();
		rc = read_slot(ctx, slot_idx, cur_slot);
		acq_read_ms = mxfs_pal_time_ms() - acq_read_t0;
		if (acq_read_ms > acq_read_max_ms)
			acq_read_max_ms = acq_read_ms;
		if (rc)
			goto out;
		slot_seen = true;

		/* sess38 P139 tail-census accumulation (cheap bit tests on the
		 * read we already did; emitted only for >800ms waits). */
		if (!(cur_slot->waiters & ctx->node_bit))
			p139_bit_lost++;
		if (cur_slot->yield_to & ctx->node_bit)
			p139_chosen++;
		else if (cur_slot->yield_to)
			p139_foreign++;
		if (!(cur_slot->holders_ex | cur_slot->holders_pw |
		      cur_slot->holders_pr | cur_slot->holders_cw |
		      cur_slot->holders_cr))
			p139_free_defer++;

		/* P298 blocker classification (cheap bit tests on the read we
		 * already did; see the locals). */
		if ((cur_slot->holders_ex | cur_slot->holders_pw) &
		    ~ctx->node_bit)
			p298_bk_wr++;
		else if ((cur_slot->holders_pr | cur_slot->holders_cw |
			  cur_slot->holders_cr) & ~ctx->node_bit)
			p298_bk_shr++;
		if (p297_tkt_logged && cur_slot->yield_to &&
		    !(cur_slot->yield_to & ctx->node_bit))
			p298_tkt_lost++;

		/* P297-TKT (sess296, D-503 ruling step 1): first sighting of a
		 * ticket naming US.  Paired by realms with the releaser's
		 * exwin "nom" line (unlock CAS commit) and this waiter's later
		 * "promote" exwin line (grant), this decomposes the nom
		 * handoff's unlock→adopt idle time into release→sighting
		 * (nudge delivery / sleep attribution) vs sighting→claim
		 * (CAS latency).  wake= names how we woke for THIS read
		 * (1=nudge, 2=poll backstop, 3=oversleep past a swallowed
		 * nudge — the documented prepare-race cost, now measured);
		 * miss= counts swallowed nudges over the whole wait so far. */
		if (resource->type == MXFS_LTYPE_INODE && !p297_tkt_logged &&
		    (cur_slot->yield_to & ctx->node_bit)) {
			static int p297_n;

			p297_tkt_logged = true;
			if (p297_n++ < 20000)
				pr_warn("mxfs: P297-TKT ino=%llu mode=%u el_ms=%llu wake=%d slept_ms=%llu read_ms=%llu miss=%d reads=%d gen=%llu yt=%llx realms=%llu\n",
					(unsigned long long)resource->ino,
					mode,
					(unsigned long long)(mxfs_pal_time_ms() - start),
					last_wake,
					(unsigned long long)last_sleep_ms,
					(unsigned long long)acq_read_ms,
					p297_miss, slot_reads,
					(unsigned long long)cur_slot->generation,
					(unsigned long long)cur_slot->yield_to,
					(unsigned long long)mxfs_pal_time_real_ms());
		}

		/* v0.10.43 (RULE-4): when an INODE acquire is stuck far past a
		 * normal handoff, dump the FULL on-disk slot state periodically
		 * (unconditional, ratelimited) so the holderless-slot wedge at
		 * the dir-reuse boundary is diagnosable without instr=1 — shows
		 * whether waiters/waiters_ex/yield_to is what blocks promotion. */
		if (resource->type == MXFS_LTYPE_INODE) {
			uint64_t el = mxfs_pal_time_ms() - start;
			if (el > 15000 &&
			    mxfs_pal_time_ms() - last_stuck_dump_ms > 8000) {
				/* sess34: myslot names OUR disklock slot so a
				 * fleet-wide P-ACQ-STUCK merge maps every
				 * holder bit to a node (slots are CLAIMED at
				 * join, not rank-ordered — the sess34 orphan
				 * capture could not identify slot 16's owner). */
				uint64_t sod_h;
				int sod_myslot = -1;
				{
					int sod_i;
					for (sod_i = 0; sod_i < 64; sod_i++)
						if (ctx->node_bit &
						    (1ULL << sod_i)) {
							sod_myslot = sod_i;
							break;
						}
				}

				last_stuck_dump_ms = mxfs_pal_time_ms();
				pr_warn_ratelimited(
				    "mxfs: P-ACQ-STUCK ino=%llu slot=%u myslot=%d want=%u el_ms=%llu magic=%x gen=%llu gm=%u hex=%llx hpw=%llx hpr=%llx w=%llx wex=%llx yt=%llx ysm=%llu streak=%u read_ms=%llu read_max_ms=%llu cand=%llx scrubs=%d laps=%d\n",
				    (unsigned long long)resource->ino, slot_idx,
				    sod_myslot,
				    mode, (unsigned long long)el, cur_slot->magic,
				    (unsigned long long)cur_slot->generation,
				    cur_slot->granted_mode,
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pw,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters,
				    (unsigned long long)cur_slot->waiters_ex,
				    (unsigned long long)cur_slot->yield_to,
				    (unsigned long long)cur_slot->yield_set_ms,
				    cur_slot->ex_grant_streak,
				    (unsigned long long)acq_read_ms,
				    (unsigned long long)acq_read_max_ms,
				    (unsigned long long)ctx->closure_cand_mask,
				    scrub_hits, slot_reads);
				/* sess34 SELF-ORPHAN detector: the sole wire
				 * holder is THIS NODE while this waiter is
				 * still pre-CAS — a grant with no in-core
				 * consumer (the orphan family; reap design
				 * per Gemini pends this capture proving the
				 * shape + naming the birth path). */
				sod_h = cur_slot->holders_ex |
					cur_slot->holders_pw |
					cur_slot->holders_pr |
					cur_slot->holders_cw |
					cur_slot->holders_cr;
				if ((sod_h & ctx->node_bit) &&
				    !(sod_h & ~ctx->node_bit))
					pr_warn(
				    "mxfs: P-ACQ-SELF-ORPHAN ino=%llu slot=%u myslot=%d el_ms=%llu gm=%u gen=%llu — sole wire holder is THIS node while this waiter starves (wire grant with no in-core consumer)\n",
					    (unsigned long long)resource->ino,
					    slot_idx, sod_myslot,
					    (unsigned long long)el,
					    cur_slot->granted_mode,
					    (unsigned long long)cur_slot->generation);
			}
		}

		/* v0.5.3: periodic UDP BAST re-send while blocked (see above).
		 * sess8: DO NOT shorten this cadence.  Flat 25ms and a
		 * 4x25ms leading burst both regressed cc@32 (60s -> 84-91s):
		 * most waits are <100ms, so any leading burst multiplies the
		 * whole cluster's hint volume, and the hint flood shares the
		 * recv socket + recv thread with the GRANT nudges — drowning
		 * the very wakeups the handoff depends on. */
		if (mxfs_pal_time_ms() - last_bast_ms >= MXFS_CAW_BAST_RESEND_MS) {
			caw_send_bast_mcast(ctx, resource, mode);
			bast_resends++;
			last_bast_ms = mxfs_pal_time_ms();
		}

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on() &&
		    (first_iter ||
		     cur_slot->magic != prev_magic ||
		     cur_slot->generation != prev_gen ||
		     cur_slot->holders_ex != prev_hex ||
		     cur_slot->holders_pr != prev_hpr ||
		     cur_slot->granted_mode != prev_granted)) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR GRANT-POLL ino=%llu slot=%u "
				"magic=%x gen=%llu hex=%llx hpr=%llx "
				"granted=%u want=%u t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				cur_slot->magic,
				(unsigned long long)cur_slot->generation,
				(unsigned long long)cur_slot->holders_ex,
				(unsigned long long)cur_slot->holders_pr,
				cur_slot->granted_mode, mode,
				(unsigned long long)mxfs_pal_time_ms());
			prev_magic = cur_slot->magic;
			prev_gen = cur_slot->generation;
			prev_hex = cur_slot->holders_ex;
			prev_hpr = cur_slot->holders_pr;
			prev_granted = cur_slot->granted_mode;
			first_iter = false;
		}

		/* Slot cleared? Resource gone */
		if (cur_slot->magic != MXFS_CAW_MAGIC) {
			rc = -ENOENT;
			goto out;
		}

		/*
		 * sess374 (sess357 ruling part 1) — CANCEL A WAIT THE VERDICT
		 * HAS OVERTAKEN.
		 *
		 * A resource INSIDE a quarantined victim domain is meant to
		 * stay frozen; the acquire gate already refuses new attempts
		 * on it.  But this waiter passed that gate BEFORE the verdict
		 * imported, and nothing here ever re-asked — so it sat out the
		 * full DLM timeout against a grant that can never be released
		 * (measured sess374: verdict at t=171s, this waiter reached
		 * the refusal gate at t=467s).  Ask every lap instead.  The
		 * oracle is a lockless read of a monotonic in-memory map, so
		 * this costs two loads on a healthy cluster — cheaper than the
		 * slot read this lap already paid for.
		 *
		 * -EIO is deliberate: it is exactly what the XFS-side
		 * quarantine gate returns for the same condition, so the
		 * caller cannot tell a wait that was cancelled from one that
		 * never started, which is the point.
		 */
		{
			int (*qrf)(void *, const struct mxfs_resource_id *) =
				ctx->wait_refuse_fn;
			uint64_t self_h = (cur_slot->holders_ex |
					   cur_slot->holders_pw |
					   cur_slot->holders_pr |
					   cur_slot->holders_cw |
					   cur_slot->holders_cr) &
					  ctx->node_bit;

			if (quar_skip_lap) {
				/* One lap owed to the ADOPT arm — see below. */
				quar_skip_lap = false;
			} else if (qrf && !self_h &&
				   qrf(ctx->wait_refuse_data, resource) > 0) {
				static int qwc_n;

				if (qwc_n++ < 500)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P240-QUAR-WAITCANCEL type=%u "
					    "ino=%llu ag=%u mode=%u el_ms=%llu — "
					    "resource entered a quarantined victim "
					    "domain while this acquire was already "
					    "waiting; cancelling instead of waiting "
					    "out the DLM timeout",
					    resource->type,
					    (unsigned long long)resource->ino,
					    resource->ag_number, mode,
					    (unsigned long long)(mxfs_pal_time_ms() - start));
				/*
				 * Leave the slot exactly as the TIMEOUT give-up
				 * would.  Returning straight to `out` would
				 * strand our waiter bit on disk with nobody
				 * behind it — the sess48 phantom-waiter wedge —
				 * and a quarantined slot is the last place that
				 * should accumulate one, because nothing will
				 * ever release the grant that would otherwise
				 * sweep it.
				 */
				caw_drop_own_waiter(ctx, slot_idx, resource,
						    lreq, true, mode, false, 0);
				/*
				 * DIRECT-HANDOFF RACE (sess374 RULE-5 review
				 * item c).  A peer's release CAS can transfer
				 * the grant to us — setting our holder bit and
				 * clearing our waiter bit in one CAS — either
				 * before the read above (handled by the
				 * `!self_h` guard, which lets the ADOPT arm
				 * below run instead) or concurrently with the
				 * drop.  Returning -EIO on top of that would
				 * leave an on-disk grant with no in-core
				 * consumer: the P-ACQ-SELF-ORPHAN shape, and on
				 * a quarantined resource nothing would ever
				 * sweep it.  So re-read: if we are a holder
				 * now, owe the ADOPT arm one lap so the grant
				 * is taken properly and tracked.  The operation
				 * still fails — at the XFS quarantine gate —
				 * and the grant is released the normal way.
				 */
				if (read_slot(ctx, slot_idx, cur_slot) == 0 &&
				    cur_slot->magic == MXFS_CAW_MAGIC &&
				    ((cur_slot->holders_ex |
				      cur_slot->holders_pw |
				      cur_slot->holders_pr |
				      cur_slot->holders_cw |
				      cur_slot->holders_cr) & ctx->node_bit)) {
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P240-QUAR-WAITCANCEL-RACE "
					    "type=%u ino=%llu ag=%u — a direct "
					    "handoff granted us this resource "
					    "while we were cancelling; adopting "
					    "it so it is not orphaned on disk",
					    resource->type,
					    (unsigned long long)resource->ino,
					    resource->ag_number);
					quar_skip_lap = true;
					continue;
				}
				rc = -EIO;
				goto out;
			}
		}

		/*
		 * sess374 (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356, sess363
		 * ruling item B / G1) — DEMAND-TRIGGERED OUT-OF-CLOSURE SCRUB.
		 *
		 * This is the single demand chokepoint: every blocking acquire
		 * lands here, whatever the blocking state is (holder bits in
		 * any mode, a waiter/waiters_ex fairness entry, or a yield_to
		 * ticket left by a node that then died).  If one of the nodes
		 * blocking us is a REFUSAL victim whose terminal verdict does
		 * NOT cover this resource, its state here is frozen for no
		 * reason and every waiter on it runs to -110 and shuts the
		 * node down (measured sess356: 4 clean umounts, then the
		 * cluster).  Repair it in place rather than waiting out a
		 * timeout that cannot succeed.
		 *
		 * Armed only after 3s — normal contention resolves in
		 * milliseconds and must not pay for heartbeat reads — and
		 * re-armed no more than every 2s, so a long wait against a
		 * genuinely in-closure grant costs one gate read per 2s.  On a
		 * successful strip we loop straight back to the read rather
		 * than sleeping: the slot just changed underneath us.
		 */
		if (ctx->closure_scrub_fn &&
		    (caw_victim_state_mask(cur_slot, ~ctx->node_bit) &
		     ctx->closure_cand_mask)) {
			uint64_t sc_now = mxfs_pal_time_ms();

			scrub_hits++;

			/*
			 * FIRST attempt is immediate (review item 9: repair
			 * must precede the timeout cascade, not trail an
			 * arbitrary delay).  It costs nothing to arrive here
			 * on a healthy cluster: the candidate-mask test above
			 * is a register operation, and it is false unless a
			 * terminal refusal has actually been imported for a
			 * node whose bits are on THIS slot.  Retries are
			 * throttled to 2s, which only bites when the verdict
			 * says the resource is IN closure and the state is
			 * therefore meant to stay frozen.
			 */
			if (!last_scrub_ms || sc_now - last_scrub_ms > 2000) {
				uint64_t blk = caw_victim_state_mask(cur_slot,
							~ctx->node_bit);

				last_scrub_ms = sc_now;
				if (caw_closure_scrub_slot(ctx, slot_idx,
							   resource, blk,
							   "WAIT",
							   sc_now - start) > 0)
					continue;
			}
		}

		/*
		 * sess37 DIRECT-HANDOFF ADOPT.  A releaser's unlock CAS can
		 * transfer ownership to us outright (mxfs_caw_direct_handoff):
		 * it sets our holder bit, CLEARS our waiter bits, zeroes the
		 * ticket and does epoch/streak bookkeeping for us.  Adopt on
		 * sight — no claim CAW.  Ownership-incarnation conditions
		 * (GPT ruling): our registration for THIS acquire committed at
		 * generation reg_gen; adopt only when the slot moved PAST that
		 * write (gen > reg_gen), our waiter bit is GONE (the handoff
		 * clears it; a stale pre-registration self-bit coexists with a
		 * live waiter bit and cannot show this state), and our holder
		 * bit is set in the REQUESTED mode's bitmap.  Also heals an
		 * AMBIGUOUS own promote CAW (reported miscompare but landed) —
		 * previously an untracked wire grant (the sess34 SIGKILL wedge
		 * family) or a P-SELF-STALE-EDEADLK bounce.
		 */
		if (reg_gen && cur_slot->generation > reg_gen &&
		    !(cur_slot->waiters & ctx->node_bit)) {
			uint64_t *ad_hp = holders_for_mode(cur_slot, mode);

			if (ad_hp && (*ad_hp & ctx->node_bit)) {
				uint32_t prev_epoch = 0;
				bool ad_handoff = true;
				/* The mode we ACTUALLY hold in THIS image, never
				 * the requested mode: an acquire may request PR
				 * while the image also shows our EX bit, and the
				 * write authority belongs to the EX tenure. */
				uint8_t ad_held = node_held_mode(cur_slot,
								 ctx->node_bit);
				const char *ad_reject = NULL;

				/*
				 * sess109 ruling blocker 3 — VALIDATE BEFORE
				 * ADOPTING.  Adoption is RECOGNITION of a durable
				 * grant, never creation of authority, so a
				 * write-capable adopted grant must carry its own
				 * proof in the SAME image:
				 *
				 *  - last_ex_slot names US.  The image must agree
				 *    on who the tenure belongs to, not merely that
				 *    our bit is up.
				 *  - ex_grant_epoch is nonzero (zero is "no write
				 *    tenure was ever minted on this resource").
				 *  - the epoch ADVANCED past what our registration
				 *    saw.  The sequence only ever increases within
				 *    one resource lineage (sess108 tombstone
				 *    carry), so `> reg_epoch` is exactly "a new
				 *    tenure was minted since we queued".  EQUAL
				 *    means a releaser installed our holder bit
				 *    WITHOUT minting — a pre-sess108 node — so the
				 *    token names ITS tenure, not ours.  LESS means
				 *    the slot lineage restarted underneath us.
				 *
				 * FAIL CLOSED = DO NOT ADOPT.  Falling through
				 * reaches the self-hold check below, which returns
				 * -EDEADLK (an EX/PW self-hold is never compatible
				 * with an EX/PW request); the caller's BAST
				 * pipeline drains, clears the on-disk bit and
				 * re-acquires from a clean NL state where the
				 * normal grant CAS mints properly.  That is the
				 * ruling's "reacquired through a correct
				 * transition".  Never rc == 0 on a stale or absent
				 * token: that would turn an uninitialised
				 * authority record into a confidently wrong one.
				 */
				if (mxfs_mode_can_write(ad_held)) {
					if (cur_slot->last_ex_slot != ctx->node_slot)
						ad_reject = "last_ex_slot";
					else if (cur_slot->ex_grant_epoch == 0)
						ad_reject = "zero_epoch";
					else if (cur_slot->ex_grant_epoch <= reg_epoch)
						ad_reject = "unminted";
				}

				if (ad_reject) {
					static int p6h_rj;

					if (p6h_rj++ < 2000)
						pr_warn("mxfs: P6H-ADOPT-REFUSE type=%c id=%llu mode=%u held=%u why=%s gep=%llu reg_gep=%llu lex=%u self=%u gen=%llu reg_gen=%llu\n",
							resource->type == MXFS_LTYPE_INODE ? 'I' :
							resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
							(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
								resource->ino :
								(uint64_t)resource->ag_number),
							mode, ad_held, ad_reject,
							(unsigned long long)cur_slot->ex_grant_epoch,
							(unsigned long long)reg_epoch,
							cur_slot->last_ex_slot,
							ctx->node_slot,
							(unsigned long long)cur_slot->generation,
							(unsigned long long)reg_gen);
				} else if (!lreq_clr_still_good(ctx, resource,
								&wsnap)) {
					/*
					 * sess118 CLEAR-WINDOW VALIDATION — the
					 * sess115 ruling's "adoption stays
					 * PROVISIONAL and retries after".
					 *
					 * This arm publishes a grant it never
					 * wrote: the PEER's release CAS set our
					 * holder bit, and we only read it.  So
					 * unlike the slow-path grant there is no
					 * local CAS for a concurrent destructive
					 * clear to miscompare against, and unlike
					 * the already-held shortcuts there is no
					 * `releasing` mark consulted either — this
					 * was the biggest of the three holes.
					 *
					 * Validated FIRST, before any side effect,
					 * so a refusal costs nothing but a re-read.
					 */
					ctx->lreq_clr_refuse++;
					pr_warn_ratelimited("mxfs: P250-LREQ-CLR-REFUSE type=%c id=%llu arm=adopt mode=%u held=%u — a destructive local clear ran under the handoff image; re-reading\n",
						resource->type == MXFS_LTYPE_INODE ? 'I' :
						resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
						(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
							resource->ino : (uint64_t)resource->ag_number),
						mode, ad_held);
					mxfs_pal_sleep_ms(1);
					continue;
				} else {
					/* Foreign EX-class tenure since OUR last grant
					 * of this resource?  dir_epoch answers exactly
					 * that; no cached meta = assume yes (safe:
					 * forces the reload gate). */
					if (caw_grant_meta_get_epoch(ctx, resource,
								     &prev_epoch))
						ad_handoff = (prev_epoch !=
							      cur_slot->dir_epoch);
					/* Blocker 3: provenance from the EXACT image
					 * that established adoption, captured before
					 * anything else can touch this slot.
					 * reaffirm=1 — this tenure was minted by the
					 * RELEASER's CAS, not by one of ours. */
					caw_grant_result_fill(gres, resource, cur_slot,
							      ad_held, true);
					caw_grant_seq_prebump(ctx, resource);
					track_held(ctx, slot_idx);
					caw_grant_meta_store(ctx, resource,
							     cur_slot->dir_epoch,
							     ad_handoff,
							     cur_slot->dir_block0_fsb,
							     cur_slot->dir_block0_gen);
					if (resource->type == MXFS_LTYPE_INODE) {
						static int p6h_n;

						if (p6h_n++ < 2000)
							pr_warn("mxfs: P6H-ADOPT ino=%llu mode=%u held=%u elapsed_ms=%llu gen=%llu reg_gen=%llu handoff=%d reads=%d gep=%llu reg_gep=%llu st=%u realms=%llu\n",
								(unsigned long long)resource->ino,
								mode, ad_held,
								(unsigned long long)(mxfs_pal_time_ms() - start),
								(unsigned long long)cur_slot->generation,
								(unsigned long long)reg_gen,
								ad_handoff ? 1 : 0,
								slot_reads,
								(unsigned long long)cur_slot->ex_grant_epoch,
								(unsigned long long)reg_epoch,
								gres ? gres->status : 0,
								(unsigned long long)mxfs_pal_time_real_ms());
					}
					caw_exwin_log(resource, "adopt", mode,
						      ctx->node_slot,
						      mxfs_pal_time_ms() - start,
						      cur_slot->yield_to,
						      cur_slot->waiters_ex);
					/* P298 (sess298, D-503): sub-step
					 * attribution for the slow-adopt tail
					 * — the adopt exit skips the P138/P139
					 * census, so this is the only line
					 * that decomposes the 1.8s median
					 * sighting->adopt window.  el =
					 * slept + reads*read_svc + caw_svc +
					 * processing; bk_* classify what each
					 * read saw blocking promotion. */
					if (resource->type == MXFS_LTYPE_INODE &&
					    mxfs_pal_time_ms() - start > 800) {
						static int p298_n;

						if (p298_n++ < 2000)
							pr_warn("mxfs: P298-ADOPTCENSUS ino=%llu mode=%u el_ms=%llu reads=%d bk_wr=%d bk_shr=%d free=%d chosen=%d tkt_lost=%d ytd=%d doze=%d caw_try=%d caw_miss=%d svc_ms=%llu slept_ms=%llu miss=%d realms=%llu\n",
								(unsigned long long)resource->ino,
								mode,
								(unsigned long long)(mxfs_pal_time_ms() - start),
								slot_reads,
								p298_bk_wr,
								p298_bk_shr,
								p139_free_defer,
								p139_chosen,
								p298_tkt_lost,
								yt_defer,
								p139_doze250,
								caw_try, caw_miss,
								(unsigned long long)caw_svc_ms,
								(unsigned long long)sleep_tot_ms,
								p297_miss,
								(unsigned long long)mxfs_pal_time_real_ms());
					}
					rc = 0;
					goto out;
				}
			}
		}

		/* v0.10.44 ROOT FIX (dir_reuse@32 cluster wedge): if the slot
		 * shows OUR OWN bit held in a mode that CONFLICTS with what we
		 * are waiting for, the blocker is us — a STALE SELF-HOLD.  This
		 * happens at the dir-reuse boundary: rank1 frees+recreates the
		 * shared dir inode; a peer that held EX on the freed incarnation
		 * has its in-core DLM state reset to NL (fresh reclaimed inode)
		 * WITHOUT clearing its on-disk holder bit (resource_id carries
		 * no inode-generation, so the reused inode maps to the SAME CAW
		 * slot and inherits the prior tenure's bit).  We can NEVER become
		 * compatible waiting for ourselves — the whole cluster then wedges
		 * 360s on that inode (PROVEN B6: test32 held bit31 EX in slot
		 * 51115, in-core NONE/NL, all 32 nodes starved -> rc=-110).
		 * Return -EDEADLK so mxfs_dlm_ilock_begin routes through the
		 * proven bast_process recovery (drain + clear the on-disk bit +
		 * i_dlm_mode=NL) and retries from a clean NL state — identical to
		 * the main-loop upgrade-deadlock resolver. */
		if (node_held_mode(cur_slot, ctx->node_bit) != MXFS_LOCK_NL &&
		    !is_compatible(cur_slot, mode)) {
			if (resource->type == MXFS_LTYPE_INODE)
				pr_warn_ratelimited(
				    "mxfs: P-SELF-STALE-EDEADLK ino=%llu slot=%u want=%u held=%u hex=%llx hpr=%llx w=%llx — self-hold blocks own acquire; -EDEADLK to clear\n",
				    (unsigned long long)resource->ino, slot_idx,
				    mode,
				    node_held_mode(cur_slot, ctx->node_bit),
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters);
			rc = -EDEADLK;
			goto out;
		}

		if (is_compatible(cur_slot, mode)) {
			if (!first_compat_ms)
				first_compat_ms = mxfs_pal_time_ms();
			/*
			 * sess2(ccloop 26c41354) FAIR HANDOFF: honor the
			 * round-robin EX ticket the releaser set in yield_to.
			 * If a DIFFERENT node is the chosen next (yield_to set,
			 * our bit absent) and we are a FRESH waiter (we hold NL
			 * — an upgrader keeps conversion priority, sess130), do
			 * NOT self-promote: let the chosen EX waiter go first.
			 * This replaces the free-for-all where an unlucky node's
			 * poll cadence never wins (16-node victim-node loss).  A
			 * STALE ticket (>5s: chosen node died) is CAS-cleared
			 * here so no waiter deadlocks.  Inode locks only.
			 */
			/*
			 * ccloop c7ee71c6 sess24 SHARED-CLASS BYPASS (see the
			 * measurement in mxfs_caw_pr_batch_nodefer's comment).
			 * yt_guards_ex is deliberately BROADER than "the ticket
			 * names an EX waiter": a batch ticket snapshotted while
			 * the slot was PR-only can be followed by a fresh EX
			 * waiter, and that waiter must still be protected, so
			 * any EX waiter on the slot disables the bypass.
			 */
			bool yt_guards_ex =
				(cur_slot->yield_to & cur_slot->waiters_ex) ||
				(cur_slot->waiters & cur_slot->waiters_ex);
			bool shared_req = (mode == MXFS_LOCK_PR ||
					   mode == MXFS_LOCK_CR);
			/* sess24 BOUNDED PATIENCE: our OWN wait, not yt_age --
			 * the ticket's clock is re-armed on every EX handoff
			 * (measured: age_ms=0..8 while this waiter's ytd hit
			 * 86), so it can never bound anything. */
			bool pr_impatient = (shared_req &&
					     mxfs_caw_pr_defer_max_ms > 0 &&
					     (mxfs_pal_time_ms() - start) >=
					     (uint64_t)mxfs_caw_pr_defer_max_ms);
			bool pr_nodefer = (mxfs_caw_pr_batch_nodefer &&
					   shared_req && !yt_guards_ex) ||
					  pr_impatient;

			/* ccloop c7ee71c6 sess24: capped, NOT caw_instr_on()-
			 * gated.  mxfs.instr defaults to 0 and its own comment
			 * says enabling it is "thousands of printk/sec on the
			 * lock hot path ... ~100x slower" — so gating a pace
			 * diagnostic behind it makes the pace unmeasurable, and
			 * a zero reading unfalsifiable (the first A/B of this
			 * fix read nodefer=0 for exactly that reason and proved
			 * nothing).  A hard 200-line cap per module load is
			 * self-limiting the way P138's 4000-cap is. */
			if (pr_nodefer && cur_slot->yield_to != 0 &&
			    !(cur_slot->yield_to & ctx->node_bit) &&
			    resource->type == MXFS_LTYPE_INODE) {
				static int p203_n;

				if (p203_n++ < 200)
					pr_warn(
					    "mxfs: P203-PR-NODEFER ino=%llu mode=%u why=%s yt=%llx w=%llx wex=%llx waited_ms=%llu ytd=%d\n",
					    (unsigned long long)resource->ino, mode,
					    pr_impatient ? "patience" : "no-ex-waiter",
					    (unsigned long long)cur_slot->yield_to,
					    (unsigned long long)cur_slot->waiters,
					    (unsigned long long)cur_slot->waiters_ex,
					    (unsigned long long)(mxfs_pal_time_ms() - start),
					    yt_defer);
			}

			if (mxfs_caw_fair_handoff &&
			    resource->type == MXFS_LTYPE_INODE &&
			    cur_slot->yield_to != 0 &&
			    !(cur_slot->yield_to & ctx->node_bit) &&
			    !pr_nodefer &&
			    node_held_mode(cur_slot, ctx->node_bit) ==
				MXFS_LOCK_NL) {
				uint64_t yt_now = mxfs_pal_time_real_ms();
				uint64_t yt_age = (yt_now > cur_slot->yield_set_ms) ?
						  (yt_now - cur_slot->yield_set_ms) : 0;
				/*
				 * sess299 (ruling item 8): the ticket is a
				 * RESERVATION while any named node is still a
				 * registered waiter.  Age alone never clears
				 * it — a live nominee that has waited >5s is
				 * exactly the starved waiter the reservation
				 * exists to protect.  Only a ticket whose
				 * every bit has left `waiters` (deregister,
				 * cancel, lease purge — those are the paths
				 * that clear waiter bits) is demonstrably
				 * dead and may be aged out.
				 */
				bool yt_live = (cur_slot->yield_to &
						cur_slot->waiters) != 0;

				if (yt_age < MXFS_CAW_YIELD_TIMEOUT_MS ||
				    yt_live) {
					/* not our turn — keep waiting */
					yt_defer++;
					/* ccloop c7ee71c6 sess24 RULE-4: the
					 * sess24 shared-class bypass measured
					 * ZERO engagements (P203 never fired)
					 * while this site still took 6140
					 * deferrals on a mode=PR wait, so
					 * yt_guards_ex must be true here.  Print
					 * the slot's own waiter masks so WHICH
					 * EX waiter (or which stale leaked
					 * waiters_ex bit) blocks the bypass is a
					 * measurement, not a guess.  First 200
					 * per module load: enough to census one
					 * workload, cheap enough to leave on. */
					if (resource->type == MXFS_LTYPE_INODE) {
						static int p204_n;

						if (p204_n++ < 200)
							pr_warn(
							    "mxfs: P204-YT-DEFER ino=%llu req_mode=%u yt=%llx w=%llx wex=%llx hpr=%llx hex=%llx nb=%llx age_ms=%llu ytd=%d\n",
							    (unsigned long long)resource->ino,
							    mode,
							    (unsigned long long)cur_slot->yield_to,
							    (unsigned long long)cur_slot->waiters,
							    (unsigned long long)cur_slot->waiters_ex,
							    (unsigned long long)cur_slot->holders_pr,
							    (unsigned long long)cur_slot->holders_ex,
							    (unsigned long long)ctx->node_bit,
							    (unsigned long long)yt_age,
							    yt_defer);
					}
					/* sess35: the ticket names another node
					 * — only its promote/release can
					 * change our situation, and that CAW
					 * sends a targeted nudge.  Long-doze
					 * instead of herd-polling. */
					p139_doze250++;
					sleep_t0 = mxfs_pal_time_ms();
					{
						int wfl = caw_acquire_poll_sleep(
							ctx, resource, start,
							&poll_ms,
							MXFS_CAW_DEFER_POLL_MS,
							pre_read_seq);

						last_sleep_ms =
							mxfs_pal_time_ms() -
							sleep_t0;
						sleep_tot_ms += last_sleep_ms;
						if (wfl & MXFS_CAW_WAKE_MISS)
							p297_miss++;
						last_wake =
						    (wfl & MXFS_CAW_WAKE_NUDGE) ?
							1 :
						    (wfl & MXFS_CAW_WAKE_MISS) ?
							3 : 2;
					}
					continue;
				}
				/* stale ticket (chosen node died OR a persistent
				 * pr_w streak-yield aged out — v0.10.40): clear
				 * + retry.  This is the safety valve that breaks
				 * the EX-starvation deadlock. */
				if (resource->type == MXFS_LTYPE_INODE)
					pr_warn_ratelimited(
					    "mxfs: P-YT-STALECLR ino=%llu yt=%llx age_ms=%llu req_mode=%u\n",
					    (unsigned long long)resource->ino,
					    (unsigned long long)cur_slot->yield_to,
					    (unsigned long long)yt_age,
					    mode);
				*new_slot = *cur_slot;
				new_slot->yield_to = 0;
				new_slot->yield_set_ms = 0;
				new_slot->generation++;
				caw_try++;
				caw_t0 = mxfs_pal_time_ms();
				(void)caw_slot(ctx, slot_idx, cur_slot,
					       new_slot);
				caw_svc_ms += mxfs_pal_time_ms() - caw_t0;
				continue;
			}
			/* Try to promote from waiter to holder */
			*new_slot = *cur_slot;
			new_slot->waiters &= ~ctx->node_bit;
			new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50: no longer an exclusive waiter */

			/* Clear our bit from yield_to — we were yielded to and are taking our turn */
			if (new_slot->yield_to & ctx->node_bit)
				new_slot->yield_to &= ~ctx->node_bit;

			{
				uint64_t *hp = holders_for_mode(new_slot, mode);
				if (hp)
					*hp |= ctx->node_bit;
			}
			/*
			 * sess38 BATCH-COMPLETION-ON-CLAIM (P139 census root):
			 * when a streak-yield PR batch ticket names N readers,
			 * the release-side P6H-PRBATCH arm admits them only if
			 * the releaser was the LAST holder; otherwise all N
			 * self-claimed ONE CAS AT A TIME — measured 9 nodes x
			 * ~22 tries x ~40ms inflated service = ~900ms
			 * simultaneous PR admission storms (each success
			 * invalidating the other 8's compare base), one per
			 * round, setting the dir_reuse round wall.  Fix per
			 * the RULE-5 GPT ruling ("any node may CAS the next
			 * state transition"): the FIRST member whose claim CAS
			 * wins admits EVERY still-registered shared-class
			 * sibling of the ticket in the SAME write.  Siblings
			 * adopt on sight exactly as for the release-side batch
			 * (identical on-disk result; adopt logic is author-
			 * agnostic).  Recovery story unchanged per reader:
			 * abort-reconcile clears a landed grant for an
			 * abandoned acquire, lease purge covers death.
			 */
			if (mode == MXFS_LOCK_PR && mxfs_caw_direct_handoff &&
			    (cur_slot->yield_to & ctx->node_bit)) {
				uint64_t sibs = cur_slot->yield_to &
						new_slot->waiters &
						~new_slot->waiters_ex &
						~ctx->node_bit;

				if (sibs) {
					new_slot->holders_pr |= sibs;
					new_slot->waiters &= ~sibs;
					new_slot->yield_to = 0;
					if (resource->type ==
					    MXFS_LTYPE_INODE) {
						static int p6h_pcb_n;

						if (p6h_pcb_n++ < 2000)
							pr_warn("mxfs: P6H-PRCLAIMBATCH ino=%llu mask=%llx n=%d realms=%llu\n",
								(unsigned long long)resource->ino,
								(unsigned long long)sibs,
								mxfs_pal_popcount64(sibs),
								(unsigned long long)mxfs_pal_time_real_ms());
					}
				}
			}
			caw_grant_streak_note(new_slot, mode);
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->waiter_mode =
				recompute_waiter_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			caw_revoke_consume(new_slot, cur_slot);
			wait_handoff = caw_grant_epoch_update(new_slot,
							      cur_slot,
							      ctx->node_slot,
							      mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			caw_try++;
			caw_t0 = mxfs_pal_time_ms();
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			caw_svc_ms += mxfs_pal_time_ms() - caw_t0;
			if (rc == -EAGAIN) {
				caw_miss++;
				continue; /* Someone else changed it, retry */
			}
			if (rc)
				caw_err++;
			if (rc)
				goto out;

			caw_check_exclusion(ctx, resource, new_slot, mode);
			caw_verify_grant_persisted(ctx, resource, slot_idx, mode);
			track_held(ctx, slot_idx);
			/* sess97 step 5.3(b): provenance from the image that
			 * just CAS-ed successfully, before anything else can
			 * touch this slot. */
			caw_grant_result_fill(gres, resource, new_slot, mode,
					      false);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     wait_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			/* ccloop 72513a13 sess3: our grant CAW just changed
			 * the slot; other queued waiters (e.g. the rest of a
			 * PR class joining a shared grant) should re-read now
			 * rather than after their poll interval.
			 *
			 * sess35 NUDGE v2: an EX grant makes NOBODY grantable
			 * — waking the queue is a pure herd (each wake = one
			 * FUA read at the shared target).  Skip it; waiters
			 * learn at the next release nudge.  A shared grant
			 * can admit the rest of the PR class: wake exactly
			 * them (waiters that are not EX waiters). */
			if (new_slot->waiters & ~ctx->node_bit) {
				uint64_t wmask = 0;

				if (mode != MXFS_LOCK_EX)
					wmask = new_slot->waiters &
						~new_slot->waiters_ex &
						~ctx->node_bit;
				if (wmask)
					caw_send_grant_mcast(ctx, resource,
							     wmask);
			}
			caw_exwin_log(resource, "promote", mode, ctx->node_slot,
				      mxfs_pal_time_ms() - start,
				      cur_slot->yield_to, cur_slot->waiters_ex);
			rc = 0; /* Granted */
			/* sess131 P131-WAITLONG: always-on starvation probe —
			 * any grant that waited >1s is a fairness defect
			 * (zero_silent_loss 16-node storm tail analysis). */
			if (caw_instr_on() &&
			    mxfs_pal_time_ms() - start > 1000)
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P131-WAITLONG type=%u ino=%llu ag=%u "
				    "mode=%u elapsed_ms=%llu",
				    resource->type,
				    (unsigned long long)resource->ino,
				    resource->ag_number, mode,
				    (unsigned long long)(mxfs_pal_time_ms() - start));
			if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P13-INSTR GRANT-WAIT-OK ino=%llu "
					"slot=%u mode=%u elapsed_ms=%llu",
					(unsigned long long)resource->ino,
					slot_idx, mode,
					(unsigned long long)(mxfs_pal_time_ms() - start));
			}
			/*
			 * v0.5.6 P138 (always-on, >5ms, ratelimited):
			 * waiter-side total for a contended grant.  Pair with
			 * the holder's P138-BAST line (same ino) to attribute
			 * a slow cross-node lock migration to holder release
			 * vs delivery/discovery dead time.
			 */
			if (resource->type == MXFS_LTYPE_INODE &&
			    mxfs_pal_time_ms() - start > 5) {
				/* sess8: capped (not ratelimited — storm runs
				 * lost most lines) + T1 anatomy fields.
				 * ffw_ms = grantable->grant claim latency;
				 * ytd = ticket deferrals while grantable;
				 * realms = wall clock for cross-node hop
				 * pairing with the releaser's EXIT realns. */
				static int p138_n;
				uint64_t now_ms = mxfs_pal_time_ms();

				/* sess38 P139 tail census: the rotating multi-
				 * second outlier that sets every dir_reuse
				 * round wall.  Unconditional (tail events are
				 * rare by definition); discriminates queue-
				 * position loss vs claim latency vs bounded-
				 * bypass violation vs lost-nudge dozing. */
				if (now_ms - start > 800) {
					static int p139_n;

					if (p139_n++ < 2000)
						pr_warn(
						    "mxfs: P139-TAILCENSUS ino=%llu mode=%u elapsed_ms=%llu ffw_ms=%llu reads=%d bit_lost=%d chosen=%d foreign_yt=%d free_defer=%d doze250=%d ytd=%d caw_try=%d caw_miss=%d realms=%llu\n",
						    (unsigned long long)resource->ino,
						    mode,
						    (unsigned long long)(now_ms - start),
						    (unsigned long long)(first_compat_ms ?
							now_ms - first_compat_ms : 0),
						    slot_reads, p139_bit_lost,
						    p139_chosen, p139_foreign,
						    p139_free_defer, p139_doze250,
						    yt_defer, caw_try, caw_miss,
						    (unsigned long long)mxfs_pal_time_real_ms());
				}
				if (p138_n++ < 4000)
					pr_warn(
					    "mxfs: P138-WAIT ino=%llu mode=%u elapsed_ms=%llu ffw_ms=%llu ytd=%d poll=%u caw_try=%d caw_miss=%d caw_err=%d caw_svc_ms=%llu reads=%d realms=%llu\n",
						(unsigned long long)resource->ino,
						mode,
						(unsigned long long)(now_ms - start),
						(unsigned long long)(first_compat_ms ?
							now_ms - first_compat_ms : 0),
						yt_defer, poll_ms,
						caw_try, caw_miss, caw_err,
						(unsigned long long)caw_svc_ms, slot_reads,
						(unsigned long long)mxfs_pal_time_real_ms());
			}
			goto out;
		}

		/* sess35 NUDGE v2: a foreign EX holder excludes every grant
		 * until its release, and that release's CAW sends a targeted
		 * nudge — long-doze instead of herd-polling the slot.  Any
		 * other shape (free slot raced away, PR class forming, CAS
		 * miss) keeps the fast cadence. */
		if (cur_slot->holders_ex & ~ctx->node_bit)
			p139_doze250++;
		/*
		 * sess386 (RULE-5 ruling, bounded-reserve fix for the 474
		 * AGI-hold leg): caller-supplied ABSOLUTE deadline.  Checked
		 * HERE — after this lap's read and every grant-attempt arm —
		 * so a grant seen on the final read wins over the deadline
		 * (the ruling's grant-wins rule); reaching the sleep proves
		 * this lap did not grant.  Exits through the exact same
		 * robust cancel path as the base timeout (caw_drop_own_waiter
		 * retry-until-clear + ABORT-RECONCILE for a handoff that
		 * races the cancel), which is the proven linearization point.
		 */
		if (deadline_ms && mxfs_pal_time_ms() >= deadline_ms) {
			pr_warn_ratelimited(
			    "mxfs: P-RESV-DEADLINE type=%u ino=%llu ag=%u mode=%u el_ms=%llu reads=%d — bounded acquire expired; cancelling waiter\n",
				resource->type,
				(unsigned long long)resource->ino,
				resource->ag_number, mode,
				(unsigned long long)(mxfs_pal_time_ms() - start),
				slot_reads);
			break;
		}
		sleep_t0 = mxfs_pal_time_ms();
		/* Never oversleep a live deadline: clamp this lap's poll. */
		if (deadline_ms) {
			uint64_t now_ms = mxfs_pal_time_ms();
			uint64_t left = deadline_ms > now_ms ?
					deadline_ms - now_ms : 1;

			if (poll_ms > left)
				poll_ms = (uint32_t)left;
		}
		{
			int wfl = caw_acquire_poll_sleep(ctx, resource, start,
							 &poll_ms,
							 (cur_slot->holders_ex &
							  ~ctx->node_bit) ?
							 MXFS_CAW_DEFER_POLL_MS :
							 0, pre_read_seq);

			last_sleep_ms = mxfs_pal_time_ms() - sleep_t0;
			sleep_tot_ms += last_sleep_ms;
			if (wfl & MXFS_CAW_WAKE_MISS)
				p297_miss++;
			last_wake = (wfl & MXFS_CAW_WAKE_NUDGE) ? 1 :
				    (wfl & MXFS_CAW_WAKE_MISS) ? 3 : 2;
		}
	}

	/* Timeout — clean up waiter bit.  A caller-bounded (deadline_ms)
	 * expiry is an EXPECTED contention outcome already logged by
	 * P-RESV-DEADLINE above — do not print the alarming base-timeout
	 * line for it. */
	if (!deadline_ms || mxfs_pal_time_ms() - start >= MXFS_CAW_WAIT_TIMEOUT_MS)
		mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: disk lock acquisition timed out after %llu ms "
		     "(base %u ms, liveness-extended cap %u ms)",
		     (unsigned long long)(mxfs_pal_time_ms() - start),
		     MXFS_CAW_WAIT_TIMEOUT_MS, MXFS_CAW_WAIT_HARDCAP_MS);
	if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P13-INSTR GRANT-WAIT-TIMEOUT ino=%llu slot=%u "
			"want_mode=%u t_ms=%llu",
			(unsigned long long)resource->ino, slot_idx, mode,
			(unsigned long long)mxfs_pal_time_ms());
	}

	/* sess48: robust cleanup — the old bounded 10-retry CAS loop here could
	 * lose every attempt under a 16-node hot-slot CAS storm, leaking our
	 * EX-waiter bit permanently (phantom-waiter wedge).  Retry until our bit
	 * is confirmed clear. */
	caw_drop_own_waiter(ctx, slot_idx, resource, lreq, true, mode, false,
			    0);

	rc = -ETIMEDOUT;

out:
	/*
	 * sess109 structural defense (ruling item B): make "rc == 0 implies a
	 * fully-initialised grant result" an ENFORCED invariant rather than a
	 * convention that each new success arm has to remember.  Every success
	 * path in this function fills gres from the exact image it granted on;
	 * an UNSET status escaping here means a NEW arm was added that grants
	 * without recording provenance — the exact defect class blocker 3 was
	 * (sess106 measured it as st_unset on all 32 nodes).  Report it loudly
	 * and name the resource, so the gap is found in a log rather than by
	 * the replayer trusting a zeroed token.
	 */
	if (rc == 0 && gres && gres->status == MXFS_GAUTH_UNSET) {
		static int p_unset_n;

		if (p_unset_n++ < 200)
			pr_warn("mxfs: P242-GRANT-UNSET-WAIT type=%c id=%llu slot=%u mode=%u — success with no provenance (grant arm did not fill the result)\n",
				resource->type == MXFS_LTYPE_INODE ? 'I' :
				resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
				(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
					resource->ino : (uint64_t)resource->ag_number),
				slot_idx, mode);
	}
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/* ─── In-memory lock tracking for single-node bypass ─── */

static void mem_lock_track(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t mode)
{
	int i;

	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);

	/* Update existing entry if same resource */
	for (i = 0; i < ctx->mem_lock_count; i++) {
		if (memcmp(&ctx->mem_locks[i].resource, resource,
			   sizeof(*resource)) == 0) {
			ctx->mem_locks[i].mode = mode;
			mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
			return;
		}
	}

	/* Add new entry */
	if (ctx->mem_lock_count < ctx->max_held) {
		ctx->mem_locks[ctx->mem_lock_count].resource = *resource;
		ctx->mem_locks[ctx->mem_lock_count].mode = mode;
		ctx->mem_lock_count++;
	}

	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
}

static void mem_lock_untrack(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource)
{
	int i;

	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);

	for (i = 0; i < ctx->mem_lock_count; i++) {
		if (memcmp(&ctx->mem_locks[i].resource, resource,
			   sizeof(*resource)) == 0) {
			ctx->mem_locks[i] =
				ctx->mem_locks[--ctx->mem_lock_count];
			break;
		}
	}

	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
}

/*
 * sess39: desync the compare-and-write storm on a hot INODE lock slot.
 *
 * Under N-node concurrent same-directory rename, every node read-modify-CAS
 * the SAME inode lock slot in lockstep.  Each MISCOMPARE returns -EAGAIN and
 * the outer loop retries with no delay, so an unlucky node can lose all
 * MXFS_CAW_MAX_RETRIES rounds; the acquire then returns -ETIMEDOUT and
 * mxfs_dlm_ilock_begin force-shuts-down the filesystem (observed: "DLM inode
 * lock unrecoverable ... rc=-110").  A small node-phased jittered sleep
 * breaks the lockstep so each contender gets uncontended CAS windows and the
 * operation converges well within the retry budget.
 *
 * SCOPE: inode locks only.  AG locks under streaming write (dd) retry
 * frequently for non-contention reasons; a cumulative backoff there
 * regressed throughput and hung xfs_ilock (v0.3.46 added / v0.3.50 reverted
 * a global backoff for exactly this reason).  Keeping AG locks on the tight
 * loop preserves that result while fixing the inode-contention livelock.
 *
 * The delay is a true-random draw per attempt (v0.10.35 — the earlier
 * node-phased modulo produced only 7 distinct sequences, phase-locking
 * collision groups at 32 nodes), widening gently with retry count, bounded
 * low and skipped for the first couple of retries so the uncontended
 * common case stays fast.
 */
static void caw_inode_backoff(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      int retry)
{
	uint32_t ms;

	if (!resource || resource->type != MXFS_LTYPE_INODE)
		return;
	if (retry < 2)
		return;	/* keep the uncontended common case tight */

	/*
	 * v0.10.35: TRUE-RANDOM jitter.  The deterministic
	 * (retry + local_node * 5) % 7 phased only 7 distinct sequences —
	 * at 32 nodes, ~5 nodes share each phase and re-collide on every
	 * retry (proven: 32-node rm storm, 31 holders CAS-clearing the same
	 * slot; P138-BAST su tails of 60-101ms from persistent collision
	 * groups gate every unlink at ~45ms).  A random draw per attempt
	 * breaks the phase lock; the window widens gently with retry so a
	 * deep convoy spreads out, capped at 20ms to keep worst-case
	 * recovery snappy.
	 */
	{
		uint32_t cap = 4u + 2u * (uint32_t)retry;
		uint8_t rnd;

		if (cap > 20u)
			cap = 20u;
		mxfs_pal_get_random_bytes(&rnd, sizeof(rnd));
		ms = rnd % cap;		/* 0-inclusive: no mandatory tax */
	}
	if (ms)
		mxfs_pal_sleep_ms(ms);
}

/*
 * sess39: ALWAYS-ON exclusive-grant invariant check.  After we record a
 * grant in `slot`, verify the slot's holder bitmaps obey DLM exclusion:
 *  - if WE hold EX/PW, NO other node may hold ANY mode;
 *  - if WE hold PR/CR/CW, NO node may hold EX/PW.
 * A violation means two nodes believe they hold incompatible modes on the
 * same resource at once — the single fault that would explain the on-disk
 * corruption (double allocation, bmap/iunlink/SB corruption) seen under
 * concurrent same-dir rename.  Cheap (bitmask ops), fires only on the bug,
 * ratelimited; NOT gated on the instr param so it surfaces in production.
 */
static void caw_check_exclusion(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				const struct mxfs_caw_lock_slot *slot,
				uint8_t mode)
{
	uint64_t self = ctx->node_bit;
	uint64_t others_ex = slot->holders_ex & ~self;
	uint64_t others_pw = slot->holders_pw & ~self;
	uint64_t others_pr = slot->holders_pr & ~self;
	uint64_t others_cw = slot->holders_cw & ~self;
	uint64_t others_any = others_ex | others_pw | others_pr | others_cw |
			      (slot->holders_cr & ~self);
	bool	bad = false;

	if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW) {
		if (others_any)
			bad = true;
	} else if (mode == MXFS_LOCK_PR || mode == MXFS_LOCK_CR ||
		   mode == MXFS_LOCK_CW) {
		if (others_ex || others_pw)
			bad = true;
	}

	if (unlikely(bad))
		mxfs_pal_log(MXFS_LOG_ERR,
		    "mxfs: CAW-EXCL-VIOLATION ino=%llu type=%u our_mode=%u "
		    "self=%llx h_ex=%llx h_pw=%llx h_pr=%llx h_cw=%llx h_cr=%llx",
		    (unsigned long long)resource->ino, resource->type, mode,
		    (unsigned long long)self,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->holders_cw,
		    (unsigned long long)slot->holders_cr);
}

/*
 * sess44 P87: decisive DLM-split test.  After an EX/PW grant CAS reports
 * SUCCESS, re-read the slot straight from disk and verify our bit is the
 * ONLY EX holder.  caw_check_exclusion() above only inspects the in-core
 * new_slot we constructed, so it cannot detect a CAS that "succeeded" but
 * did not persist exclusively (the documented sess26 failure: SCSI CAW
 * reports CAS-success without durably persisting).  If our bit is MISSING
 * from the on-disk holders_ex, or another node's bit is also set, two nodes
 * believe they hold the AG EX => concurrent same-AG metadata modify =>
 * bnobt/AGF lost-update (the pristine-revert + xfs_alloc.c:2231 overlap).
 * EX/PW are single-holder modes so the on-disk holders_ex must equal exactly
 * our node_bit.  Ratelimited at the PAL log; fires only on the rare split.
 */
static void caw_verify_grant_persisted(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       uint32_t slot_idx, uint8_t mode)
{
	struct mxfs_caw_lock_slot *vs;
	/* ccloop 72513a13 sess3: this read-back was 1 FUA read per EX grant
	 * — ~1 op per created/unlinked file cluster-wide.  The sess26 target
	 * misbehavior it detects (CAS reports success but does not persist)
	 * is not per-resource: SAMPLE inode grants 1/64 and keep AG grants
	 * (free-space lost-update blast radius) at every-grant.  The counter
	 * race is benign (sampling only). */
	static uint32_t p87_sample;

	if (mode != MXFS_LOCK_EX && mode != MXFS_LOCK_PW)
		return;
	if (resource->type == MXFS_LTYPE_INODE && (p87_sample++ & 63) != 0)
		return;
	vs = mxfs_pal_alloc(sizeof(*vs));
	if (!vs)
		return;
	if (read_slot(ctx, slot_idx, vs) == 0) {
		if ((vs->holders_ex & ctx->node_bit) == 0 ||
		    mxfs_pal_popcount64(vs->holders_ex) != 1) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "mxfs: P87-CAW-SPLIT slot=%u mode=%u self=%llx "
			    "disk_h_ex=%llx popcnt=%d (post-CAS grant did NOT "
			    "persist exclusively => DLM split / lost-update root)",
			    slot_idx, mode,
			    (unsigned long long)ctx->node_bit,
			    (unsigned long long)vs->holders_ex,
			    mxfs_pal_popcount64(vs->holders_ex));
		}
	}
	mxfs_pal_free(vs);
}

/* ─── mxfs_dlm_caw_lock ─── */

static int caw_lock_body(struct mxfs_dlm_caw_ctx *ctx,
		        const struct mxfs_resource_id *resource,
		        uint8_t mode, uint32_t flags,
		        bool attested, uint64_t local_epoch,
		        uint8_t *granted_mode,
		        struct mxfs_grant_result *gres,
		        uint64_t deadline_ms)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint32_t last_read_idx = UINT32_MAX;
	uint8_t our_mode;
	int retry;
	int rc;
	/* ccloop RULE4: prove the hot-slot CAS-storm exhaustion mechanism for
	 * INODE EX-acquire — count CAS -EAGAIN losses per site, dump on
	 * MXFS_CAW_MAX_RETRIES exhaustion (the path that force-shuts-down). */
	int ea_claim = 0, ea_compat = 0, ea_regwait = 0;
	/*
	 * sess40 (D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN).  MEASURED: at 32-way
	 * cold-read storms an acquire can lose the claim/recycle race for the
	 * SAME resource 100 times in ~1.3-1.8s, hit the bare
	 * MXFS_CAW_MAX_RETRIES count, return -ETIMEDOUT, and be escalated by
	 * mxfs_dlm_ilock_begin to SHUTDOWN_CORRUPT_INCORE — taking 10-32 nodes
	 * down.  P91-CLAIMEXH captured both losing shapes: a peer had claimed
	 * the very slot we targeted FOR THE SAME RESOURCE (empty_idx == the
	 * resource's live slot), and a same-resource tombstone recycled under
	 * contention.  Both mean PROGRESS IS POSSIBLE — someone is winning, we
	 * are merely the loser this round.
	 *
	 * Losing a claim race is safe to retry, exactly like the unlock path
	 * (MXFS_CAW_UNLOCK_DEADLINE_MS exists for the same reason: giving up
	 * is worse than retrying, and we hold nothing that could
	 * double-grant).  So a claim-race-dominated acquire gets a wall-clock
	 * deadline instead of a bare count.  Armed only once a claim race is
	 * actually LOST, so a genuine dead-holder wait still exits on the
	 * count and stays with its own liveness extension.
	 */
	uint64_t claim_deadline = 0;
	int div_lo = 0, div_hi = 0, yield_bo = 0, yield_stale = 0, wait_enoent = 0;
	int ea_adopt = 0;	/* sess53: adopt-CAS lost to a concurrent settle */
	/* sess38 P139: whole-acquire clock — a tail event can span SEVERAL
	 * wait_for_grant invocations (each outer retry re-registers), so the
	 * per-wait census under-reports; LOCKTOTAL at `out` catches it. */
	uint64_t p139_lock_start = mxfs_pal_time_ms();
	/* sess31 (ccloop c7ee71c6) D-CAW-YIELD-STARVATION-SHUTDOWN state:
	 * fresh_yreg  — we CAS-registered our waiter bit from the compatible-
	 *               yield path (fix A), so releases include us in the
	 *               yield_to ticket they snapshot from `waiters`;
	 * yield_consec — consecutive compatible-yield deferrals; monotonic for
	 *               the life of this acquire on purpose (GPT condition:
	 *               a ticket restamp or a lost claim CAS must NOT reset
	 *               it, or continuous restamping reproduces the
	 *               starvation);
	 * ybypass     — times fix B stopped deferring and took the claim. */
	bool fresh_yreg = false;
	int yield_consec = 0, ybypass = 0;
	int last_our_mode = -1;
	uint8_t last_wmode = 0;
	uint64_t last_hex = 0, last_hpr = 0;
	bool grant_handoff = false;	/* v0.6.0 EX-handoff epoch observation */
	bool claim_handoff = false;	/* claim-empty via same-res tombstone */
	struct mxfs_caw_lreq *lreq = NULL;	/* sess112 local request registry */
	uint8_t held_mode = MXFS_LOCK_NL;	/* what we ended up holding */
	/*
	 * sess118: clear-window snapshot for the two memory-only "already
	 * held" shortcuts.  Re-armed at the TOP of every retry iteration,
	 * BEFORE the slot read it protects — see the ordering argument above
	 * lreq_clr_snap.  A snapshot taken after the read cannot see a clear
	 * that both began and committed in the read/snap gap.
	 */
	struct mxfs_caw_clr_snap csnap = { 0, true, false };

	/* sess97: no grant proven yet.  Every early return below therefore
	 * leaves the caller with a non-proving result, which is the required
	 * fail-closed default. */
	mxfs_grant_result_init(gres);

	if (!ctx || !resource)
		return -EINVAL;

	if (mode == MXFS_LOCK_NL) {
		if (granted_mode)
			*granted_mode = MXFS_LOCK_NL;
		return 0;
	}

	/* Single-node fast path: no peers, grant in-memory only */
	if (ctx->single_node) {
		mem_lock_track(ctx, resource, mode);
		if (granted_mode)
			*granted_mode = mode;
		return 0;
	}

	/* sess78 DIAGNOSTIC: measure the perf ceiling without per-inode disk
	 * CAW.  Grant INODE-type locks in-memory only (UNSAFE; diag param). */
	{
		extern int mxfs_inode_caw_local;
		extern int mxfs_inode_caw_skip;
		/* Ceiling measurement: grant with NO mem_lock_track (avoids the
		 * O(n^2) linear scan that the caw_local path incurs) and NO disk
		 * CAW.  SOLO no-contention diagnostic only. */
		if (mxfs_inode_caw_skip &&
		    resource->type == MXFS_LTYPE_INODE) {
			if (granted_mode)
				*granted_mode = mode;
			return 0;
		}
		if (mxfs_inode_caw_local &&
		    resource->type == MXFS_LTYPE_INODE) {
			mem_lock_track(ctx, resource, mode);
			if (granted_mode)
				*granted_mode = mode;
			return 0;
		}
	}

	/*
	 * sess112: JOIN THE LOCAL REQUEST REGISTRY before registering anything
	 * on disk.  From here on this attempt is visible to every other local
	 * thread on this resource, so none of them can cancel the waiter or
	 * holder bit we are about to depend on (dlm_caw.h, ctx->lreq).
	 *
	 * A registry that cannot record the attempt REFUSES it.  Continuing
	 * would leave a later reconcile reading "nobody else is here" from a
	 * table that merely failed to allocate — and acting on that false
	 * reading is how a live local tenure loses its authority bit.  -ENOMEM
	 * to a caller that will retry is the cheap side of that trade.
	 */
	lreq = lreq_join(ctx, resource, mode);
	if (!lreq) {
		ctx->lreq_nomem++;
		pr_warn_ratelimited("mxfs: P247-LREQ-NOMEM type=%c id=%llu mode=%u — acquisition refused: local request registry could not record the attempt\n",
			resource->type == MXFS_LTYPE_INODE ? 'I' :
			resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
			(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
				resource->ino : (uint64_t)resource->ag_number),
			mode);
		return -ENOMEM;
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		lreq_finish(ctx, resource, lreq, mode, MXFS_LOCK_NL);
		return -ENOMEM;
	}

	for (retry = 0;
	     retry < MXFS_CAW_MAX_RETRIES ||
	     (claim_deadline && mxfs_pal_time_ms() < claim_deadline);
	     retry++) {
		/*
		 * v0.3.46 attempted exponential backoff (1ms→32ms cap) per
		 * retry to prevent CAS-storm exhaustion.  Reverted v0.3.50:
		 * under sustained dd contention, the cumulative backoff time
		 * causes xfs_ilock requests to hang indefinitely (kernel
		 * hung-task warnings).  CAW exhaustion was a symptom of
		 * underlying coordination races, not the root issue — slowing
		 * the retries just trades one failure for another.
		 *
		 * sess39: that revert was correct for AG locks; re-introduce a
		 * node-phased jittered backoff scoped to INODE locks only, to
		 * desync the same-slot CAS storm that otherwise -ETIMEDOUTs and
		 * shuts the FS down under concurrent same-dir rename.
		 */
		caw_inode_backoff(ctx, resource, retry);

		/* v0.5.3: capture which slot the probe read LAST so the
		 * claim path below can reuse cur_slot as the CAS compare
		 * buffer when the probe terminated at the very slot it is
		 * about to claim (the common no-tombstone case) instead of
		 * re-reading it (was 1 serialized FUA read per create). */
		last_read_idx = UINT32_MAX;
		/* sess118: arm the clear-window snapshot BEFORE the read whose
		 * image the already-held shortcuts publish on. */
		lreq_clr_snap(ctx, resource, &csnap);
		rc = find_slot_skip(ctx, resource, &slot_idx, cur_slot,
				    &empty_idx, UINT32_MAX, &last_read_idx,
				    0);

		/* P15-INSTR: AG-only CAW traffic logging — v0.5.3: gated behind
		 * mxfs.instr (was UNGATED: one pr_warn per AG CAW iteration, 1410
		 * lines in one 2-node rsync, printed while holding the lock path —
		 * a measurable slice of the multi-node penalty; sess36 policy). */
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on()) {
			if (rc == 0) {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-iter ag=%u mode=%u retry=%d "
				    "find=found slot=%u gen=%u gm=%u "
				    "h_ex=%llx h_pw=%llx h_pr=%llx "
				    "w=%llx wm=%u yt=%llx ys_ms=%llu",
				    resource->ag_number, mode, retry,
				    slot_idx, cur_slot->generation,
				    cur_slot->granted_mode,
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pw,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters,
				    cur_slot->waiter_mode,
				    (unsigned long long)cur_slot->yield_to,
				    (unsigned long long)cur_slot->yield_set_ms);
			} else {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-iter ag=%u mode=%u retry=%d "
				    "find=rc%d empty_idx=%u",
				    resource->ag_number, mode, retry,
				    rc, empty_idx);
			}
		}

		if (rc == -ENOENT) {
			/* Resource not in any slot — claim an empty slot */
			if (empty_idx == UINT32_MAX) {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "dlm_caw: no empty slot for "
					     "ino=%llu type=%u",
					     (unsigned long long)resource->ino,
					     resource->type);
				rc = -ENOSPC;
				goto out;
			}

			/* Bug 93: the CAS compare buffer must hold the actual
			 * on-disk content of the empty slot (it may contain
			 * stale/uninitialized non-zero data), not zeros.
			 * v0.5.3: when the probe TERMINATED at empty_idx the
			 * content is already in cur_slot from find_slot_skip's
			 * final read_slot — reuse it.  Only re-read when the
			 * insertion point is an earlier tombstone/ghost slot
			 * (probe read past it, clobbering cur_slot). */
			/*
			 * sess40 ROOT FIX (D-CAW-CLAIM-RETRY-EXHAUSTION-
			 * SHUTDOWN), PROVEN by P92-CLAIMCAS: the old
			 * `last_read_idx != empty_idx` skip assumed the
			 * probe's final read was a fresh per-slot read.  It
			 * can equally be an entry taken from the probe's SPAN
			 * buffer, and a span entry that is neither LIVE nor
			 * TOMBSTONE nor zero is accepted verbatim (see
			 * slot_appears_corrupt: it returns false for any
			 * non-LIVE magic, so no re-read is triggered).  That
			 * image then became the CAS COMPARE — captured on
			 * three nodes as cmp[magic=b4bc1b3d gen=4045629598]
			 * against disk[magic=4d584357 gen=1], first differing
			 * byte 0, fresh_read_skipped=1.  A compare that can
			 * never match makes the claim spin until the acquire
			 * gives up, which mxfs_dlm_ilock_begin escalates to a
			 * filesystem shutdown and cascades cluster-wide.
			 * ALWAYS read the claim target fresh: one extra
			 * sector read on the claim path only, and it feeds the
			 * daf50d34 live-magic guard below with truth.
			 */
			rc = read_slot(ctx, empty_idx, cur_slot);
			if (rc)
				goto out;
			/* daf50d34 sess2 ROOT FIX (mkdir-storm dirent loss, RULE-4
			 * PROVEN by P135-FOREIGN-STRIP caller=mxfs_dlm_caw_lock+0x459
			 * ×3 in one 5-round storm): the re-read above is a TOCTOU
			 * LAUNDERER.  Between the probe classifying empty_idx as
			 * claimable and this re-read, a PEER's fresh claim of the
			 * same tombstone can land; the re-read then returns the
			 * peer's LIVE slot image, and the CAS below — whose whole
			 * purpose is "replace iff still the empty image I probed" —
			 * succeeds against the CURRENT medium, wiping the peer's
			 * holder bits (write image is memset-fresh) and resetting
			 * generation to 1.  The peer keeps believing it holds EX →
			 * double-EX → its committed dir change is destage-refused
			 * (held=0) → durable dirent loss (node1/node3/node15 storm
			 * family).  A live-magic image at our chosen empty_idx is
			 * always a lost claim race: re-probe instead of claiming
			 * over it (if it is OUR resource the next probe FINDS it;
			 * if a foreign resource landed there the next probe picks a
			 * different empty slot). */
			if (cur_slot->magic == MXFS_CAW_MAGIC) {
				if (caw_instr_on())
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-CLAIM-RACE-LOST type=%u ino=%llu "
					    "slot=%u res_ino=%llu hex=%llx hpr=%llx "
					    "gen=%u — live slot materialized at chosen "
					    "empty idx; re-probing",
					    resource->type,
					    (unsigned long long)resource->ino,
					    empty_idx,
					    (unsigned long long)cur_slot->resource.ino,
					    (unsigned long long)cur_slot->holders_ex,
					    (unsigned long long)cur_slot->holders_pr,
					    cur_slot->generation);
				ea_claim++;
				if (!claim_deadline &&
				    resource->type == MXFS_LTYPE_INODE)
					claim_deadline = mxfs_pal_time_ms() +
						MXFS_CAW_UNLOCK_DEADLINE_MS;
				mxfs_pal_sleep_ms(1);
				continue;
			}
			/* sess46 (GPT retention invariant): a DIFFERENT-resource
			 * tombstone carrying open_holders must never be recycled
			 * — the fresh init would wipe another file's open-unlink
			 * protection.  Provably unreachable (every tombstone
			 * site gates on open_holders==0; the same-resource case
			 * inherits above), so this is an assertion: if it ever
			 * fires, a corruption or new code path fabricated the
			 * state.  Resurrect it in place as a LIVE bit-only slot
			 * for ITS OWN resource (bits belong on live slots; a
			 * live slot is never offered as an insertion point, so
			 * the re-probe converges to a different empty slot
			 * instead of looping on this one). */
			if (cur_slot->magic == MXFS_CAW_TOMBSTONE_MAGIC &&
			    cur_slot->open_holders &&
			    cur_slot->resource.volume == resource->volume &&
			    memcmp(&cur_slot->resource, resource,
				   sizeof(*resource)) != 0) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P-OPENBITS-TOMB-RESURRECT type=%u ino=%llu slot=%u tomb_ino=%llu oh=%llx — bit-carrying tombstone of another resource at chosen empty idx; resurrecting instead of wiping",
				    resource->type,
				    (unsigned long long)resource->ino,
				    empty_idx,
				    (unsigned long long)cur_slot->resource.ino,
				    (unsigned long long)cur_slot->open_holders);
				*new_slot = *cur_slot;
				new_slot->magic = MXFS_CAW_MAGIC;
				new_slot->generation++;
				new_slot->granted_mode = MXFS_LOCK_NL;
				new_slot->waiter_mode = MXFS_LOCK_NL;
				new_slot->last_modified_ms = mxfs_pal_time_ms();
				(void)caw_slot(ctx, empty_idx, cur_slot,
					       new_slot);
				ea_claim++;
				mxfs_pal_sleep_ms(1);
				continue;
			}
			memset(new_slot, 0, sizeof(*new_slot));
			new_slot->magic = MXFS_CAW_MAGIC;
			new_slot->generation = 1;
			new_slot->resource = *resource;
			new_slot->last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
			caw_claim_inherit_epoch(new_slot, cur_slot, resource);
			/* sess176: fresh binding (or legacy zero-lineage
			 * recycle) — mint the lineage inside the claim image
			 * so it is durable in the same CAS that binds the
			 * resource.  Mint failure fails the claim (ruling:
			 * no secure randomness, no fresh binding). */
			if (!new_slot->resource_lineage) {
				new_slot->resource_lineage = caw_mint_lineage();
				if (!new_slot->resource_lineage) {
					mxfs_pal_log(MXFS_LOG_ERR,
					    "dlm_caw: P275-LINEAGE-RNG-FAIL type=%u ino=%llu slot=%u — RNG returned all-zero draws; failing claim closed",
					    resource->type,
					    (unsigned long long)resource->ino,
					    empty_idx);
					rc = -EIO;
					goto out;
				}
			}
			{
				uint64_t *hp = holders_for_mode(new_slot,
								mode);
				if (hp)
					*hp = ctx->node_bit;
			}
			caw_grant_streak_note(new_slot, mode);
			new_slot->granted_mode = mode;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			/* handoff CAN be true here: a recycled same-resource
			 * tombstone carries last_ex_slot (idle-gap handoff) */
			claim_handoff = caw_grant_epoch_update(new_slot,
							       cur_slot,
							       ctx->node_slot,
							       mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, empty_idx, cur_slot, new_slot);
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=claim-empty slot=%u cas_rc=%d",
				    resource->ag_number, retry, empty_idx, rc);
			if (rc == -EAGAIN) {
				ea_claim++;
				if (!claim_deadline &&
				    resource->type == MXFS_LTYPE_INODE)
					claim_deadline = mxfs_pal_time_ms() +
						MXFS_CAW_UNLOCK_DEADLINE_MS;
				/*
				 * sess40 RULE-4: a claim that miscompares
				 * hundreds of times against a slot whose
				 * on-disk generation is NOT advancing (P91
				 * captured tgt gen=2 stable across 6s) is not
				 * "someone else keeps winning".  Re-read the
				 * target fresh and diff it against the exact
				 * buffer we submitted as the CAS compare: a
				 * difference names a STALE COMPARE IMAGE (the
				 * probe's span buffer is reused as the
				 * compare when the probe terminated at
				 * empty_idx, skipping the re-read); no
				 * difference means the device is rejecting a
				 * byte-identical compare, which is a
				 * transport/LBA problem, not a lock race.
				 */
				if (resource->type == MXFS_LTYPE_INODE &&
				    (ea_claim % 64) == 0) {
					struct mxfs_caw_lock_slot *fr =
						mxfs_pal_alloc(sizeof(*fr));

					if (fr) {
						int frc = read_slot(ctx,
							empty_idx, fr);
						int diff = -1;
						unsigned int k;
						const uint8_t *a =
							(const uint8_t *)cur_slot;
						const uint8_t *b =
							(const uint8_t *)fr;

						if (frc == 0) {
							for (k = 0; k < sizeof(*fr); k++)
								if (a[k] != b[k]) {
									diff = (int)k;
									break;
								}
						}
						pr_warn("mxfs: P92-CLAIMCAS ino=%llu idx=%u n=%d rd_rc=%d first_diff=%d cmp[magic=%x gen=%u] disk[magic=%x gen=%u] fresh_read_skipped=%d\n",
							(unsigned long long)resource->ino,
							empty_idx, ea_claim, frc,
							diff, cur_slot->magic,
							cur_slot->generation,
							fr->magic, fr->generation,
							(last_read_idx == empty_idx) ? 1 : 0);
						mxfs_pal_free(fr);
					}
				}
				continue; /* MISCOMPARE, retry */
			}
			if (rc)
				goto out;

			/*
			 * P49-INSTR (sess26 diagnostic): post-CAS verify-read.
			 * v0.3.108 final: extra SCSI read per CAS-success
			 * doubles the SCSI command count in caw_lock claim
			 * path.  Disabling P49 to reduce SCSI-queue pressure;
			 * the divergence info is preserved in sess26 docs.
			 * Set MXFS_P49_ENABLE=1 to re-enable for diagnosis.
			 */
			if (0 && resource->type == MXFS_LTYPE_AG) {
				struct mxfs_caw_lock_slot verify_slot;
				int v_rc = read_slot(ctx, empty_idx, &verify_slot);
				uint8_t v_our_mode;
				/* v0.3.108: tested msleep(1) before verify
				 * read — no improvement in pass rate.  Async
				 * completion isn't the cause of the
				 * post-CAS divergence we observe. */
				v_our_mode = node_held_mode(&verify_slot,
							    ctx->node_bit);
				if (v_rc != 0 || v_our_mode != mode) {
					const uint8_t *vb = (const uint8_t *)&verify_slot;
					const uint8_t *nb = (const uint8_t *)new_slot;
					const uint8_t *cb = (const uint8_t *)cur_slot;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR cur-slot-bytes 0..31 (compare-buf for CAS): "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    cb[0],cb[1],cb[2],cb[3],
					    cb[4],cb[5],cb[6],cb[7],
					    cb[8],cb[9],cb[10],cb[11],
					    cb[12],cb[13],cb[14],cb[15],
					    cb[16],cb[17],cb[18],cb[19],
					    cb[20],cb[21],cb[22],cb[23],
					    cb[24],cb[25],cb[26],cb[27],
					    cb[28],cb[29],cb[30],cb[31]);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR claim-empty-diverged "
					    "ag=%u slot=%u v_rc=%d "
					    "v_magic=0x%x v_gen=%u "
					    "v_gm=%u v_our_mode=%u expected=%u "
					    "v_h_ex=%llx v_h_pw=%llx v_waiters=%llx "
					    "we_wrote_ex=%llx node_bit=%llx",
					    resource->ag_number, empty_idx,
					    v_rc, verify_slot.magic,
					    verify_slot.generation,
					    verify_slot.granted_mode,
					    v_our_mode, mode,
					    (unsigned long long)
					    verify_slot.holders_ex,
					    (unsigned long long)
					    verify_slot.holders_pw,
					    (unsigned long long)
					    verify_slot.waiters,
					    (unsigned long long)
					    new_slot->holders_ex,
					    (unsigned long long)
					    ctx->node_bit);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR diverged-bytes 0..31: "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    vb[0],vb[1],vb[2],vb[3],
					    vb[4],vb[5],vb[6],vb[7],
					    vb[8],vb[9],vb[10],vb[11],
					    vb[12],vb[13],vb[14],vb[15],
					    vb[16],vb[17],vb[18],vb[19],
					    vb[20],vb[21],vb[22],vb[23],
					    vb[24],vb[25],vb[26],vb[27],
					    vb[28],vb[29],vb[30],vb[31]);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR we-wrote-bytes 0..31: "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    nb[0],nb[1],nb[2],nb[3],
					    nb[4],nb[5],nb[6],nb[7],
					    nb[8],nb[9],nb[10],nb[11],
					    nb[12],nb[13],nb[14],nb[15],
					    nb[16],nb[17],nb[18],nb[19],
					    nb[20],nb[21],nb[22],nb[23],
					    nb[24],nb[25],nb[26],nb[27],
					    nb[28],nb[29],nb[30],nb[31]);
				}
			}

			/*
			 * sess47 CLAIM-RACE detector: right after claiming a
			 * fresh slot, verify the resource lives in EXACTLY ONE
			 * live slot.  >1 => another node concurrently claimed a
			 * different empty slot for the same resource (the
			 * suspected root of the bnobt stale-pristine clobber).
			 * Detection only this build — proves/refutes before any
			 * fix.  Always-on (fires only on the bug), ratelimited.
			 */
			/* sess84: extended to INODE locks (was AG-only).  The
			 * shortform-dir lost-update (node1.txt durably vanishes
			 * from a shared dir) shows ZERO CAW-EXCL-VIOLATION — that
			 * detector reads ONE slot, so it cannot see a claim-race
			 * where the SAME inode resource lands in TWO live slots
			 * (each with a single, non-conflicting EX holder) →
			 * concurrent EX on the dir inode via different slots. */
			/* v0.5.3 (ccloop 14d31183 scaling_curve): skip the
			 * post-claim chain re-scan when we claimed AT THE HASH
			 * BASE slot.  A racing peer's probe for the same
			 * resource starts at the same base: pre-our-CAW it
			 * targets the SAME base slot (CAW serializes — exactly
			 * one claim wins, the loser re-probes and finds our
			 * live entry); post-our-CAW it finds our live entry at
			 * the chain head and registers as waiter.  Either way
			 * a second live slot for the resource cannot come into
			 * existence, so the scan can only ever return 1 here.
			 * Off-base claims (chain had live/tombstone slots
			 * before our insertion point) keep the full detector —
			 * that is where the sess47/sess84 dup-slot race lives.
			 * Measured: the re-scan was 1441 of 6120 slot reads in
			 * a 705-create rsync (~2 serialized FUA reads per
			 * create), nearly all base-claims. */
			if ((resource->type == MXFS_LTYPE_AG ||
			     resource->type == MXFS_LTYPE_INODE) &&
			    empty_idx != resource_hash_raw(resource) %
					 MXFS_CAW_MAX_SLOTS) {
				uint32_t dup[8];
				uint64_t hex_or = 0;
				int ndup = caw_count_resource_slots(ctx,
					resource, dup, 8, &hex_or);
				if (ndup > 1)
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: CAW-DUP-SLOT type=%u ag=%u "
					    "ino=%llu nslots=%d mine=%u "
					    "slots=[%u,%u,%u,%u] holders_ex_or=%llx "
					    "(claim-race: same resource in >1 live "
					    "slot => concurrent EX via diff slots)",
					    resource->type, resource->ag_number,
					    (unsigned long long)resource->ino,
					    ndup, empty_idx,
					    dup[0], ndup>1?dup[1]:0,
					    ndup>2?dup[2]:0, ndup>3?dup[3]:0,
					    (unsigned long long)hex_or);
			}

			track_held(ctx, empty_idx);
			slot_hint_store(ctx, resource, empty_idx);
			/* sess97 step 5.3(b): provenance from the claim CAS. */
			caw_grant_result_fill(gres, resource, new_slot, mode,
					      false);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     claim_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			caw_exwin_log(resource, "claim", mode, ctx->node_slot,
				      0, 0, 0);
			if (granted_mode)
				*granted_mode = mode;
			rc = 0;
			goto out;
		}

		if (rc)
			goto out; /* I/O error */

		/* Check if we already hold this lock at the requested mode */
		our_mode = node_held_mode(cur_slot, ctx->node_bit);
		if (our_mode == mode) {
			/*
			 * v0.3.85 (sess25): divergence detection. The "we hold
			 * the requested mode" check returns success without
			 * verifying that no PEER also holds a conflicting mode.
			 * Sess24 P35 captured both T1 and T2 with their bits set
			 * in the EX bitmap simultaneously on AG=0 for ~50s — both
			 * fast-pathed acquires forever, modifying AG-meta in
			 * parallel, producing bnobt LEFT/RIGHT-FAIL.
			 *
			 * Suspected source: single→multi flush_held_to_disk OR's
			 * our bit unconditionally; if peer ran concurrently,
			 * both bits end up set without conflict resolution.  Or
			 * any path where our local belief drifts from disk.
			 *
			 * Fix: when our bit appears set but a peer also holds an
			 * incompatible mode, our bit is provably stale (lock
			 * compatibility table forbids two EX holders, etc.).
			 * Clear our bit via CAW, untrack locally, retry from
			 * top so the acquire goes through the normal conflict-
			 * detection path.
			 */
			if (!compatible_excluding_self(cur_slot, mode,
						       ctx->node_bit)) {
				*new_slot = *cur_slot;
				{
					uint64_t *hp = holders_for_mode(
						new_slot, our_mode);
					if (hp)
						*hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();
				/* sess120 audit site 1 of 3 — see
				 * caw_slot_clearing.  Strips our holder bit
				 * because a peer holds an incompatible mode. */
				rc = caw_slot_clearing(ctx, resource, slot_idx,
						       cur_slot, new_slot,
						       "diverg-lo", our_mode);
				if (resource->type == MXFS_LTYPE_AG)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P37-INSTR caw-divergence "
					    "ag=%u retry=%d our_mode=%u "
					    "peer-incompat cas_rc=%d "
					    "h_ex=%llx h_pw=%llx h_pr=%llx",
					    resource->ag_number, retry,
					    our_mode, rc,
					    (unsigned long long)
					    cur_slot->holders_ex,
					    (unsigned long long)
					    cur_slot->holders_pw,
					    (unsigned long long)
					    cur_slot->holders_pr);
				/* P109 Phase 1.1 (NEWARCH): instrument every
				 * on-disk holder-bit clear so the P106-STALE-EX
				 * culprit path can be identified.  This site
				 * clears OUR bit mid-acquire because a peer
				 * holds an incompatible mode (our bit was
				 * stale).  Caller's in-core i_dlm_mode/state
				 * is still set to the previous belief — the
				 * slow-path return path SHOULD reset it but
				 * if there's a race with a concurrent fast-
				 * path acquire on the same inode, we leak a
				 * stale-cached holder. */
				if (caw_instr_on() ||
				    (resource->type == MXFS_LTYPE_INODE &&
				     caw_diverg_logged++ < 50))
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-DIVERG-LO type=%s "
					    "id=%llu our_mode=%u req=%u "
					    "cas_rc=%d slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, rc, slot_idx);
				if (rc == 0)
					untrack_held(ctx, slot_idx);
				if (rc == -EAGAIN || rc == 0) {
					div_lo++;
					last_our_mode = our_mode;
					last_hex = cur_slot->holders_ex;
					last_hpr = cur_slot->holders_pr;
					continue;
				}
				goto out;
			}

			/* sess53: claim a retained bit from our previous
			 * incarnation before returning success on it, so the
			 * settle purge cannot strip it out from under us. */
			rc = caw_adopt_retained(ctx, resource, slot_idx,
						cur_slot, new_slot, our_mode);
			if (rc == -EAGAIN) {
				ea_adopt++;
				continue;
			}
			if (rc)
				goto out;

			/* v0.6.3: gate + grant record in ONE critical
			 * section (see caw_grant_meta_store_unless_releasing).
			 * A false return means our own unlock is concurrently
			 * clearing this bit — the observed hold is a torn
			 * read of a release in flight; wait it out and
			 * re-probe. */
			if (!caw_grant_meta_store_unless_releasing(ctx,
					resource, cur_slot->dir_epoch, false,
					cur_slot->dir_block0_fsb,
					cur_slot->dir_block0_gen)) {
				static int relwait_logged;

				if (relwait_logged < 20) {
					relwait_logged++;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-SHORTCUT-RELWAIT type=%u "
					    "ino=%llu retry=%d",
					    resource->type,
					    (unsigned long long)resource->ino,
					    retry);
				}
				mxfs_pal_sleep_ms(1);
				continue;
			}
			/*
			 * sess118 CLEAR-WINDOW VALIDATION (sess115 ruling
			 * blocker 2: a memory-only publication stays
			 * PROVISIONAL until it can prove no destructive local
			 * clear ran under the image it is publishing on).
			 *
			 * This is the non-aliasing half of the gate directly
			 * above.  caw_grant_meta_store_unless_releasing keys
			 * off grant_meta, a NO-CHAIN hash, so a colliding
			 * FOREIGN resource evicts the `releasing` mark that
			 * protects this shortcut and the gate silently passes.
			 * The lreq table is chained and keyed by the resource
			 * itself, so it cannot alias.
			 *
			 * Refusing is free: `continue` re-reads the slot and
			 * re-decides.  The side effects already taken (the
			 * grant_meta store, and any adopt CAS above) are
			 * harmless on retry — a grant_seq bump only makes a
			 * concurrent unlock abort, which errs toward leaving
			 * the holder bit SET.
			 */
			if (!lreq_clr_still_good(ctx, resource, &csnap)) {
				ctx->lreq_clr_refuse++;
				pr_warn_ratelimited("mxfs: P250-LREQ-CLR-REFUSE type=%c id=%llu arm=held mode=%u retry=%d — a destructive local clear ran under the image this shortcut would publish on; re-reading\n",
					resource->type == MXFS_LTYPE_INODE ? 'I' :
					resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
					(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
						resource->ino : (uint64_t)resource->ag_number),
					our_mode, retry);
				mxfs_pal_sleep_ms(1);
				continue;
			}
			/*
			 * sess290 (D-488 legs 7 ruling, sess289): REAFFIRM
			 * GUARD + forced READOPT mint.  An ATTESTED caller
			 * passes the write-authority epoch it currently has
			 * PUBLISHED in core for this resource.  Reaffirming
			 * with the slot's old epoch is only legal when that
			 * published epoch is nonzero and matches the slot —
			 * an ordinary reentrant acquire of a live tenure.
			 * Own bit + attested epoch 0 is NOT reaffirmation:
			 * it is a post-surrender readopt of a stranded bit
			 * (the release-commit already WRITE_ONCE'd the epoch
			 * to 0 — an authority surrender), and returning the
			 * slot's surrendered epoch would resurrect it as
			 * write authority.  Mint a FRESH epoch through a
			 * real CAS instead (Enew != Eold, bit never absent).
			 * Post-drain provenance holds by construction for
			 * the attested AG caller: every release-commit that
			 * zeroes the published epoch runs strictly after the
			 * Invariant-1 drain pipeline, so the orphaned bit
			 * cannot cover undrained pre-surrender dirt.  The
			 * mount adopt window is exempt — inheritance there
			 * is the sess52-ruled authority-manifest adoption
			 * and deliberately does NOT restamp.
			 */
			if (attested && mxfs_mode_can_write(our_mode) &&
			    !ctx->mount_adopt_window &&
			    local_epoch != cur_slot->ex_grant_epoch) {
				if (local_epoch != 0) {
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: P294-REAFFIRM-EPOCH-MISMATCH type=%u ag=%u ino=%llu local=%llu slot=%llu mode=%u — attested published epoch disagrees with slot; failing closed",
					    resource->type, resource->ag_number,
					    (unsigned long long)resource->ino,
					    (unsigned long long)local_epoch,
					    (unsigned long long)cur_slot->ex_grant_epoch,
					    our_mode);
					rc = -ESTALE;
					goto out;
				}
				*new_slot = *cur_slot;
				new_slot->generation++;
				new_slot->last_modified_ms = mxfs_pal_time_ms();
				new_slot->last_ex_slot = ctx->node_slot;
				new_slot->ex_grant_epoch =
					caw_next_grant_epoch(cur_slot->ex_grant_epoch);
				rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
				if (rc == -EAGAIN)
					continue; /* raced; re-read and re-decide */
				if (rc) {
					/* Ambiguous/failed I/O: no publication.
					 * If the mint landed, a later readopt
					 * mints AGAIN off the new image — Eold
					 * is never restored either way. */
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: P294-READOPT-MINT-FAIL type=%u ag=%u ino=%llu rc=%d Eold=%llu — mint CAS unproven, acquire fails closed",
					    resource->type, resource->ag_number,
					    (unsigned long long)resource->ino, rc,
					    (unsigned long long)cur_slot->ex_grant_epoch);
					goto out;
				}
				if (!is_tracked_held(ctx, slot_idx))
					track_held(ctx, slot_idx);
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P294-READOPT-MINT type=%u ag=%u ino=%llu Eold=%llu Enew=%llu gen=%u — stranded own bit readopted under a fresh minted epoch",
				    resource->type, resource->ag_number,
				    (unsigned long long)resource->ino,
				    (unsigned long long)cur_slot->ex_grant_epoch,
				    (unsigned long long)new_slot->ex_grant_epoch,
				    new_slot->generation);
				caw_grant_result_fill(gres, resource, new_slot,
						      our_mode, false);
				if (granted_mode)
					*granted_mode = mode;
				rc = 0;
				goto out;
			}

			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=already-held our_mode=%u",
				    resource->ag_number, retry, our_mode);
			/* sess97 step 5.3(b): no CAS ran, but THIS image is
			 * first-hand evidence — it shows our holder bit and
			 * the epoch of the tenure that set it, read together.
			 * Marked reaffirm so the consumer can tell it from a
			 * freshly minted grant. */
			caw_grant_result_fill(gres, resource, cur_slot,
					      our_mode, true);
			if (granted_mode)
				*granted_mode = mode;
			rc = 0; /* Already hold it */
			goto out;
		}

		/* Check if we hold a higher mode that subsumes the request */
		if (our_mode != MXFS_LOCK_NL && our_mode >= mode) {
			/*
			 * v0.3.85 (sess25): same divergence check as above for
			 * the higher-mode-subsumes case.
			 */
			if (!compatible_excluding_self(cur_slot, our_mode,
						       ctx->node_bit)) {
				*new_slot = *cur_slot;
				{
					uint64_t *hp = holders_for_mode(
						new_slot, our_mode);
					if (hp)
						*hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();
				/* sess120 audit site 2 of 3 — see
				 * caw_slot_clearing. */
				rc = caw_slot_clearing(ctx, resource, slot_idx,
						       cur_slot, new_slot,
						       "diverg-hi", our_mode);
				if (resource->type == MXFS_LTYPE_AG)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P37-INSTR caw-divergence-higher "
					    "ag=%u retry=%d our_mode=%u "
					    "peer-incompat cas_rc=%d",
					    resource->ag_number, retry,
					    our_mode, rc);
				/* P109 Phase 1.1 (NEWARCH) — divergence guard,
				 * higher-mode-subsumes path.  Same hazard as
				 * DIVERG-LO: clears OUR bit while caller's
				 * in-core mode/state is unchanged. */
				if (caw_instr_on() ||
				    (resource->type == MXFS_LTYPE_INODE &&
				     caw_diverg_logged++ < 50))
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-DIVERG-HI type=%s "
					    "id=%llu our_mode=%u req=%u "
					    "cas_rc=%d slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, rc, slot_idx);
				if (rc == 0)
					untrack_held(ctx, slot_idx);
				if (rc == -EAGAIN || rc == 0) {
					div_hi++;
					last_our_mode = our_mode;
					last_hex = cur_slot->holders_ex;
					last_hpr = cur_slot->holders_pr;
					continue;
				}
				goto out;
			}

			/* sess53: see the adopt gate above — same hazard on
			 * the higher-mode-subsumes fast path. */
			rc = caw_adopt_retained(ctx, resource, slot_idx,
						cur_slot, new_slot, our_mode);
			if (rc == -EAGAIN) {
				ea_adopt++;
				continue;
			}
			if (rc)
				goto out;

			/* v0.6.3: see the already-held gate above. */
			if (!caw_grant_meta_store_unless_releasing(ctx,
					resource, cur_slot->dir_epoch, false,
					cur_slot->dir_block0_fsb,
					cur_slot->dir_block0_gen)) {
				static int relwait_hi_logged;

				if (relwait_hi_logged < 20) {
					relwait_hi_logged++;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-SHORTCUT-RELWAIT-HI type=%u "
					    "ino=%llu retry=%d",
					    resource->type,
					    (unsigned long long)resource->ino,
					    retry);
				}
				mxfs_pal_sleep_ms(1);
				continue;
			}
			/* sess118: see the clear-window validation on the
			 * exact-mode arm above — same hazard, same remedy. */
			if (!lreq_clr_still_good(ctx, resource, &csnap)) {
				ctx->lreq_clr_refuse++;
				pr_warn_ratelimited("mxfs: P250-LREQ-CLR-REFUSE type=%c id=%llu arm=held-hi mode=%u retry=%d — a destructive local clear ran under the image this shortcut would publish on; re-reading\n",
					resource->type == MXFS_LTYPE_INODE ? 'I' :
					resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
					(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
						resource->ino : (uint64_t)resource->ag_number),
					our_mode, retry);
				mxfs_pal_sleep_ms(1);
				continue;
			}
			/* sess290: same reaffirm guard as the exact-mode arm.
			 * Unreachable for the attested AG caller (AG locks
			 * are EX-only, so subsumption cannot fire), but the
			 * invariant — an attested caller never receives an
			 * epoch it did not already publish — must hold on
			 * every reaffirm exit.  No mint here: a caller that
			 * reaches this arm attested-and-mismatched is a
			 * protocol violation, not a readopt. */
			if (attested && mxfs_mode_can_write(our_mode) &&
			    !ctx->mount_adopt_window &&
			    local_epoch != cur_slot->ex_grant_epoch) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P294-REAFFIRM-EPOCH-MISMATCH type=%u ag=%u ino=%llu local=%llu slot=%llu mode=%u arm=held-hi — failing closed",
				    resource->type, resource->ag_number,
				    (unsigned long long)resource->ino,
				    (unsigned long long)local_epoch,
				    (unsigned long long)cur_slot->ex_grant_epoch,
				    our_mode);
				rc = -ESTALE;
				goto out;
			}
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=already-held-higher our_mode=%u",
				    resource->ag_number, retry, our_mode);
			/* sess97 step 5.3(b): as above — our_mode, not the
			 * (lower) requested mode, is what this image proves. */
			caw_grant_result_fill(gres, resource, cur_slot,
					      our_mode, true);
			if (granted_mode)
				*granted_mode = our_mode;
			rc = 0; /* Current mode is sufficient */
			goto out;
		}

		/*
		 * sess50 anti-starvation (PROVEN root of the ~60-120s barrier
		 * dir-visibility stall): continuous PR readers across nodes were
		 * re-granting PR among themselves (slot generation churned ~1650x
		 * over a 69s stall) while a peer's EX request waited forever —
		 * the EX writer could never find a window with zero PR holders,
		 * so its dir modification (e.g. a barrier marker) stayed
		 * invisible.  Fix: for a FRESH acquire (our_mode==NL), if a peer
		 * is already waiting for a mode INCOMPATIBLE with ours, do not
		 * grab the compatible lock — fall through to the waiter-register
		 * path so current holders drain and the waiter gets granted.
		 * Recursion/upgrade (our_mode != NL) is exempt: those callers
		 * already hold the resource and must not deadlock against a peer
		 * waiter.  Same-mode waiters (e.g. PR vs PR) stay compatible and
		 * are allowed in (no starvation there).
		 */
		bool defer_for_waiter =
			(our_mode == MXFS_LOCK_NL) &&
			(mode == MXFS_LOCK_PR || mode == MXFS_LOCK_CR ||
			 mode == MXFS_LOCK_CW) &&
			(cur_slot->waiter_mode == MXFS_LOCK_EX ||
			 cur_slot->waiter_mode == MXFS_LOCK_PW) &&
			((cur_slot->waiters & ~ctx->node_bit) != 0);

		/*
		 * Compatibility check: if we already hold a lower mode
		 * (upgrade case, e.g. PR→EX), exclude ourselves from the
		 * compatibility test.  Otherwise is_compatible sees our
		 * own PR as conflicting with the EX request, triggering a
		 * self-BAST that races with ilock_begin and can leave
		 * i_dlm_state=NONE while EX is held on disk — causing
		 * the next external BAST to release without flush.
		 */
		if (!defer_for_waiter &&
		    ((our_mode != MXFS_LOCK_NL)
		    ? compatible_excluding_self(cur_slot, mode,
						ctx->node_bit)
		    : is_compatible(cur_slot, mode))) {
			/*
			 * Yield-to-priority: if yield_to has bits set for
			 * OTHER nodes (not us), back off to let those nodes
			 * acquire first. This prevents the releasing node
			 * from immediately reacquiring before waiters get
			 * a chance.
			 */
			if (cur_slot->yield_to != 0) {
				uint64_t yield_now = mxfs_pal_time_real_ms();
				uint64_t yield_age =
					(yield_now > cur_slot->yield_set_ms) ?
					(yield_now - cur_slot->yield_set_ms) : 0;

				/* sess299 (ruling item 8): a ticket naming a
				 * still-registered waiter is a live
				 * reservation — never age-cleared.  Only a
				 * ticket with no registered waiter left
				 * behind it (deregister/cancel/lease-purge)
				 * goes stale.  The deferral this branch does
				 * remains bounded for a registered fresh
				 * acquire by P221-YIELD-BOUND below. */
				if (yield_age < MXFS_CAW_YIELD_TIMEOUT_MS ||
				    (cur_slot->yield_to &
				     cur_slot->waiters)) {
					/*
					 * sess130 conversion-priority (PROVEN
					 * livelock, P-CAWEXH yield_bo=100):
					 * an UPGRADER (our_mode != NL, e.g.
					 * PR→EX for unlink) that passed the
					 * compat check is the SOLE holder —
					 * the yield_to waiters it would defer
					 * to are themselves blocked on OUR
					 * held mode, and every peer release
					 * re-arms yield_set_ms so the hint
					 * never goes stale.  Deferring here
					 * livelocks until -ETIMEDOUT →
					 * force-shutdown.  Standard DLM rule:
					 * conversions take priority over new
					 * requests.  Only FRESH acquires
					 * (our_mode == NL) honor yield_to.
					 */
					bool yt_pr_only =
						(cur_slot->yield_to &
						 cur_slot->waiters_ex) == 0;
					bool held_pr_compat =
						(our_mode == MXFS_LOCK_PR ||
						 our_mode == MXFS_LOCK_CR);
					/*
					 * v0.10.41: an upgrader normally keeps
					 * conversion priority (bypasses yield_to).
					 * BUT if the ticket is a pure-PR batch
					 * (the streak anti-starvation yield to the
					 * shared class) and our HELD mode is
					 * PR-compatible, the PR waiters do NOT
					 * block on our held mode (PR+PR share) —
					 * so deferring lets them batch-promote with
					 * NO sess130 livelock, and their PR grant
					 * resets the streak so we upgrade right
					 * after they drain.  This stops PR-reader
					 * (stat/readdir) 360s starvation behind
					 * PR->EX creators at 32 nodes (dir_reuse
					 * B3: test5 comm=stat mode=3 rc=-110). */
					if (!(cur_slot->yield_to &
					      ctx->node_bit) &&
					    (our_mode == MXFS_LOCK_NL ||
					     (yt_pr_only && held_pr_compat))) {
						bool ybound_go = false;

						/*
						 * sess31 (ccloop c7ee71c6)
						 * D-CAW-YIELD-STARVATION-SHUTDOWN.
						 * This compatible-defer path never
						 * registered in `waiters`, yet
						 * releases rebuild the ticket as
						 * yield_to = waiters — so a polite
						 * fresh acquirer was INVISIBLE to
						 * the rotation it deferred to.
						 * Under continuous handoff the
						 * ticket never emptied and never
						 * named it: measured as P-CAWEXH
						 * yield_bo=100 ea_claim=0 on ten
						 * nodes at once, each then killing
						 * its own FS via the rc=-110
						 * ilock_begin shutdown policy.
						 * Fix (GPT-reviewed, RULE 5):
						 *  A) register our waiter bit on
						 *     the first deferral (once;
						 *     the claim CAS clears it) so
						 *     the next release's ticket
						 *     includes us;
						 *  B) after caw_fresh_yield_bound
						 *     consecutive deferrals as a
						 *     REGISTERED waiter, stop
						 *     deferring and take the
						 *     compatible claim — we are
						 *     mode-compatible, so admitting
						 *     ourselves preempts nobody; a
						 *     yield hint is an advisory
						 *     courtesy and an unbounded
						 *     courtesy is a livelock.
						 * Scope: fresh INODE acquires only.
						 * Conversions keep sess130 priority
						 * and the v0.10.41 pure-PR-batch
						 * exception; defer_for_waiter has
						 * already run (writer priority
						 * outranks this whole branch).
						 */
						if (our_mode == MXFS_LOCK_NL &&
						    resource->type ==
						    MXFS_LTYPE_INODE) {
							extern int mxfs_caw_fresh_register;
							extern int mxfs_caw_fresh_yield_bound;

							if (mxfs_caw_fresh_register &&
							    !fresh_yreg) {
								*new_slot = *cur_slot;
								new_slot->waiters |=
									ctx->node_bit;
								if (mode > new_slot->waiter_mode)
									new_slot->waiter_mode = mode;
								new_slot->generation++;
								if (caw_slot(ctx, slot_idx,
									     cur_slot,
									     new_slot) == 0)
									fresh_yreg = true;
								/* Win or lose, the slot
								 * image moved — re-read
								 * before deciding. */
								yield_consec++;
								last_our_mode = our_mode;
								last_hex = cur_slot->holders_ex;
								last_hpr = cur_slot->holders_pr;
								continue;
							}
							yield_consec++;
							if (fresh_yreg &&
							    mxfs_caw_fresh_yield_bound > 0 &&
							    yield_consec >=
							    mxfs_caw_fresh_yield_bound) {
								ybound_go = true;
								ybypass++;
								pr_warn_ratelimited(
								    "mxfs: P221-YIELD-BOUND ino=%llu req=%u consec=%d yt=%llx wex=%llx hpr=%llx — registered fresh acquire stops deferring; taking the compatible claim\n",
								    (unsigned long long)resource->ino,
								    mode, yield_consec,
								    (unsigned long long)cur_slot->yield_to,
								    (unsigned long long)cur_slot->waiters_ex,
								    (unsigned long long)cur_slot->holders_pr);
							}
						}
						/*
						 * Fresh acquire, OR an upgrader
						 * yielding to a compatible PR
						 * batch — back off.
						 */
						if (!ybound_go) {
						if (our_mode != MXFS_LOCK_NL &&
						    resource->type ==
						    MXFS_LTYPE_INODE)
							pr_warn_ratelimited(
							    "mxfs: P-UPG-PRYIELD ino=%llu our_mode=%u req=%u yt=%llx wex=%llx\n",
							    (unsigned long long)resource->ino,
							    our_mode, mode,
							    (unsigned long long)cur_slot->yield_to,
							    (unsigned long long)cur_slot->waiters_ex);
						if (resource->type ==
						    MXFS_LTYPE_AG &&
						    caw_instr_on())
							mxfs_pal_log(
							    MXFS_LOG_WARN,
							    "P15-INSTR caw-act "
							    "ag=%u retry=%d "
							    "action=yield-backoff "
							    "yield_age_ms=%llu "
							    "yt=%llx",
							    resource->ag_number,
							    retry,
							    (unsigned long long)
							    yield_age,
							    (unsigned long long)
							    cur_slot->yield_to);
						mxfs_pal_sleep_ms(
						    MXFS_CAW_YIELD_BACKOFF_MS +
						    (ctx->local_node % 10));
						yield_bo++;
						last_our_mode = our_mode;
						last_hex = cur_slot->holders_ex;
						last_hpr = cur_slot->holders_pr;
						continue;
						}
						/* ybound_go: fall through to
						 * the compatible claim below
						 * (fix B — bounded courtesy).
						 */
					}
					if (our_mode != MXFS_LOCK_NL &&
					    !(cur_slot->yield_to &
					      ctx->node_bit) &&
					    resource->type == MXFS_LTYPE_INODE &&
					    caw_instr_on())
						pr_warn_ratelimited(
						    "mxfs: P130-YIELD-UPG-BYPASS ino=%llu our_mode=%u req=%u yt=%llx h_pr=%llx h_ex=%llx\n",
						    (unsigned long long)resource->ino,
						    our_mode, mode,
						    (unsigned long long)cur_slot->yield_to,
						    (unsigned long long)cur_slot->holders_pr,
						    (unsigned long long)cur_slot->holders_ex);
				} else {
					/*
					 * yield_to is stale (>5s). Clear it
					 * via CAW to prevent deadlock if the
					 * yielded-to node died.
					 */
					*new_slot = *cur_slot;
					new_slot->yield_to = 0;
					new_slot->yield_set_ms = 0;
					new_slot->generation++;

					rc = caw_slot(ctx, slot_idx,
						      cur_slot, new_slot);
					if (resource->type == MXFS_LTYPE_AG &&
					    caw_instr_on())
						mxfs_pal_log(MXFS_LOG_WARN,
						    "P15-INSTR caw-act ag=%u "
						    "retry=%d "
						    "action=yield-stale-clear "
						    "yield_age_ms=%llu cas_rc=%d",
						    resource->ag_number, retry,
						    (unsigned long long)
						    yield_age, rc);
					/* Win or lose, re-read and retry */
					yield_stale++;
					continue;
				}
			}

			/* Compatible — add ourselves */
			*new_slot = *cur_slot;

			/* If we're in yield_to, clear our bit */
			if (new_slot->yield_to & ctx->node_bit)
				new_slot->yield_to &= ~ctx->node_bit;

			/* sess31 D-CAW-YIELD-STARVATION-SHUTDOWN fix A: a fresh
			 * acquire may have registered as a waiter from the
			 * compatible-yield path.  The grant IS the claim — leave
			 * neither our waiter bit nor a stale raised waiter_mode
			 * behind, in the same CAS as the grant. */
			if (new_slot->waiters & ctx->node_bit) {
				new_slot->waiters &= ~ctx->node_bit;
				new_slot->waiters_ex &= ~ctx->node_bit;
				new_slot->waiter_mode =
					recompute_waiter_mode(new_slot);
			}

			/* If upgrading, clear old mode first */
			if (our_mode != MXFS_LOCK_NL) {
				uint64_t *old_hp = holders_for_mode(new_slot,
								    our_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
				/* P109 Phase 1.1 (NEWARCH) — UPGRADE clears our
				 * old mode bit BUT the SAME CAS also sets our
				 * new mode bit, so at no point is the on-disk
				 * slot reporting "we hold neither" — caller's
				 * in-core state (still at our_mode) won't see a
				 * stale-empty window for this resource.  Lower
				 * hazard than UPGRADE-DDL below; instrument
				 * anyway for completeness. */
				if (caw_instr_on())
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-UPGRADE type=%s "
					    "id=%llu old_mode=%u new_mode=%u "
					    "slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, slot_idx);
			}

			{
				uint64_t *hp = holders_for_mode(new_slot,
								mode);
				if (hp)
					*hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			caw_revoke_consume(new_slot, cur_slot);
			grant_handoff = caw_grant_epoch_update(new_slot,
							       cur_slot,
							       ctx->node_slot,
							       mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=compat-add slot=%u our_mode=%u "
				    "new_gm=%u cas_rc=%d",
				    resource->ag_number, retry, slot_idx,
				    our_mode, new_slot->granted_mode, rc);
			if (rc == -EAGAIN) {
				ea_compat++;
				continue;
			}
			if (rc)
				goto out;

			caw_check_exclusion(ctx, resource, new_slot, mode);
			caw_verify_grant_persisted(ctx, resource, slot_idx, mode);
			track_held(ctx, slot_idx);
			/* sess97 step 5.3(b): provenance from the compat-add
			 * CAS (this is also the PR->EX upgrade path). */
			caw_grant_result_fill(gres, resource, new_slot, mode,
					      false);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     grant_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			/* sess8 (ccloop 72513a13) T1 anatomy: a CONTENDED slot
			 * (ticket installed or EX waiters queued) claimed here
			 * without entering caw_wait_for_grant means the winner
			 * ARRIVED after the release (late-arrival hop) — the
			 * ytself field says whether the releaser's round-robin
			 * ticket had named us while we were absent. */
			if (resource->type == MXFS_LTYPE_INODE &&
			    (cur_slot->yield_to != 0 ||
			     (cur_slot->waiters_ex & ~ctx->node_bit) != 0)) {
				static int p139_n;

				if (p139_n++ < 4000)
					pr_warn(
					    "mxfs: P139-COLDCLAIM ino=%llu mode=%u yt=%llx ytself=%d wex=%llx realms=%llu\n",
					    (unsigned long long)resource->ino,
					    mode,
					    (unsigned long long)cur_slot->yield_to,
					    (cur_slot->yield_to & ctx->node_bit) ? 1 : 0,
					    (unsigned long long)(cur_slot->waiters_ex & ~ctx->node_bit),
					    (unsigned long long)mxfs_pal_time_real_ms());
			}
			caw_exwin_log(resource, "cold", mode, ctx->node_slot,
				      0, cur_slot->yield_to,
				      cur_slot->waiters_ex);
			if (granted_mode)
				*granted_mode = mode;
			rc = 0;
			goto out;
		}

		/* Incompatible — check flags */
		if (flags & MXFS_LKF_NOQUEUE) {
			/*
			 * D-AGLOCK-...-LIVELOCK-488 (sess243 RULE-5 ruling):
			 * a plain NOQUEUE loser leaves NO trace — it exits
			 * here, before waiter registration and before the
			 * BAST multicast below.  Against a lazily-CACHED
			 * holder (which by design demotes only when BASTed)
			 * that is a signal-free conflict: the contender spins
			 * -EAGAIN forever and no peer ever has a reason to let
			 * go.  Proven on the 32-node rig: test30 cycled all 25
			 * AGs for >190 sweep laps against idle peers.
			 *
			 * A caller that carries MXFS_LKF_DEMAND asks us to
			 * leave PERSISTENT demand behind instead.  Set the
			 * sticky anonymous revoke bit in the slot (never
			 * cleared by us — only by the holder's release CAS or
			 * by a fresh grant on an unowned slot) and follow it
			 * with the UDP hint as a latency accelerator.  The
			 * disk bit is what makes this sound: a systematic
			 * multicast failure (misconfig, wedged dispatcher,
			 * rcvbuf overload) degrades the fix to "slow" rather
			 * than back to "livelocked", because the holder's poll
			 * thread reads the bit on its next slot refresh.
			 *
			 * Best effort by design: a lost CAS race means some
			 * other node just rewrote the slot, and we are about
			 * to return -EAGAIN and be called again anyway.
			 */
			if ((flags & MXFS_LKF_DEMAND) && !cur_slot->revoke) {
				*new_slot = *cur_slot;
				new_slot->revoke = 1;
				new_slot->generation++;
				new_slot->last_modified_ms = mxfs_pal_time_ms();
				(void)caw_slot(ctx, slot_idx, cur_slot,
					       new_slot);
			}
			if (flags & MXFS_LKF_DEMAND)
				caw_send_bast_mcast(ctx, resource, mode);
			/*
			 * sess374 (sess363 ruling item B / G1): the SECOND
			 * demand chokepoint.  A NOQUEUE contender never enters
			 * caw_wait_for_grant, so the scrub above would never
			 * see it — and the AG sweep that livelocked in
			 * D-...-488 is exactly a NOQUEUE loop.  Same repair,
			 * rate-limited cluster-wide-cheaply on the ctx because
			 * these callers spin.  The control flow does NOT
			 * change: we still return -EAGAIN and the caller
			 * retries, which is when it observes the repair.
			 */
			if (ctx->closure_scrub_fn) {
				uint64_t blk = caw_victim_state_mask(cur_slot,
							~ctx->node_bit);

				/*
				 * The throttle is consulted ONLY once a
				 * candidate bit is actually present on the
				 * slot in conflict (review item 8): a stream
				 * of conflicts on healthy resources must
				 * never spend the frozen slot's repair
				 * opportunity.
				 *
				 * Winner election is ATOMIC (review round 2,
				 * item 3).  These callers spin, so a bare
				 * timestamp compare would let every CPU in
				 * the loop pass at once; the counter admits
				 * exactly one scrub at a time and the
				 * timestamp is only read/written by that
				 * winner.
				 */
				if (blk & ctx->closure_cand_mask) {
					if (mxfs_atomic32_inc(
						    &ctx->noq_scrub_busy) == 1) {
						uint64_t nq_now =
							mxfs_pal_time_ms();

						if (nq_now -
						    ctx->noq_scrub_last_ms
						    >= 1000) {
							ctx->noq_scrub_last_ms =
								nq_now;
							(void)caw_closure_scrub_slot(
								ctx, slot_idx,
								resource, blk,
								"NOQ", 0);
						}
					}
					mxfs_atomic32_dec(
						&ctx->noq_scrub_busy);
				}
			}
			rc = -EAGAIN;
			goto out;
		}
		if (flags & MXFS_LKF_TRYLOCK) {
			rc = -EWOULDBLOCK;
			goto out;
		}

		/*
		 * Upgrade-deadlock prevention: if we already hold some mode
		 * and the upgrade is blocked, release our current mode before
		 * waiting.  Otherwise two nodes both holding PR and both
		 * wanting EX deadlock symmetrically — each waits for the
		 * other to release, but neither thread can unlock because
		 * both are stuck inside caw_lock.  Releasing our mode first
		 * lets the other side's compat check pass, break the cycle.
		 * We'll fall through to the waiter-register path and re-
		 * acquire at the higher mode after the other node is done.
		 */
		if (our_mode != MXFS_LOCK_NL) {
			/*
			 * NEWARCH Phase 1.3 (Gemini chokepoint design):
			 *
			 * REMOVED the in-caw_lock release-and-wait.  The old
			 * code cleared our holder bit on disk and registered
			 * us as a waiter — but did so SILENTLY, so the upper
			 * layer's in-core i_dlm_mode stayed at our_mode while
			 * the on-disk truth was "we hold nothing".  Concurrent
			 * same-node ilock_begin callers fast-pathed on that
			 * stale belief → P106-STALE-EX → durable lost-update.
			 *
			 * Return -EDEADLK instead.  The upper layer
			 * (mxfs_dlm_ilock_begin) catches this, drops the lock
			 * through the proper BAST pipeline (state→BAST,
			 * queue bast_process which flushes + invalidates +
			 * clears the on-disk bit + sets i_dlm_mode=NL atomically),
			 * then re-enters caw_lock from a clean NL state.  No
			 * window where the on-disk bit and in-core mode can
			 * diverge.
			 *
			 * caw_lock now has a strict contract: it either
			 * upgrades-in-place atomically (the compat-add path
			 * above clears+adds in the same CAS) OR acquires from
			 * NL.  It never silently demotes.  This is invariant
			 * #1 ("no on-disk unlock without completed drain")
			 * applied to caw_lock itself.
			 */
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=upgrade-deadlk-return our_mode=%u "
				    "req=%u (caller orchestrates release)",
				    resource->ag_number, retry,
				    our_mode, mode);
			if (caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P109-CAW-EDEADLK type=%s id=%llu "
				    "our_mode=%u req=%u slot=%u "
				    "(returning -EDEADLK; caller drops through BAST)",
				    resource->type == MXFS_LTYPE_INODE ?
					"I" :
				    resource->type == MXFS_LTYPE_AG ?
					"A" : "O",
				    (unsigned long long)(
				      resource->type == MXFS_LTYPE_INODE ?
				        resource->ino :
				        (uint64_t)resource->ag_number),
				    our_mode, mode, slot_idx);
			rc = -EDEADLK;
			goto out;
		}

		/* Register as waiter.
		 *
		 * sess114: the exclusive-waiter predicate is mxfs_mode_can_write()
		 * and nothing else.  The registry's `writers` counter authorizes
		 * the waiters_ex DOWNGRADE on the same predicate, so an
		 * open-coded copy here could drift and hand the reconciler a
		 * counter that does not describe the bit it is clearing.
		 *
		 * waiter_mode is DERIVED, never raised in place.  The clearing
		 * paths already recompute it from the bitmaps; a setter that
		 * instead raised monotonically over the full mode enum disagreed
		 * with that derivation about what the field means (a PW waiter
		 * left waiter_mode=PW, which the next unlock by any node silently
		 * rewrote to EX).  One function, one meaning.
		 */
		*new_slot = *cur_slot;
		new_slot->waiters |= ctx->node_bit;
		if (mxfs_mode_can_write(mode))
			new_slot->waiters_ex |= ctx->node_bit;   /* sess50: track exclusive waiter */
		new_slot->waiter_mode = recompute_waiter_mode(new_slot);
		new_slot->generation++;

		last_our_mode = our_mode;
		last_wmode = cur_slot->waiter_mode;
		last_hex = cur_slot->holders_ex;
		last_hpr = cur_slot->holders_pr;

		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "P15-INSTR caw-act ag=%u retry=%d "
			    "action=register-waiter slot=%u cas_rc=%d",
			    resource->ag_number, retry, slot_idx, rc);
		if (rc == -EAGAIN) {
			ea_regwait++;
			continue;
		}
		if (rc)
			goto out;

		/* Send UDP BAST multicast (best effort hint) */
		caw_send_bast_mcast(ctx, resource, mode);

		/* Wait for grant */
		rc = caw_wait_for_grant(ctx, slot_idx, resource, mode,
					new_slot->generation,
					new_slot->ex_grant_epoch, lreq, gres,
					deadline_ms);
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "P15-INSTR caw-act ag=%u retry=%d "
			    "action=wait-for-grant-done slot=%u rc=%d",
			    resource->ag_number, retry, slot_idx, rc);
		/* v0.6.0: the promote CAS in caw_wait_for_grant granted exactly
		 * `mode`; report it.  This path left *granted_mode UNSET, so the
		 * caller's uninitialized stack value made P52-PARTIAL-GRANT fire
		 * 1462x in one 4-node dir_reuse run (pure noise, and any future
		 * caller honoring granted_mode would misbehave). */
		if (rc == 0 && granted_mode)
			*granted_mode = mode;
		/*
		 * Slot was cleared while we were waiting (e.g. the last
		 * holder's unlock raced with our waiter-registration CAW, or
		 * a sibling-node lease-expiry purge wiped the slot).  The
		 * resource always exists (inode/AG numbers are durable), so
		 * retry the outer loop — find_slot will either re-locate it
		 * or take the empty-slot claim path.
		 */
		if (rc == -ENOENT) {
			wait_enoent++;
			continue;
		}
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: lock exhausted %d retries for ino=%llu type=%u",
		     MXFS_CAW_MAX_RETRIES,
		     (unsigned long long)resource->ino,
		     resource->type);
	/* ccloop RULE4: dump WHICH CAS site exhausted the retry budget so we
	 * know whether the hot-slot storm is on claim/compat-add/register-waiter,
	 * and the final holder/waiter picture at the moment we give up. */
	if (resource->type == MXFS_LTYPE_INODE)
		pr_warn("mxfs: P-CAWEXH ino=%llu req=%u our_mode=%d ea_claim=%d ea_compat=%d ea_regwait=%d div=%d div_hi=%d ea_adopt=%d yield_bo=%d yield_stale=%d wait_enoent=%d yreg=%d ybypass=%d last_hex=%llx last_hpr=%llx\n",
			(unsigned long long)resource->ino, mode, last_our_mode,
			ea_claim, ea_compat, ea_regwait, div_lo, div_hi,
			ea_adopt, yield_bo,
			yield_stale, wait_enoent,
			fresh_yreg ? 1 : 0, ybypass,
			(unsigned long long)last_hex,
			(unsigned long long)last_hpr);
	/*
	 * sess40 (D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN, the measurement the
	 * ledger entry prescribes).  A claim-dominated exhaustion is the
	 * signature that cascades the cluster: every retry is ea_claim, the
	 * requester never registers as a waiter, and the acquire escalates to
	 * a filesystem shutdown.  Three candidate mechanisms have to be told
	 * apart, and only the state AT the moment we give up can do it:
	 *   (a) genuine N-way claim contention on ONE insertion point —
	 *       expect base far from the target and the target churning;
	 *   (b) a BROKEN PROBE CHAIN: a live slot for this resource exists
	 *       somewhere but a truly-empty slot between base and it
	 *       terminates the probe, so find_slot keeps saying ENOENT while
	 *       a peer holds the lock (the observed on-disk shape: slot LIVE
	 *       hex!=0 waiters=0 while every requester was in claim);
	 *   (c) a stale compare image — the CAS target's content differs from
	 *       what we read for reasons other than another claimer.
	 * So print the hash base, the insertion point we kept CASing, what is
	 * actually AT that index now, and the result of a FULL re-probe for
	 * the resource (scan_idx = where a live slot for it really lives, or
	 * NOSLOT).  One extra scan on an already-fatal path.
	 */
	if (resource->type == MXFS_LTYPE_INODE) {
		struct mxfs_caw_lock_slot *dbg = mxfs_pal_alloc(sizeof(*dbg));
		uint32_t dbg_base =
			resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
		uint32_t scan_idx = UINT32_MAX;
		uint32_t tgt_magic = 0, tgt_gen = 0;
		uint64_t tgt_ino = 0, tgt_hex = 0, tgt_vol = 0;
		uint32_t i;

		if (dbg) {
			if (empty_idx != UINT32_MAX &&
			    read_slot(ctx, empty_idx, dbg) == 0) {
				tgt_magic = dbg->magic;
				tgt_gen = dbg->generation;
				tgt_ino = dbg->resource.ino;
				tgt_hex = dbg->holders_ex;
				tgt_vol = dbg->resource.volume;
			}
			/* Exhaustive scan: does a live slot for this resource
			 * exist ANYWHERE?  If yes while find_slot said ENOENT,
			 * the probe chain is broken — mechanism (b). */
			/* Bounded to the probe chain's reachable window: a
			 * full 65536-slot walk is ~20s of shared-LUN I/O on
			 * an already-fatal path and would itself deepen the
			 * incident. */
			for (i = 0; i < 4096; i++) {
				uint32_t si = (dbg_base + i) %
					MXFS_CAW_MAX_SLOTS;

				if (read_slot(ctx, si, dbg) != 0)
					continue;
				if (dbg->magic == MXFS_CAW_MAGIC &&
				    memcmp(&dbg->resource, resource,
					   sizeof(*resource)) == 0) {
					scan_idx = si;
					break;
				}
			}
			mxfs_pal_free(dbg);
		}
		pr_warn("mxfs: P91-CLAIMEXH ino=%llu req=%u base=%u empty_idx=%u slot_idx=%u tgt[magic=%x gen=%u ino=%llu vol=%llx hex=%llx] scan_idx=%d verdict=%s\n",
			(unsigned long long)resource->ino, mode, dbg_base,
			empty_idx, slot_idx, tgt_magic, tgt_gen,
			(unsigned long long)tgt_ino,
			(unsigned long long)tgt_vol,
			(unsigned long long)tgt_hex,
			scan_idx == UINT32_MAX ? -1 : (int)scan_idx,
			scan_idx == UINT32_MAX ? "no-live-slot(contention)" :
				"LIVE-SLOT-EXISTS(probe-chain-broken)");
	}
	/* sess48: we may have registered a waiter bit on the last slot before
	 * exhausting retries — drop it so a stale EX waiter can't starve peer
	 * readers via defer_for_waiter. */
	caw_drop_own_waiter(ctx, slot_idx, resource, lreq, true, mode, false,
			    0);
	rc = -ETIMEDOUT;

out:
	/* sess38 P139-LOCKTOTAL: whole-acquire tail census (multi-retry
	 * shape).  Unconditional; tail events are rare by definition.
	 *
	 * sess380: the 800ms floor made this probe BLIND to the workload it
	 * exists to explain.  32-node shared-directory creates cost p95 424ms
	 * / max 471ms per create — every one of them under the floor — while
	 * the per-wait P138 probe (>5ms per wait_for_grant call) fired only 4
	 * times fleet-wide on the same run.  Both thresholds miss it because
	 * the acquire is MANY sub-5ms waits with outer retries in between, not
	 * one long wait: exactly the shape P139 was added to catch, just an
	 * order of magnitude smaller than its floor.  The floor is a knob now
	 * so the census can be pointed at the actual distribution; the default
	 * is unchanged. */
	if (resource->type == MXFS_LTYPE_INODE &&
	    mxfs_pal_time_ms() - p139_lock_start > mxfs_caw_locktotal_ms) {
		static int p139t_n;

		if (p139t_n++ < 20000)
			pr_warn("mxfs: P139-LOCKTOTAL ino=%llu req=%u rc=%d total_ms=%llu retries=%d ea_claim=%d ea_compat=%d ea_regwait=%d yield_bo=%d yield_stale=%d realms=%llu\n",
				(unsigned long long)resource->ino, mode, rc,
				(unsigned long long)(mxfs_pal_time_ms() -
						     p139_lock_start),
				retry, ea_claim, ea_compat, ea_regwait,
				yield_bo, yield_stale,
				(unsigned long long)mxfs_pal_time_real_ms());
	}
	/*
	 * sess109 structural defense (ruling item B), outer half.  Every arm
	 * that reaches this label with rc == 0 acquired a DURABLE grant and
	 * must have recorded which slot image authorised it.  (The in-memory
	 * fast paths — single_node and the mxfs_inode_caw_local/_skip
	 * diagnostics — return directly above and never reach here, so they
	 * cannot trip this.)
	 */
	if (rc == 0 && gres && gres->status == MXFS_GAUTH_UNSET) {
		static int p_unset_n;

		if (p_unset_n++ < 200)
			pr_warn("mxfs: P242-GRANT-UNSET-LOCK type=%c id=%llu slot=%u mode=%u retry=%d — durable grant with no provenance\n",
				resource->type == MXFS_LTYPE_INODE ? 'I' :
				resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
				(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
					resource->ino : (uint64_t)resource->ag_number),
				slot_idx, mode, retry);
	}
	/*
	 * sess112: publish the tenure and leave the registry in ONE critical
	 * section.  Prefer the mode the granting IMAGE showed us holding
	 * (gres->mode) over the mode we asked for: an acquire may request PR
	 * and find its own EX bit already up, and it is the EX holder bit a
	 * later give-up must be forbidden from clearing.
	 */
	if (rc == 0) {
		if (gres && gres->mode != MXFS_LOCK_NL)
			held_mode = gres->mode;
		else if (granted_mode && *granted_mode != MXFS_LOCK_NL)
			held_mode = *granted_mode;
		else
			held_mode = mode;
	}
	lreq_finish(ctx, resource, lreq, mode, held_mode);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/*
 * One of the two obligation PUBLISHERS, and therefore one of the two calls the
 * quiescence proof is actually about: caw_op_leave runs after lreq_finish, so
 * every publication this acquire could make is ordered before its decrement
 * under lreq_lock.
 */
int mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx,
		        const struct mxfs_resource_id *resource,
		        uint8_t mode, uint32_t flags,
		        uint8_t *granted_mode,
		        struct mxfs_grant_result *gres)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_lock_body(ctx, resource, mode, flags, false, 0,
			   granted_mode, gres, 0);
	caw_op_leave(ctx);
	return rc;
}

/*
 * sess386 (RULE-5 ruling, D-NOINO-RELFENCE-AIL-FREEZE-474 leg A): acquire with
 * an ABSOLUTE wall-clock deadline (mxfs_pal_time_ms domain; 0 = unbounded).
 * On expiry the waiter is cancelled through the same robust
 * caw_drop_own_waiter path as the base timeout (grant-wins: a grant seen on
 * the final poll read is returned as success; a handoff that races the cancel
 * is reconciled by ABORT-RECONCILE) and -ETIMEDOUT is returned.  For callers
 * that must not park a blocking cluster acquire under a held local resource
 * (AGI buffer, ILOCK) — the measured 474 collapse leg.
 */
int mxfs_dlm_caw_lock_deadline(struct mxfs_dlm_caw_ctx *ctx,
		        const struct mxfs_resource_id *resource,
		        uint8_t mode, uint32_t flags,
		        uint8_t *granted_mode,
		        struct mxfs_grant_result *gres,
		        uint64_t deadline_ms)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_lock_body(ctx, resource, mode, flags, false, 0,
			   granted_mode, gres, deadline_ms);
	caw_op_leave(ctx);
	return rc;
}

/*
 * sess290 (D-488 leg 7, sess289 ruling): acquire with an ATTESTED local
 * published epoch.  `local_epoch` is the write-authority epoch the caller
 * currently has PUBLISHED in core for this resource (0 = none — either no
 * tenure or a surrendered one).  The attestation is what lets the
 * already-held fast paths distinguish an ordinary reentrant acquire
 * (published epoch matches the slot → reaffirm) from a post-surrender
 * readopt of a stranded own bit (published epoch 0 → forced fresh mint,
 * never the surrendered epoch).  Callers must only attest when their
 * release-commit discipline guarantees the published epoch is zeroed
 * strictly AFTER the Invariant-1 drain (true for the AG paths).
 */
int mxfs_dlm_caw_lock_attested(struct mxfs_dlm_caw_ctx *ctx,
		        const struct mxfs_resource_id *resource,
		        uint8_t mode, uint32_t flags,
		        uint64_t local_epoch,
		        uint8_t *granted_mode,
		        struct mxfs_grant_result *gres)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_lock_body(ctx, resource, mode, flags, true, local_epoch,
			   granted_mode, gres, 0);
	caw_op_leave(ctx);
	return rc;
}

/* ─── mxfs_dlm_caw_unlock ─── */

int mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx,
			   const struct mxfs_resource_id *resource)
{
	/* Pure delegation — mxfs_dlm_caw_unlock_gen owns the gate. */
	return mxfs_dlm_caw_unlock_gen(ctx, resource, 0, false, 0);
}

/*
 * v0.6.2: gen-aware unlock.  expected_gen32 != 0 anchors the abort check at
 * the CALLER's release-decision capture (mxfs_dlm_caw_grant_seq32) instead of
 * unlock entry, closing the window where a local re-grant lands between the
 * caller's compare and this function's snapshot.  expected_gen32 == 0 keeps
 * the entry-time snapshot (unconditional release semantics preserved for
 * eviction/unmount/purge callers).
 *
 * ccloop cc87fed3 sess8: is_free -- when true, this unlock corresponds to a
 * genuinely FREED inode (caller has already verified nlink==0 and is doing
 * destructive inactivation), not an idle-gap release of a still-live inode.
 * If the release ends up writing a tombstone (no other holders/waiters),
 * ALSO clear dir_epoch/last_ex_slot in that SAME CAS -- piggybacking on the
 * unlock this function already performs, zero extra I/O.  Without this, a
 * reused inode number inherits the freed incarnation's last_ex_slot via
 * caw_claim_inherit_epoch, sees a false cross-node handoff on its first EX,
 * and pays the private-subdir FUA-storm coherency path a brand-new inode has
 * no business paying for (dlm_scaling@32 op-rate collapse).  A prior attempt
 * at this fix (P144, now removed) tried to detect+clear the tombstone via a
 * SEPARATE find_slot+read+CAS call issued right after this function returned
 * -- besides being structurally broken (find_slot's rc==0 "found" contract
 * only ever fires for a LIVE slot, so it silently no-op'd 2190/2190 times in
 * a live 32-node run), a corrected standalone version that DID work measurably
 * regressed the same test to 0/32 (from 27/32 with the broken no-op version)
 * by adding a synchronous extra read+CAS round-trip to every single free,
 * confirming the TRAP-1 warning already on record (mxfs_dlm_caw_purge_node
 * header): extra per-free FUA I/O measurably eats the shared aggregate
 * iSCSI-command-rate ceiling that ALL 32 nodes' foreground ops compete for,
 * even off the per-op latency path.  Piggybacking here is the only form of
 * this fix that costs nothing.
 */
static int caw_unlock_gen_body(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t expected_gen32, bool is_free,
			    int open_op,
			    enum mxfs_unlock_state *state_out)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint64_t rel_seq0;
	uint64_t unlock_deadline = 0;
	uint64_t p6h_handoff_bit = 0;	/* sess37: nudge target when this release hands off */
	struct mxfs_caw_lreq *unlk_clr = NULL;	/* sess117 clear window */
	uint64_t pub_seq0 = 0;
	bool clr_committed = false;
	/*
	 * D-488 (sess273 ruling): tri-state outcome.  UNKNOWN until a path
	 * proves otherwise; every exit below must classify.  UNKNOWN means
	 * the release CAW may have committed without our knowing (find_slot
	 * I/O error, CAS hard error after possible write) — the caller must
	 * verify with a read-back, never assume.
	 */
	enum mxfs_unlock_state ustate = MXFS_UNLOCK_UNKNOWN;
	int retry;
	/* sess380 P381-UNLK-CONTEND: unlock-CAS race accounting. */
	uint32_t p381_miss = 0, p381_sleep_ms = 0;
	uint64_t p381_t0 = 0;
	/* sess380 fast-retry classification state; see
	 * caw_unlk_delta_is_registration and the mxfs_caw_unlock_fastretry
	 * block comment. */
	struct mxfs_caw_lock_slot *prev_slot = NULL, *scratch_slot = NULL;
	bool unlk_classify_pending = false;
	uint32_t p381_benign = 0, p381_contended = 0, p381_fast = 0;
	uint32_t p381_why[CAW_UNLKD_MAX] = { 0 };
	uint32_t fast_burst = 0;
	uint64_t fast_burst_t0 = 0;
	int rc;

	if (state_out)
		*state_out = MXFS_UNLOCK_UNKNOWN;

	if (!ctx || !resource)
		return -EINVAL;

	/* Single-node fast path: just remove from in-memory tracking */
	if (ctx->single_node) {
		mem_lock_untrack(ctx, resource);
		if (state_out)
			*state_out = MXFS_UNLOCK_RELEASED;
		return 0;
	}

	/* sess78 DIAGNOSTIC: matches the in-memory-only INODE grant above. */
	{
		extern int mxfs_inode_caw_local;
		if (mxfs_inode_caw_local &&
		    resource->type == MXFS_LTYPE_INODE) {
			mem_lock_untrack(ctx, resource);
			if (state_out)
				*state_out = MXFS_UNLOCK_RELEASED;
			return 0;
		}
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	/* sess380: the two extra images the miscompare classifier needs — the
	 * one we last CAW'd against, and a scratch to reconstruct into. */
	prev_slot = mxfs_pal_alloc(sizeof(*prev_slot));
	scratch_slot = mxfs_pal_alloc(sizeof(*scratch_slot));
	if (!cur_slot || !new_slot || !prev_slot || !scratch_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		mxfs_pal_free(prev_slot);
		mxfs_pal_free(scratch_slot);
		/* Nothing was attempted — the bit is still ours. */
		if (state_out)
			*state_out = MXFS_UNLOCK_STILL_HELD;
		return -ENOMEM;
	}

	/* v0.6.2 unlock-vs-regrant closure: serialize against the local
	 * already-held acquire shortcut and arm the re-grant abort check
	 * (see caw_grant_meta_seq block comment). */
	caw_release_mark(ctx, resource, true);

	/*
	 * sess3(ccloop 26c41354): under a 16-node hot-shared-dir CAS storm the
	 * INODE unlock CAS keeps miscomparing (peers mutate the slot between our
	 * read and our compare-and-write).  With the fixed 100-retry cap it can
	 * exhaust -> -EIO -> the caller leaves the lock HELD -> the waiting peer
	 * re-BASTs -> mxfs-ino-bast requeues -> kworker storm / load 870 WEDGE.
	 * A miscompare is ALWAYS transient (someone else's CAS just landed; our
	 * bit-clear is still valid on re-read), and unlike acquire, retrying an
	 * unlock longer is SAFE (we still hold the lock, only release later — no
	 * double-grant window).  So when caw_unlock_backoff is set, bound the
	 * INODE-unlock retry by a generous wall clock instead of a tight count:
	 * the lock ALWAYS eventually releases, breaking the re-BAST amplification.
	 *
	 * sess6 (ccloop 72513a13): ICLUSTER unlocks get the same wall-clock
	 * bound.  PROVEN at 32/cawd (cc NO_TERMINAL wedge): the type=6 unlock
	 * kept the tight 100-retry cap, exhausted against 32-node waiter-bit
	 * churn, and the swallowed failure left a stale on-disk cluster EX
	 * (slot-8 bit) that starved all 32 nodes' PR acquires 380s+ (the
	 * holder heartbeats, so P-WAIT-EXTEND extends forever).  Unlock
	 * retry-to-deadline is exactly as safe here as for inodes: we still
	 * hold the grant, releasing later is never a double-grant.
	 *
	 * sess120: derived BEFORE the clear window opens, because the window's
	 * own bounded wait shares this deadline and so can never extend the
	 * unlock budget beyond what it already was.
	 */
	/*
	 * D-488 (sess273 ruling, leg 5): the INODE/ICLUSTER type gate is
	 * REMOVED — AG unlocks get the same wall-clock deadline.  The AG
	 * type previously had only the tight 100-retry cap; exhausting it
	 * against 32-node waiter-bit churn silently stranded the on-disk
	 * EX bit (the -488 birth).  Unlock retry-to-deadline is exactly as
	 * safe for AGs as for inodes: we still hold the grant, releasing
	 * later is never a double-grant.
	 */
	if (mxfs_caw_unlock_backoff)
		unlock_deadline = mxfs_pal_time_ms() + MXFS_CAW_UNLOCK_DEADLINE_MS;

	/*
	 * sess117: the release is a destructive clear of THIS node's bits, so
	 * it declares a clear window alongside the legacy releasing mark.  Two
	 * things the mark cannot do on its own: grant_meta is a NO-CHAIN hash,
	 * so a colliding foreign resource can evict the mark and expose the
	 * already-held shortcut; and the mark is edge-triggered, so a release
	 * that begins AND ends between a publication's slot read and its
	 * publication is invisible to it.  The lreq table is chained and keyed
	 * by the resource, and clr_seq is a count rather than a flag, so
	 * neither hole survives.
	 *
	 * sess120 FAIL CLOSED (GPT sess118 ruling item 5).  This used to
	 * proceed under the legacy mark alone, on the argument that stranding
	 * the lock held is worse than the residual aliasing hole.  That trade
	 * is not available: the ruling is that "an ENOMEM fallback that
	 * proceeds without registry coverage is a correctness defect", and the
	 * two outcomes are not comparable anyway — a stranded lock is a stall
	 * that resolves when the peer re-BASTs and this node retries, while an
	 * unlinearized clear silently strips a bit a local writer is still
	 * using and loses data.  A stall is recoverable; corruption is not.
	 *
	 * The reason it is now affordable is that the window is allocation-free
	 * on this path: this node holds the grant it is releasing, so
	 * lreq_finish has published tenure[] and lreq_gc cannot have freed the
	 * entry.  lreq_clr_begin finds it and never calls the allocator.  For
	 * the residual case the reserve covers it, and the wait below shares
	 * this unlock's own deadline.
	 */
	/*
	 * sess124: NO obligation is published here, deliberately.  A release
	 * that cannot complete leaves the lock HELD — local tenure[] still
	 * covers the bit, so it is authorised rather than stale, and the
	 * collector is this node's next unlock (the peer re-BASTs).  Owing it
	 * would hand the owed worker a bit whose plan can only ever come back
	 * `holder_moot`, i.e. pure churn against a live local writer.
	 */
	if (ctx->lreq && ctx->lreq_lock) {
		if (lreq_clr_begin_wait(ctx, resource, NULL, &pub_seq0, NULL,
					&unlk_clr, unlock_deadline) < 0) {
			ctx->lreq_nomem++;
			pr_warn_ratelimited("mxfs: P251-LREQ-DRY unlock-window type=%u ino=%llu dry=%llu — REFUSING the release, lock stays held (peer will re-BAST)\n",
					    resource->type,
					    (unsigned long long)resource->ino,
					    (unsigned long long)ctx->lreq_reserve_dry);
			caw_release_mark(ctx, resource, false);
			mxfs_pal_free(cur_slot);
			mxfs_pal_free(new_slot);
			mxfs_pal_free(prev_slot);
			mxfs_pal_free(scratch_slot);
			/* Refused before any CAS — the bit is still ours. */
			if (state_out)
				*state_out = MXFS_UNLOCK_STILL_HELD;
			return -EIO;
		}
	}
	rel_seq0 = caw_grant_meta_seq(ctx, resource);
	if (expected_gen32 != 0 &&
	    ((uint32_t)rel_seq0 ?: (rel_seq0 ? 1 : 0)) != expected_gen32) {
		/* a re-grant landed between the caller's capture and here */
		lreq_clr_end(ctx, unlk_clr, false);
		caw_release_mark(ctx, resource, false);
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		mxfs_pal_free(prev_slot);
		mxfs_pal_free(scratch_slot);
		/* No CAS issued — the bit belongs to the NEW tenure. */
		if (state_out)
			*state_out = MXFS_UNLOCK_STILL_HELD;
		return -ESTALE;
	}

	/* sess380 P381-UNLK-CONTEND accounting; see the probe below. */
	p381_t0 = mxfs_pal_time_ms();
	for (retry = 0;
	     retry < MXFS_CAW_MAX_RETRIES ||
	     (unlock_deadline && mxfs_pal_time_ms() < unlock_deadline);
	     retry++) {
		if (caw_grant_meta_seq(ctx, resource) != rel_seq0)
			goto regrant_abort;
		caw_inode_backoff(ctx, resource, retry);	/* sess39 */
		rc = find_slot(ctx, resource, &slot_idx, cur_slot, &empty_idx);
		if (rc == -ENOENT) {
			/*
			 * D-488 (ruling leg 4): a clean not-found IS a proven
			 * clear — own-bit reads go through the same target that
			 * served our writes (write-back cache makes own writes
			 * always visible), and a garbled read surfaces as an
			 * I/O error, not -ENOENT.  But for a resource the
			 * caller believed HELD it is anomalous (the slot should
			 * exist with our bit): make it loud for AGs so a
			 * vanish-under-tenure is attributable, never silent.
			 */
			if (resource->type == MXFS_LTYPE_AG)
				pr_warn_ratelimited(
				    "mxfs: P274-AGUNLK-NOSLOT ag=%u — unlock found no live slot for an AG we believed held (treated RELEASED)\n",
				    resource->ag_number);
			ustate = MXFS_UNLOCK_RELEASED;
			rc = 0; /* Not found — nothing to unlock */
			goto out;
		}
		if (rc) {
			/*
			 * D-488: find_slot I/O error — we cannot know whether
			 * an earlier iteration's CAS committed.  UNKNOWN; the
			 * caller must verify by read-back before trusting
			 * either direction.
			 */
			pr_warn_ratelimited(
			    "mxfs: P274-UNLK-FINDSLOT-ERR type=%u id=%llu rc=%d retry=%d — unlock outcome UNKNOWN\n",
			    resource->type,
			    (unsigned long long)(resource->type ==
				MXFS_LTYPE_AG ? (uint64_t)resource->ag_number :
				resource->ino),
			    rc, retry);
			ustate = MXFS_UNLOCK_UNKNOWN;
			goto out;
		}

		/*
		 * sess380: classify the PREVIOUS iteration's MISCOMPARE now
		 * that we hold a fresh image, and — only when
		 * mxfs_caw_unlock_fastretry is on — decide here whether that
		 * miscompare earns the jittered backoff.
		 *
		 * The decision has to live here rather than at the -EAGAIN
		 * site because classifying needs the fresh image, and the
		 * fresh image is what find_slot above just produced.  With the
		 * knob OFF the sleep still happens at the -EAGAIN site exactly
		 * as before and this block only COUNTS, so the off arm is
		 * behaviourally identical to the pre-sess380 code and the A/B
		 * is a single flag.
		 */
		if (unlk_classify_pending) {
			int why = caw_unlk_delta_classify(prev_slot, cur_slot,
							  scratch_slot,
							  ctx->node_bit);
			bool benign = (why == CAW_UNLKD_BENIGN);

			unlk_classify_pending = false;
			if (why >= 0 && why < CAW_UNLKD_MAX)
				p381_why[why]++;
			if (benign)
				p381_benign++;
			else
				p381_contended++;

			if (mxfs_caw_unlock_fastretry) {
				uint64_t nowms = mxfs_pal_time_ms();
				bool burst_ok;

				if (!fast_burst)
					fast_burst_t0 = nowms;
				burst_ok = fast_burst <
					     (uint32_t)max(1, mxfs_caw_unlock_fastretry_max) &&
					   (nowms - fast_burst_t0) <
					     (uint64_t)max(1, mxfs_caw_unlock_fastretry_ms);

				if (benign && burst_ok) {
					/* Not a contest — a peer registered
					 * interest and we recompute from its
					 * image.  Go straight back at it. */
					fast_burst++;
					p381_fast++;
				} else if (mxfs_caw_unlock_backoff &&
					   resource->type == MXFS_LTYPE_INODE) {
					uint32_t nap = 1 + (retry & 7) +
						       (ctx->local_node % 8);

					/* Fall back to the proven path, and
					 * end the burst so a long run of
					 * benign deltas cannot starve the
					 * releaser without ever backing off. */
					fast_burst = 0;
					p381_sleep_ms += nap;
					mxfs_pal_sleep_ms(nap);
					/* We slept holding a now-stale image;
					 * refresh it before building the CAS,
					 * or the compare is guaranteed to
					 * miss.  Targeted read: the slot index
					 * is already resolved. */
					rc = read_slot(ctx, slot_idx, cur_slot);
					if (rc) {
						pr_warn_ratelimited(
						    "mxfs: P274-UNLK-REREAD-ERR type=%u id=%llu rc=%d retry=%d — unlock outcome UNKNOWN\n",
						    resource->type,
						    (unsigned long long)(resource->type ==
							MXFS_LTYPE_AG ? (uint64_t)resource->ag_number :
							resource->ino),
						    rc, retry);
						ustate = MXFS_UNLOCK_UNKNOWN;
						goto out;
					}
					if (cur_slot->magic != MXFS_CAW_MAGIC) {
						/* Slot recycled under us; let
						 * the next find_slot re-bind
						 * rather than CAS a stranger. */
						continue;
					}
				} else {
					fast_burst = 0;
				}
			}
		}

		/*
		 * sess135 (ccloop 14d31183) P108 root-cause hardening: if our
		 * bit is in NO holder bitmap and NOT in waiters, there is
		 * nothing to unlock — return WITHOUT a CAS.  The prior
		 * unconditional clear+CAS made every stale-BAST cleanup
		 * unlock a gen-bump write (2441/run measured on the hot
		 * shared-dir slot), and its miscompare-retry loop re-read
		 * and re-cleared whatever appeared — including a fresh EX
		 * grant CAS'd in by this node's own concurrent slow-path
		 * acquire (proven: P135-INO-UNLOCK bast_notify 88.3794 →
		 * P106-EXGRANT 88.3806 → strip hex=1->0 88.3814 → P108).
		 */
		if (node_held_mode(cur_slot, ctx->node_bit) == MXFS_LOCK_NL &&
		    !(cur_slot->waiters & ctx->node_bit) &&
		    !(cur_slot->yield_to & ctx->node_bit)) {
			untrack_held(ctx, slot_idx);
			/* sess112: the slot already shows us holding nothing,
			 * so no local tenure can still be relying on a bit
			 * here — retire the registry's view with it. */
			lreq_release_all(ctx, resource, pub_seq0);
			/* D-488: read-verified — our bit is clear on disk. */
			ustate = MXFS_UNLOCK_RELEASED;
			rc = 0;
			goto out;
		}

		*new_slot = *cur_slot;
		p6h_handoff_bit = 0;	/* sess37: fresh image, fresh decision */

		/* Clear our bit from ALL holder bitmaps */
		new_slot->holders_ex &= ~ctx->node_bit;
		new_slot->holders_pw &= ~ctx->node_bit;
		new_slot->holders_pr &= ~ctx->node_bit;
		new_slot->holders_cw &= ~ctx->node_bit;
		new_slot->holders_cr &= ~ctx->node_bit;
		new_slot->granted_mode = recompute_granted_mode(new_slot);
		new_slot->generation++;
		new_slot->last_modified_ms = mxfs_pal_time_ms();
		/*
		 * D-AGLOCK-...-LIVELOCK-488: consume the sticky revoke in the
		 * SAME CAS that drops our holder bits, and do it HERE — before
		 * the fair-handoff/direct-handoff arms below re-add a waiter as
		 * a holder — so a release that hands straight off still clears
		 * the demand it satisfied.
		 */
		caw_revoke_consume(new_slot, new_slot);
		/* P109 Phase 1.1 (NEWARCH) — canonical unlock entry.  Every
		 * call here clears OUR bit in every mode bitmap atomically.
		 * The OK caller is xfs's mxfs_dlm_bast_process (which sets
		 * i_dlm_mode = NL under spinlock BEFORE invoking us); any
		 * non-bast caller of mxfs_dlm_caw_unlock would leak a
		 * stale-cached i_dlm_mode.  Logs cur->granted_mode so the
		 * stale-EX hunt can identify whether unlock was called for
		 * a slot already showing our bit clear. */
		if (caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P109-CLR-UNLOCK type=%s id=%llu "
			    "cur_gm=%u cur_h_ex=%llx cur_h_pr=%llx slot=%u",
			    resource->type == MXFS_LTYPE_INODE ? "I" :
			    resource->type == MXFS_LTYPE_AG ? "A" : "O",
			    (unsigned long long)(
			      resource->type == MXFS_LTYPE_INODE ?
			        resource->ino :
			        (uint64_t)resource->ag_number),
			    cur_slot->granted_mode,
			    (unsigned long long)cur_slot->holders_ex,
			    (unsigned long long)cur_slot->holders_pr,
			    slot_idx);

		/*
		 * Yield-to-priority: if there are waiters, give them
		 * priority over the releasing node by setting yield_to.
		 * This prevents the releasing node from immediately
		 * reacquiring before any waiter gets a chance.
		 */
		if (cur_slot->waiters) {
			uint64_t ex_w = cur_slot->waiters_ex &
					cur_slot->waiters;
			uint64_t pr_w = cur_slot->waiters &
					~cur_slot->waiters_ex;

			if (mxfs_caw_fair_handoff &&
			    resource->type == MXFS_LTYPE_INODE && ex_w) {
				/*
				 * sess2(ccloop 26c41354) FAIR HANDOFF: among EX
				 * waiters hand off to ONE round-robin next (first
				 * after our node bit, wrapping) instead of all.
				 * The chosen node clears yield_to on promote and
				 * picks the next on its own release, bounding each
				 * EX waiter's wait to O(N) handoffs — kills the
				 * self-promote free-for-all (16-node victim-node
				 * loss).  PR-only waiters still batch-grant below.
				 *
				 * v0.10.39 shared-class anti-starvation: the pure
				 * EX round-robin starves PR waiters FOREVER while
				 * EX waiters keep arriving (proven: 32-node
				 * dir_reuse — verify's readdir PR starved 240s
				 * behind 31 creators' dir-EX rotation, rc=-110
				 * shutdown).  Once the slot has granted
				 * MXFS_CAW_EX_STREAK_YIELD consecutive EX-class
				 * tenures, yield ONE turn to the WHOLE shared
				 * class (PR-PR compatible: they all promote
				 * together, and their grant resets the streak
				 * inside the same CAS).
				 */
				bool streak_yield = (pr_w &&
					cur_slot->ex_grant_streak >=
					MXFS_CAW_EX_STREAK_YIELD);
				/*
				 * sess299 STICKY TICKET (RULE-5 sess298
				 * ruling, D-503): a standing valid EX
				 * reservation is carried forward by EVERY
				 * intermediate releaser — never re-nominated
				 * over, never replaced by a streak-yield PR
				 * batch (which may DELAY it via the batch
				 * arm below, but the reservation survives
				 * and the nominee is granted on drain).
				 * Only when no reservation stands does this
				 * release nominate fresh, and then
				 * relative to last_ex_slot so all releasers
				 * agree on the same round-robin next.
				 */
				uint64_t ex_resv =
					caw_standing_ex_resv(cur_slot);
				if (ex_resv)
					new_slot->yield_to = ex_resv;
				else if (streak_yield)
					new_slot->yield_to = pr_w;
				else
					new_slot->yield_to =
						caw_pick_next_ex_waiter(
							ex_w,
							caw_last_ex_bit(
								cur_slot));
				/*
				 * sess37 DIRECT GRANT HANDOFF (see the
				 * mxfs_caw_direct_handoff param comment for
				 * the measured case).  When we are the LAST
				 * holder leaving and fair-handoff picked EX
				 * waiter W, this SAME CAS makes W the holder:
				 * no ticket window (readers stop deferring to
				 * an unclaimed ticket), no winner claim CAW
				 * (its miscompare storm disappears), and the
				 * epoch/streak bookkeeping W's promote would
				 * have done happens here FOR W.  W's poll
				 * adopts on sight (P6H-ADOPT).  An abandoned
				 * W reconciles in caw_drop_own_waiter; a dead
				 * W is lease-purged — same recovery story as
				 * a winner that claimed and then died.
				 */
				/*
				 * sess37 addendum — PR-CLASS BATCH GRANT on
				 * the streak-yield arm.  Measured on 314 with
				 * EX handoff alone: 823 streak yields vs 310
				 * EX handoffs per anatomy run — the dominant
				 * residual was the PR class claiming its
				 * ticket one CAS at a time (1639 miscompares,
				 * ticket dwell while the first reader wakes).
				 * Same CAS, same recovery story per reader as
				 * the EX handoff: abort-reconcile clears a
				 * landed grant for an abandoned acquire, lease
				 * purge covers death.  PR grants do not touch
				 * dir_epoch/last_ex_slot; the class grant
				 * resets the EX streak exactly as the first
				 * PR promote would have (v0.10.42 contract).
				 */
				/* sess38 (P139 census): the last-holder guard
				 * was stricter than PR admission needs — PR
				 * coexists with PR/CR, so batch-admit while
				 * sibling shared holders remain; only an
				 * exclusive-class holder blocks the batch.
				 * (Old guard skipped the batch whenever ANY
				 * holder remained, leaving the ticket to be
				 * self-claimed one CAS at a time = the ~900ms
				 * 9-node admission storm.) */
				if (mxfs_caw_direct_handoff && streak_yield &&
				    !(new_slot->holders_ex |
				      new_slot->holders_pw |
				      new_slot->holders_cw)) {
					uint64_t prbits = pr_w;

					new_slot->holders_pr |= prbits;
					new_slot->waiters &= ~prbits;
					/* sess299: the PR batch DELAYS a
					 * standing EX reservation, never
					 * consumes it — keep the ticket so
					 * the nominee is granted when the
					 * batch drains (ruling item 5). */
					new_slot->yield_to = ex_resv;
					caw_grant_streak_note(new_slot,
							      MXFS_LOCK_PR);
					new_slot->granted_mode =
						recompute_granted_mode(new_slot);
					new_slot->waiter_mode =
						recompute_waiter_mode(new_slot);
					p6h_handoff_bit = prbits;
					if (resource->type ==
					    MXFS_LTYPE_INODE) {
						static int p6h_prb_n;

						if (p6h_prb_n++ < 2000)
							pr_warn("mxfs: P6H-PRBATCH ino=%llu mask=%llx n=%d gen=%llu realms=%llu\n",
								(unsigned long long)resource->ino,
								(unsigned long long)prbits,
								mxfs_pal_popcount64(prbits),
								(unsigned long long)new_slot->generation,
								(unsigned long long)mxfs_pal_time_real_ms());
					}
				}
				/*
				 * sess299 DEADLOCK GUARD (ruling item 6): a
				 * sticky reservation naming an UPGRADER —
				 * the sole remaining PR holder waiting for
				 * EX — can never see the slot holderless
				 * (its own PR bit prevents that), so the
				 * handoff must atomically CONVERT it PR→EX
				 * instead of waiting for zero holders.
				 */
				if (mxfs_caw_direct_handoff && !streak_yield &&
				    caw_handoff_nominee_ok(cur_slot, new_slot) &&
				    (!slot_has_holders(new_slot) ||
				     (new_slot->holders_pr ==
				      new_slot->yield_to &&
				      !(new_slot->holders_ex |
					new_slot->holders_pw |
					new_slot->holders_cw |
					new_slot->holders_cr)))) {
					uint64_t wbit = new_slot->yield_to;
					int w_slotno =
						__builtin_ctzll(wbit);
					bool w_handoff;

					new_slot->holders_pr &= ~wbit;
					new_slot->holders_ex |= wbit;
					new_slot->waiters &= ~wbit;
					new_slot->waiters_ex &= ~wbit;
					new_slot->yield_to = 0;
					/*
					 * sess108 (ruling blockers 1+2): THIS
					 * CAS is the transition from "no
					 * write-capable holder" to "W holds EX",
					 * so it is where W's tenure token is
					 * minted.  The identity of the node
					 * issuing the C&W is irrelevant — the
					 * holder bit and last_ex_slot name the
					 * beneficiary and the CAS is the
					 * linearization point.  Before this, the
					 * arm hand-rolled dir_epoch/last_ex_slot
					 * and left ex_grant_epoch naming the
					 * RELEASER's ended tenure, so every
					 * adopted grant had nothing true to
					 * install (sess106 P241: st_unset on all
					 * 32 nodes).  Same helper as every
					 * self-promote — no second policy.
					 */
					w_handoff = caw_grant_epoch_update(
							new_slot,
							cur_slot,
							(uint8_t)w_slotno,
							MXFS_LOCK_EX);
					caw_grant_streak_note(new_slot,
							      MXFS_LOCK_EX);
					new_slot->granted_mode =
						recompute_granted_mode(new_slot);
					new_slot->waiter_mode =
						recompute_waiter_mode(new_slot);
					p6h_handoff_bit = wbit;
					if (resource->type ==
					    MXFS_LTYPE_INODE) {
						static int p6h_ho_n;

						if (p6h_ho_n++ < 2000)
							pr_warn("mxfs: P6H-HANDOFF ino=%llu to_slot=%d gen=%llu epoch=%u gep=%llu handoff=%d realms=%llu\n",
								(unsigned long long)resource->ino,
								w_slotno,
								(unsigned long long)new_slot->generation,
								new_slot->dir_epoch,
								(unsigned long long)new_slot->ex_grant_epoch,
								w_handoff ? 1 : 0,
								(unsigned long long)mxfs_pal_time_real_ms());
					}
				}
				/* v0.10.42: do NOT reset the streak here.  It
				 * resets ONLY when the PR class actually
				 * promotes (caw_grant_streak_note on a PR
				 * grant).  Resetting on yield (v0.10.40) made
				 * streak-yield fire only ~2x/run so the
				 * v0.10.41 upgrader-defer never engaged and
				 * PR/EX still starved (B3 PR, B4 EX).  Keeping
				 * the streak high fires yield_to=pr_w on every
				 * overlap release; the upgrader-defer then
				 * guarantees pr_w promotes (no B2 EX-deadlock)
				 * and THAT PR grant resets the streak. */
				/* v0.10.40: only (re)arm the stale-clock when the
				 * ticket VALUE changes.  A persistent yield_to
				 * (pr_w that cannot promote while an EX holder
				 * lingers) MUST age out so the acquire-path 5s
				 * stale-clear can break the deadlock — otherwise
				 * every peer release refreshes yield_set_ms and
				 * the hint never goes stale (sess130 livelock,
				 * re-opened for fresh EX waiters by the v0.10.39
				 * streak yield: 32-node dir_reuse r3, 20 nodes
				 * EX-starved 360s -> rc=-110 shutdown). */
				new_slot->yield_set_ms =
					caw_yield_stamp(cur_slot,
						new_slot->yield_to);
				if (streak_yield)
					pr_warn_ratelimited(
					    "mxfs: P-STREAK-YIELD ino=%llu streak=%u pr_w=%llx ex_w=%llx yt=%llx armed=%d\n",
					    (unsigned long long)resource->ino,
					    cur_slot->ex_grant_streak,
					    (unsigned long long)pr_w,
					    (unsigned long long)ex_w,
					    (unsigned long long)new_slot->yield_to,
					    (int)(new_slot->yield_to !=
						  cur_slot->yield_to));
			} else {
				new_slot->yield_to = cur_slot->waiters;
				new_slot->yield_set_ms =
					caw_yield_stamp(cur_slot, new_slot->yield_to);
			}
		}

		/* If no holders and no waiters, write a tombstone so the
		 * probe chain remains traversable.  See find_slot.  Keeps
		 * resource + dir_epoch (idle-gap handoff continuity) UNLESS
		 * this release is for a genuinely freed inode (is_free), in
		 * which case that continuity would be a FALSE handoff signal
		 * for whatever unrelated file next reuses this inode number
		 * -- clear it in this same CAS (see this function's own
		 * comment for the full mechanism + why it must be here and
		 * not a separate follow-up call). */
		/* sess41 (GPT audit C1): publication inseparable from release —
		 * the open-holder bit change rides the SAME CAS that removes
		 * this node's holder bits.  The old two-CAS shape (best-effort
		 * open_set, then unlock) had a silent-failure window: the set
		 * could exhaust its retries, the release still landed, and a
		 * peer's B6 guard then freed a file we hold open. */
		if (open_op > 0)
			new_slot->open_holders |= ctx->node_bit;
		else if (open_op < 0)
			new_slot->open_holders &= ~ctx->node_bit;
		/* sess40: a genuinely freed inode ends all open protection —
		 * the defer guard upstream prevents free while peers hold
		 * opens, so bits here are a dead incarnation's residue. */
		if (is_free)
			new_slot->open_holders = 0;
		/* sess40: a slot with live open-holder bits must stay LIVE —
		 * tombstones are recyclable by DIFFERENT resources, which
		 * would destroy an open-unlinked file's protection.  The
		 * open_clear CAS tombstones once the last bit drops. */
		if (!slot_has_holders(new_slot) && !new_slot->waiters &&
		    !new_slot->open_holders) {
			caw_tombstone_slot(new_slot);
			if (is_free && (new_slot->dir_epoch != 0 ||
			    new_slot->last_ex_slot != MXFS_CAW_EX_SLOT_NONE)) {
				new_slot->dir_epoch = 0;
				new_slot->last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
				pr_warn_ratelimited(
				    "mxfs: P144-EPOCH-FREE-RESET ino=%llu slot=%u — cleared stale dir_epoch/last_ex_slot at inode free (unlock piggyback)\n",
				    (unsigned long long)resource->ino, slot_idx);
			}
		}

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR CAW-UNLOCK ino=%llu slot=%u "
				"cur_hex=%llx cur_hpr=%llx cur_gen=%llu "
				"new_hex=%llx new_hpr=%llx new_gen=%llu "
				"tomb=%d t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				(unsigned long long)cur_slot->holders_ex,
				(unsigned long long)cur_slot->holders_pr,
				(unsigned long long)cur_slot->generation,
				(unsigned long long)new_slot->holders_ex,
				(unsigned long long)new_slot->holders_pr,
				(unsigned long long)new_slot->generation,
				(new_slot->magic == MXFS_CAW_TOMBSTONE_MAGIC),
				(unsigned long long)mxfs_pal_time_ms());
		}

		/* v0.6.3: last-instant anchor re-check.  The already-held
		 * shortcut grants are MEMORY-ONLY (no slot write), so a CAS
		 * miscompare will never surface a mid-loop local re-grant —
		 * this check is the only barrier between such a grant and
		 * our clear committing over it.  find_slot's disk read above
		 * gives the shortcut's store ample time to land. */
		if (caw_grant_meta_seq(ctx, resource) != rel_seq0)
			goto regrant_abort;
		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR CAW-UNLOCK-RESULT ino=%llu "
				"slot=%u rc=%d t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				rc, (unsigned long long)mxfs_pal_time_ms());
		}

		if (rc == -EAGAIN) {
			/*
			 * sess2(ccloop 26c41354): jittered backoff on the
			 * INODE unlock CAS miscompare (mxfs_caw_unlock_backoff)
			 * to desync the 16-node hot-slot CAS storm so the
			 * unlock wins instead of tight-looping to exhaustion ->
			 * -EIO -> stuck-lock BAST-storm WEDGE (dir_reuse: load
			 * 870, 1000+ mxfs-ino-bast kworkers).  The acquire path
			 * already desyncs (sess39); the unlock lacked it.
			 * Node-phased + retry-escalating so contenders spread.
			 */
			p381_miss++;
			/*
			 * sess380: keep the image we just CAW'd against so the
			 * next iteration can classify what beat us.  This runs
			 * in BOTH arms — the classification telemetry is
			 * collected even with the optimisation off.
			 */
			*prev_slot = *cur_slot;
			unlk_classify_pending = true;
			if (!mxfs_caw_unlock_fastretry &&
			    mxfs_caw_unlock_backoff &&
			    resource->type == MXFS_LTYPE_INODE) {
				uint32_t p381_nap = 1 + (retry & 7) +
						    (ctx->local_node % 8);

				p381_sleep_ms += p381_nap;
				mxfs_pal_sleep_ms(p381_nap);
			}
			continue;
		}
		if (rc) {
			/*
			 * sess119 (ruling item 3): the CAS did not report
			 * success, but neither did it report a miscompare — the
			 * release CAW may have reached the target and stripped
			 * our bit.  Close the clear window as COMMITTED so a
			 * publication validating across it re-reads instead of
			 * trusting a holder bit that may already be gone.
			 *
			 * Local tenure is deliberately NOT retired here:
			 * lreq_release_all runs only on a CONFIRMED clear (a
			 * stale-high tenure only makes later plans refuse,
			 * which is the safe direction), whereas clr_seq must
			 * move on the merely-possible one.
			 */
			if (caw_may_have_written(rc))
				clr_committed = true;
			/*
			 * D-488: hard CAS error — the write may or may not
			 * have reached the slot.  UNKNOWN either way (even
			 * when caw_may_have_written is false the transport
			 * error means we did not read back a proof).  Caller
			 * verifies by read-back.
			 */
			pr_warn_ratelimited(
			    "mxfs: P274-UNLK-CAS-ERR type=%u id=%llu rc=%d may_have_written=%d retry=%d — unlock outcome UNKNOWN\n",
			    resource->type,
			    (unsigned long long)(resource->type ==
				MXFS_LTYPE_AG ? (uint64_t)resource->ag_number :
				resource->ino),
			    rc, clr_committed ? 1 : 0, retry);
			ustate = MXFS_UNLOCK_UNKNOWN;
			goto out;
		}

		/* v0.6.4 P141: attribute every committed EX-bit clear on an
		 * INODE resource.  Residual P106-STALE-EX events (test4
		 * ino=137 @380.662, prebump build) show a fresh grant's bit
		 * vanishing ~1.3ms after EXGRANT with NO regrant-abort — the
		 * gen-aware loop provably cannot do that (read-after-CAS ⇒
		 * check-after-prebump), so SOME path is stripping the bit.
		 * seq_now vs rel_seq0 discriminates: seq_now advanced ⇒ this
		 * unlock raced a re-grant and the checks missed (ordering
		 * bug); seq unchanged ⇒ this unlock was legitimate and the
		 * phantom's clearer is elsewhere (DIVERG/dead/release-all). */
		if (resource->type == MXFS_LTYPE_INODE &&
		    (cur_slot->holders_ex & ctx->node_bit)) {
			static int p141_n;

			if (p141_n++ < 500)
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P141-UNLK-EXCLR ino=%llu expected=%u rel_seq0=%llu seq_now=%llu retry=%d gen=%llu",
				    (unsigned long long)resource->ino,
				    expected_gen32,
				    (unsigned long long)rel_seq0,
				    (unsigned long long)caw_grant_meta_seq(ctx, resource),
				    retry,
				    (unsigned long long)cur_slot->generation);
		}
		/*
		 * sess380 P381-UNLK-CONTEND (D-32NODE-SHARED-DIR-CREATE-PACE).
		 *
		 * The holder-side release of a contended directory inode was
		 * measured at 26-48 ms, of which P138-BAST's `sx` field says
		 * 95-98% is the WIRE UNLOCK, not the drain pipeline (drain is
		 * 2-4 ms). This probe says why, in numbers rather than by
		 * inference: how many times this unlock's CAS MISCOMPARED and
		 * how long it slept before it finally won.
		 *
		 * The suspected shape is a positive feedback loop that makes
		 * contention self-amplifying: the holder's unlock CAS races the
		 * WAITER-BIT CASes of the very nodes waiting for it, so every
		 * waiter that registers invalidates the holder's compare image
		 * and costs it another 1-15 ms nap. More waiters => longer
		 * hold => more waiters arrive during the hold. If that is
		 * right, miscmp should scale with the number of contenders and
		 * sleep_ms should account for nearly all of `sx`.
		 *
		 * Only fires when the unlock actually lost at least one race,
		 * so an uncontended unlock prints nothing.
		 */
		if (retry > 0 && resource->type == MXFS_LTYPE_INODE) {
			static int p381_n;

			if (p381_n++ < 20000)
				pr_warn("mxfs: P381-UNLK-CONTEND ino=%llu retries=%d miscmp=%u sleep_ms=%u wall_ms=%llu backoff=%d benign=%u contended=%u fast=%u fr=%d ident=%u multigen=%u selfbits=%u removed=%u noreg=%u holders=%u yieldto=%u control=%u\n",
					(unsigned long long)resource->ino,
					retry, p381_miss, p381_sleep_ms,
					(unsigned long long)(mxfs_pal_time_ms() -
							     p381_t0),
					mxfs_caw_unlock_backoff,
					p381_benign, p381_contended, p381_fast,
					mxfs_caw_unlock_fastretry,
					p381_why[CAW_UNLKD_IDENTITY],
					p381_why[CAW_UNLKD_MULTIGEN],
					p381_why[CAW_UNLKD_SELFBITS],
					p381_why[CAW_UNLKD_REMOVED],
					p381_why[CAW_UNLKD_NOREG],
					p381_why[CAW_UNLKD_HOLDERS],
					p381_why[CAW_UNLKD_YIELDTO],
					p381_why[CAW_UNLKD_CONTROL]);
		}
		untrack_held(ctx, slot_idx);
		/* sess112: the unlock CAS just committed and it cleared our bit
		 * in EVERY mode bitmap, so every local tenure on this resource
		 * is gone.  Retiring them here (and only here — on a CONFIRMED
		 * clear) re-arms the give-up reconcile for the next acquire. */
		clr_committed = true;
		lreq_release_all(ctx, resource, pub_seq0);
		/* ccloop 72513a13 sess3: our clear just committed and peers
		 * were waiting on this slot — nudge them awake instead of
		 * letting them ride out the poll interval.
		 *
		 * sess35 NUDGE v2: target the wake.  If the release armed a
		 * handoff ticket (single EX waiter or the PR class), only
		 * those nodes can act; everyone else would read-and-defer.
		 * No ticket (slot went free / batch arm) = wake the field. */
		/*
		 * sess380 P382-WAKE (D-32NODE-SHARED-DIR-CREATE-PACE).
		 *
		 * MEASURED on 256 creates into ONE directory from 32 nodes,
		 * counting every command this cluster issued to that
		 * directory's CAW slot: 6,808 READ(16)+FUA against 510 CAWs.
		 * READS OUTNUMBER WRITES 13 TO 1 and are 93% of all traffic on
		 * the sector -- 26.6 reads per create. The whole CAS-collision
		 * framing (mine and this defect's) was chasing 7% of the load.
		 *
		 * 6,808 reads / 249 landed writes = 27 reads per successful
		 * slot mutation, and there are 31 peers. That is the signature
		 * of the WAKE-THE-FIELD branch below: a release with no single
		 * chosen successor multicasts to every waiter, all 31 wake and
		 * each issues a synchronous FUA read of this one sector, and 30
		 * of them find the lock still ungrantable and sleep again. It
		 * is an O(N) read storm per handoff, i.e. O(N^2) per round of
		 * work, on the hottest LBA in the filesystem -- and those reads
		 * also serialise against every CAW at the target, because SBC
		 * requires COMPARE AND WRITE to be atomic.
		 *
		 * Record which branch each release takes and how many nodes it
		 * wakes, so the policy question ("always mint one successor
		 * instead of waking the field") is decided on counts rather
		 * than on this inference.
		 */
		if (resource->type == MXFS_LTYPE_INODE) {
			static int p382_n;
			uint64_t p382_field = cur_slot->waiters & ~ctx->node_bit;
			uint64_t p382_tgt = p6h_handoff_bit ? p6h_handoff_bit :
					    (new_slot->yield_to ?
					     new_slot->yield_to : p382_field);

			if (p382_field && p382_n++ < 20000)
				pr_warn("mxfs: P382-WAKE ino=%llu kind=%s woken=%u waiters=%u waiters_ex=%u gm=%u->%u\n",
					(unsigned long long)resource->ino,
					p6h_handoff_bit ? "mint" :
					  (new_slot->yield_to ? "ticket" : "field"),
					mxfs_pal_popcount64(p382_tgt),
					mxfs_pal_popcount64(p382_field),
					mxfs_pal_popcount64(cur_slot->waiters_ex &
							    cur_slot->waiters),
					cur_slot->granted_mode,
					new_slot->granted_mode);
		}
		if (p6h_handoff_bit)
			caw_send_grant_mcast(ctx, resource, p6h_handoff_bit);
		else if (cur_slot->waiters & ~ctx->node_bit)
			caw_send_grant_mcast(ctx, resource,
					     new_slot->yield_to ?
					     new_slot->yield_to :
					     (cur_slot->waiters &
					      ~ctx->node_bit));
		/* sess285 D-501 probe: CAS-committed release-side view.  A
		 * single-bit EX handoff (mint) or un-minted single-bit ticket
		 * (nom) names the releaser's chosen winner; both are logged
		 * with the pre-release EX-waiter field so the nomination
		 * distribution is measurable, not inferred. */
		if (p6h_handoff_bit && !(p6h_handoff_bit & (p6h_handoff_bit - 1)))
			caw_exwin_log(resource, "mint", MXFS_LOCK_EX,
				      __builtin_ctzll(p6h_handoff_bit), 0,
				      cur_slot->yield_to,
				      cur_slot->waiters & cur_slot->waiters_ex);
		else if (!p6h_handoff_bit && new_slot->yield_to &&
			 !(new_slot->yield_to & (new_slot->yield_to - 1)) &&
			 (new_slot->yield_to & cur_slot->waiters_ex))
			caw_exwin_log(resource, "nom", MXFS_LOCK_EX,
				      __builtin_ctzll(new_slot->yield_to), 0,
				      cur_slot->yield_to,
				      cur_slot->waiters & cur_slot->waiters_ex);
		/* D-488: the clearing CAS committed — proven clear. */
		ustate = MXFS_UNLOCK_RELEASED;
		rc = 0;
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: unlock exhausted %d retries (deadline_ms=%llu) for ino=%llu type=%u",
		     retry,
		     (unsigned long long)unlock_deadline,
		     (unsigned long long)resource->ino,
		     resource->type);
	/*
	 * D-488: retry exhaustion means every attempt MISCOMPARED — a
	 * miscompare is a read-back proving our CAS did NOT commit, so the
	 * bit is provably still ours.  STILL_HELD, not UNKNOWN.
	 */
	ustate = MXFS_UNLOCK_STILL_HELD;
	rc = -EIO;
	goto out;

regrant_abort:
	/* A local acquire re-granted this resource since the release began —
	 * the on-disk bit belongs to the NEW tenure.  Leave it. */
	{
		static int regrant_abort_logged;

		if (regrant_abort_logged < 50) {
			regrant_abort_logged++;
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P-UNLOCK-REGRANT-ABORT type=%u "
			    "ino=%llu ag=%u retry=%d",
			    resource->type,
			    (unsigned long long)resource->ino,
			    resource->ag_number, retry);
		}
	}
	/* gen-anchored callers get -ESTALE (stranded: the release did NOT
	 * happen; re-arm the BAST).  Legacy unconditional callers keep 0. */
	rc = expected_gen32 ? -ESTALE : 0;
	/* D-488: no CAS committed — the bit is the new tenure's, still ours. */
	ustate = MXFS_UNLOCK_STILL_HELD;

out:
	/* sess117: close the clear window BEFORE dropping the legacy mark, so
	 * the two exclusions never both read "open" for an instant. */
	lreq_clr_end(ctx, unlk_clr, clr_committed);
	caw_release_mark(ctx, resource, false);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	mxfs_pal_free(prev_slot);
	mxfs_pal_free(scratch_slot);
	if (state_out)
		*state_out = ustate;
	return rc;
}

/*
 * A release writes slots, so it must not run concurrently with the exclusive
 * release_all phase of teardown; a refusal here leaves the lock held, which is
 * the safe direction — teardown's own release_all is what clears it, and the
 * residue check is what proves it did.
 */
int mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t expected_gen32, bool is_free,
			    int open_op)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_unlock_gen_body(ctx, resource, expected_gen32, is_free,
				 open_op, NULL);
	caw_op_leave(ctx);
	return rc;
}

/*
 * D-488 (sess273 ruling): unlock with a tri-state outcome the caller can
 * act on.  Same gate and body as mxfs_dlm_caw_unlock_gen; the out-param
 * reports RELEASED / STILL_HELD / UNKNOWN as proven by the body's own
 * reads and CAS results.  On -ESHUTDOWN nothing was attempted (teardown's
 * release_all owns the clear), so the bit is still ours: STILL_HELD.
 */
int mxfs_dlm_caw_unlock_state(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      enum mxfs_unlock_state *state_out)
{
	int rc;

	if (state_out)
		*state_out = MXFS_UNLOCK_UNKNOWN;
	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx)) {
		if (state_out)
			*state_out = MXFS_UNLOCK_STILL_HELD;
		return -ESHUTDOWN;
	}
	rc = caw_unlock_gen_body(ctx, resource, 0, false, 0, state_out);
	caw_op_leave(ctx);
	return rc;
}

/* ─── mxfs_dlm_caw_held (sess39 read-only diagnostic) ─── */
/* Returns 1 if THIS node currently holds the resource on disk, 0 if not,
 * <0 on I/O error.  One slot read; no modification. */
int mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t our_mode;
	int rc;

	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 1;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return -ENOMEM;
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		/* sess135 P135: a held() miss on a low inode is the P108
		 * trigger — log whether the slot is GONE vs an I/O error. */
		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P135-HELD-MISS ino=%llu rc=%d "
			    "(no live slot found) self=%llx",
			    (unsigned long long)resource->ino, rc,
			    (unsigned long long)ctx->node_bit);
		mxfs_pal_free(slot);
		return (rc == -ENOENT) ? 0 : rc;
	}
	our_mode = node_held_mode(slot, ctx->node_bit);
	if (our_mode == MXFS_LOCK_NL &&
	    resource->type == MXFS_LTYPE_INODE &&
	    caw_instr_on())
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P135-HELD-MISS ino=%llu slot=%u gen=%u "
		    "hex=%llx hpr=%llx hpw=%llx w=%llx gm=%u yt=%llx "
		    "self=%llx (bit absent from live slot)",
		    (unsigned long long)resource->ino, slot_idx,
		    slot->generation,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->waiters,
		    slot->granted_mode,
		    (unsigned long long)slot->yield_to,
		    (unsigned long long)ctx->node_bit);
	mxfs_pal_free(slot);
	return (our_mode != MXFS_LOCK_NL) ? 1 : 0;
}

/*
 * ccloop cc87fed3 sess3 (RULE 4 PROVEN — fence_during_write@8/caw D-state
 * deadlock): mxfs_dlm_caw_held() above collapses the real per-node mode to a
 * boolean, which is unsafe for a caller (mxfs_v5_dlm_inode_granted_mode ->
 * mxfs_ilock_admit_ioend / P79-NESTADMIT) that upgrades ip->i_dlm_mode to
 * whatever it reads back — collapsing a real PR-only hold to "EX" would let
 * a local writer believe it has exclusive access when the cluster only
 * granted shared/read.  Returns the actual MXFS_LOCK_* mode this node holds
 * on `resource` (NL if not found / no slot / OOM), mirroring
 * mxfs_dlm_granted_mode()'s TCP-side contract exactly so
 * mxfs_v5_dlm_inode_granted_mode can treat both transports uniformly.
 */
uint8_t mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t our_mode;
	int rc;

	if (!ctx || !resource)
		return MXFS_LOCK_NL;
	if (ctx->single_node)
		return MXFS_LOCK_EX;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return MXFS_LOCK_NL;
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		mxfs_pal_free(slot);
		return MXFS_LOCK_NL;
	}
	our_mode = node_held_mode(slot, ctx->node_bit);
	mxfs_pal_free(slot);
	return our_mode;
}

/*
 * sess40 (D-CROSSNODE-OPEN-UNLINK): read the open-holder bitmap for an inode
 * resource.  VALIDITY CONTRACT: meaningful only while the caller holds a
 * grant on the resource (post-acquire) — an idle slot's bits ride the live
 * slot the caller's own claim just (re)established via the same-resource
 * inherit; without a grant a tombstoned slot is invisible to find_slot and
 * this returns 0.  The destructive-inactivation defer guard runs under the
 * inode EX it already takes, satisfying this by construction.
 * Returns 0 on no-slot/OOM (fails toward "no peers" for NON-guard callers —
 * do not use this without a grant for a free/no-free decision).
 */
int mxfs_dlm_caw_open_holders(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint64_t *oh_out)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	int rc;

	if (!oh_out)
		return -EINVAL;
	*oh_out = 0;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return -ENOMEM;	/* sess41 C5: OOM must DEFER, not read "empty" */
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		/* The B6 caller holds the inode EX, so a live slot MUST
		 * exist (its own acquire claimed one).  No-slot here means
		 * the probe failed or the table is unreadable — fail closed. */
		mxfs_pal_free(slot);
		return rc < 0 ? rc : -EIO;
	}
	*oh_out = slot->open_holders;
	mxfs_pal_free(slot);
	return 0;
}

/* sess41 C1: mxfs_dlm_caw_open_set removed — publication now rides the
 * release CAS (open_op in mxfs_dlm_caw_unlock_gen); a standalone pre-release
 * set had an unfixable silent-failure window.
 *
 * sess46: REINTRODUCED for ICLUSTER-routed inodes as mxfs_dlm_caw_open_set
 * below — with a DIFFERENT contract that closes the C1 window.  The C1
 * hazard was an UNGATED pair (set could exhaust retries while the release
 * still landed).  The iclus caller GATES the cluster-resource release on
 * this call's success (failure → grant retained, release retried), which is
 * the GPT C9 ordering contract: publication-before-release, ordering
 * replaces the CAS fold.  The per-inode path keeps the C1 fold unchanged. */

/*
 * sess46: durable standalone SET of THIS node's open-holder bit for a
 * resource that may have NO slot (ICLUSTER-routed files never per-inode
 * lock, so no claim ever created one).  Semantics:
 *   - live slot found        → CAS the bit in.
 *   - no record              → claim a LIVE BIT-ONLY slot (zero holder
 *                              bitmaps, granted NL, open bit set).  Claim
 *                              discipline mirrors the lock claim: fresh
 *                              compare read, live-magic → lost race →
 *                              re-probe, same-resource tombstone inherits
 *                              epoch lineage AND carried bits.
 *   - dup created by a concurrent fresh claim on another node (both saw
 *     -ENOENT, chain mutated between walks so their empty_idx differed)
 *     → resolved by caw_open_set_dedup: merge every bit into the CANONICAL
 *     record (first in probe order — deterministic and identical on every
 *     node) and tombstone the loser.  Duplicate live slots are harmless to
 *     locking while routing is on (routed files never per-inode lock) but
 *     would be the sess47 two-EX-holders corruption after a knob=0 reboot.
 * Returns 0 only when the bit is durably on disk; any failure must gate
 * the caller's cluster release (fail closed).
 */
static int caw_open_set_dedup(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint32_t mine_idx,
			      struct mxfs_caw_lock_slot *cur,
			      struct mxfs_caw_lock_slot *new_slot)
{
	uint32_t canon_idx = 0, empty_idx = UINT32_MAX;
	int tries, rc;

	for (tries = 0; tries < MXFS_CAW_MAX_RETRIES; tries++) {
		rc = find_slot(ctx, resource, &canon_idx, cur, &empty_idx);
		if (rc)
			return rc;
		if (canon_idx == mine_idx)
			return 0;	/* mine IS canonical; losers merge here */
		/* merge every bit my record carries into the canonical */
		rc = read_slot(ctx, mine_idx, new_slot);
		if (rc)
			return rc;
		if (new_slot->magic != MXFS_CAW_MAGIC ||
		    memcmp(&new_slot->resource, resource,
			   sizeof(*resource)) != 0)
			return 0;	/* mine already resolved elsewhere */
		if (slot_has_holders(new_slot)) {
			/* A holder bit on a routed file's per-inode slot
			 * should be impossible while routing is on — leave
			 * it standing (bits already merged below on a prior
			 * lap or visible to the dup-aware probe) and shout. */
			mxfs_pal_log(MXFS_LOG_ERR,
			    "mxfs: P-OPENSET-DUP-HOLDERS ino=%llu mine=%u canon=%u hex=%llx hpr=%llx — locked dup left standing",
			    (unsigned long long)resource->ino, mine_idx,
			    canon_idx,
			    (unsigned long long)new_slot->holders_ex,
			    (unsigned long long)new_slot->holders_pr);
			return 0;
		}
		if (new_slot->open_holders & ~cur->open_holders) {
			struct mxfs_caw_lock_slot merged = *cur;

			merged.open_holders |= new_slot->open_holders;
			merged.generation++;
			merged.last_modified_ms = mxfs_pal_time_ms();
			rc = caw_slot(ctx, canon_idx, cur, &merged);
			if (rc == -EAGAIN) {
				mxfs_pal_sleep_ms(1);
				continue;
			}
			if (rc)
				return rc;
		}
		/* bits are all in the canonical — tombstone my record with
		 * bits cleared (they live on the canonical now) */
		*cur = *new_slot;
		new_slot->open_holders = 0;
		new_slot->generation++;	/* every transition bumps (ABA) */
		caw_tombstone_slot(new_slot);
		rc = caw_slot(ctx, mine_idx, cur, new_slot);
		if (rc == -EAGAIN) {
			mxfs_pal_sleep_ms(1);
			continue;
		}
		if (rc == 0)
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P-OPENSET-DEDUP ino=%llu merged mine=%u into canon=%u",
			    (unsigned long long)resource->ino, mine_idx,
			    canon_idx);
		return rc;
	}
	return -ETIMEDOUT;
}

static int caw_open_set_body(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *cur, *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	int tries, rc = -EIO;

	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	cur = mxfs_pal_alloc(sizeof(*cur) * 2);
	if (!cur)
		return -ENOMEM;
	new_slot = cur + 1;
	for (tries = 0; tries < MXFS_CAW_MAX_RETRIES; tries++) {
		rc = find_slot(ctx, resource, &slot_idx, cur, &empty_idx);
		if (rc == 0) {
			if (cur->open_holders & ctx->node_bit)
				break;			/* already durable */
			*new_slot = *cur;
			new_slot->open_holders |= ctx->node_bit;
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			rc = caw_slot(ctx, slot_idx, cur, new_slot);
			if (rc == -EAGAIN) {
				mxfs_pal_sleep_ms(1);
				continue;
			}
			break;				/* 0 or hard error */
		}
		if (rc != -ENOENT)
			break;				/* probe I/O error */
		if (empty_idx == UINT32_MAX) {
			rc = -ENOSPC;			/* table full: fail closed */
			break;
		}
		/* Fresh compare read — Bug 93 + the sess40/daf50d34 TOCTOU
		 * discipline, verbatim from the lock claim path. */
		rc = read_slot(ctx, empty_idx, cur);
		if (rc)
			break;
		if (cur->magic == MXFS_CAW_MAGIC) {
			mxfs_pal_sleep_ms(1);		/* lost race — re-probe */
			continue;
		}
		if (cur->magic == MXFS_CAW_TOMBSTONE_MAGIC &&
		    cur->open_holders &&
		    cur->resource.volume == resource->volume &&
		    memcmp(&cur->resource, resource, sizeof(*resource)) != 0) {
			/* foreign bit-carrying tombstone (assertion state —
			 * see P-OPENBITS-TOMB-RESURRECT in the claim path):
			 * resurrect it live so the re-probe converges to a
			 * different insertion point instead of looping. */
			*new_slot = *cur;
			new_slot->magic = MXFS_CAW_MAGIC;
			new_slot->generation++;
			new_slot->granted_mode = MXFS_LOCK_NL;
			new_slot->waiter_mode = MXFS_LOCK_NL;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			(void)caw_slot(ctx, empty_idx, cur, new_slot);
			mxfs_pal_sleep_ms(1);
			continue;
		}
		memset(new_slot, 0, sizeof(*new_slot));
		new_slot->magic = MXFS_CAW_MAGIC;
		new_slot->generation = 1;
		new_slot->resource = *resource;
		new_slot->last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
		caw_claim_inherit_epoch(new_slot, cur, resource);
		/* sess176: same mint-or-fail discipline as the lock claim
		 * path — an open_set that binds the resource fresh is a
		 * binding creation and needs a lineage. */
		if (!new_slot->resource_lineage) {
			new_slot->resource_lineage = caw_mint_lineage();
			if (!new_slot->resource_lineage) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "dlm_caw: P275-LINEAGE-RNG-FAIL type=%u ino=%llu slot=%u (open_set) — RNG returned all-zero draws; failing claim closed",
				    resource->type,
				    (unsigned long long)resource->ino,
				    empty_idx);
				rc = -EIO;
				break;
			}
		}
		new_slot->open_holders |= ctx->node_bit;
		new_slot->granted_mode = MXFS_LOCK_NL;
		new_slot->waiter_mode = MXFS_LOCK_NL;
		new_slot->last_modified_ms = mxfs_pal_time_ms();
		rc = caw_slot(ctx, empty_idx, cur, new_slot);
		if (rc == -EAGAIN) {
			mxfs_pal_sleep_ms(1);
			continue;
		}
		if (rc)
			break;
		slot_hint_store(ctx, resource, empty_idx);
		/* Off-base fresh claim → dup window (sess47 family).  Resolve
		 * rather than merely detect: routed resources are re-claimed
		 * by open_set on OTHER nodes concurrently, and a standing dup
		 * becomes two-EX-holders corruption after a knob=0 reboot. */
		if (empty_idx != resource_hash_raw(resource) %
				 MXFS_CAW_MAX_SLOTS)
			rc = caw_open_set_dedup(ctx, resource, empty_idx,
						cur, new_slot);
		break;
	}
	if (tries >= MXFS_CAW_MAX_RETRIES && rc == -EAGAIN)
		rc = -ETIMEDOUT;
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_dlm_caw_open_set(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_open_set_body(ctx, resource);
	caw_op_leave(ctx);
	return rc;
}

/*
 * sess46: B6 open-bit read for a caller that holds NO per-inode claim (the
 * ICLUSTER-routed freer holds the CLUSTER EX instead; linearization comes
 * from publication-before-release on the publisher side).  The per-inode
 * mxfs_dlm_caw_open_holders contract ("no slot under held EX = probe failure
 * → fail closed") is wrong here: a routed file that was never opened has,
 * correctly, no record at all.  Result classes:
 *   0 + bits     → live record found (find_slot: hint fast path + span
 *                  walk, claim-identical probe rules).
 *   0 + *oh_out=0 + *authoritative → find_slot walked the chain to its
 *                  zero terminator without a match: authoritative absence.
 *   negative     → I/O error: absence NOT provable, caller defers.
 *
 * WHY find_slot AND NOT a bespoke per-slot walk: bits always live on the
 * CANONICAL LIVE record.  Every tombstone-creation site gates on
 * open_holders==0, the C1 release fold leaves a bit-carrying slot LIVE,
 * repair now preserves bits, claim-inherit restores the (unreachable)
 * carried case, and open_set's dedup merges dup bits INTO the canonical
 * BEFORE tombstoning the loser — all under publication-before-release, so
 * the freer's cluster EX linearizes after any in-flight publish.  The
 * first-cut per-slot fresh-read walk paid ~chain-length serial sector
 * reads per routed IFREE for that phantom and collapsed dir_reuse round
 * pace (103 iget-miss lookup failures = creators' destages starved behind
 * the rm-rf inactivation wave).  Residual accepted exposure: a PERSISTENT
 * garbage sector where a bit-carrying live slot stood is walked past as
 * recyclable (P93 logs it) — single-sector corruption class, same as the
 * per-inode path's practical behavior.
 */
int mxfs_dlm_caw_open_probe(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint64_t *oh_out, bool *authoritative)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	int rc;

	if (!oh_out || !authoritative)
		return -EINVAL;
	*oh_out = 0;
	*authoritative = false;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node) {
		*authoritative = true;
		return 0;
	}
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return -ENOMEM;
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc == 0) {
		*oh_out = slot->open_holders;
		*authoritative = true;
	} else if (rc == -ENOENT) {
		/* clean walk, no record: never published ⇒ no peer opens */
		*authoritative = true;
		rc = 0;
	}
	mxfs_pal_free(slot);
	return rc;
}


/*
 * sess40: clear THIS node's open-holder bit (lazy-clear consumer: evict of
 * an inode with no remaining local protected activity, or a reap-driven
 * revalidation).  Also clears on tombstoned slots (idle-gap carriers), and
 * tombstones a live slot the clear leaves fully empty.  Best-effort: bounded
 * CAS retries; a persistently-set bit only delays a peer's deferred reap.
 */
static void caw_open_clear_body(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *cur, *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	int tries;

	if (!ctx || !resource || ctx->single_node)
		return;
	cur = mxfs_pal_alloc(sizeof(*cur) * 2);
	if (!cur)
		return;
	new_slot = cur + 1;
	/* sess46 note: single-record clear via find_slot is CORRECT because
	 * bits always live on the canonical LIVE record (see the
	 * open_probe comment: tombstone sites gate on bits==0, dedup merges
	 * before tombstoning, claim-inherit restores the carried case).  A
	 * chain-walk variant was tried and reverted — it paid serial sector
	 * reads per clear for a phantom.  Residual: a crash mid-dedup can
	 * strand a loser record's bit until fencing (safe direction). */
	for (tries = 0; tries < 8; tries++) {
		int rc = find_slot(ctx, resource, &slot_idx, cur, &empty_idx);

		if (rc)
			break;	/* no live slot: nothing published (the old
				 * idle-gap-tombstone case is now handled by
				 * claim-inherit actually restoring bits). */
		if (!(cur->open_holders & ctx->node_bit))
			break;
		*new_slot = *cur;
		new_slot->open_holders &= ~ctx->node_bit;
		new_slot->generation++;
		new_slot->last_modified_ms = mxfs_pal_time_ms();
		if (!slot_has_holders(new_slot) && !new_slot->waiters &&
		    !new_slot->open_holders)
			caw_tombstone_slot(new_slot);
		rc = caw_slot(ctx, slot_idx, cur, new_slot);
		if (rc != -EAGAIN)
			break;
	}
	mxfs_pal_free(cur);
}

void mxfs_dlm_caw_open_clear(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource)
{
	if (!caw_op_enter(ctx))
		return;
	caw_open_clear_body(ctx, resource);
	caw_op_leave(ctx);
}

/* v0.6.4 P142: raw slot image dump for the P106-STALE-EX forensic — called
 * by the XFS dir fast-path ONLY at the phantom moment (cached EX, held==0),
 * so every line is signal.  Logs the exact image the verify path would read
 * (hint short-circuit included) plus the hint value. */
void mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint32_t hint = UINT32_MAX;
	int rc;

	if (!ctx || !resource || ctx->single_node)
		return;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return;
	slot_hint_get(ctx, resource, &hint);
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P142-STALE-IMG ino=%llu NO-SLOT rc=%d hint=%u empty=%u self=%llx",
		    (unsigned long long)resource->ino, rc, hint, empty_idx,
		    (unsigned long long)ctx->node_bit);
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P142-STALE-IMG ino=%llu slot=%u hint=%u gen=%u hex=%llx hpw=%llx hpr=%llx w=%llx yt=%llx gm=%u epoch=%u lastex=%u self=%llx",
		    (unsigned long long)resource->ino, slot_idx, hint,
		    slot->generation,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->waiters,
		    (unsigned long long)slot->yield_to,
		    slot->granted_mode, slot->dir_epoch, slot->last_ex_slot,
		    (unsigned long long)ctx->node_bit);
	}
	mxfs_pal_free(slot);
}

/* ─── mxfs_dlm_caw_ex_count (sess52 RULE-4 concurrent-EX detector) ─────────
 * The never-run measurement specified at xfs_alloc.c:2201 / state.md:
 * read the ENTIRE probe chain for `resource` RAW (via caw_count_resource_slots,
 * which does NOT trigger slot_appears_corrupt's popcount>1 auto-repair across
 * separate slots) and return popcount(OR of holders_ex across all live slots).
 * popcount>1 == two distinct nodes hold EX on the same AG simultaneously ==
 * the transient concurrent-EX that produces the gen-current-but-disk-stale
 * bnobt write (P88 disk_differs=1 ag_held=1 buf_gen==pag_gen).  *nslots_out
 * receives the live-slot count (>1 == sess47 claim-race: two slots same
 * resource).  Read-only; no slot modification.  Returns the EX popcount, or
 * <0 on error. */
int mxfs_dlm_caw_ex_count(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  int *nslots_out)
{
	uint32_t dup_slots[8];
	uint64_t holders_ex_or = 0;
	int n;

	if (nslots_out)
		*nslots_out = 0;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	n = caw_count_resource_slots(ctx, resource, dup_slots,
				     8, &holders_ex_or);
	if (n < 0)
		return n;
	if (nslots_out)
		*nslots_out = n;
	return (int)mxfs_pal_popcount64(holders_ex_or);
}

/* ─── mxfs_dlm_caw_self_held_scan (ccloop a864 sess3, RULE-4 orphan probe) ───
 * Duplicate-immune "does THIS node hold `resource` EX on disk" check.  Walks
 * the ENTIRE probe chain (via caw_count_resource_slots) instead of the hinted
 * find_slot, so it stays correct even when the resource lives in >1 live slot
 * (claim-race dup) — the exact blind spot that lets the hinted mxfs_dlm_caw_held
 * miss an orphaned EX bit a peer's scan still sees.  Returns 1 if our node_bit
 * is set in holders_ex OR'd across every live slot for the resource, 0 if not,
 * <0 on error.  *nslots_out = live-slot count (>1 => dup); *hex_or_out = OR of
 * holders_ex across them.  Read-only. */
int mxfs_dlm_caw_self_held_scan(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				int *nslots_out, uint64_t *hex_or_out)
{
	uint32_t dup_slots[8];
	uint64_t holders_ex_or = 0;
	int n;

	if (nslots_out)
		*nslots_out = 0;
	if (hex_or_out)
		*hex_or_out = 0;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 1;
	n = caw_count_resource_slots(ctx, resource, dup_slots, 8,
				     &holders_ex_or);
	if (n < 0)
		return n;
	if (nslots_out)
		*nslots_out = n;
	if (hex_or_out)
		*hex_or_out = holders_ex_or;
	return (holders_ex_or & ctx->node_bit) ? 1 : 0;
}

/* ─── mxfs_dlm_caw_force_release_self (ccloop a864 sess3 orphan reclaim) ───
 * UNCONDITIONAL scan-based self-release: walk the WHOLE probe chain and CAS-clear
 * our node_bit from EVERY live slot matching `resource`, in EVERY holder/waiter/
 * yield bitmap.  Unlike mxfs_dlm_caw_unlock_gen this does NOT consult the local
 * grant-meta seq gate and does NOT early-return on a hinted find_slot miss — it
 * is the recovery for an ORPHANED holder bit that the normal release left set
 * (bast_process's unlock ignored its return / aborted on a transient seq change,
 * leaving in-core mode=NL + state stuck DEMOTING while the on-disk bit persists,
 * so every peer BAST is swallowed and the cluster wedges — PROVEN dir_reuse@32:
 * held_raw=5 scan_mine=1 nslots=1, i.e. the bit is cleanly findable but never
 * cleared).  The CALLER MUST have serialized against a legitimate local re-grant
 * (in-core mode==NL with state==DEMOTING, which blocks the same-node acquire fast
 * path) so no fresh grant is clobbered; cross-node, only THIS node ever sets our
 * bit, so clearing it is safe.  Returns #slots cleared, or <0 on error. */

/*
 * sess121 (GPT sess118 ruling item 7).  The caller's attestation that dependent
 * activity on this resource has stopped — see struct mxfs_forcerel_attest in
 * dlm_caw.h for why this is a parameter and not a comment.
 *
 * This does not VERIFY the facts; nothing at this layer can.  It verifies that
 * the caller made a COMPLETE statement, so a future call site that has not
 * thought about quiescence fails loudly instead of stripping our bit out of
 * every slot on the probe chain while XFS is still issuing I/O against it.
 */
static int caw_forcerel_precondition(const struct mxfs_resource_id *resource,
				     const struct mxfs_forcerel_attest *att)
{
	const char *site = (att && att->site) ? att->site : "(unnamed)";

	if (!att || att->basis == MXFS_FORCEREL_BASIS_NONE) {
		pr_warn_ratelimited("mxfs: P252-FORCEREL-PRECOND site=%s type=%u ino=%llu — scan-based self-release REFUSED: no quiescence attestation (see struct mxfs_forcerel_attest)\n",
				    site, resource->type,
				    (unsigned long long)resource->ino);
		return -EINVAL;
	}
	/*
	 * The ruling's one exemption: a terminally fenced or shutting-down mount
	 * issues no further dependent I/O whatever is still admitted, so there
	 * is nothing left to be quiescent with respect to.
	 */
	if (att->basis == MXFS_FORCEREL_BASIS_TERMINAL)
		return 0;
	if (att->basis != MXFS_FORCEREL_BASIS_QUIESCED ||
	    !att->no_local_grant || !att->no_dependent_users ||
	    !att->new_users_blocked || !att->writeback_drained) {
		pr_warn_ratelimited("mxfs: P252-FORCEREL-PRECOND site=%s type=%u ino=%llu basis=%u grant=%d users=%d blocked=%d drained=%d — scan-based self-release REFUSED: incomplete quiescence attestation\n",
				    site, resource->type,
				    (unsigned long long)resource->ino,
				    att->basis, att->no_local_grant,
				    att->no_dependent_users,
				    att->new_users_blocked,
				    att->writeback_drained);
		return -EINVAL;
	}
	return 0;
}

static int caw_force_release_self_body(struct mxfs_dlm_caw_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    const struct mxfs_forcerel_attest *att)
{
	struct mxfs_caw_lock_slot *cur;
	struct mxfs_caw_lock_slot *new;
	struct mxfs_caw_lreq *clr = NULL;	/* sess117 clear window */
	uint64_t pub_seq0 = 0;
	uint32_t base;
	uint32_t i;
	int cleared = 0;
	bool may_have_cleared = false;		/* sess119 ruling items 3 + 8 */

	if (!ctx || !resource)
		return -EINVAL;
	/*
	 * sess121: the precondition is checked BEFORE the single_node early
	 * return, so an attestation-less caller is named even on a mount where
	 * this happens to be a no-op today.  The whole point is that the defect
	 * surfaces at the call site rather than on the one rig configuration
	 * that exercises it.
	 */
	if (caw_forcerel_precondition(resource, att) < 0)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	cur = mxfs_pal_alloc(sizeof(*cur));
	new = mxfs_pal_alloc(sizeof(*new));
	if (!cur || !new) {
		mxfs_pal_free(cur);
		mxfs_pal_free(new);
		return -ENOMEM;
	}
	/*
	 * sess117: this is the most destructive clear in the file — it strips
	 * our bit from EVERY bitmap in EVERY matching slot, waiters and yield
	 * included, with no per-attempt plan at all.  The caller's serialization
	 * is an XFS-layer one (in-core mode NL + state DEMOTING), which says
	 * nothing about OTHER local CAW attempts on the same resource, so it
	 * takes the same window every other destructive path takes.
	 */
	/*
	 * sess120 FAIL CLOSED (GPT sess118 ruling item 5).  This used to log and
	 * proceed "unlinearized", which is the worst place in the file to do it:
	 * this function strips our bit from EVERY bitmap in EVERY matching slot
	 * with no per-attempt plan, so an unlinearized run can cancel a local
	 * grant, a local waiter registration and a handoff ticket in one pass.
	 * Refusing costs the caller a retry of an orphan reclaim that is itself
	 * a recovery for a bit that has already been stuck for a while; -EAGAIN
	 * names it as retryable rather than fatal.
	 */
	/*
	 * sess124: no obligation published — this path has no single mode to
	 * owe (it strips every bitmap in every matching slot) and it is itself
	 * the reclaim of record, driven by a caller that retries.  Handing the
	 * owed worker an all-modes obligation on a resource this node believes
	 * it holds nothing on would put a blanket stripper behind a plan whose
	 * only guard is tenure[], which is exactly the shape the sess116
	 * `e == NULL` corruption had.
	 */
	if (ctx->lreq && ctx->lreq_lock) {
		if (lreq_clr_begin_wait(ctx, resource, NULL, &pub_seq0, NULL,
					&clr, 0) < 0) {
			ctx->lreq_nomem++;
			pr_warn_ratelimited("mxfs: P251-LREQ-DRY force-release-window type=%u ino=%llu dry=%llu — orphan reclaim REFUSED (retryable)\n",
					    resource->type,
					    (unsigned long long)resource->ino,
					    (unsigned long long)ctx->lreq_reserve_dry);
			mxfs_pal_free(cur);
			mxfs_pal_free(new);
			return -EAGAIN;
		}
	}
	base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	for (i = 0; i < MXFS_CAW_CLAIMRACE_SCAN_MAX; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;
		int attempt;

		if (read_slot(ctx, idx, cur) != 0)
			continue;
		if (cur->magic == 0)
			break;			/* end of probe chain */
		if (cur->magic != MXFS_CAW_MAGIC)
			continue;		/* tombstone — keep walking */
		if (memcmp(&cur->resource, resource, sizeof(*resource)) != 0)
			continue;		/* live slot, different resource */

		/* live slot for our resource — CAS-clear our bit if present */
		for (attempt = 0; attempt < MXFS_CAW_MAX_RETRIES; attempt++) {
			uint64_t mine = (cur->holders_ex | cur->holders_pw |
					 cur->holders_pr | cur->holders_cw |
					 cur->holders_cr | cur->waiters |
					 cur->yield_to) & ctx->node_bit;
			int rc;

			if (!mine) {
				untrack_held(ctx, idx);
				lreq_release_all(ctx, resource, pub_seq0);
				break;		/* our bit not in this slot */
			}
			*new = *cur;
			new->holders_ex &= ~ctx->node_bit;
			new->holders_pw &= ~ctx->node_bit;
			new->holders_pr &= ~ctx->node_bit;
			new->holders_cw &= ~ctx->node_bit;
			new->holders_cr &= ~ctx->node_bit;
			new->waiters    &= ~ctx->node_bit;
			new->waiters_ex &= ~ctx->node_bit;
			new->yield_to   &= ~ctx->node_bit;
			new->granted_mode = recompute_granted_mode(new);
			new->generation++;
			new->last_modified_ms = mxfs_pal_time_ms();
			rc = caw_slot(ctx, idx, cur, new);
			/*
			 * sess119 (ruling item 8, MULTI-STEP CLEARS): this walks
			 * up to CLAIMRACE_SCAN_MAX slots and issues an
			 * independent CAS in each, so "did this window strip a
			 * bit?" is the OR over every sub-operation, not the
			 * outcome of the last one.  `cleared` counts only the
			 * confirmed ones (it is the function's return value and
			 * callers log it), so the clear-sequence answer is
			 * tracked separately and includes the ambiguous results
			 * (ruling item 3).
			 */
			if (caw_may_have_written(rc))
				may_have_cleared = true;
			if (rc == 0) {
				untrack_held(ctx, idx);
				lreq_release_all(ctx, resource, pub_seq0);
				cleared++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: CAW-FORCE-REL type=%u ino=%llu slot=%u gen=%u->%u self=%llx (orphan holder bit cleared)",
				    resource->type,
				    (unsigned long long)resource->ino, idx,
				    cur->generation, new->generation,
				    (unsigned long long)ctx->node_bit);
				break;
			}
			if (rc == -EAGAIN) {
				/* CAS miscompare — re-read and retry this slot */
				if (read_slot(ctx, idx, cur) != 0)
					break;
				continue;
			}
			break;			/* I/O error — give up on this slot */
		}
	}
	lreq_clr_end(ctx, clr, may_have_cleared);
	mxfs_pal_free(cur);
	mxfs_pal_free(new);
	return cleared;
}

int mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    const struct mxfs_forcerel_attest *att)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_force_release_self_body(ctx, resource, att);
	caw_op_leave(ctx);
	return rc;
}

/* ─── mxfs_dlm_caw_convert ─── */

static int caw_convert_body(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t new_mode,
			    struct mxfs_grant_result *gres)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t old_mode;
	int retry;
	int rc;
	struct mxfs_caw_lreq *lreq = NULL;	/* sess112 local request registry */
	uint8_t conv_from = MXFS_LOCK_NL;	/* tenure this convert consumed */

	mxfs_grant_result_init(gres);	/* sess97: fail closed on every exit */

	if (!ctx || !resource)
		return -EINVAL;

	/*
	 * sess131: caw_unlock_gen_body, NOT the public mxfs_dlm_caw_unlock —
	 * this call is already inside the admission gate, and re-entering it
	 * would both double-count and let a gate that closed mid-convert refuse
	 * an operation that was already admitted.
	 */
	if (new_mode == MXFS_LOCK_NL)
		return caw_unlock_gen_body(ctx, resource, 0, false, 0, NULL);

	/* Single-node fast path: just update in-memory tracking */
	if (ctx->single_node) {
		mem_lock_track(ctx, resource, new_mode);
		return 0;
	}

	/* sess112: a convert registers an on-disk waiter for new_mode exactly
	 * like an acquire does, so it must be visible in the registry for the
	 * whole of that request — and refused outright if it cannot be. */
	lreq = lreq_join(ctx, resource, new_mode);
	if (!lreq) {
		ctx->lreq_nomem++;
		pr_warn_ratelimited("mxfs: P247-LREQ-NOMEM type=%c id=%llu mode=%u conv — conversion refused: local request registry could not record the attempt\n",
			resource->type == MXFS_LTYPE_INODE ? 'I' :
			resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
			(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
				resource->ino : (uint64_t)resource->ag_number),
			new_mode);
		return -ENOMEM;
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		lreq_finish(ctx, resource, lreq, new_mode, MXFS_LOCK_NL);
		return -ENOMEM;
	}

	for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
		caw_inode_backoff(ctx, resource, retry);	/* sess39 */
		rc = find_slot(ctx, resource, &slot_idx, cur_slot, &empty_idx);
		if (rc == -ENOENT) {
			rc = -ENOENT; /* Can't convert a lock we don't hold */
			goto out;
		}
		if (rc)
			goto out;

		/* Verify we actually hold the lock */
		old_mode = node_held_mode(cur_slot, ctx->node_bit);
		if (old_mode == MXFS_LOCK_NL) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: convert but node %u not holding "
				     "lock on ino=%llu type=%u",
				     ctx->local_node,
				     (unsigned long long)resource->ino,
				     resource->type);
			rc = -EINVAL;
			goto out;
		}
		/* sess112: remember what we are converting AWAY from — the
		 * success arm below clears this mode's holder bit, so its
		 * registry tenure has to be retired at `out`. */
		conv_from = old_mode;

		/* Same mode — no-op */
		if (old_mode == new_mode) {
			rc = 0;
			goto out;
		}

		/* Downgrade: always compatible with existing holders since
		 * we're reducing our lock strength */
		if (new_mode < old_mode) {
			*new_slot = *cur_slot;
			{
				uint64_t *old_hp = holders_for_mode(new_slot,
								    old_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
			}
			{
				uint64_t *new_hp = holders_for_mode(new_slot,
								    new_mode);
				if (new_hp)
					*new_hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			/*
			 * sess120 audit site 3 of 3 — see caw_slot_clearing.
			 * This one is the least obvious of the three and the
			 * most consequential: the CAS sets the new LOWER mode
			 * bit but strips the old HIGHER one, so a local thread
			 * still holding tenure[old_mode] silently loses its
			 * on-disk authority.  The subsumption argument that
			 * exempts the grant paths runs the other way here —
			 * node_held_mode returns the highest bit set, and the
			 * highest bit just went DOWN.
			 */
			rc = caw_slot_clearing(ctx, resource, slot_idx,
					       cur_slot, new_slot,
					       "convert-downgrade",
					       MXFS_LOCK_NL);
			if (rc == -EAGAIN)
				continue;
			if (rc == 0)
				caw_grant_meta_store(ctx, resource,
						     new_slot->dir_epoch,
						     false,
						     new_slot->dir_block0_fsb,
						     new_slot->dir_block0_gen);
			goto out;
		}

		/* Upgrade: check compatibility excluding ourselves */
		if (compatible_excluding_self(cur_slot, new_mode,
					       ctx->node_bit)) {
			bool cv_handoff;

			*new_slot = *cur_slot;
			{
				uint64_t *old_hp = holders_for_mode(new_slot,
								    old_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
			}
			{
				uint64_t *new_hp = holders_for_mode(new_slot,
								    new_mode);
				if (new_hp)
					*new_hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			cv_handoff = caw_grant_epoch_update(new_slot,
							    cur_slot,
							    ctx->node_slot,
							    new_mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (rc == -EAGAIN)
				continue;
			if (rc == 0) {
				/* sess97 step 5.3(b): provenance from the
				 * convert CAS (the PR->EX upgrade). */
				caw_grant_result_fill(gres, resource, new_slot,
						      new_mode, false);
				caw_grant_meta_store(ctx, resource,
						     new_slot->dir_epoch,
						     cv_handoff,
						     new_slot->dir_block0_fsb,
						     new_slot->dir_block0_gen);
				caw_exwin_log(resource, "convert", new_mode,
					      ctx->node_slot, 0,
					      cur_slot->yield_to,
					      cur_slot->waiters_ex);
			}
			goto out;
		}

		/* Upgrade not compatible — register as waiter for upgrade.
		 * sess114: same predicate and same derivation as the acquire
		 * registration above; see the comment there. */
		*new_slot = *cur_slot;
		new_slot->waiters |= ctx->node_bit;
		if (mxfs_mode_can_write(new_mode))
			new_slot->waiters_ex |= ctx->node_bit;   /* sess50: track exclusive waiter */
		new_slot->waiter_mode = recompute_waiter_mode(new_slot);
		new_slot->generation++;

		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		if (rc == -EAGAIN)
			continue;
		if (rc)
			goto out;

		/* Send BAST hint */
		caw_send_bast_mcast(ctx, resource, new_mode);

		/* Wait for grant. On success, the waiter-to-holder
		 * promotion in caw_wait_for_grant sets the new mode.
		 * We still need to clear the old mode on success. */
		rc = caw_wait_for_grant(ctx, slot_idx, resource, new_mode,
					new_slot->generation,
					new_slot->ex_grant_epoch, lreq, gres,
					0);
		if (rc == 0) {
			/* Clear old mode — we now hold new_mode */
			int clear_retry;
			for (clear_retry = 0; clear_retry < 20; clear_retry++) {
				int rc2 = read_slot(ctx, slot_idx, cur_slot);
				if (rc2)
					break;
				*new_slot = *cur_slot;
				{
					uint64_t *old_hp =
						holders_for_mode(new_slot,
								 old_mode);
					if (old_hp)
						*old_hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();

				rc2 = caw_slot(ctx, slot_idx, cur_slot,
					       new_slot);
				if (rc2 != -EAGAIN)
					break;
			}
		}
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: convert exhausted %d retries for ino=%llu type=%u",
		     MXFS_CAW_MAX_RETRIES,
		     (unsigned long long)resource->ino,
		     resource->type);
	/* sess48: drop any waiter bit registered for the upgrade before giving
	 * up, else it lingers as a phantom EX waiter starving peer readers. */
	caw_drop_own_waiter(ctx, slot_idx, resource, lreq, true,
			    new_mode, false, 0);
	rc = -ETIMEDOUT;

out:
	/* sess109 structural defense (ruling item B): a converted mode is a
	 * new tenure whenever it becomes write-capable, so success here must
	 * carry provenance exactly as an acquire does. */
	if (rc == 0 && gres && gres->status == MXFS_GAUTH_UNSET) {
		static int p_unset_n;

		if (p_unset_n++ < 200)
			pr_warn("mxfs: P242-GRANT-UNSET-CONV type=%c id=%llu slot=%u new_mode=%u — converted grant with no provenance\n",
				resource->type == MXFS_LTYPE_INODE ? 'I' :
				resource->type == MXFS_LTYPE_AG ? 'A' : 'O',
				(unsigned long long)(resource->type == MXFS_LTYPE_INODE ?
					resource->ino : (uint64_t)resource->ag_number),
				slot_idx, new_mode);
	}
	/*
	 * sess112: a successful convert MOVES the local tenure — the old
	 * mode's holder bit was cleared by the same operation, so its tenure
	 * must be retired here or a later give-up on that mode would be
	 * refused forever by a count that no longer describes anything.
	 * Retire first, publish second: the new tenure is published inside
	 * lreq_finish while this attempt is still joined.
	 */
	if (rc == 0 && conv_from != MXFS_LOCK_NL && ctx->lreq_lock && lreq) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		if (conv_from < MXFS_LOCK_MODE_COUNT && lreq->tenure[conv_from])
			lreq->tenure[conv_from]--;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	}
	lreq_finish(ctx, resource, lreq, new_mode,
		    rc == 0 ? new_mode : MXFS_LOCK_NL);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/*
 * The second obligation PUBLISHER (see mxfs_dlm_caw_lock).  gres is
 * initialised inside the body, so a gate refusal must fail it closed here
 * too — every caller reads gres unconditionally.
 */
int mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t new_mode,
			    struct mxfs_grant_result *gres)
{
	int rc;

	if (!ctx) {
		mxfs_grant_result_init(gres);
		return -EINVAL;
	}
	if (!caw_op_enter(ctx)) {
		mxfs_grant_result_init(gres);
		return -ESHUTDOWN;
	}
	rc = caw_convert_body(ctx, resource, new_mode, gres);
	caw_op_leave(ctx);
	return rc;
}

/* ─── mxfs_dlm_caw_release_all ─── */

/*
 * sess131 (GPT sess130 ruling, step 3): publish the residue of a release_all
 * slot that did NOT confirm clear.
 *
 * Before this, release_all's three failure exits — a read error, a bad magic,
 * and 20 exhausted CAS retries — each did `break; untrack_held()`, i.e. dropped
 * the slot from local tracking with this node's bits still on disk and NOTHING
 * anywhere that remembered them.  That is the same shape sess122 fixed in
 * caw_drop_own_waiter and it is worse here, because release_all is the LAST
 * sweep: after it there is no acquire path left to notice.
 *
 * The obligation published is MAXIMAL — every holder mode release_all clears
 * plus both waiter bitmaps — because the failed pass does not know which of
 * them it left behind.  The worker discharges the ones already clear for the
 * cost of one slot read; under-publishing loses a bit permanently.
 *
 * This is only reachable now that the exclusive release_all runs BEFORE the
 * teardown drain (the sess130 lifecycle order).  Under the old order the
 * publication would have landed after the worker had already joined and could
 * never have been collected.
 *
 * Returns false when the obligation could NOT be recorded — a dry reserve.
 * That is not a soft failure: nothing will retry the bits and nothing but the
 * caller's escalation will report them.
 */
static bool caw_owe_residue(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t slot_hint)
{
	struct mxfs_caw_owed_intent intent;
	struct mxfs_caw_lreq *e;
	uint8_t m;

	if (!ctx || !ctx->lreq || !ctx->lreq_lock || !resource)
		return false;

	intent.holder_mask = 0;
	for (m = MXFS_LOCK_NL + 1; m < MXFS_LOCK_MODE_COUNT; m++)
		intent.holder_mask |= 1u << m;
	intent.waiters = true;
	intent.waiters_ex = true;
	intent.slot_hint = slot_hint;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	e = lreq_find(ctx, resource);
	if (!e) {
		e = lreq_reserve_take(ctx);
		if (e) {
			uint32_t b = lreq_bucket(resource);

			e->resource = *resource;
			e->next = ctx->lreq[b];
			ctx->lreq[b] = e;
		}
	}
	if (e)
		lreq_owed_merge(ctx, e, &intent);
	else
		ctx->lreq_reserve_dry++;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);

	/* Outside the lock — the worker's park re-acquires it. */
	if (e && ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);

	return e != NULL;
}

/* ─── sess309 step-6 F1: WEDGED-release pins ─── */

int mxfs_dlm_caw_pin_resource(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *res)
{
	int i, rc = -ENOSPC;

	if (!ctx || !res)
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->held.lock);
	for (i = 0; i < ctx->pinned_n; i++) {
		if (memcmp(&ctx->pinned_res[i], res, sizeof(*res)) == 0) {
			rc = 0;
			goto out;
		}
	}
	if (ctx->pinned_n < MXFS_CAW_MAX_PINNED) {
		ctx->pinned_res[ctx->pinned_n++] = *res;
		rc = 0;
	}
out:
	mxfs_pal_mutex_unlock(ctx->held.lock);
	pr_err("mxfs: P-WEDGE-PIN node=%u type=%u id=%llu rc=%d — resource pinned against wholesale release; departure will not be clean until proven or fenced\n",
	       ctx->local_node, res->type,
	       (unsigned long long)(res->type == MXFS_LTYPE_AG ?
				    (uint64_t)res->ag_number : res->ino),
	       rc);
	return rc;
}

static bool caw_res_pinned(struct mxfs_dlm_caw_ctx *ctx,
			   const struct mxfs_resource_id *res)
{
	bool p = false;
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);
	for (i = 0; i < ctx->pinned_n; i++) {
		if (memcmp(&ctx->pinned_res[i], res, sizeof(*res)) == 0) {
			p = true;
			break;
		}
	}
	mxfs_pal_mutex_unlock(ctx->held.lock);
	return p;
}

/*
 * `owed` counts slots whose clear failed but whose residue was recorded, so the
 * teardown drain will retry them.  `lost` counts slots whose residue could NOT
 * be recorded at all — an unreadable slot (no resource to key an obligation on),
 * a corrupt one, or a dry reserve.  A nonzero `lost` means this node cannot
 * prove its bits are off the disk and must not claim a clean departure.
 * Either pointer may be NULL.
 */
static void caw_release_all_body(struct mxfs_dlm_caw_ctx *ctx,
				 uint32_t *owed, uint32_t *lost)
{
	uint32_t *local_slots;
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t n_owed = 0, n_lost = 0;
	int local_count;
	int i;

	if (owed)
		*owed = 0;
	if (lost)
		*lost = 0;

	if (!ctx)
		return;

	/* Clear in-memory lock tracking regardless of mode */
	if (ctx->mem_lock_mutex) {
		mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
		ctx->mem_lock_count = 0;
		mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: releasing all locks for node %u",
		     ctx->local_node);

	local_slots = mxfs_pal_alloc(256 * sizeof(uint32_t));
	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!local_slots || !cur_slot || !new_slot) {
		/*
		 * sess131 (GPT sess130 ruling, step 3): this releases NOTHING
		 * and, unlike a per-slot failure, cannot even name the slots it
		 * failed on.  Every tracked slot is residue.  GPT was explicit
		 * that an allocation failure preventing publication must
		 * ESCALATE rather than log and continue — the caller turns a
		 * nonzero `lost` into a refused clean departure.
		 */
		mxfs_pal_mutex_lock(ctx->held.lock);
		local_count = ctx->held.count;
		mxfs_pal_mutex_unlock(ctx->held.lock);
		n_lost = local_count > 0 ? (uint32_t)local_count : 1;
		pr_err("mxfs: P257-RELEASEALL-NOMEM node=%u held=%d — release_all could not allocate its working buffers; NO slot was cleared and no obligation could be recorded for any of them\n",
		       ctx->local_node, local_count);
		mxfs_pal_free(local_slots);
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		if (lost)
			*lost = n_lost;
		return;
	}

	/*
	 * Snapshot held list under lock, then release outside the lock.
	 * Process in batches of 256 to avoid massive stack allocation.
	 */
	for (;;) {
		mxfs_pal_mutex_lock(ctx->held.lock);
		local_count = ctx->held.count;
		if (local_count > 256)
			local_count = 256;
		if (local_count == 0) {
			mxfs_pal_mutex_unlock(ctx->held.lock);
			break;
		}
		memcpy(local_slots, ctx->held.slots,
		       local_count * sizeof(uint32_t));
		mxfs_pal_mutex_unlock(ctx->held.lock);

		for (i = 0; i < local_count; i++) {
			int retry;
			/*
			 * sess131: the clear is CONFIRMED only by a CAS that
			 * returned 0.  Every other way out of this loop leaves
			 * bits on disk, and `res_known` says whether the slot
			 * read far enough to name the resource an obligation
			 * would have to be keyed on.
			 */
			bool cleared = false;
			bool res_known = false;
			bool pinned = false;	/* sess309 wedged-release pin */
			int last_rc = 0;
			/*
			 * Captured from the LAST GOOD read, not read back off
			 * cur_slot at the end: a read_slot that fails on a
			 * later retry may have already scribbled the buffer,
			 * and an obligation keyed on a garbage resource is
			 * worse than none — it is a permanent registry entry
			 * naming a resource that does not exist.
			 */
			struct mxfs_resource_id res;
			/*
			 * sess151 (D-RELEASEALL-LREQ-RETIRE-MISSING): the
			 * registry anchor for the post-clear retire.  Sampled
			 * ONCE at the slot's first known resource identity,
			 * BEFORE the first CAS that could strip our bits —
			 * re-sampling on a later retry would move the release
			 * boundary forward and could eat a publication that
			 * landed between a failed CAS and the next read.
			 */
			uint64_t pub_seq0 = 0;
			bool seq_sampled = false;
			bool seq_churned = false;
			/*
			 * sess154 (P248 fix B): one in-line CAS re-issue per
			 * slot on -ESHUTDOWN.  The observed natural failure is
			 * a transport UNIT ATTENTION surfacing here as
			 * -ESHUTDOWN (caw_slot's !running check swallows the
			 * real errno during stop), and one extra iteration —
			 * whose read_slot absorbs the pending UA before a
			 * fresh CAS — clears it.  Bound 1: a genuinely dying
			 * queue must keep failing fast, and the owed path
			 * remains the correctness backstop.
			 */
			int io_retry = 0;
			struct mxfs_resource_id seq_res;

			memset(&res, 0, sizeof(res));
			memset(&seq_res, 0, sizeof(seq_res));

			for (retry = 0; retry < 20; retry++) {
				int rc = read_slot(ctx, local_slots[i],
						   cur_slot);
				if (rc) {
					last_rc = rc;
					break;
				}
				if (cur_slot->magic != MXFS_CAW_MAGIC) {
					last_rc = -EBADF;
					break;
				}
				res = cur_slot->resource;
				res_known = true;

				/* sess309: a WEDGED-release pin refuses the
				 * clear outright — no CAS, no obligation.
				 * The bits stay on the slot so peers fence
				 * this node and recover the resource with
				 * their death-detection machinery instead
				 * of trusting an unproven release. */
				if (caw_res_pinned(ctx, &res)) {
					pinned = true;
					break;
				}

				/*
				 * sess151: first identity → sample the anchor.
				 * Identity CHURN across retries (the slot was
				 * reused for a different resource mid-loop)
				 * means the anchor no longer names what a
				 * later CAS would clear — decline the blanket
				 * retire entirely, fail-closed: the entry
				 * survives to the P248 destroy report rather
				 * than risk retiring a tenure this release
				 * never covered.  lreq_find keys entries by
				 * memcmp over the whole resource_id, so the
				 * same compare decides churn.
				 */
				if (!seq_sampled) {
					seq_res = res;
					pub_seq0 = lreq_pub_seq_peek(ctx, &res);
					seq_sampled = true;
				} else if (memcmp(&seq_res, &res,
						  sizeof(res)) != 0) {
					seq_churned = true;
				}

				*new_slot = *cur_slot;
				new_slot->holders_ex &= ~ctx->node_bit;
				new_slot->holders_pw &= ~ctx->node_bit;
				new_slot->holders_pr &= ~ctx->node_bit;
				new_slot->holders_cw &= ~ctx->node_bit;
				new_slot->holders_cr &= ~ctx->node_bit;
				new_slot->waiters &= ~ctx->node_bit;
				new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50 */
				new_slot->yield_to &= ~ctx->node_bit;
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->waiter_mode =
					recompute_waiter_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();

				/* sess40: unmount ends this node's protected
				 * activity; peers' open bits keep the slot
				 * live. */
				new_slot->open_holders &= ~ctx->node_bit;
				if (!slot_has_holders(new_slot) &&
				    !new_slot->waiters &&
				    !new_slot->open_holders)
					caw_tombstone_slot(new_slot);

				if (caw_inject_take(&mxfs_caw_inject_ra_casfail))
					rc = -ESHUTDOWN;	/* sess154 K1 */
				else
					rc = caw_slot(ctx, local_slots[i],
						      cur_slot, new_slot);
				/* P109 Phase 1.1 (NEWARCH) — RELEASE-ALL clears
				 * our bit on every tracked slot at umount.  If
				 * this fires mid-run (not at umount) it's an
				 * unexpected bulk-release that would leak stale
				 * cached i_dlm_mode across many inodes at once.
				 * cur_slot still has the resource embedded. */
				{
				static int p141_ra_n;
				if ((caw_instr_on() || p141_ra_n++ < 200) &&
				    retry == 0)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-RELEASE-ALL type=%s "
					    "id=%llu cur_gm=%u slot=%u cas_rc=%d",
					    cur_slot->resource.type ==
					        MXFS_LTYPE_INODE ? "I" :
					    cur_slot->resource.type ==
					        MXFS_LTYPE_AG ? "A" : "O",
					    (unsigned long long)(
					      cur_slot->resource.type ==
					        MXFS_LTYPE_INODE ?
					        cur_slot->resource.ino :
					        (uint64_t)
					        cur_slot->resource.ag_number),
					    cur_slot->granted_mode,
					    local_slots[i], rc);
				}
				last_rc = rc;
				if (rc == 0)
					cleared = true;
				/* sess154 (P248 fix B): see io_retry above. */
				if (rc == -ESHUTDOWN && io_retry < 1) {
					io_retry++;
					ctx->lreq_rel_ioretry++;
					continue;
				}
				if (rc != -EAGAIN)
					break;
			}

			/*
			 * sess380 (D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379):
			 * this loop is the suspected O(N^2) amplifier of the
			 * mass-unmount hot-LBA storm — N departing nodes each
			 * re-read and re-CAS the SAME shared slot with no
			 * backoff and no jitter, so every winner turns the
			 * other N-1 into MISCOMPAREs that immediately try
			 * again.  Log the per-slot attempt count so the storm's
			 * real command multiplier is on the record, per node
			 * and per slot.  Fires only when a retry actually
			 * happened, so an uncontended departure prints nothing.
			 */
			if (retry > 0)
				pr_warn("mxfs: P380-RA-CASRETRY node=%u slot=%u attempts=%d cleared=%d last_rc=%d\n",
					ctx->local_node, local_slots[i],
					retry + 1, cleared ? 1 : 0, last_rc);

			/*
			 * sess131 (GPT sess130 ruling, step 3): a failed clear
			 * becomes an OBLIGATION, not a dropped slot.  The
			 * untrack below is unconditional and always was — the
			 * held list is torn down here regardless — so without
			 * this the residue had no remaining record anywhere.
			 */
			if (pinned) {
				n_lost++;
				pr_err("mxfs: P-WEDGE-PIN-RELEASEALL node=%u slot=%u — pinned wedged-release resource left on disk; clean departure refused, peers must fence and recover\n",
				       ctx->local_node, local_slots[i]);
			} else if (!cleared) {
				bool pubd = res_known &&
					caw_owe_residue(ctx, &res,
							local_slots[i]);

				if (pubd) {
					n_owed++;
				} else {
					n_lost++;
					pr_err_ratelimited("mxfs: P257-RELEASEALL-LOST node=%u slot=%u rc=%d res_known=%d — release_all left this node's bits on the slot and could not record an obligation for them; clean departure refused\n",
							   ctx->local_node,
							   local_slots[i],
							   last_rc, res_known);
				}
			}

			untrack_held(ctx, local_slots[i]);
			/*
			 * sess151 (D-RELEASEALL-LREQ-RETIRE-MISSING): mirror
			 * the single-resource unlock path — on a CONFIRMED
			 * clear every local tenure on this resource is gone,
			 * so retire the registry entry, guarded by the anchor
			 * sampled before the first CAS (lreq_release_all
			 * keeps the entry if a publication landed inside the
			 * window).  untrack_held-then-retire order is
			 * deliberate: tenure keeps the entry non-GC-eligible
			 * in the interval.  The not-cleared-but-owed case
			 * must NOT retire — the obligation needs the entry
			 * for the collector and the departure verdict.
			 */
			if (cleared && res_known && !seq_churned)
				lreq_release_all(ctx, &res, pub_seq0);
			mxfs_pal_cond_resched();
		}
	}

	mxfs_pal_free(local_slots);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);

	/*
	 * sess134 (GPT sess133 ruling A3): the traversal FINISHED.  Set only
	 * here, at the single exit that has actually walked the whole held list
	 * — the NULL-ctx and allocation-failure exits above return without it,
	 * and stop()'s verdict treats a false as fatal to the clean-departure
	 * claim.  "release_all was entered" is not the fact the claim needs.
	 */
	if (ctx->lreq_lock) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		ctx->release_all_done = true;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	} else {
		ctx->release_all_done = true;
	}

	if (n_owed || n_lost)
		pr_warn("mxfs: P257-RELEASEALL-RESIDUE node=%u owed=%u lost=%u — slots release_all could not confirm clear; `owed` go to the teardown drain, `lost` have no record at all\n",
			ctx->local_node, n_owed, n_lost);
	else
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "dlm_caw: all locks released for node %u",
			     ctx->local_node);

	/* sess154 (P248 fix B): positive observation that the in-line retry
	 * ran.  Context-cumulative, so a second release_all pass reprints the
	 * running total rather than losing the first pass's count. */
	if (ctx->lreq_rel_ioretry)
		pr_warn("mxfs: P268-RELEASEALL-IORETRY node=%u n=%llu — release_all re-issued a slot CAS once after -ESHUTDOWN (transport UA absorbed in-line)\n",
			ctx->local_node,
			(unsigned long long)ctx->lreq_rel_ioretry);

	if (owed)
		*owed = n_owed;
	if (lost)
		*lost = n_lost;
}

void mxfs_dlm_caw_release_all(struct mxfs_dlm_caw_ctx *ctx)
{
	caw_release_all_body(ctx, NULL, NULL);
}

/* ─── mxfs_dlm_caw_purge_node ─── */

int mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx,
			       uint8_t dead_slot)
{
	uint64_t dead_mask;

	if (!ctx)
		return -EINVAL;

	if (dead_slot >= 64) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: purge_node: invalid dead_slot %u",
			     dead_slot);
		return -EINVAL;
	}

	/*
	 * sess70 (ccloop 14d31183) zero_silent_loss FIX — eviction-cascade
	 * amplifier (RULE 4 step 2b, PROVEN by the test1 stack:
	 * disklock_hb_fn -> v5_lease_expire_cb -> mxfs_dlm_caw_purge_node ->
	 * read_slot -> blk_execute_rq, D-state for tens of seconds while peers
	 * fenced live nodes and the verify find starved on the dir ilock).
	 * purge_node runs ON the disklock heartbeat thread.  The old body
	 * scanned ALL 65536 CAW slots with ONE FUA read_slot each (~5-60s on
	 * the contended single shared LUN), and while it scanned THIS node
	 * could not write its own heartbeat -> peers evicted IT in turn ->
	 * fence (SCSI PR preempt) -> reservation-conflict log I/O error -> FS
	 * shutdown (test2 t=440: "DLM shutting down" then "reservation
	 * conflict ... op WRITE" then "log error 0x2") -> the whole-cluster
	 * eviction-cascade collapse.  The batched mxfs_dlm_caw_purge_dead_nodes
	 * already scans the table in 32-slot (16 KiB) chunks (<1s) with
	 * IDENTICAL per-slot clear+CAS semantics; a single dead slot is just
	 * the mask (1 << dead_slot).  Delegate so the heartbeat thread is freed
	 * in well under one beat interval and the cascade cannot start.
	 */
	dead_mask = 1ULL << dead_slot;

	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-H22-PURGE-NODE ENTRY dead_slot=%u (batched)",
		     dead_slot);

	return mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask);
}

/* ─── mxfs_dlm_caw_purge_dead_nodes ─── */

/*
 * sess374 (sess363 RULE-5 ruling item A: "REUSE the full-purge mutation
 * discipline — do not fork the strip logic").  The exact field list, mode
 * recomputation, generation bump and stamp caw_purge_dead_nodes_body has
 * always applied, lifted verbatim so the selective closure purge and the
 * survivor-side scrub mutate a slot the SAME way a full purge does.  A
 * forked strip is how a later field addition reaches one path and not the
 * other, and the two paths that would diverge are both authority-bearing.
 *
 * Tombstoning stays with the callers: only they know whether their mode
 * (KEEP_EX) forbids it.
 *
 * Returns true iff EX/PW bits of `mask` were RETAINED (KEEP_EX accounting).
 */
static bool caw_strip_node_state(struct mxfs_caw_lock_slot *ns, uint64_t mask,
				 bool keep_ex)
{
	bool retained = false;

	/* sess52 (step 4a): under KEEP_EX the EX/PW bits ARE the authority
	 * manifest — leave them (and ex_grant_epoch) untouched. */
	if (!keep_ex) {
		ns->holders_ex &= ~mask;
		ns->holders_pw &= ~mask;
	} else if ((ns->holders_ex & mask) || (ns->holders_pw & mask)) {
		retained = true;
	}
	ns->holders_pr &= ~mask;
	ns->holders_cw &= ~mask;
	ns->holders_cr &= ~mask;
	ns->waiters &= ~mask;
	ns->waiters_ex &= ~mask;	/* sess50 */
	ns->yield_to &= ~mask;
	/* sess40: a fenced node can have no protected activity — strip its
	 * open-holder bits so deferred reaps of its opens converge. */
	ns->open_holders &= ~mask;
	ns->granted_mode = recompute_granted_mode(ns);
	ns->waiter_mode = recompute_waiter_mode(ns);
	ns->generation++;
	ns->last_modified_ms = mxfs_pal_time_ms();
	return retained;
}

/*
 * sess374: the FULL footprint of one node on a slot — every field
 * caw_strip_node_state clears.  caw_purge_candidate below is deliberately
 * narrower (it is a full-purge cost optimization and predates waiters_ex /
 * yield_to), so the selective paths must NOT reuse it: a slot whose only
 * victim state is a waiters_ex or yield_to bit is exactly the frozen-grant
 * shape D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 strands survivors on.
 */
static uint64_t caw_victim_state_mask(const struct mxfs_caw_lock_slot *s,
				      uint64_t mask)
{
	return (s->holders_ex | s->holders_pw | s->holders_pr |
		s->holders_cw | s->holders_cr | s->waiters |
		s->waiters_ex | s->yield_to | s->open_holders) & mask;
}

/*
 * sess375: WHICH of the nine fields carried the victim on this image.  The
 * strip logs it so a test can assert the SHAPE that was cleared, not merely
 * that something was: the ruling's waiter-only and open-holder-only hazards
 * are indistinguishable from an EX strip in the old log line.  Derived from
 * the exact image a CAS is about to consume, never from the batch hint.
 */
#define MXFS_CAW_VFOOT_EX	0x001u
#define MXFS_CAW_VFOOT_PW	0x002u
#define MXFS_CAW_VFOOT_PR	0x004u
#define MXFS_CAW_VFOOT_CW	0x008u
#define MXFS_CAW_VFOOT_CR	0x010u
#define MXFS_CAW_VFOOT_WAIT	0x020u
#define MXFS_CAW_VFOOT_WAITEX	0x040u
#define MXFS_CAW_VFOOT_YIELD	0x080u
#define MXFS_CAW_VFOOT_OPEN	0x100u
#define MXFS_CAW_VFOOT_HOLDER	(MXFS_CAW_VFOOT_EX | MXFS_CAW_VFOOT_PW | \
				 MXFS_CAW_VFOOT_PR | MXFS_CAW_VFOOT_CW | \
				 MXFS_CAW_VFOOT_CR)

static uint32_t caw_victim_footprint(const struct mxfs_caw_lock_slot *s,
				     uint64_t mask)
{
	uint32_t f = 0;

	if (s->holders_ex & mask)	f |= MXFS_CAW_VFOOT_EX;
	if (s->holders_pw & mask)	f |= MXFS_CAW_VFOOT_PW;
	if (s->holders_pr & mask)	f |= MXFS_CAW_VFOOT_PR;
	if (s->holders_cw & mask)	f |= MXFS_CAW_VFOOT_CW;
	if (s->holders_cr & mask)	f |= MXFS_CAW_VFOOT_CR;
	if (s->waiters & mask)		f |= MXFS_CAW_VFOOT_WAIT;
	if (s->waiters_ex & mask)	f |= MXFS_CAW_VFOOT_WAITEX;
	if (s->yield_to & mask)		f |= MXFS_CAW_VFOOT_YIELD;
	if (s->open_holders & mask)	f |= MXFS_CAW_VFOOT_OPEN;
	return f;
}

/*
 * sess375: per-attempt observation record for one closure strip.  It exists so
 * a reuse-race run can be reported as "the hazard was exercised" or "the
 * hazard never fired" rather than as an undifferentiated pass — a run that
 * survives a race it never actually hit proves nothing.
 *
 * `vfoot` is the footprint of the image the successful CAS consumed.  The
 * counters distinguish the three distinct ways the batched candidacy hint can
 * go stale from ordinary CAS contention, which on its own says nothing about
 * reuse.
 */
struct caw_closure_obs {
	uint32_t	vfoot;		/* footprint the winning CAS cleared */
	uint32_t	hint_vanished;	/* authoritative read: tombstoned/empty */
	uint32_t	hint_bit_gone;	/* authoritative read: victim already stripped */
	uint32_t	hint_res_moved;	/* authoritative read: DIFFERENT resource */
	uint32_t	class_flipped;	/* hint said out-of-closure, image says in */
	uint32_t	cas_miscompare;	/* image moved under the CAS */
};

/* Same resource, ignoring the fields that are not part of its identity. */
static bool caw_resource_same(const struct mxfs_resource_id *a,
			      const struct mxfs_resource_id *b)
{
	return a->type == b->type && a->volume == b->volume &&
	       a->ino == b->ino && a->offset == b->offset &&
	       a->ag_number == b->ag_number;
}

/*
 * sess52: does this slot carry anything the purge would strip?
 *
 * Under keep_ex the EX/PW holder bits are being RETAINED, so on their
 * own they are not a reason to touch the slot — only the modes and
 * ancillary bits we do strip make it a candidate.  Getting this wrong
 * costs a pointless CAS per retained slot, not correctness, but the
 * mount own-slot scan covers all 65536 slots so the distinction is
 * worth having.
 */
static bool caw_purge_candidate(const struct mxfs_caw_lock_slot *s,
				uint64_t dead_mask, bool keep_ex)
{
	if (!keep_ex && ((s->holders_ex & dead_mask) ||
			 (s->holders_pw & dead_mask)))
		return true;
	return (s->holders_pr & dead_mask) ||
	       (s->holders_cw & dead_mask) ||
	       (s->holders_cr & dead_mask) ||
	       (s->waiters & dead_mask) ||
	       (s->open_holders & dead_mask);
}

int mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx,
				     uint64_t dead_mask)
{
	return mxfs_dlm_caw_purge_dead_nodes_ex(ctx, dead_mask, 0);
}

void mxfs_dlm_caw_set_adopt_window(struct mxfs_dlm_caw_ctx *ctx, bool on)
{
	if (!ctx)
		return;
	ctx->mount_adopt_window = on;
	if (!on)
		ctx->mount_retained = 0;
}

int mxfs_dlm_caw_retained_count(struct mxfs_dlm_caw_ctx *ctx)
{
	return ctx ? ctx->mount_retained : 0;
}

static int caw_purge_dead_nodes_body(struct mxfs_dlm_caw_ctx *ctx,
				     uint64_t dead_mask, uint32_t flags)
{
	const bool keep_ex = !!(flags & MXFS_CAW_PURGE_KEEP_EX);
	const bool skip_tracked = !!(flags & MXFS_CAW_PURGE_SKIP_TRACKED);
	int retained = 0;
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	struct mxfs_caw_lock_slot *batch;
	const uint32_t BATCH_SLOTS = 32;   /* 32 * 512 = 16 KiB, kzalloc/contiguous */
	uint32_t slot;
	int purged = 0;
	/*
	 * sess59 (GPT sess57 review item 6D): completeness accounting.
	 *
	 * Every per-slot failure below used to be a silent `continue` or
	 * `break`, and the function still returned a success-shaped count.
	 * A caller that publishes "this node's recovery is done" on the
	 * strength of that return then strips the pending marker and zeroes
	 * the dead heartbeat while the dead node's authority bits are STILL
	 * on disk — orphan grants that block every future acquire with no
	 * owner left to release them and no evidence that a purge is owed.
	 *
	 * `unread` counts slots whose authoritative content we never
	 * obtained (so they may be dead-owned grants); `wfail` counts
	 * confirmed candidates we failed to rewrite.  Either makes the
	 * purge unprovable, and the function reports -EIO.
	 */
	int unread = 0;
	int wfail = 0;

	if (!ctx || !dead_mask)
		return 0;

	/*
	 * sess53: SKIP_TRACKED's whole safety argument is that ctx->held is a
	 * COMPLETE record of what this mount holds.  If any grant ever failed
	 * to record itself, it is not, and an untracked bit may be a live
	 * hold — purging it would strip authority from under a holder.
	 * Refuse rather than guess: leave the manifest intact and report.
	 */
	if (skip_tracked && ctx->held_overflow) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P226-PURGE-REFUSED held-table overflowed "
			     "on this mount — tracked set is incomplete, so "
			     "SKIP_TRACKED cannot distinguish a live hold from "
			     "a dead one.  Manifest left intact.");
		return -EOVERFLOW;
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}
	/* Optional batch buffer to scan the 65536-slot table in 32 KiB
	 * chunks instead of one 512 B read per slot.  The full scan is on
	 * the mount critical path (own-slot purge), so 65536 single-slot
	 * reads cost ~5 s; chunked reads cut that to well under 1 s.  If the
	 * allocation fails we fall back to per-slot reads — correctness is
	 * unchanged either way, only the find phase is batched. */
	batch = mxfs_pal_alloc((size_t)BATCH_SLOTS * MXFS_CAW_SLOT_SIZE);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: mount-time purge for dead_mask 0x%llx",
		     (unsigned long long)dead_mask);
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-H22-PURGE-MASK ENTRY dead_mask=0x%llx",
		     (unsigned long long)dead_mask);

	for (slot = 0; slot < MXFS_CAW_MAX_SLOTS; ) {
		uint32_t chunk = BATCH_SLOTS;
		uint32_t i;
		int batch_rc;

		if (slot + chunk > MXFS_CAW_MAX_SLOTS)
			chunk = MXFS_CAW_MAX_SLOTS - slot;

		/* Find phase: pull the chunk in one I/O when possible. */
		batch_rc = batch ? mxfs_pal_bdev_read_prio(ctx->dev,
					slot_offset(ctx, slot), batch,
					chunk * MXFS_CAW_SLOT_SIZE)
				 : -ENOMEM;

		for (i = 0; i < chunk; i++) {
			uint32_t sidx = slot + i;
			int retry;
			int rc;

			if (batch_rc == 0) {
				/* Cheap in-memory candidacy test against the
				 * batch copy: skip the empty / tombstone /
				 * unrelated majority without a per-slot read. */
				struct mxfs_caw_lock_slot *cand = &batch[i];

				if (cand->magic != MXFS_CAW_MAGIC)
					continue;
				/* sess52: never strip a slot this mount is
				 * actively holding (settle sweep). */
				if (skip_tracked && is_tracked_held(ctx, sidx))
					continue;
				/* sess41 (PROVEN opener_death): a dead node
				 * whose only footprint is an OPEN-HOLDER bit
				 * (publish-then-release is the NORMAL open-
				 * unlink shape) was skipped here, so the
				 * strip below never ran and every peer's B6
				 * deferred forever against a dead opener. */
				if (!caw_purge_candidate(cand, dead_mask,
							 keep_ex)) {
					if (keep_ex &&
					    ((cand->holders_ex & dead_mask) ||
					     (cand->holders_pw & dead_mask)))
						retained++;
					continue;
				}
			} else {
				/* Fallback (no batch buffer or read error):
				 * authoritative per-slot read decides. */
				if (skip_tracked && is_tracked_held(ctx, sidx))
					continue;
				if (read_slot(ctx, sidx, cur_slot)) {
					/* Unreadable — it may be a
					 * dead-owned grant.  Keep going
					 * (one bad sector must not abandon
					 * the table) but the pass is no
					 * longer a proof. */
					unread++;
					continue;
				}
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					continue;
				if (!caw_purge_candidate(cur_slot, dead_mask,
							 keep_ex)) {
					if (keep_ex &&
					    ((cur_slot->holders_ex & dead_mask) ||
					     (cur_slot->holders_pw & dead_mask)))
						retained++;
					continue;
				}
			}

			/* Candidate — purge with an authoritative re-read +
			 * CAS retry (identical to the original per-slot path;
			 * the batch copy is only a candidacy hint). */
			for (retry = 0; retry < 20; retry++) {
				rc = read_slot(ctx, sidx, cur_slot);
				if (rc) {
					/* Confirmed candidate we can no
					 * longer read — its dead-owner bits
					 * are presumed still set. */
					unread++;
					break;
				}
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					break;
				/* Re-confirm on the authoritative copy — a
				 * concurrent purge may have cleared the bits.
				 *
				 * sess52: also re-test tracking here.  The
				 * settle sweep races an in-flight adopt, which
				 * CASes the slot and calls track_held; if it
				 * won that race between our candidacy test and
				 * this read, the slot is now a LIVE hold and
				 * must not be stripped. */
				if (skip_tracked && is_tracked_held(ctx, sidx))
					break;
				if (!caw_purge_candidate(cur_slot, dead_mask,
							 keep_ex))
					break;

				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P-H22-PURGE-MASK SLOT slot=%u "
					"res_type=%u res_ino=%llu res_ag=%u"
					"dead_mask=0x%llx cur_hex=%llx",
					sidx, cur_slot->resource.type,
					(unsigned long long)cur_slot->resource.ino,
					cur_slot->resource.ag_number,
					(unsigned long long)dead_mask,
					(unsigned long long)cur_slot->holders_ex);

				*new_slot = *cur_slot;
				if (caw_strip_node_state(new_slot, dead_mask,
							 keep_ex))
					retained++;

				/* Tombstone the slot if completely empty
				 * (sess40: live peers' open bits keep it).
				 *
				 * sess52: NEVER under KEEP_EX.  A retained
				 * EX/PW bit keeps slot_has_holders() true so
				 * this cannot fire for the slots we care
				 * about, but the guard is explicit because
				 * caw_tombstone_slot resets the slot to a
				 * no-holder image, and the retained EX/PW bit
				 * IS the foreign-replay authority manifest
				 * this whole mode exists to preserve.
				 * (sess108: the tombstone now CARRIES
				 * ex_grant_epoch, so the token itself survives,
				 * but the holder bits do not — the guard stands
				 * unchanged.) */
				if (!keep_ex &&
				    !slot_has_holders(new_slot) &&
				    !new_slot->waiters &&
				    !new_slot->open_holders)
					caw_tombstone_slot(new_slot);

				rc = caw_slot(ctx, sidx, cur_slot, new_slot);
				if (rc == -EAGAIN) {
					/* Contended: re-read and retry.  The
					 * last iteration falling out of the
					 * loop still owes a purge — accounted
					 * after the loop. */
					if (retry == 19)
						wfail++;
					continue;
				}
				if (rc) {
					/* The dead owner's bits are still on
					 * disk and we could not clear them. */
					wfail++;
					break;
				}
				{
					/* v0.6.4 P141: a dead-node purge is
					 * the only bit-clear a victim's local
					 * seq machinery can NEVER see.  A
					 * FALSE eviction here (lease glitch
					 * under storm) mints a phantom
					 * cached-EX on a live peer — name
					 * every purge + the stripped bits. */
					static int p141_dead_n;

					if (p141_dead_n++ < 200)
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P141-DEAD-EXCLR type=%u ino=%llu ag=%u slot=%u dead_mask=%llx cleared_ex=%llx cleared_pr=%llx self=%llx",
						    cur_slot->resource.type,
						    (unsigned long long)cur_slot->resource.ino,
						    cur_slot->resource.ag_number,
						    sidx,
						    (unsigned long long)dead_mask,
						    (unsigned long long)(cur_slot->holders_ex & dead_mask),
						    (unsigned long long)(cur_slot->holders_pr & dead_mask),
						    (unsigned long long)ctx->node_bit);
					purged++;
				}
				break;
			}
		}

		slot += chunk;
		/* Yield periodically during full scan */
		mxfs_pal_cond_resched();
	}

	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	mxfs_pal_free(batch);

	if (keep_ex)
		ctx->mount_retained = retained;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: mount-time purge complete: %d stale lock slots cleared",
		     purged);
	if (flags)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-H22-PURGE-MASK DONE mask=0x%llx flags=0x%x "
			     "purged=%d retained_ex=%d",
			     (unsigned long long)dead_mask, flags,
			     purged, retained);

	/* sess59 item 6D: an incomplete purge is not a purge.  Report it so
	 * no caller publishes recovery on the strength of leftover bits. */
	if (unread || wfail) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P231-PURGE-INCOMPLETE mask=0x%llx flags=0x%x "
			     "purged=%d unread=%d wfail=%d — the dead node's "
			     "authority bits may still be on disk; recovery "
			     "MUST NOT be published as complete",
			     (unsigned long long)dead_mask, flags,
			     purged, unread, wfail);
		return -EIO;
	}
	return purged;
}

/*
 * A purge rewrites other nodes' bits across the whole slot table, so it is the
 * single widest slot writer there is — it must never overlap the exclusive
 * release_all phase.
 */
int mxfs_dlm_caw_purge_dead_nodes_ex(struct mxfs_dlm_caw_ctx *ctx,
				     uint64_t dead_mask, uint32_t flags)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_purge_dead_nodes_body(ctx, dead_mask, flags);
	caw_op_leave(ctx);
	return rc;
}

/* ─── selective out-of-closure purge + survivor-side scrub ─── */

/*
 * sess374 (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356, sess363 RULE-5 ruling).
 *
 * When a foreign-slice replay is REFUSED, the victim's domain is quarantined
 * cluster-wide and its grants stay frozen ON PURPOSE — that is what the
 * quarantine is.  But the victim also holds grants on resources the refusal
 * says nothing about (the root inode's EX from an AG-scoped refusal is the
 * measured case, sess356: every clean umount then took -110 and the cluster
 * shut down).  Those are provably OUT of the closure and must be revoked, or
 * a bounded, correctly-scoped refusal keeps costing the whole fleet.
 *
 * Two entry points, one discipline:
 *
 *   PUBLISHER (mxfs_dlm_caw_purge_victim_selective) — the refusal publisher
 *   runs one table scan between publishing the verdict and releasing its
 *   recovery lease.  It holds the lease, so its gate is the leased
 *   snapshot/revalidate pair.
 *
 *   SURVIVOR (caw_closure_scrub_slot) — any node that finds itself BLOCKED on
 *   victim-owned state repairs just that slot, on demand.  It can hold no
 *   lease (none is obtainable over a quarantined descriptor), so its gate is
 *   the leaseless terminal check, which fails closed on a live slot.  The
 *   publisher can die mid-scan, or never have run at all (its own node was
 *   the one that died); demand-triggered repair is what makes the fix
 *   converge without an elected reconciler.
 *
 * Invariants both obey (ruling items A and B):
 *   - ONE victim per mutation.  A victim's gate never authorizes stripping
 *     another node's bits; a slot carrying several victims is repaired by
 *     independent gate+classify passes.
 *   - Every destructive CAS is preceded by an authoritative re-read, a
 *     re-classification of THAT image (slot reuse is caught by the CAS
 *     generation compare, and the new resource gets classified afresh), and
 *     a FRESH gate evaluation.  No gate result is amortized.
 *   - Classification is tri-state: >0 out-of-closure (purge), 0 keep, <0
 *     error — an errno must never be read as "keep".
 *   - Gate failure stops the whole operation immediately and reports
 *     retry-required.  CASes already completed stand: each was individually
 *     authorized.
 *   - Partial never reports success.
 */

/*
 * One slot, one victim, one strip.  Shared by both entry points.
 *
 * `cur`/`new` are caller-owned scratch (a full slot image each).  On entry
 * `cur` must already hold an image of slot_idx; it is re-read authoritatively
 * before any mutation.  Returns 1 if a CAS landed, 0 if the slot needed
 * nothing (or the classifier kept it), <0 on error/abort.
 */
/* sess376: which chokepoint drove this strip — see
 * mxfs_caw_inject_closure_pause_who and the P299-SCRUB-TRY census. */
#define MXFS_CAW_STRIP_WHO_SCAN		1
#define MXFS_CAW_STRIP_WHO_SCRUB	2

/*
 * sess376 (RULE-5 review): every strip attempt gets an id.  The injected pause
 * and the per-attempt outcome lines are otherwise correlated only by slot and
 * caller, which is inferential once two callers can be inside the same slot at
 * once — exactly the interleaving these tests construct.
 */
static mxfs_atomic32_t caw_strip_inv_seq;

static int caw_closure_strip_one(struct mxfs_dlm_caw_ctx *ctx,
				 uint32_t slot_idx,
				 uint64_t victim_bit,
				 int (*classify)(void *arg,
						 const struct mxfs_resource_id *res),
				 void *carg,
				 int (*gate)(void *arg),
				 void *garg,
				 int max_retry,
				 struct mxfs_caw_lock_slot *cur,
				 struct mxfs_caw_lock_slot *new,
				 uint32_t *kept,
				 const struct mxfs_resource_id *hint,
				 struct caw_closure_obs *obs,
				 int who)
{
	int retry;
	uint32_t inv = (uint32_t)mxfs_atomic32_inc(&caw_strip_inv_seq);

	for (retry = 0; retry <= max_retry; retry++) {
		uint64_t wake;
		int cls;
		int rc;

		/* sess375 hazard hook: widen the hint -> authoritative-read
		 * window so real concurrent code can tombstone and re-bind the
		 * slot inside it.  Timing only; no image is written here. */
		if (retry == 0 && mxfs_caw_inject_closure_pause_where == 1 &&
		    (mxfs_caw_inject_closure_pause_slot < 0 ||
		     (uint32_t)mxfs_caw_inject_closure_pause_slot == slot_idx) &&
		    (mxfs_caw_inject_closure_pause_who == 0 ||
		     mxfs_caw_inject_closure_pause_who == who) &&
		    caw_inject_take(&mxfs_caw_inject_closure_pause_n)) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-INJECT-PAUSE slot=%u inv=%u who=%d "
			    "where=1 ms=%d — hint->authoritative-read window "
			    "widened for this caller",
			    slot_idx, inv, who,
			    mxfs_caw_inject_closure_pause_ms);
			mxfs_pal_sleep_ms(mxfs_caw_inject_closure_pause_ms);
		}

		rc = read_slot(ctx, slot_idx, cur);
		if (rc)
			return rc;
		if (cur->magic != MXFS_CAW_MAGIC) {
			if (obs && retry == 0 && hint)
				obs->hint_vanished++;
			return 0;		/* empty / tombstoned */
		}
		if (obs && retry == 0 && hint &&
		    !caw_resource_same(hint, &cur->resource)) {
			obs->hint_res_moved++;
			/*
			 * sess376: the aggregate counter is accumulated over a
			 * WHOLE 65536-slot scan, so "moved=1" on the summary
			 * line names no slot and no resource.  This names both,
			 * plus the identity fields a reuse claim rests on
			 * (generation restarts per binding; resource_lineage is
			 * a fresh random 64-bit id for a fresh binding and is
			 * inherited only by a same-resource tombstone recycle).
			 */
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-HINT-MOVED slot=%u inv=%u who=%d "
			    "hint_type=%u hint_ino=%llu found_type=%u "
			    "found_ino=%llu gen=%u lineage=0x%llx "
			    "vbit_present=%d — the authoritative re-read found "
			    "a DIFFERENT resource than the batch hint",
			    slot_idx, inv, who, hint->type,
			    (unsigned long long)hint->ino, cur->resource.type,
			    (unsigned long long)cur->resource.ino,
			    cur->generation,
			    (unsigned long long)cur->resource_lineage,
			    caw_victim_state_mask(cur, victim_bit) ? 1 : 0);
		}
		if (!caw_victim_state_mask(cur, victim_bit)) {
			/* Reachable and common: a survivor's demand scrub got
			 * to this slot between the hint and this read. */
			if (obs && retry == 0 && hint)
				obs->hint_bit_gone++;
			return 0;		/* someone else already did it */
		}

		/* Re-derive the WHOLE decision from THIS image — the slot may
		 * have been reused for a different resource since the last
		 * look, and the classification is resource-scoped. */
		cls = classify(carg, &cur->resource);
		if (cls < 0)
			return cls;		/* never silently "keep" */
		if (cls == 0) {
			if (kept)
				(*kept)++;
			/* The hint made this slot a candidate and the
			 * authoritative image says IN closure: the reuse
			 * defense actually fired on this slot. */
			if (obs && hint &&
			    !caw_resource_same(hint, &cur->resource)) {
				obs->class_flipped++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P299-HINT-FLIPPED slot=%u inv=%u "
				    "who=%d hint_ino=%llu found_ino=%llu "
				    "gen=%u lineage=0x%llx — reused slot "
				    "classified IN closure; stays frozen",
				    slot_idx, inv, who,
				    (unsigned long long)hint->ino,
				    (unsigned long long)cur->resource.ino,
				    cur->generation,
				    (unsigned long long)cur->resource_lineage);
			}
			return 0;		/* in closure: stays frozen */
		}

		/* Fresh authority, immediately before the destructive CAS. */
		if (gate) {
			if (caw_inject_take(&mxfs_caw_inject_closure_gate_skip)) {
				/* let this one through — see the knob */
			} else if (caw_inject_take(&mxfs_caw_inject_closure_gate)) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P299-INJECT-GATE slot=%u — per-CAS "
				    "closure gate forced to -ESTALE",
				    slot_idx);
				return -ESTALE;
			}
			rc = gate(garg);
			if (rc)
				return rc;
		}

		*new = *cur;
		caw_strip_node_state(new, victim_bit, false);
		if (!slot_has_holders(new) && !new->waiters &&
		    !new->open_holders)
			caw_tombstone_slot(new);

		/* sess375 hazard hook: widen the gate -> CAS window.  The CAS
		 * compares the WHOLE image, so anything that lands here must
		 * miscompare and force a re-read + re-classify. */
		if (mxfs_caw_inject_closure_pause_where == 2 &&
		    (mxfs_caw_inject_closure_pause_slot < 0 ||
		     (uint32_t)mxfs_caw_inject_closure_pause_slot == slot_idx) &&
		    (mxfs_caw_inject_closure_pause_who == 0 ||
		     mxfs_caw_inject_closure_pause_who == who) &&
		    caw_inject_take(&mxfs_caw_inject_closure_pause_n)) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-INJECT-PAUSE slot=%u inv=%u who=%d "
			    "where=2 ms=%d — gate->CAS window widened for this "
			    "caller", slot_idx, inv, who,
			    mxfs_caw_inject_closure_pause_ms);
			mxfs_pal_sleep_ms(mxfs_caw_inject_closure_pause_ms);
		}

		if (caw_inject_take(&mxfs_caw_inject_closure_cas)) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "mxfs: P299-INJECT-CAS slot=%u — closure-strip CAS "
			    "forced to miscompare", slot_idx);
			rc = -EAGAIN;
		} else {
			rc = caw_slot(ctx, slot_idx, cur, new);
		}
		if (rc == -EAGAIN) {
			if (obs)
				obs->cas_miscompare++;
			/*
			 * sess376 ABA evidence: the CAS compares the WHOLE
			 * image, so a miscompare means the slot moved between
			 * our authoritative read and the write.  Log the image
			 * we expected — the retry re-reads and re-classifies,
			 * and the pair of lines is what shows a stale expected
			 * image can never be re-satisfied by a rebind.
			 */
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-STRIP-CASMISS slot=%u inv=%u who=%d "
			    "retry=%d expect_ino=%llu expect_gen=%u "
			    "expect_lineage=0x%llx expect_vfoot=0x%x",
			    slot_idx, inv, who, retry,
			    (unsigned long long)cur->resource.ino,
			    cur->generation,
			    (unsigned long long)cur->resource_lineage,
			    caw_victim_footprint(cur, victim_bit));
			continue;		/* contended: reread, reclassify, regate */
		}
		if (rc)
			return rc;

		if (obs)
			obs->vfoot = caw_victim_footprint(cur, victim_bit);

		/* Ruling hazard 4: a strip that unblocks a resource must wake
		 * the live waiters on it in the same breath, or the repair is
		 * only visible at the next poll backstop. */
		wake = new->waiters | new->waiters_ex;
		if (wake)
			caw_send_grant_mcast(ctx, &cur->resource, wake);
		return 1;
	}
	return -EAGAIN;				/* CAS retries exhausted */
}

static int caw_purge_victim_selective_body(struct mxfs_dlm_caw_ctx *ctx,
					   uint8_t victim_slot,
					   int (*classify)(void *arg,
						const struct mxfs_resource_id *res),
					   void *carg,
					   int (*gate)(void *arg),
					   void *garg,
					   uint32_t *out_purged,
					   uint32_t *out_kept)
{
	const uint64_t victim_bit = 1ULL << victim_slot;
	const uint32_t BATCH_SLOTS = 32;
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	struct mxfs_caw_lock_slot *batch;
	uint32_t purged = 0, kept = 0;
	int unread = 0, wfail = 0;
	uint32_t slot;
	int abort_rc = 0;
	int rc;
	struct caw_closure_obs obs = { 0 };
	struct mxfs_resource_id hint_res;
	uint32_t vf_waiter_only = 0, vf_open_only = 0;

	/* Phase 0: prove the gate BEFORE reading a single slot.  A refused
	 * gate here means nothing was ever authorized. */
	if (gate) {
		rc = gate(garg);
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
				"mxfs: P299-CLOSURE-GATE victim_slot=%u rc=%d — "
				"selective purge refused at phase 0; every "
				"victim grant stays frozen", victim_slot, rc);
			return rc;
		}
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}
	batch = mxfs_pal_alloc((size_t)BATCH_SLOTS * MXFS_CAW_SLOT_SIZE);

	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P299-CLOSURE-SCAN ENTRY victim_slot=%u bit=0x%llx",
		     victim_slot, (unsigned long long)victim_bit);

	for (slot = 0; slot < MXFS_CAW_MAX_SLOTS && !abort_rc; ) {
		uint32_t chunk = BATCH_SLOTS;
		uint32_t i;
		int batch_rc;

		if (slot + chunk > MXFS_CAW_MAX_SLOTS)
			chunk = MXFS_CAW_MAX_SLOTS - slot;

		batch_rc = batch ? mxfs_pal_bdev_read_prio(ctx->dev,
					slot_offset(ctx, slot), batch,
					chunk * MXFS_CAW_SLOT_SIZE)
				 : -ENOMEM;

		for (i = 0; i < chunk; i++) {
			uint32_t sidx = slot + i;
			const struct mxfs_resource_id *hint = NULL;

			/* Find phase.  The batch copy is a candidacy HINT
			 * only; caw_closure_strip_one re-reads. */
			if (batch_rc == 0) {
				if (batch[i].magic != MXFS_CAW_MAGIC)
					continue;
				if (!caw_victim_state_mask(&batch[i],
							   victim_bit))
					continue;
				/* Copy it out: `batch` is reused per chunk and
				 * the strip may sleep at the sess375 hook. */
				hint_res = batch[i].resource;
				hint = &hint_res;
			} else {
				if (read_slot(ctx, sidx, cur_slot)) {
					/* May be a victim-owned grant we can
					 * no longer see — the scan is no
					 * longer a proof. */
					unread++;
					continue;
				}
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					continue;
				if (!caw_victim_state_mask(cur_slot,
							   victim_bit))
					continue;
				hint_res = cur_slot->resource;
				hint = &hint_res;
			}

			obs.vfoot = 0;
			rc = caw_closure_strip_one(ctx, sidx, victim_bit,
						   classify, carg, gate, garg,
						   19, cur_slot, new_slot,
						   &kept, hint, &obs,
						   MXFS_CAW_STRIP_WHO_SCAN);
			if (rc == 1) {
				purged++;
				if ((obs.vfoot & (MXFS_CAW_VFOOT_WAIT |
						  MXFS_CAW_VFOOT_WAITEX)) &&
				    !(obs.vfoot & (MXFS_CAW_VFOOT_HOLDER |
						   MXFS_CAW_VFOOT_OPEN)))
					vf_waiter_only++;
				if (obs.vfoot == MXFS_CAW_VFOOT_OPEN)
					vf_open_only++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P299-CLOSURE-STRIP slot=%u type=%u "
				    "ino=%llu ag=%u victim_slot=%u vfoot=0x%x",
				    sidx, cur_slot->resource.type,
				    (unsigned long long)cur_slot->resource.ino,
				    cur_slot->resource.ag_number, victim_slot,
				    obs.vfoot);
				continue;
			}
			if (rc == 0)
				continue;
			if (rc == -EAGAIN) {
				/* CAS retries exhausted on a confirmed
				 * candidate: its bits are still on disk. */
				wfail++;
				continue;
			}
			/* Gate failure, classifier error, or I/O on the
			 * authoritative path: stop publishing immediately.
			 * Completed CASes stand — each was individually
			 * authorized by its own fresh gate. */
			abort_rc = rc;
			mxfs_pal_log(MXFS_LOG_ERR,
			    "mxfs: P299-CLOSURE-REFROZE victim_slot=%u scan=%u "
			    "purged=%u rc=%d — authority/verdict moved or the "
			    "slot could not be re-read; purge STOPPED "
			    "(remaining grants stay frozen)",
			    victim_slot, sidx, purged, rc);
			break;
		}

		slot += chunk;
		mxfs_pal_cond_resched();
	}

	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	mxfs_pal_free(batch);

	if (out_purged)
		*out_purged = purged;
	if (out_kept)
		*out_kept = kept;

	mxfs_pal_log(MXFS_LOG_WARN,
	    "mxfs: P299-CLOSURE-PURGE victim_slot=%u purged=%u kept=%u "
	    "unread=%d wfail=%d abort_rc=%d — out-of-closure CAW grants "
	    "force-revoked; in-closure grants stay frozen",
	    victim_slot, purged, kept, unread, wfail, abort_rc);

	/*
	 * sess375: what SHAPES were cleared, and whether the reuse hazard was
	 * actually exercised.  A reuse-race run that shows moved=0 flipped=0
	 * vanished=0 did NOT hit the hazard and must be reported as such, not
	 * as a pass — surviving a race you never ran is not evidence.
	 */
	mxfs_pal_log(MXFS_LOG_WARN,
	    "mxfs: P299-CLOSURE-SHAPES victim_slot=%u waiter_only=%u "
	    "open_only=%u | hint vanished=%u bit_gone=%u moved=%u flipped=%u "
	    "cas_miscompare=%u",
	    victim_slot, vf_waiter_only, vf_open_only, obs.hint_vanished,
	    obs.hint_bit_gone, obs.hint_res_moved, obs.class_flipped,
	    obs.cas_miscompare);

	if (abort_rc)
		return abort_rc;
	if (unread || wfail) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "mxfs: P299-CLOSURE-INCOMPLETE victim_slot=%u purged=%u "
		    "unread=%d wfail=%d — victim state may still be on disk; "
		    "the closure purge MUST NOT be reported complete",
		    victim_slot, purged, unread, wfail);
		return -EIO;
	}
	return 0;
}

/* Contract in dlm_caw.h. */
int mxfs_dlm_caw_purge_victim_selective(struct mxfs_dlm_caw_ctx *ctx,
					uint8_t victim_slot,
					int (*classify)(void *arg,
						const struct mxfs_resource_id *res),
					void *carg,
					int (*gate)(void *arg),
					void *garg,
					uint32_t *out_purged,
					uint32_t *out_kept)
{
	int rc;

	if (out_purged)
		*out_purged = 0;
	if (out_kept)
		*out_kept = 0;
	if (!ctx || !classify || victim_slot >= 64)
		return -EINVAL;
	/* Never strip this node's own state through the closure path: our own
	 * grants are live, and no terminal verdict about us could be acted on
	 * by us anyway. */
	if ((1ULL << victim_slot) == ctx->node_bit)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_purge_victim_selective_body(ctx, victim_slot, classify, carg,
					     gate, garg, out_purged, out_kept);
	caw_op_leave(ctx);
	return rc;
}

/*
 * Survivor-side demand scrub (ruling item B / G1).  `cand_mask` is every
 * foreign node bit present in the caller's image of slot_idx.  Each bit is
 * offered to the scrub oracle independently — one victim per mutation — and
 * the oracle re-answers on the authoritative image before every CAS.
 *
 * Returns the number of bits actually stripped (0 = nothing repairable),
 * or <0 on a hard error.  A per-bit refusal or transient failure is NOT an
 * error: the caller simply keeps waiting, exactly as before the fix.
 */
/*
 * Per-bit adapter: caw_closure_strip_one classifies by resource alone, but the
 * scrub oracle also needs to know WHICH node's state is being considered (it
 * must re-read that node's heartbeat sector and re-prove the terminal verdict
 * before every answer).  The oracle IS the leaseless gate: because
 * caw_closure_strip_one re-invokes the classifier on the authoritative image
 * immediately before each CAS, every scrub CAS is authorized by a heartbeat
 * read taken after the image it mutates.
 */
struct caw_scrub_carg {
	struct mxfs_dlm_caw_ctx	*ctx;
	int			(*fn)(void *, uint8_t,
				      const struct mxfs_resource_id *);
	void			*data;
	uint8_t			bit;
};

static int caw_scrub_classify(void *arg, const struct mxfs_resource_id *res)
{
	struct caw_scrub_carg *sc = arg;

	return sc->fn(sc->data, sc->bit, res);
}

static int caw_closure_scrub_slot(struct mxfs_dlm_caw_ctx *ctx,
				  uint32_t slot_idx,
				  const struct mxfs_resource_id *res,
				  uint64_t cand_mask,
				  const char *site,
				  uint64_t el_ms)
{
	struct mxfs_caw_lock_slot *cur;
	struct mxfs_caw_lock_slot *new;
	/* Read the callback ONCE: it is cleared at teardown, and re-reading it
	 * per bit would let an unregistration land between the test and the
	 * call (review item 10). */
	int (*scrub_fn)(void *, uint8_t, const struct mxfs_resource_id *) =
		ctx->closure_scrub_fn;
	int stripped = 0;
	int hard_rc = 0;
	int bit;
	struct caw_closure_obs obs = { 0 };
	/*
	 * sess376 (D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375,
	 * RULE-4 step 1).  A demand scrub that strips nothing is SILENT: every
	 * "keep", "already clean" and "slot moved" answer returns 0 with no
	 * log, so a waiter that ran to its timeout could not be distinguished
	 * from one whose hook was never entered at all.  That ambiguity is
	 * what made sess375 record an unproven mechanism.  This census fires
	 * once per scrub ATTEMPT — i.e. only while a terminal refusal verdict
	 * for a node blocking THIS slot has actually been imported, so it is
	 * silent on a healthy cluster — and names the chokepoint, the wait's
	 * age, and which of the four zero-return reasons applied.
	 */
	uint32_t kept = 0;

	if (!scrub_fn || !cand_mask)
		return 0;
	/*
	 * SKIP-ONLY candidate filter (RULE-5 review items 2+3).  Restrict to
	 * foreign bits whose heartbeat slot this mount has already imported a
	 * terminal AG_MASK verdict for.  This is the whole cost story: with no
	 * refusal anywhere in the cluster — the normal case — a scrub attempt
	 * costs zero I/O and the hooks below are free.  The hint authorizes
	 * nothing; every strip still goes through the fresh platter gate.
	 */
	cand_mask &= ctx->closure_cand_mask & ~ctx->node_bit;
	if (!cand_mask)
		return 0;

	/*
	 * OWN scratch, never the caller's.  Both hook sites call this from
	 * inside a loop whose cur_slot/new_slot are LIVE state: the wait
	 * loop's direct-handoff ADOPT arm publishes on the image cur_slot
	 * held when its clear-window snapshot was armed, and
	 * caw_closure_strip_one re-reads unconditionally.  Handing it the
	 * caller's buffers would silently swap that image out from under the
	 * arm on every scrub that strips NOTHING (the common case, where the
	 * caller does not restart its loop).
	 */
	cur = mxfs_pal_alloc(sizeof(*cur));
	new = mxfs_pal_alloc(sizeof(*new));
	if (!cur || !new) {
		mxfs_pal_free(cur);
		mxfs_pal_free(new);
		return 0;
	}

	for (bit = 0; bit < 64 && !hard_rc; bit++) {
		uint64_t vbit = 1ULL << bit;
		struct caw_scrub_carg sc = { ctx, scrub_fn,
					     ctx->closure_scrub_data,
					     (uint8_t)bit };
		int rc;

		if (!(cand_mask & vbit))
			continue;

		/*
		 * No separate pre-filter read: caw_closure_strip_one asks the
		 * oracle on the AUTHORITATIVE image immediately before the
		 * CAS, and the oracle IS the leaseless gate.  A second earlier
		 * ask would double the heartbeat reads and authorize nothing
		 * the later one does not (review item 3).
		 */
		obs.vfoot = 0;
		rc = caw_closure_strip_one(ctx, slot_idx, vbit,
					   caw_scrub_classify, &sc,
					   NULL, NULL, 5, cur, new, &kept,
					   res, &obs,
					   MXFS_CAW_STRIP_WHO_SCRUB);
		if (rc == 1) {
			stripped++;
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-SCRUB-STRIP slot=%u victim_slot=%d "
			    "type=%u ino=%llu ag=%u vfoot=0x%x — blocking "
			    "out-of-closure state force-revoked on demand",
			    slot_idx, bit, cur->resource.type,
			    (unsigned long long)cur->resource.ino,
			    cur->resource.ag_number, obs.vfoot);
			continue;
		}
		if (rc == 0 || rc == -EAGAIN)
			continue;	/* kept, already clean, or contended */
		/*
		 * Review item 6: a gate/oracle/platter failure is NOT a
		 * negative cache result.  Stop offering further bits on this
		 * slot and report it — the caller keeps waiting, which is the
		 * pre-fix behavior, but the failure is visible rather than
		 * laundered into "nothing to do".
		 */
		hard_rc = rc;
		mxfs_pal_log(MXFS_LOG_ERR,
		    "mxfs: P299-SCRUB-ABORT slot=%u victim_slot=%d rc=%d — "
		    "out-of-closure gate could not be evaluated; blocking "
		    "state left frozen", slot_idx, bit, rc);
	}
	mxfs_pal_free(cur);
	mxfs_pal_free(new);
	{
		static int scrub_try_n;

		if (scrub_try_n++ < 20000)
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P299-SCRUB-TRY site=%s slot=%u type=%u "
			    "ino=%llu el_ms=%llu cand=0x%llx stripped=%d "
			    "kept=%u vanished=%u bit_gone=%u res_moved=%u "
			    "flipped=%u cas_mis=%u hard_rc=%d",
			    site ? site : "?", slot_idx,
			    res ? res->type : 0,
			    (unsigned long long)(res ? res->ino : 0),
			    (unsigned long long)el_ms,
			    (unsigned long long)cand_mask, stripped, kept,
			    obs.hint_vanished, obs.hint_bit_gone,
			    obs.hint_res_moved, obs.class_flipped,
			    obs.cas_miscompare, hard_rc);
	}
	if (hard_rc && !stripped)
		return hard_rc;
	return stripped;
}

/*
 * sess58 (D-FOREIGN-REPLAY step 4a, GPT review item 6A) — read-only census
 * of what a set of node slots still owns in the shared table.
 *
 * The mount recovery barrier needs to know whether a node it has confirmed
 * dead but COULD NOT FENCE still owns anything a subsequent blocking
 * acquire would wait on.  If it does, xfs_log_mount_finish's intent replay
 * and iunlink processing will each stall the full CAW wait timeout on it
 * and then fail — mount recovery blocked by a grant whose only release path
 * was gated on mount recovery finishing.  The barrier fails the mount
 * instead, and this scan is the evidence that decision is made from.
 *
 * Nothing is modified.  A guess in either direction is unacceptable, so an
 * incomplete read is an ERROR, never a zero: an unread slot may hold
 * anything.  Callers MUST treat a negative return as "blocking".
 *
 * Returns the number of slots carrying ANY footprint of node_mask (holder
 * in any mode, waiter, or open-holder), or -EIO if the table could not be
 * read in full.  *out_ex, when non-NULL, receives the subset holding EX or
 * PW — the authority manifest proper, reported separately because it is
 * what a foreign replay gate reads.
 */
int mxfs_dlm_caw_footprint_scan(struct mxfs_dlm_caw_ctx *ctx,
				uint64_t node_mask, int *out_ex)
{
	struct mxfs_caw_lock_slot *one;
	struct mxfs_caw_lock_slot *batch;
	const uint32_t BATCH_SLOTS = 32;
	uint32_t slot;
	int nfound = 0;
	int nex = 0;
	int nunread = 0;

	if (out_ex)
		*out_ex = 0;
	if (!ctx || !node_mask)
		return 0;

	one = mxfs_pal_alloc(sizeof(*one));
	if (!one)
		return -ENOMEM;
	batch = mxfs_pal_alloc((size_t)BATCH_SLOTS * MXFS_CAW_SLOT_SIZE);

	for (slot = 0; slot < MXFS_CAW_MAX_SLOTS; ) {
		uint32_t chunk = BATCH_SLOTS;
		uint32_t i;
		int batch_rc;

		if (slot + chunk > MXFS_CAW_MAX_SLOTS)
			chunk = MXFS_CAW_MAX_SLOTS - slot;

		batch_rc = batch ? mxfs_pal_bdev_read_prio(ctx->dev,
					slot_offset(ctx, slot), batch,
					chunk * MXFS_CAW_SLOT_SIZE)
				 : -ENOMEM;

		for (i = 0; i < chunk; i++) {
			const struct mxfs_caw_lock_slot *s;

			if (batch_rc == 0) {
				s = &batch[i];
			} else {
				if (read_slot(ctx, slot + i, one)) {
					nunread++;
					continue;
				}
				s = one;
			}
			if (s->magic != MXFS_CAW_MAGIC)
				continue;
			if (!caw_purge_candidate(s, node_mask, false))
				continue;
			nfound++;
			if ((s->holders_ex & node_mask) ||
			    (s->holders_pw & node_mask))
				nex++;
		}

		slot += chunk;
		mxfs_pal_cond_resched();
	}

	mxfs_pal_free(one);
	mxfs_pal_free(batch);

	if (nunread) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P227-FOOTPRINT-UNREAD mask=0x%llx %d slot(s) "
			     "unreadable — census incomplete, caller must assume "
			     "the mask is still blocking",
			     (unsigned long long)node_mask, nunread);
		return -EIO;
	}

	if (out_ex)
		*out_ex = nex;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P227-FOOTPRINT mask=0x%llx slots=%d of_which_ex_pw=%d",
		     (unsigned long long)node_mask, nfound, nex);
	return nfound;
}

/* ─── sess128 BAST dispatch queue ─── */

/*
 * The CONSERVATIVE JOIN of two requested modes.
 *
 * Merging two BAST hints for one resource must not lose a release that either
 * hint on its own would have caused.  The action a callback takes is gated on
 * !lock_compat[our_mode][requested], so the merged mode must conflict with
 * EVERY mode either input conflicts with.  Return the mode satisfying that
 * with the SMALLEST conflict set, so the merge is not gratuitously pessimistic
 * — a PR+CR merge stays PR rather than escalating to EX and forcing peers'
 * cached dir images cold.
 *
 * The lock modes are a lattice, NOT a total order (CW and PR are
 * incomparable), so numeric max(a,b) is wrong: max(CW,PR) = PR, but PR does
 * not conflict with CR while... — more to the point, PR's conflict set
 * {CW,PW,EX} does not contain CW's {PR,PW,EX}, so a CW waiter's BAST merged
 * "up" to PR would stop waking a PR holder that must release for it.  The
 * search below gets PW there, which is correct.
 *
 * EX is a fixed point: EX's conflict set is maximal, so join(anything, EX) is
 * EX.  That is what keeps the XFS layer's i_dlm_dir_want_ex latch (set only
 * for an EX requester) intact across coalescing.
 */
static uint8_t caw_bast_mode_join(uint8_t a, uint8_t b)
{
	uint8_t m, x;
	uint8_t best = MXFS_LOCK_EX;
	int best_conf = MXFS_LOCK_MODE_COUNT + 1;

	if (a >= MXFS_LOCK_MODE_COUNT)
		a = MXFS_LOCK_EX;
	if (b >= MXFS_LOCK_MODE_COUNT)
		b = MXFS_LOCK_EX;
	if (a == b)
		return a;

	for (m = 0; m < MXFS_LOCK_MODE_COUNT; m++) {
		bool covers = true;
		int conf = 0;

		for (x = 0; x < MXFS_LOCK_MODE_COUNT; x++) {
			bool need = !lock_compat[x][a] || !lock_compat[x][b];

			if (!lock_compat[x][m])
				conf++;
			else if (need)
				covers = false;
		}
		if (covers && conf < best_conf) {
			best = m;
			best_conf = conf;
		}
	}
	return best;
}

static void caw_bastq_free(struct mxfs_dlm_caw_ctx *ctx)
{
	if (!ctx)
		return;
	mxfs_pal_cond_destroy(ctx->bq.cond);
	ctx->bq.cond = NULL;
	mxfs_pal_mutex_destroy(ctx->bq.lock);
	ctx->bq.lock = NULL;
	mxfs_pal_free(ctx->bq.hash);
	ctx->bq.hash = NULL;
	mxfs_pal_free(ctx->bq.pool);
	ctx->bq.pool = NULL;
	ctx->bq.freelist = NULL;
	ctx->bq.head = NULL;
	ctx->bq.tail = NULL;
	ctx->bq.depth = 0;
}

/*
 * Allocate the whole queue up front.  Nothing on the packet path may allocate:
 * the receive thread's entire job is to keep the socket drained.
 *
 * Failure is NOT fatal.  caw_bast_submit() falls back to running the callback
 * on the producer thread, which is exactly the pre-sess128 behaviour — slow,
 * but correct.  A mount must not be refused over a diagnostic-grade
 * optimisation, and the poll thread remains a complete BAST channel.
 */
static int caw_bastq_init(struct mxfs_dlm_caw_ctx *ctx)
{
	uint32_t i;

	ctx->bq.pool = mxfs_pal_alloc(MXFS_CAW_BASTQ_ENTRIES *
				      sizeof(*ctx->bq.pool));
	ctx->bq.hash = mxfs_pal_alloc(MXFS_CAW_BASTQ_BUCKETS *
				      sizeof(*ctx->bq.hash));
	ctx->bq.lock = mxfs_pal_mutex_create();
	ctx->bq.cond = mxfs_pal_cond_create();
	if (!ctx->bq.pool || !ctx->bq.hash || !ctx->bq.lock || !ctx->bq.cond) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "dlm_caw: BAST dispatch queue alloc failed — "
			     "falling back to inline callbacks on the "
			     "producer threads");
		caw_bastq_free(ctx);
		return -ENOMEM;
	}

	/* mxfs_pal_alloc zeroes, so every entry is already FREE with NULL
	 * links; just thread the free list. */
	for (i = 0; i < MXFS_CAW_BASTQ_ENTRIES; i++) {
		ctx->bq.pool[i].qnext = ctx->bq.freelist;
		ctx->bq.freelist = &ctx->bq.pool[i];
	}
	return 0;
}

/* Ready-queue push at the TAIL.  Caller holds bq.lock. */
static void caw_bastq_enqueue_locked(struct mxfs_dlm_caw_ctx *ctx,
				     struct mxfs_caw_bq_ent *e)
{
	e->qnext = NULL;
	if (ctx->bq.tail)
		ctx->bq.tail->qnext = e;
	else
		ctx->bq.head = e;
	ctx->bq.tail = e;
	ctx->bq.depth++;
	if (ctx->bq.depth > ctx->bq.hiwater)
		ctx->bq.hiwater = ctx->bq.depth;
}

/* Caller holds bq.lock. */
static struct mxfs_caw_bq_ent *
caw_bastq_lookup_locked(struct mxfs_dlm_caw_ctx *ctx, uint32_t bucket,
			const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_bq_ent *e;

	for (e = ctx->bq.hash[bucket]; e; e = e->hnext) {
		if (memcmp(&e->resource, resource, sizeof(*resource)) == 0)
			return e;
	}
	return NULL;
}

/* Caller holds bq.lock. */
static void caw_bastq_unhash_locked(struct mxfs_dlm_caw_ctx *ctx,
				    uint32_t bucket,
				    struct mxfs_caw_bq_ent *e)
{
	struct mxfs_caw_bq_ent **pp = &ctx->bq.hash[bucket];

	while (*pp) {
		if (*pp == e) {
			*pp = e->hnext;
			e->hnext = NULL;
			return;
		}
		pp = &(*pp)->hnext;
	}
}

/*
 * THE SINGLE ENTRY POINT for every BAST producer.  O(1), no device I/O, no
 * allocation, and the lock is held only across pointer surgery.
 *
 * Three cases, linearized under one lock so a hint can never be lost against a
 * dispatcher completing:
 *   absent  -> take a free entry, publish it QUEUED, wake a dispatcher
 *   QUEUED  -> join the mode into the pending entry and drop the packet
 *   RUNNING -> set re-arm and join into rearm_mode; the dispatcher re-queues
 *              it on completion, because its callback may have snapshotted
 *              state before this new waiter became visible
 */
static void caw_bast_submit(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t requested_mode)
{
	struct mxfs_caw_bq_ent *e;
	uint32_t bucket;

	if (!ctx->bast_cb)
		return;

	/* No queue (alloc failed at create): pre-sess128 behaviour. */
	if (!ctx->bq.pool || !ctx->bq.lock || !ctx->bq.cond) {
		ctx->bq.inline_cb++;
		ctx->bast_cb((struct mxfs_dlm_ctx *)ctx->cb_data,
			     resource, ctx->local_node, requested_mode);
		return;
	}

	bucket = resource_hash_raw(resource) % MXFS_CAW_BASTQ_BUCKETS;

	mxfs_pal_mutex_lock(ctx->bq.lock);
	ctx->bq.submitted++;

	e = caw_bastq_lookup_locked(ctx, bucket, resource);
	if (e) {
		if (e->state == MXFS_CAW_BQ_RUNNING) {
			e->rearm_mode = e->rearm ?
				caw_bast_mode_join(e->rearm_mode,
						   requested_mode) :
				requested_mode;
			e->rearm = 1;
			ctx->bq.rearmed++;
		} else {
			e->queued_mode = caw_bast_mode_join(e->queued_mode,
							    requested_mode);
			e->merges++;
			ctx->bq.merged++;
		}
		mxfs_pal_mutex_unlock(ctx->bq.lock);
		return;
	}

	e = ctx->bq.freelist;
	if (!e) {
		/*
		 * Pool exhausted.  Dropping is survivable — the waiter keeps
		 * re-sending its hint every MXFS_CAW_BAST_RESEND_MS for as
		 * long as it is blocked, and the disk poll independently
		 * rediscovers the conflict from the slot's waiter bits — but
		 * it is NOT free: both recovery channels are slower than the
		 * hint.  Pin the poll to its FAST cadence so the backstop
		 * actually covers the loss instead of relaxing back to
		 * POLL_RELAX_MS, and say so out loud.
		 */
		ctx->bq.overflow++;
		ctx->bq.fastpoll_until_ms = mxfs_pal_time_ms() +
					    MXFS_CAW_BASTQ_FASTPOLL_MS;
		mxfs_pal_mutex_unlock(ctx->bq.lock);
		pr_warn_ratelimited(
		    "mxfs: P264-BASTQ-FULL ino=%llu type=%u mode=%u — BAST dispatch queue exhausted (%u entries), hint dropped; disk poll pinned FAST for %ums\n",
			(unsigned long long)resource->ino, resource->type,
			requested_mode, (unsigned)MXFS_CAW_BASTQ_ENTRIES,
			(unsigned)MXFS_CAW_BASTQ_FASTPOLL_MS);
		return;
	}
	ctx->bq.freelist = e->qnext;

	e->resource = *resource;
	e->state = MXFS_CAW_BQ_QUEUED;
	e->queued_mode = requested_mode;
	e->rearm = 0;
	e->rearm_mode = 0;
	e->merges = 0;
	e->enq_ms = mxfs_pal_time_ms();
	e->hnext = ctx->bq.hash[bucket];
	ctx->bq.hash[bucket] = e;
	caw_bastq_enqueue_locked(ctx, e);

	mxfs_pal_cond_signal(ctx->bq.cond);
	mxfs_pal_mutex_unlock(ctx->bq.lock);
}

/*
 * Dispatcher.  Pops one resource, runs the callback OUTSIDE the queue lock,
 * then either retires the entry or re-queues it at the tail if a hint arrived
 * while it ran.
 *
 * This thread inherits exactly what bast_recv_fn used to do, so the teardown
 * contract is the same one caw_join_bounded enforces for bast_recv/bast_poll:
 * it holds a live pointer into the XFS mount through ctx->bast_cb and must be
 * joined before that mount can be freed.
 */
static void caw_bast_disp_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;

	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST dispatcher started");

	while (ctx->running) {
		struct mxfs_caw_bq_ent *e;
		struct mxfs_resource_id resource;
		uint8_t mode;
		uint32_t bucket;

		mxfs_pal_mutex_lock(ctx->bq.lock);
		while (ctx->running && !ctx->bq.head)
			mxfs_pal_cond_timedwait(ctx->bq.cond, ctx->bq.lock,
						MXFS_CAW_BASTQ_WAIT_MS);
		e = ctx->bq.head;
		if (!ctx->running || !e) {
			mxfs_pal_mutex_unlock(ctx->bq.lock);
			if (!ctx->running)
				break;
			continue;
		}
		ctx->bq.head = e->qnext;
		if (!ctx->bq.head)
			ctx->bq.tail = NULL;
		e->qnext = NULL;
		ctx->bq.depth--;
		e->state = MXFS_CAW_BQ_RUNNING;
		ctx->bq.running_n++;
		ctx->bq.dispatched++;
		/* Copy the key out: the entry stays hashed (so a concurrent
		 * submit finds it and re-arms) but must not be read unlocked. */
		resource = e->resource;
		mode = e->queued_mode;
		mxfs_pal_mutex_unlock(ctx->bq.lock);

		if (ctx->bast_cb)
			ctx->bast_cb((struct mxfs_dlm_ctx *)ctx->cb_data,
				     &resource, ctx->local_node, mode);

		bucket = resource_hash_raw(&resource) % MXFS_CAW_BASTQ_BUCKETS;

		mxfs_pal_mutex_lock(ctx->bq.lock);
		ctx->bq.running_n--;
		if (e->rearm) {
			e->queued_mode = e->rearm_mode;
			e->rearm = 0;
			e->rearm_mode = 0;
			e->merges = 0;
			e->enq_ms = mxfs_pal_time_ms();
			e->state = MXFS_CAW_BQ_QUEUED;
			caw_bastq_enqueue_locked(ctx, e);
			mxfs_pal_cond_signal(ctx->bq.cond);
		} else {
			caw_bastq_unhash_locked(ctx, bucket, e);
			e->state = MXFS_CAW_BQ_FREE;
			e->qnext = ctx->bq.freelist;
			ctx->bq.freelist = e;
		}
		mxfs_pal_mutex_unlock(ctx->bq.lock);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST dispatcher exiting");
}

/*
 * Join every dispatcher.  CALLER MUST HAVE CLEARED ctx->running FIRST, and
 * must already have joined BOTH producers (bast_recv, bast_poll) — a producer
 * still alive can submit into a queue whose consumers are leaving, and that
 * hint is then lost with no backstop, which is precisely the failure this
 * whole change exists to remove.
 *
 * The broadcast is an optimisation, not the exit mechanism: each dispatcher
 * blocks in a MXFS_CAW_BASTQ_WAIT_MS timedwait, so one that races past the
 * `running` check and into the wait still leaves within that bound.  Bounded
 * for the same reason the producers are — these threads call ctx->bast_cb,
 * which reaches into the XFS mount the VFS is about to free.
 */
static void caw_bastq_join_workers(struct mxfs_dlm_caw_ctx *ctx,
				   uint64_t esc_at_ms)
{
	int w;

	if (ctx->bq.cond && ctx->bq.lock) {
		mxfs_pal_mutex_lock(ctx->bq.lock);
		mxfs_pal_cond_broadcast(ctx->bq.cond);
		mxfs_pal_mutex_unlock(ctx->bq.lock);
	}

	for (w = 0; w < MXFS_CAW_BAST_WORKERS; w++)
		caw_join_bounded(ctx, &ctx->bast_disp_thread[w],
				 "bast_disp", esc_at_ms);
}

/*
 * Harvestable counters for the dispatch queue.  Without these there is no way
 * to prove the coalescing ratio, which is the entire claim this change makes;
 * `dispatched` far below `submitted` IS the fix working, and a nonzero
 * `overflow` or `inline_cb` means it is not doing what it claims.
 *
 * Read without the queue lock on purpose: these are monotone counters read for
 * a report, and taking bq.lock here would put a diagnostic on the critical
 * path of every submit.  A torn 64-bit read on a 32-bit target costs one
 * misprinted line in a log, which is the right trade.
 */
static void caw_bastq_report(struct mxfs_dlm_caw_ctx *ctx, const char *when)
{
	if (!ctx->bq.pool && !ctx->bq.inline_cb)
		return;

	pr_info("mxfs: P265-BASTQ-STATS node=%u at=%s submitted=%llu dispatched=%llu merged=%llu rearmed=%llu overflow=%llu inline=%llu depth=%u hiwater=%u running=%u\n",
		ctx->local_node, when,
		(unsigned long long)ctx->bq.submitted,
		(unsigned long long)ctx->bq.dispatched,
		(unsigned long long)ctx->bq.merged,
		(unsigned long long)ctx->bq.rearmed,
		(unsigned long long)ctx->bq.overflow,
		(unsigned long long)ctx->bq.inline_cb,
		ctx->bq.depth, ctx->bq.hiwater, ctx->bq.running_n);
}

/* ─── BAST poll thread ─── */

static void bast_poll_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;
	uint32_t *batch;
	uint32_t poll_interval = MXFS_CAW_BAST_POLL_MS;
	uint32_t rot = 0;	/* v0.5.3 rotating scan start (coverage >256 held) */
	uint64_t bq_report_ms = mxfs_pal_time_ms();
	int batch_count;
	int i;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: BAST poll thread started (node %u, %u ms interval)",
		     ctx->local_node, MXFS_CAW_BAST_POLL_MS);

	/* Allocate batch buffer for held slot snapshot */
	batch = mxfs_pal_alloc(256 * sizeof(uint32_t));
	if (!batch) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: BAST poll alloc failed, thread exiting");
		return;
	}

	while (ctx->running) {
		bool saw_contention = false;
		uint64_t now_ms;

		mxfs_pal_mutex_lock(ctx->stop_lock);
		mxfs_pal_cond_timedwait(ctx->stop_cond, ctx->stop_lock,
					poll_interval);
		mxfs_pal_mutex_unlock(ctx->stop_lock);
		if (!ctx->running)
			break;

		/* Periodic queue report.  This thread already wakes on a
		 * cadence, so it costs nothing extra to piggyback on. */
		now_ms = mxfs_pal_time_ms();
		if (now_ms - bq_report_ms >= MXFS_CAW_BASTQ_REPORT_MS) {
			bq_report_ms = now_ms;
			caw_bastq_report(ctx, "periodic");
		}

		/* Single-node: no peers can set waiter flags, skip
		 * disk polling entirely to avoid unnecessary I/O. */
		if (ctx->single_node)
			continue;

		/* Snapshot held list under lock.
		 * v0.5.3: rotate the 256-entry window across the full held
		 * list — the old code only ever scanned held.slots[0..255],
		 * so any conflict on a lock past index 255 was invisible to
		 * the disk-poll fallback (latent coverage gap once a node
		 * caches >256 locks, which a single rsync already does). */
		mxfs_pal_mutex_lock(ctx->held.lock);
		batch_count = ctx->held.count;
		if (batch_count > 256) {
			uint32_t start = rot % (uint32_t)ctx->held.count;
			uint32_t first = (uint32_t)ctx->held.count - start;

			if (first > 256)
				first = 256;
			memcpy(batch, ctx->held.slots + start,
			       first * sizeof(uint32_t));
			if (first < 256)
				memcpy(batch + first, ctx->held.slots,
				       (256 - first) * sizeof(uint32_t));
			batch_count = 256;
			rot += 256;
		} else {
			memcpy(batch, ctx->held.slots,
			       batch_count * sizeof(uint32_t));
		}
		mxfs_pal_mutex_unlock(ctx->held.lock);

		for (i = 0; i < batch_count; i++) {
			struct mxfs_caw_lock_slot slot;
			uint8_t our_mode;
			int rc;

			if (!ctx->running)
				break;

			rc = read_slot(ctx, batch[i], &slot);
			if (rc)
				continue;
			if (slot.magic != MXFS_CAW_MAGIC)
				continue;

			our_mode = node_held_mode(&slot, ctx->node_bit);

			/*
			 * sess50 detector: catch an incompatible CO-HOLD that no
			 * waiter exists for.  The waiter-driven BAST below cannot
			 * resolve a state where a peer already HOLDS a mode
			 * incompatible with ours (e.g. we cache PR, a peer holds
			 * EX) — neither side is "waiting", so the dir-read stale
			 * never refreshes (the ~60-120s barrier stall).  Detect it
			 * here in the poll thread (away from the perturbation-
			 * sensitive dir ilock fast path).  Ratelimited, fires only
			 * on the bug.
			 */
			if (our_mode != MXFS_LOCK_NL) {
				uint64_t self = ctx->node_bit;
				uint64_t o_ex = slot.holders_ex & ~self;
				uint64_t o_pw = slot.holders_pw & ~self;
				uint64_t o_pr = slot.holders_pr & ~self;
				uint64_t o_cw = slot.holders_cw & ~self;
				uint64_t o_cr = slot.holders_cr & ~self;
				bool cohold_bad = false;

				if (our_mode == MXFS_LOCK_EX ||
				    our_mode == MXFS_LOCK_PW) {
					if (o_ex | o_pw | o_pr | o_cw | o_cr)
						cohold_bad = true;
				} else { /* PR/CR/CW */
					if (o_ex | o_pw)
						cohold_bad = true;
				}
				if (unlikely(cohold_bad))
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: SESS50-COHOLD ino=%llu type=%u our_mode=%u "
					    "self=%llx h_ex=%llx h_pw=%llx h_pr=%llx h_cw=%llx h_cr=%llx waiters=%llx wmode=%u",
					    (unsigned long long)slot.resource.ino,
					    slot.resource.type, our_mode,
					    (unsigned long long)self,
					    (unsigned long long)slot.holders_ex,
					    (unsigned long long)slot.holders_pw,
					    (unsigned long long)slot.holders_pr,
					    (unsigned long long)slot.holders_cw,
					    (unsigned long long)slot.holders_cr,
					    (unsigned long long)slot.waiters,
					    slot.waiter_mode);
			}

			/*
			 * D-AGLOCK-...-LIVELOCK-488: the sticky revoke bit.
			 *
			 * This is the DURABLE half of the fix and it has to be
			 * checked BEFORE the `!slot.waiters` skip below — that
			 * skip is exactly the hole.  A NOQUEUE contender never
			 * registers as a waiter (deliberately: transient waiter
			 * registration recreates the same-node waiter-cancel
			 * collision family, ledger #15), so against a lazily-
			 * cached holder there is nothing here to notice and the
			 * contender spins -EAGAIN forever.
			 *
			 * The bit carries no requester identity and no mode, so
			 * we treat it as the strongest possible demand (EX) and
			 * demote UNCONDITIONALLY — no idle-grace, which would
			 * only re-introduce a tuning-dependent livelock tail.
			 * Over-releasing is cheap: this only fires on a slot we
			 * are CACHING (no local user), and re-acquiring an
			 * uncontended AG is one CAS.
			 *
			 * ABA is handled by construction rather than by gen
			 * comparison: the bit lives IN the slot, and every
			 * transition that would invalidate it (our release,
			 * a fresh grant of the unowned slot, tombstoning)
			 * clears it inside the same CAS.
			 */
			if (slot.revoke && our_mode != MXFS_LOCK_NL &&
			    !lock_compat[our_mode][MXFS_LOCK_EX]) {
				pr_warn_ratelimited("mxfs: P280-REVOKE-RX type=%u ag=%u ino=%llu our_mode=%u h_ex=%llx waiters=%llx gen=%llu — sticky revoke; demoting\n",
					slot.resource.type,
					slot.resource.ag_number,
					(unsigned long long)slot.resource.ino,
					our_mode,
					(unsigned long long)slot.holders_ex,
					(unsigned long long)slot.waiters,
					(unsigned long long)slot.generation);
				saw_contention = true;
				caw_bast_submit(ctx, &slot.resource,
						MXFS_LOCK_EX);
				continue;
			}

			/* Check if there are waiters requesting an
			 * incompatible mode to what we hold */
			if (!slot.waiters ||
			    slot.waiter_mode == MXFS_LOCK_NL)
				continue;

			saw_contention = true;

			if (our_mode == MXFS_LOCK_NL)
				continue;

			/* sess50 starvation probe (no extra I/O — uses the slot
			 * already read above): we hold a mode and a peer is
			 * waiting for an incompatible one.  If this fires
			 * repeatedly for the SAME inode during a barrier stall,
			 * the waiter (e.g. an EX writer) is being starved by
			 * continuous compatible re-grants. */
			if (slot.resource.type == MXFS_LTYPE_INODE &&
			    !lock_compat[our_mode][slot.waiter_mode])
				pr_warn_ratelimited("mxfs: SESS50-STARVE ino=%llu our_mode=%u waiter_mode=%u waiters=%llx waiters_ex=%llx h_ex=%llx h_pr=%llx gen=%llu\n",
					(unsigned long long)slot.resource.ino,
					our_mode, slot.waiter_mode,
					(unsigned long long)slot.waiters,
					(unsigned long long)slot.waiters_ex,
					(unsigned long long)slot.holders_ex,
					(unsigned long long)slot.holders_pr,
					(unsigned long long)slot.generation);

			if (!lock_compat[our_mode][slot.waiter_mode]) {
				/*
				 * Conflict.  sess128: SUBMIT, do not call.
				 * Before this the poll thread ran the callback
				 * inline, which (a) let it race the UDP recv
				 * thread's callback for the SAME resource with
				 * nothing serializing them, and (b) made one
				 * slow release stall the rest of the rotation,
				 * so the "lossless backstop" was itself
				 * head-of-line blocked.
				 */
				caw_bast_submit(ctx, &slot.resource,
						slot.waiter_mode);
			}
		}

		/*
		 * Adaptive poll interval: fast under contention; otherwise
		 * v0.5.3 relaxes the idle interval when the UDP BAST path is
		 * operational (waiters re-send hints every 100 ms while
		 * blocked, so the disk poll is no longer the lost-packet
		 * recovery path).  When the UDP socket failed to set up the
		 * disk poll IS the only BAST channel — keep the original
		 * 200 ms cadence in that case.
		 */
		/*
		 * sess128: an overflowed dispatch queue means a hint was
		 * DROPPED, and this poll is the channel that has to find the
		 * conflict instead.  Relaxing to 4000ms right after losing a
		 * hint is the opposite of what the loss calls for, so hold
		 * FAST for MXFS_CAW_BASTQ_FASTPOLL_MS past the last overflow.
		 *
		 * NOTE for whoever revisits POLL_RELAX_MS: its comment claims
		 * the disk poll is "no longer the lost-packet recovery path"
		 * because the UDP path is operational.  RcvbufErrors=8085
		 * refuted that premise on 0.11.452.  Also, the interval is NOT
		 * the recovery bound: this loop reads a 256-slot window per
		 * pass, so a full rotation costs
		 * ceil(held.count/256) * poll_interval — at 4000ms and a large
		 * held set that is minutes, not seconds.
		 */
		if (ctx->bq.fastpoll_until_ms &&
		    mxfs_pal_time_ms() < ctx->bq.fastpoll_until_ms)
			saw_contention = true;

		poll_interval = saw_contention ?
				MXFS_CAW_BAST_POLL_FAST_MS :
				(ctx->bast_mcast_sock ?
				 MXFS_CAW_BAST_POLL_RELAX_MS :
				 MXFS_CAW_BAST_POLL_MS);
	}

	mxfs_pal_free(batch);
	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST poll thread exiting");
}

/* ─── UDP BAST receive thread ─── */

static void bast_recv_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;
	struct mxfs_caw_bast_notify msg;
	char sender_host[64];
	uint16_t sender_port;
	int len;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: BAST recv thread started (port %u)",
		     MXFS_CAW_BAST_PORT);

	while (ctx->running) {
		memset(&msg, 0, sizeof(msg));
		memset(sender_host, 0, sizeof(sender_host));
		sender_port = 0;

		len = mxfs_pal_udp_recvfrom(ctx->bast_mcast_sock,
					     &msg, sizeof(msg),
					     sender_host, sizeof(sender_host),
					     &sender_port);
		if (len < 0) {
			if (len == -EAGAIN || len == -ETIMEDOUT ||
			    len == -EINTR)
				continue;
			if (!ctx->running)
				break;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: BAST recvfrom failed: %d",
				     len);
			continue;
		}
		if (len == 0) {
			if (!ctx->running)
				break;
			continue;
		}

		/* sess35 NUDGE v2: accept the v1-sized prefix too — the
		 * wake_mask tail is optional (validated below before use),
		 * so a v1 sender's packet still parses. */
		if (len < (int)offsetof(struct mxfs_caw_bast_notify,
					wake_mask))
			continue;
		/* ccloop 72513a13 sess3: GRANT NUDGE — wake every blocked
		 * acquirer on this node so they re-read their slot NOW.
		 * sess35: v2 nudges carry wake_mask so only nodes that can
		 * act re-read; see caw_nudge_ring_wants_wake. */
		if (msg.magic == MXFS_GRANT_MAGIC) {
			if (msg.requester == ctx->local_node)
				continue;
			if (memcmp(msg.volume_uuid, ctx->volume_uuid, 16) != 0)
				continue;
			if (ctx->nudge_lock && ctx->nudge_cond) {
				struct mxfs_caw_nudge_rec *r;

				mxfs_pal_mutex_lock(ctx->nudge_lock);
				ctx->nudge_seq++;
				/* sess35 NUDGE v2: record what this nudge is
				 * about so woken waiters can judge relevance
				 * without a disk read.  v1 senders (or short
				 * packets) get version=1 = wake-all. */
				r = &ctx->nudge_ring[ctx->nudge_seq %
						     MXFS_CAW_NUDGE_RING];
				r->seq = ctx->nudge_seq;
				r->resource = msg.resource;
				if (msg.version >= 2 &&
				    len >= (int)sizeof(msg)) {
					r->version = msg.version;
					r->wake_mask = msg.wake_mask;
				} else {
					r->version = 1;
					r->wake_mask = 0;
				}
				mxfs_pal_cond_broadcast(ctx->nudge_cond);
				mxfs_pal_mutex_unlock(ctx->nudge_lock);
			}
			continue;
		}
		if (msg.magic != MXFS_BAST_MAGIC)
			continue;
		if (msg.requester == ctx->local_node)
			continue; /* Ignore our own */
		if (memcmp(msg.volume_uuid, ctx->volume_uuid, 16) != 0)
			continue; /* Wrong volume */

		/*
		 * A remote node wants a lock on this resource.
		 *
		 * sess128: SUBMIT, do not call.  This used to invoke
		 * ctx->bast_cb inline, and that callback reaches a shared-LUN
		 * SCSI read (and on the no-inode path a whole release
		 * pipeline).  On one thread, against ~19 waiters x 32 nodes
		 * re-sending every 100ms, it stalled this loop for seconds and
		 * overflowed a 4MB sk_rcvbuf — RcvbufErrors 8085, i.e. hints
		 * AND the grant nudges that share this socket were being
		 * silently dropped.  Submission is O(1) and never touches the
		 * device, so the socket now drains at line rate; a dispatcher
		 * thread runs the callback.  See struct mxfs_caw_bq_ent.
		 */
		caw_bast_submit(ctx, &msg.resource, msg.requested_mode);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST recv thread exiting");
}

/* ─── Lifecycle ─── */

/*
 * sess135: ONE unwind for every mxfs_dlm_caw_create() failure path.
 *
 * The context is memset to zero the instant it is allocated, so every pointer
 * this touches is either live or NULL, and every PAL destructor is NULL-safe
 * (mxfs_pal_free/mutex_destroy check explicitly; cond_destroy/spinlock_destroy
 * bottom out in kfree).  That makes a single unwind correct from ANY point in
 * the constructor.
 *
 * It replaces the per-site ladders, each of which had to re-list everything
 * allocated above it and so acquired a new leak every time an allocation was
 * inserted.  The stop_lock/stop_cond site had accumulated seven: mem_locks,
 * held.slots, mem_lock_mutex, slot_hints (+lock), grant_meta (+lock),
 * orphan_clock (+lock) and the whole lreq table with its reserve.
 *
 * Mirrors mxfs_dlm_caw_destroy's free list minus what can only exist after
 * start(): no threads are running and no socket is open, and the lreq buckets
 * are necessarily empty because nothing can join before create() returns the
 * pointer.  The reserve list IS drained — lreq_reserve_fill runs in here.
 */
static void caw_create_unwind(struct mxfs_dlm_caw_ctx *ctx)
{
	if (!ctx)
		return;

	while (ctx->lreq_reserve) {
		struct mxfs_caw_lreq *e = ctx->lreq_reserve;

		ctx->lreq_reserve = e->next;
		mxfs_pal_free(e);
	}
	ctx->lreq_reserve_n = 0;

	mxfs_pal_cond_destroy(ctx->lreq_cond);
	mxfs_pal_mutex_destroy(ctx->lreq_lock);
	mxfs_pal_free(ctx->lreq);

	mxfs_pal_cond_destroy(ctx->nudge_cond);
	mxfs_pal_mutex_destroy(ctx->nudge_lock);
	mxfs_pal_cond_destroy(ctx->stop_cond);
	mxfs_pal_mutex_destroy(ctx->stop_lock);

	mxfs_pal_spinlock_destroy(ctx->orphan_clock_lock);
	mxfs_pal_free(ctx->orphan_clock);
	mxfs_pal_mutex_destroy(ctx->grant_meta_lock);
	mxfs_pal_free(ctx->grant_meta);
	mxfs_pal_mutex_destroy(ctx->slot_hint_lock);
	mxfs_pal_free(ctx->slot_hints);

	caw_bastq_free(ctx);

	mxfs_pal_mutex_destroy(ctx->mem_lock_mutex);
	mxfs_pal_mutex_destroy(ctx->held.lock);
	mxfs_pal_free(ctx->mem_locks);
	mxfs_pal_free(ctx->held.slots);

	mxfs_pal_free(ctx);
}

struct mxfs_dlm_caw_ctx *mxfs_dlm_caw_create(mxfs_bdev_t *dev,
					        uint64_t disklock_offset,
					        mxfs_node_id_t local_node,
					        uint8_t node_slot,
					        const uint8_t *volume_uuid,
					        int max_held)
{
	struct mxfs_dlm_caw_ctx *ctx;

	if (!dev)
		return NULL;

	if (node_slot >= 64) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: invalid node_slot %u (must be 0-63)",
			     node_slot);
		return NULL;
	}

	/*
	 * v5 sess33: clamp max_held.  0 = use compile-time default;
	 * MXFS_CAW_MAX_SLOTS is the on-disk ceiling and the absolute
	 * upper bound for any value.
	 */
	if (max_held <= 0)
		max_held = MXFS_CAW_MAX_HELD;
	if (max_held > MXFS_CAW_MAX_SLOTS)
		max_held = MXFS_CAW_MAX_SLOTS;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));

	ctx->dev = dev;
	ctx->base_offset = disklock_offset;
	/* Lock region starts after the heartbeat area (64 slots x 512 bytes) */
	ctx->lock_region_offset = disklock_offset + MXFS_DISKLOCK_HB_SIZE;
	ctx->local_node = local_node;
	ctx->node_slot = node_slot;
	ctx->node_bit = 1ULL << node_slot;
	ctx->running = false;
	ctx->max_held = max_held;
	ctx->held.count = 0;
	ctx->bast_cb = NULL;
	ctx->cb_data = NULL;
	ctx->bast_poll_thread = NULL;
	ctx->bast_mcast_sock = NULL;
	ctx->bast_recv_thread = NULL;

	if (volume_uuid)
		memcpy(ctx->volume_uuid, volume_uuid, 16);

	ctx->held.slots = mxfs_pal_alloc((size_t)max_held * sizeof(uint32_t));
	if (!ctx->held.slots) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to alloc held.slots[%d]",
			     max_held);
		goto err;
	}

	ctx->mem_locks = mxfs_pal_alloc((size_t)max_held *
					sizeof(*ctx->mem_locks));
	if (!ctx->mem_locks) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to alloc mem_locks[%d]",
			     max_held);
		goto err;
	}

	ctx->held.lock = mxfs_pal_mutex_create();
	if (!ctx->held.lock) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create held list mutex");
		goto err;
	}

	ctx->mem_lock_mutex = mxfs_pal_mutex_create();
	if (!ctx->mem_lock_mutex) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create mem_lock mutex");
		goto err;
	}
	ctx->mem_lock_count = 0;
	ctx->single_node = false;

	/* sess128 BAST dispatch queue.  Optional like the caches below: a
	 * failed allocation degrades caw_bast_submit() to the pre-sess128
	 * inline callback on the producer thread (counted in bq.inline_cb),
	 * it does not fail create. */
	caw_bastq_init(ctx);

	/* v0.5.3 slot-index hint cache.  Optional: a failed allocation
	 * degrades to the pre-hint full-walk behavior (slot_hints NULL
	 * checks in slot_hint_get/store), it does not fail create. */
	ctx->slot_hints = mxfs_pal_alloc((size_t)MXFS_CAW_SLOTHINT_SIZE *
					 sizeof(*ctx->slot_hints));
	if (ctx->slot_hints) {
		memset(ctx->slot_hints, 0,
		       (size_t)MXFS_CAW_SLOTHINT_SIZE *
		       sizeof(*ctx->slot_hints));
		ctx->slot_hint_lock = mxfs_pal_mutex_create();
		if (!ctx->slot_hint_lock) {
			mxfs_pal_free(ctx->slot_hints);
			ctx->slot_hints = NULL;
		}
	}

	/* v0.6.0 grant-time epoch/handoff observations.  Optional like the
	 * hint cache: allocation failure degrades to epoch=0 answers (no
	 * epoch-driven adopt; ring path still covers), not a create failure. */
	ctx->grant_meta = mxfs_pal_alloc((size_t)MXFS_CAW_GRANTMETA_SIZE *
					 sizeof(*ctx->grant_meta));
	if (ctx->grant_meta) {
		memset(ctx->grant_meta, 0,
		       (size_t)MXFS_CAW_GRANTMETA_SIZE *
		       sizeof(*ctx->grant_meta));
		ctx->grant_meta_lock = mxfs_pal_mutex_create();
		if (!ctx->grant_meta_lock) {
			mxfs_pal_free(ctx->grant_meta);
			ctx->grant_meta = NULL;
		}
	}

	/* interactive session 2026-07-13: resource-scoped orphan-strand
	 * wall-clock table — see the struct comment in dlm_caw.h.  Optional
	 * like grant_meta: allocation failure degrades to get()=0 answers
	 * (the force-timeout escapes simply never fire on this ctx), not a
	 * create failure. */
	ctx->orphan_clock = mxfs_pal_alloc((size_t)MXFS_CAW_ORPHANCLOCK_SIZE *
					   sizeof(*ctx->orphan_clock));
	if (ctx->orphan_clock) {
		memset(ctx->orphan_clock, 0,
		       (size_t)MXFS_CAW_ORPHANCLOCK_SIZE *
		       sizeof(*ctx->orphan_clock));
		ctx->orphan_clock_lock = mxfs_pal_spinlock_create();
		if (!ctx->orphan_clock_lock) {
			mxfs_pal_free(ctx->orphan_clock);
			ctx->orphan_clock = NULL;
		}
	}

	/*
	 * sess112 local request registry.  Unlike the caches above, this table
	 * is NOT optional-degradable at use time: lreq_join returns NULL when
	 * it is absent and every acquire path then refuses with -ENOMEM rather
	 * than run on an unsound "nobody else is here" reading.  Allocation is
	 * a single pointer array (8KB), so failing here means the mount is out
	 * of memory anyway.
	 */
	ctx->lreq = mxfs_pal_alloc((size_t)MXFS_CAW_LREQ_BUCKETS *
				   sizeof(*ctx->lreq));
	if (ctx->lreq) {
		memset(ctx->lreq, 0,
		       (size_t)MXFS_CAW_LREQ_BUCKETS * sizeof(*ctx->lreq));
		ctx->lreq_lock = mxfs_pal_mutex_create();
		ctx->lreq_cond = mxfs_pal_cond_create();
		if (ctx->lreq_lock && ctx->lreq_cond)
			/* sess120: prime the destructive-clear reserve HERE,
			 * the one context in which allocating for it is
			 * unambiguously safe.  See ctx->lreq_reserve. */
			lreq_reserve_fill(ctx, MXFS_CAW_LREQ_RESERVE);
		if (!ctx->lreq_lock || !ctx->lreq_cond) {
			mxfs_pal_cond_destroy(ctx->lreq_cond);
			mxfs_pal_mutex_destroy(ctx->lreq_lock);
			ctx->lreq_cond = NULL;
			ctx->lreq_lock = NULL;
			mxfs_pal_free(ctx->lreq);
			ctx->lreq = NULL;
		}
	}
	if (!ctx->lreq) {
		/*
		 * sess114 (GPT ruling item 10): FAIL THE MOUNT.  This used to
		 * log and continue, which produced a mounted filesystem in
		 * which every single disk-lock acquisition returns -ENOMEM —
		 * not a designed degraded mode, just an unusable mount that
		 * reports its unusability one I/O at a time.  There is no
		 * degraded mode here by construction: the registry is the only
		 * discriminator between "another local thread depends on this
		 * bit" and "this bit is an orphan", and running without it is
		 * the unsound reading the whole mechanism exists to prevent.
		 */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: local request registry could not be created — refusing to bring up the DLM context");
		goto err;
	}

	ctx->stop_lock = mxfs_pal_mutex_create();
	ctx->stop_cond = mxfs_pal_cond_create();
	if (!ctx->stop_lock || !ctx->stop_cond) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create stop condvar");
		goto err;
	}

	/* ccloop 72513a13 sess3: grant-nudge condvar.  Allocation failure is
	 * non-fatal — caw_nudge_wait falls back to plain sleep_ms. */
	ctx->nudge_lock = mxfs_pal_mutex_create();
	ctx->nudge_cond = mxfs_pal_cond_create();
	if (!ctx->nudge_lock || !ctx->nudge_cond) {
		mxfs_pal_cond_destroy(ctx->nudge_cond);
		mxfs_pal_mutex_destroy(ctx->nudge_lock);
		ctx->nudge_lock = NULL;
		ctx->nudge_cond = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: created for node %u (slot %u, bit 0x%llx), "
		     "base_offset=%llu, lock_region_offset=%llu, "
		     "max_slots=%u max_held=%d",
		     local_node, node_slot,
		     (unsigned long long)ctx->node_bit,
		     (unsigned long long)ctx->base_offset,
		     (unsigned long long)ctx->lock_region_offset,
		     MXFS_CAW_MAX_SLOTS, ctx->max_held);

	return ctx;

err:
	caw_create_unwind(ctx);
	return NULL;
}

/*
 * sess134 (GPT sess133 ruling A3): the lifecycle transitions live here, and a
 * failed start lands in MXFS_CAW_LC_START_FAILED rather than back in NEW.
 *
 * The distinction is not cosmetic.  A start that unwound may have left
 * published residue behind — the mount-time own-slot reclaim already ran, and
 * the transient threads it tore down could have touched slots — so treating a
 * failed start as "never started, therefore clean" would be exactly the vacuous
 * pass the verdict must never produce.  stop() runs the SAME teardown body for
 * START_FAILED as for RUNNING and lets the census decide.
 */
static void caw_set_lc(struct mxfs_dlm_caw_ctx *ctx, enum mxfs_caw_lifecycle lc)
{
	if (ctx->lreq_lock) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		ctx->lc = lc;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	} else {
		ctx->lc = lc;
	}
}

int mxfs_dlm_caw_start(struct mxfs_dlm_caw_ctx *ctx)
{
	int rc;

	if (!ctx)
		return -EINVAL;

	caw_set_lc(ctx, MXFS_CAW_LC_STARTING);
	ctx->running = true;

	/*
	 * sess128: the BAST dispatchers come up FIRST, before either producer,
	 * so no submission can land on a queue with nobody draining it.  The
	 * ordering is the mirror image of teardown (producers die first, then
	 * the workers that consume what they left).
	 *
	 * Failure is non-fatal and degrades exactly as an allocation failure in
	 * caw_bastq_init does: with zero dispatchers alive the queue would fill
	 * and every hint would be dropped, which is strictly worse than the
	 * pre-sess128 behaviour, so tear the queue down and let
	 * caw_bast_submit() take its inline path.  A PARTIAL fleet is fine —
	 * one dispatcher still drains, it just serialises more.
	 */
	if (ctx->bq.pool) {
		int w;
		int nw = 0;

		for (w = 0; w < MXFS_CAW_BAST_WORKERS; w++) {
			ctx->bast_disp_thread[w] =
				mxfs_pal_thread_create(caw_bast_disp_fn, ctx);
			if (ctx->bast_disp_thread[w])
				nw++;
		}
		if (!nw) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: no BAST dispatcher could be started — falling back to inline BAST callbacks");
			caw_bastq_free(ctx);
		} else if (nw < MXFS_CAW_BAST_WORKERS) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: only %d of %d BAST dispatchers started",
				     nw, MXFS_CAW_BAST_WORKERS);
		}
	}

	/* Start BAST poll thread */
	ctx->bast_poll_thread = mxfs_pal_thread_create(bast_poll_fn, ctx);
	if (!ctx->bast_poll_thread) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to start BAST poll thread");
		ctx->running = false;
		caw_bastq_join_workers(ctx,
				       mxfs_pal_time_ms() +
					       MXFS_CAW_QUIESCE_MS);
		caw_set_lc(ctx, MXFS_CAW_LC_START_FAILED);
		return -ENOMEM;
	}

	/*
	 * sess125: the owed-cleanup worker.  FAILING THE START IS DELIBERATE.
	 * It is the only collector of obligations to clear this node's slot
	 * bits, and an obligation that is never collected leaves an EX-waiter
	 * bit behind that makes every peer defer fresh readers behind a request
	 * nobody is making — the measured 16-node >600s wedge.  Mounting without
	 * it would be mounting a filesystem that can permanently wedge its
	 * peers, so a mount that cannot start it must not proceed.
	 *
	 * Only when there IS a registry: without one the whole obligation
	 * mechanism is inert (single-node teardown / legacy paths), and a worker
	 * would have nothing to sweep.
	 */
	if (ctx->lreq && ctx->lreq_lock && ctx->lreq_cond) {
		ctx->owed_worker = mxfs_pal_thread_create(caw_owed_worker_fn,
							  ctx);
		if (!ctx->owed_worker) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "dlm_caw: failed to start owed-cleanup worker");
			/* Unwind the BAST poll thread we already started, or it
			 * runs on against a ctx the caller is about to tear
			 * down.
			 *
			 * sess134 (ruling A1's second hole): BOUNDED.  A
			 * failed-start unwind that blocks forever on a wedged
			 * transient thread makes every later waiter for
			 * `lc != STARTING` unbounded too, and that thread holds
			 * the same mount reference the running one would. */
			ctx->running = false;
			if (ctx->stop_cond)
				mxfs_pal_cond_signal(ctx->stop_cond);
			caw_join_bounded(ctx, &ctx->bast_poll_thread,
					 "bast_poll(start-unwind)",
					 mxfs_pal_time_ms() +
						MXFS_CAW_QUIESCE_MS);
			/* Producer is gone; now the consumers it fed. */
			caw_bastq_join_workers(ctx,
					       mxfs_pal_time_ms() +
						       MXFS_CAW_QUIESCE_MS);
			caw_set_lc(ctx, MXFS_CAW_LC_START_FAILED);
			return -ENOMEM;
		}
	}

	/* Setup UDP multicast BAST socket (best effort — works without it) */
	ctx->bast_mcast_sock = mxfs_pal_udp_open(MXFS_CAW_BAST_PORT);
	if (ctx->bast_mcast_sock) {
		mxfs_pal_udp_set_recv_timeout(ctx->bast_mcast_sock, 500);

		rc = mxfs_pal_udp_join_multicast(ctx->bast_mcast_sock,
						  MXFS_DISCOVERY_MCAST);
		if (rc < 0) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: multicast join failed: %d "
				     "(BAST multicast disabled, poll-only mode)",
				     rc);
			mxfs_pal_udp_close(ctx->bast_mcast_sock);
			ctx->bast_mcast_sock = NULL;
		} else {
			/* Start BAST receive thread */
			ctx->bast_recv_thread =
				mxfs_pal_thread_create(bast_recv_fn, ctx);
			if (!ctx->bast_recv_thread) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "dlm_caw: failed to start BAST "
					     "recv thread (poll-only mode)");
				mxfs_pal_udp_close(ctx->bast_mcast_sock);
				ctx->bast_mcast_sock = NULL;
			} else {
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "dlm_caw: BAST multicast enabled "
					     "on %s:%u",
					     MXFS_DISCOVERY_MCAST,
					     MXFS_CAW_BAST_PORT);
			}
		}
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "dlm_caw: failed to open BAST UDP socket "
			     "(poll-only mode)");
	}

	caw_set_lc(ctx, MXFS_CAW_LC_RUNNING);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: started for node %u", ctx->local_node);
	return 0;
}

void mxfs_dlm_caw_set_release_on_stop(struct mxfs_dlm_caw_ctx *ctx, bool on)
{
	if (ctx)
		ctx->release_on_stop = on;
}

bool mxfs_dlm_caw_departed_clean(struct mxfs_dlm_caw_ctx *ctx)
{
	bool v;

	/*
	 * No CAW context means no CAW bits to account for — a TCP-transport
	 * mount, or one that never got this far.  The question does not apply,
	 * and answering false would suppress a clean departure that has nothing
	 * to do with this mechanism.
	 */
	if (!ctx)
		return true;
	if (!ctx->lreq_lock)
		return ctx->departed_clean;

	/* sess134 (ruling A1): the owner's STORED verdict, under the lock that
	 * publishes it together with MXFS_CAW_LC_STOPPED. */
	mxfs_pal_mutex_lock(ctx->lreq_lock);
	v = ctx->departed_clean;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return v;
}

/*
 * sess132 (GPT sess130 ruling, step 5).  Both setters take lreq_lock: the
 * escalation paths read these fields under it, and the membership setter is
 * called from the v5 membership callback, which is a different thread entirely.
 * A ctx with no registry has no escalation machinery, so there is nothing to
 * register against — that case is silently a no-op rather than an error,
 * exactly as the admission gate is.
 */
void mxfs_dlm_caw_set_owed_stuck_fn(struct mxfs_dlm_caw_ctx *ctx,
				    void (*fn)(void *data), void *data)
{
	if (!ctx || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	/*
	 * Teardown clears the channel after the worker join and must not be
	 * re-opened behind it: a late registration would hand a live callback
	 * to a context whose owner is already gone.
	 */
	if (!ctx->ops_closed) {
		ctx->owed_stuck_fn = fn;
		ctx->owed_stuck_data = data;
	}
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

void mxfs_dlm_caw_set_membership(struct mxfs_dlm_caw_ctx *ctx,
				 uint64_t view, uint32_t members)
{
	if (!ctx || !ctx->lreq_lock)
		return;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	ctx->mship_view = view;
	ctx->mship_members = members;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
}

bool mxfs_dlm_caw_unsafe_to_free(struct mxfs_dlm_caw_ctx *ctx)
{
	bool v;

	if (!ctx)
		return false;
	if (!ctx->lreq_lock)
		return ctx->unsafe_to_free;

	mxfs_pal_mutex_lock(ctx->lreq_lock);
	v = ctx->unsafe_to_free;
	mxfs_pal_mutex_unlock(ctx->lreq_lock);
	return v;
}

/*
 * ─── sess131 (GPT sess130 ruling, blockers 2 + 3): TEARDOWN ───
 *
 * WHAT THIS FUNCTION HAS TO PROVE, and why the order is not negotiable.
 *
 * A clean departure tells peers they may reclaim this node's resources WITHOUT
 * the fence → slice-replay → purge protocol.  It is therefore a claim, and the
 * claim is: every bit this node set in the on-disk slot table is gone.  The old
 * shape could not support it.  `running = false` was read by no producer, so
 * nothing had quiesced; release_all ran from destroy() AFTER the worker join,
 * so anything it failed to clear could never be collected; and the drain began
 * the instant the worker's main loop ended, i.e. before release_all had
 * contributed to the obligation set it was draining.
 *
 * GPT's ruling identified the race that makes the ordering mandatory, and it
 * exists in the pre-sess131 code:
 *
 *      release_all clears every holder bit
 *      an acquire ALREADY INSIDE the door continues
 *      it succeeds and re-takes a holder bit
 *      it publishes NOTHING — success needs no cleanup
 *      quiesce observes that operation finish
 *      drain finds no obligation
 *      node sends GOODBYE while still holding the bit on disk
 *
 * So release_all must run AFTER admission closes and the in-flight count hits
 * zero, in a phase where it is the only thing touching the table:
 *
 *      1  close admission                     (no new producer)
 *      2  wait for the already-admitted       (no live producer)
 *      3  join the other producers            (no BAST-driven producer)
 *      4  release_all, EXCLUSIVELY            (publishes what it cannot clear)
 *      5  arm + run the drain                 (collects, absolute deadline)
 *      6  authoritative residue census        (registry, not queue emptiness)
 *      7  departed_clean = (census == 0)
 *
 * ON A QUIESCE THAT DOES NOT COMPLETE.  Teardown does NOT continue past a live
 * producer.  Proceeding would let a late producer publish after the final census
 * and destroy the very claim the census makes, and freeing the ctx under an
 * operation still inside it is a use-after-free.
 *
 * ─── sess134 (GPT sess133 ruling B): AND IT DOES NOT WAIT FOREVER EITHER ───
 *
 * The pre-sess134 answer to that was "escalate loudly and keep waiting", which
 * is a permanent kernel hang wearing a diagnostic.  The bound is now explicit
 * and it ends in a local fail-stop rather than a return:
 *
 *      t0 + MXFS_CAW_QUIESCE_MS        latch the expiry (sticky: a clean
 *                                      departure is now impossible for this
 *                                      attempt even if the phase completes),
 *                                      queue the force-shutdown request
 *      ... + failstop grace            mandatory non-returning fail-stop
 *
 * That deadline is ABSOLUTE for the whole teardown, not per phase: phases 2, 3
 * and 5 all block, and a bound that resets at each phase boundary is not a
 * bound.  It is also enforced by this thread, never by the escalation — the
 * work item is a channel and may never run at all.
 *
 * WHY NOT SIMPLY RETURN AT THE DEADLINE.  Returning means skipping phases 3-6,
 * so the BAST poll and BAST multicast threads are still live, still calling
 * ctx->bast_cb, and that callback reaches closures holding the XFS mount which
 * the VFS frees regardless.  Leaking the CAW context does not save it and
 * clearing bast_cb closes only the future window.  See the block comment on
 * MXFS_CAW_FAILSTOP_GRACE_MS.
 */
void mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx)
{
	uint64_t t0, esc_at, next_gripe;
	uint32_t rel_owed = 0, rel_lost = 0, left = 0;
	bool quiesced = true, rel_done = false, expired = false;
	bool release_now;
	int held_now = 0;

	if (!ctx)
		return;

	/*
	 * ─── sess134 (GPT sess133 ruling A1): ELECT THE TEARDOWN OWNER ───
	 *
	 * Exactly one caller runs the phases below.  Every other caller waits
	 * for the owner to publish MXFS_CAW_LC_STOPPED and then returns, leaving
	 * the owner's stored verdict untouched.
	 *
	 * The bug this replaces: `running` was cleared in phase 1, so a second
	 * caller arriving during phases 2-6 read `running == false`, took the
	 * "already stopped" shortcut, and returned as though teardown had
	 * COMPLETED — free to destroy and free a context the first caller was
	 * still inside.  destroy() makes exactly that second call.
	 *
	 * The wait is bounded because every phase below is bounded and ends in a
	 * fail-stop rather than an indefinite block (ruling A1's condition on
	 * this design, satisfied by caw_join_bounded and the phase-2 deadline).
	 */
	if (ctx->lreq_lock) {
		mxfs_pal_mutex_lock(ctx->lreq_lock);
		while (ctx->lc == MXFS_CAW_LC_STOPPING) {
			if (ctx->lreq_cond)
				mxfs_pal_cond_timedwait(ctx->lreq_cond,
							ctx->lreq_lock,
							MXFS_CAW_QUIESCE_POLL_MS);
			else
				break;
		}
		if (ctx->lc == MXFS_CAW_LC_STOPPED ||
		    ctx->lc == MXFS_CAW_LC_STOPPING) {
			mxfs_pal_mutex_unlock(ctx->lreq_lock);
			return;
		}
		/*
		 * NEW / STARTING / RUNNING / START_FAILED all converge here and
		 * run the SAME teardown body (ruling A3).  A never-started ctx
		 * is not automatically clean: the mount-time own-slot reclaim
		 * runs before start() and a failed start may have published
		 * residue, so the phases below must decide it, not an
		 * assumption.  Threads that were never created are no-ops.
		 */
		ctx->lc = MXFS_CAW_LC_STOPPING;
		ctx->ops_closed = true;
		ctx->running = false;
		ctx->release_all_done = false;
		ctx->lreq_owed_work_seq++;
		release_now = ctx->release_on_stop;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
	} else {
		if (ctx->lc == MXFS_CAW_LC_STOPPING ||
		    ctx->lc == MXFS_CAW_LC_STOPPED)
			return;
		ctx->lc = MXFS_CAW_LC_STOPPING;
		ctx->ops_closed = true;
		ctx->running = false;
		ctx->release_all_done = false;
		release_now = ctx->release_on_stop;
	}

	t0 = mxfs_pal_time_ms();
	esc_at = t0 + MXFS_CAW_QUIESCE_MS;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: stopping for node %u", ctx->local_node);

	/*
	 * PHASE 1 — admission is already closed and the thread loops already
	 * ended, both published INSIDE lreq_lock by the election above with the
	 * work sequence bumped in the same section (sess127, blocker 6): the
	 * owed worker's park predicate re-reads them under that lock, so a
	 * worker preempted between its test and its park cannot sleep through
	 * this.  It is also the release/acquire pairing that `volatile` alone
	 * does not give.
	 *
	 * `ops_closed` before anything else is what makes phase 2 a census of
	 * the producers rather than a sample of them.
	 *
	 * `release_on_stop` was SNAPSHOTTED in that same section (ruling A3):
	 * teardown must not observe two different answers to "does this mount
	 * release?" in two different phases.
	 */

	/* Wake BAST poll thread from condvar sleep */
	if (ctx->stop_cond)
		mxfs_pal_cond_signal(ctx->stop_cond);
	if (ctx->lreq_cond)
		mxfs_pal_cond_broadcast(ctx->lreq_cond);

	/*
	 * PHASE 2 — wait out the operations already past the door.
	 *
	 * They see `running == false` and unwind on their own deadlines; the
	 * unwind may publish obligations, and it does so under lreq_lock before
	 * decrementing ops_active under that same lock, which is the whole
	 * ordering proof (see caw_op_enter).
	 */
	if (ctx->lreq_lock && ctx->lreq_cond) {
		uint64_t failstop_at = 0;

		next_gripe = esc_at;

		mxfs_pal_mutex_lock(ctx->lreq_lock);
		while (ctx->ops_active) {
			uint64_t now = mxfs_pal_time_ms();

			/*
			 * sess134 (ruling B2): the FIRST expiry is the fault
			 * detection point.  It latches — permanently — that this
			 * departure cannot be clean, queues the force-shutdown
			 * request, and arms the one final grace.  It does NOT
			 * end the wait: a producer that leaves inside the grace
			 * still lets teardown finish its remaining phases and
			 * get the bits off the disk, which is strictly better
			 * than fail-stopping the instant the budget lapses.
			 */
			if (now >= next_gripe) {
				bool first;

				quiesced = false;
				first = caw_teardown_expire_locked(ctx);
				if (!failstop_at)
					failstop_at = now +
						caw_failstop_grace_ms();
				next_gripe = now + MXFS_CAW_QUIESCE_GRIPE_MS;
				pr_err("mxfs: P258-QUIESCE-STUCK node=%u active=%u waited_ms=%llu failstop_in_ms=%llu — %u operation(s) entered before teardown have not left; this mount cannot prove its slot bits are gone, will NOT claim a clean departure, and will fail-stop if they do not leave before the deadline\n",
				       ctx->local_node, ctx->ops_active,
				       (unsigned long long)(now - t0),
				       (unsigned long long)(failstop_at - now),
				       ctx->ops_active);
				if (first) {
					mxfs_pal_mutex_unlock(ctx->lreq_lock);
					caw_teardown_escalate_queue(ctx);
					mxfs_pal_mutex_lock(ctx->lreq_lock);
					continue;
				}
			}

			/*
			 * The terminal deadline, enforced HERE and not by the
			 * escalation: the work item is a channel and may never
			 * run.  Non-returning — see the header comment for why
			 * returning is a use-after-free rather than a retreat.
			 */
			if (failstop_at && now >= failstop_at) {
				uint32_t active = ctx->ops_active;

				mxfs_pal_mutex_unlock(ctx->lreq_lock);
				mxfs_pal_failstop("mxfs: CAW teardown: node %u still has %u operation(s) inside the DLM after %llums (quiesce budget + %ums grace); they hold references into a mount that is being freed and can still write the shared LUN — fail-stopping this node rather than corrupting the cluster",
						  ctx->local_node, active,
						  (unsigned long long)(now - t0),
						  caw_failstop_grace_ms());
			}

			mxfs_pal_cond_timedwait(ctx->lreq_cond, ctx->lreq_lock,
						MXFS_CAW_QUIESCE_POLL_MS);
		}
		ctx->quiesce_ms = mxfs_pal_time_ms() - t0;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);

		if (!quiesced)
			pr_err("mxfs: P258-QUIESCE-LATE node=%u waited_ms=%llu — the stuck operations left inside the fail-stop grace, so teardown continues; the clean-departure refusal stands\n",
			       ctx->local_node,
			       (unsigned long long)ctx->quiesce_ms);
	} else {
		/*
		 * No registry, no gate, no census.  This ctx cannot prove
		 * anything about its producers, so it must not claim a clean
		 * departure — but it also has no obligation machinery to
		 * escalate through.  (Unreachable on a mounted filesystem: the
		 * registry allocation is all-or-nothing and mount fails when it
		 * fails.)
		 */
		quiesced = false;
		ctx->departed_clean = false;
	}

	/*
	 * PHASE 3 — join the remaining publication-capable producers.
	 *
	 * The BAST threads drive releases, and a release publishes.  They must
	 * be gone before release_all runs, or phase 4 is racing exactly the way
	 * the ruling describes.  The owed worker is NOT joined here: it is the
	 * consumer, it has parked on `drain_armed`, and it is the last thing to
	 * leave.
	 *
	 * sess134 (ruling B1): BOUNDED joins.  These two threads are precisely
	 * the ones that make an abandoning return unsafe — they call
	 * ctx->bast_cb, which reaches into the XFS mount the VFS is about to
	 * free — so their deadline is the same absolute one phase 2 uses and its
	 * expiry is a fail-stop, not a skip.
	 */
	if (ctx->bast_mcast_sock)
		mxfs_pal_udp_shutdown(ctx->bast_mcast_sock);

	caw_join_bounded(ctx, &ctx->bast_recv_thread, "bast_recv", esc_at);
	caw_join_bounded(ctx, &ctx->bast_poll_thread, "bast_poll", esc_at);

	/*
	 * sess128: and only NOW the dispatchers.  Both producers are joined
	 * above, so nothing can submit any more; whatever is still queued is
	 * abandoned deliberately, because a BAST callback issued after this
	 * point would drive a release that publishes — the very thing phase 3
	 * exists to make impossible before release_all runs below.
	 */
	caw_bastq_join_workers(ctx, esc_at);
	caw_bastq_report(ctx, "stop");

	/*
	 * PHASE 4 — the exclusive release.
	 *
	 * Suppressed for a WITHDRAWN mount (release_on_stop == false): our
	 * journal slice may be unreplayed, and handing peers the locks hands
	 * them the torn state the withdraw froze.  That mount is not departing
	 * cleanly by definition, and departed_clean stays false below because
	 * the escalation latch or the caller's own withdrawal forbids it.
	 *
	 * NOT gated on `quiesced`.  Phase 2 exits only at ops_active == 0, so by
	 * here the exclusivity the ruling requires holds regardless of how long
	 * it took; a late quiesce forbids the CLAIM (via the latch), it does not
	 * make the mechanical cleanup less correct.  Skipping the release would
	 * leave strictly more bits on the disk.
	 */
	if (release_now) {
		/*
		 * sess154 (P248 fix A): the phase-4 PUBLICATION FREEZE
		 * snapshot.  Taken here — after phases 2+3 joined every
		 * publication-capable producer, immediately before the
		 * release — NOT at phase-2 exit: the BAST threads phase 3
		 * joins drive releases, and releases publish.  The teardown
		 * retire in caw_owed_release compares the live generation
		 * against this; any mismatch means a publication landed after
		 * the freeze and the retire must refuse (fail closed).
		 */
		if (ctx->lreq_lock) {
			mxfs_pal_mutex_lock(ctx->lreq_lock);
			ctx->stop_finish_gen = ctx->lreq_finish_gen;
			mxfs_pal_mutex_unlock(ctx->lreq_lock);
		} else {
			ctx->stop_finish_gen = ctx->lreq_finish_gen;
		}
		caw_release_all_body(ctx, &rel_owed, &rel_lost);
	} else {
		mxfs_pal_log(MXFS_LOG_INFO,
			     "mxfs: dlm_caw: release_all suppressed at stop for node %u (withdrawn/frozen)",
			     ctx->local_node);
	}

	/*
	 * sess134 (ruling A3): the no-release verdict term needs the held-list
	 * depth, and held.lock must be taken BEFORE lreq_lock — never nested the
	 * other way, which is the order every acquire path uses.  Snapshot it
	 * here, outside both, and let phase 6 read the snapshot.
	 */
	if (ctx->held.lock) {
		mxfs_pal_mutex_lock(ctx->held.lock);
		held_now = ctx->held.count;
		mxfs_pal_mutex_unlock(ctx->held.lock);
	}

	/*
	 * PHASE 5 — arm the drain and join its worker.
	 *
	 * Everything release_all could not clear is now IN the obligation set,
	 * so the drain is collecting the complete thing rather than a prefix of
	 * it.  The join must happen while the transport is still up: this is
	 * the last chance to get these bits off the disk.
	 */
	if (ctx->owed_worker) {
		if (ctx->lreq_lock) {
			mxfs_pal_mutex_lock(ctx->lreq_lock);
			ctx->drain_armed = true;
			ctx->lreq_owed_work_seq++;
			mxfs_pal_mutex_unlock(ctx->lreq_lock);
		}
		if (ctx->lreq_cond)
			mxfs_pal_cond_broadcast(ctx->lreq_cond);
		/*
		 * sess134 (ruling B1): bounded, like the BAST joins.  The owed
		 * worker issues CAW writes to the shared LUN, so a wedged one is
		 * exactly a thread that must not outlive this mount's belief
		 * that it has departed.
		 */
		caw_join_bounded(ctx, &ctx->owed_worker, "owed_worker", esc_at);
	}

	/*
	 * PHASE 6 — the authoritative census, and the verdict.
	 *
	 * caw_owed_count walks the registry buckets under lreq_lock; it is the
	 * state itself, not the ready-queue's emptiness (ruling item 9 — a
	 * queue can be empty because entries are claimed, backed off, or busy).
	 *
	 * `rel_lost` is separate and is not collectable: those are slots whose
	 * residue could not even be recorded.  Either one refuses the claim.
	 *
	 * Census and verdict share ONE critical section.  Reading the count and
	 * then writing the verdict under a second acquisition would let a
	 * publication land between them — which cannot happen here, since every
	 * producer is joined, but a census whose atomicity depends on an
	 * argument about who else is running is not a census.
	 */
	if (ctx->lreq_lock) {
		bool clean;

		mxfs_pal_mutex_lock(ctx->lreq_lock);
		left = caw_owed_count_locked(ctx);
		rel_done = ctx->release_all_done;
		expired = ctx->teardown_expired;
		ctx->held_at_stop = held_now;
		/*
		 * The latch, NOT the callback.  This escalation is post-join and
		 * is deliberately never delivered upward: by here the mount is
		 * already tearing down, `mxfs_dlm_shutdown_withdraw` returns
		 * early on the NULLed mp->m_mxfs_dlm anyway, and a work item
		 * armed from inside teardown is cancelled by the very
		 * cancel_work_sync that precedes it.  What DOES carry the
		 * failure out of here is the recorded state below, which the
		 * layer above reads with mxfs_dlm_caw_departed_clean() — which
		 * is exactly why ruling item 5 required the state to be the
		 * safety latch and the callback merely a channel.
		 */
		if (left || rel_lost)
			(void)caw_owed_fail_latch(ctx);
		/*
		 * ─── sess134 (GPT sess133 ruling A3): THE RELEASE TERM ───
		 *
		 * The two arms are different claims and neither implies the
		 * other:
		 *
		 *   release_now  — we swept, so the claim is that the sweep's
		 *                  TRAVERSAL FINISHED and lost nothing.  A sweep
		 *                  that returned early cleared an unknown prefix
		 *                  of the held list; "release_all was called" is
		 *                  not evidence about the suffix.
		 *   !release_now — we deliberately did not sweep (withdrawn or
		 *                  frozen), so the only way this node can still
		 *                  claim a clean departure is by having held
		 *                  nothing at all.  Any held slot is a bit left
		 *                  on the disk with no sweep behind it.
		 *
		 * `expired` is the sticky fail-stop-grace latch: a teardown that
		 * blew its budget may never claim clean, even though it
		 * subsequently finished every phase (ruling B2).
		 */
		clean = quiesced && !expired && !ctx->owed_failed &&
			left == 0 && rel_lost == 0 &&
			(release_now ? rel_done : held_now == 0);
		ctx->departed_clean = clean;
		/*
		 * Ruling item 5, second half: no escalation may be issued after
		 * the worker join, so the channel is closed here, under the
		 * same lock every publisher uses.
		 */
		ctx->owed_stuck_fn = NULL;
		ctx->owed_stuck_data = NULL;
		/*
		 * sess134 (ruling A2): the COMPLETE verdict is stored BEFORE the
		 * state is published, both in this one critical section, and the
		 * broadcast comes after both.  A waiter that sees STOPPED
		 * therefore sees the finished verdict and never an intermediate.
		 */
		ctx->lc = MXFS_CAW_LC_STOPPED;
		mxfs_pal_mutex_unlock(ctx->lreq_lock);
		if (ctx->lreq_cond)
			mxfs_pal_cond_broadcast(ctx->lreq_cond);
	} else {
		ctx->departed_clean = false;
		ctx->lc = MXFS_CAW_LC_STOPPED;
	}

	if (!ctx->departed_clean)
		pr_err("mxfs: P259-DEPART-UNCLEAN node=%u quiesced=%d expired=%d released=%d rel_done=%d held=%d rel_owed=%u rel_lost=%u owed_left=%u quiesce_ms=%llu — this node cannot prove its CAW slot bits are gone; peers must fence and replay it rather than reclaim it as a clean leaver\n",
		       ctx->local_node, quiesced, expired, release_now,
		       rel_done, held_now, rel_owed, rel_lost, left,
		       (unsigned long long)ctx->quiesce_ms);
	else
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "dlm_caw: node %u departed clean (quiesce_ms=%llu, rel_owed=%u)",
			     ctx->local_node,
			     (unsigned long long)ctx->quiesce_ms, rel_owed);
}

void mxfs_dlm_caw_destroy(struct mxfs_dlm_caw_ctx *ctx)
{
	if (!ctx)
		return;

	mxfs_dlm_caw_stop(ctx);

	/*
	 * sess131 (GPT sess130 ruling): destroy no longer releases.
	 *
	 * The release_all that used to live here ran AFTER stop() had joined the
	 * owed worker, so any obligation it published had no collector left and
	 * was lost by construction — the exact gap the lifecycle restructure
	 * exists to close.  stop() now owns the release, in the exclusive phase
	 * between quiescence and the drain.
	 *
	 * It was also a correctness bug in its own right: mxfs_v5_dlm_shutdown
	 * deliberately SKIPS the release for a withdrawn mount (the D2 freeze —
	 * our journal slice may be unreplayed and releasing hands peers torn
	 * state), and this unconditional call ran anyway and defeated it.  The
	 * suppression is now honoured because it is expressed as
	 * release_on_stop, which stop() reads.
	 */

	/*
	 * An operation admitted before teardown never left, so something still
	 * holds this pointer.  Freeing is a use-after-free; the only safe move
	 * is to leak the context and say so.  On a mount that is going away this
	 * costs one context's memory until reboot, which is strictly better than
	 * corrupting whatever the stuck thread touches next.
	 */
	/*
	 * sess134 (ruling A2): inspected under the SAME synchronization that
	 * publishes it, and after stop() above has run to MXFS_CAW_LC_STOPPED —
	 * so this reads a finished verdict whether this thread owned teardown or
	 * waited for the thread that did.
	 *
	 * SINGLE-DESTROY CONTRACT.  Serialising stop() does NOT serialise two
	 * destroy() callers: the second would free everything the first already
	 * freed.  destroy() has exactly one caller per context in-tree (the
	 * mount teardown that owns the pointer and NULLs it); this is stated
	 * rather than enforced, and a refcount is the fix if that ever changes.
	 */
	if (mxfs_dlm_caw_unsafe_to_free(ctx)) {
		pr_err("mxfs: P260-CAW-CTX-LEAKED node=%u active=%u — the DLM context is still referenced by an operation that never left teardown; it is deliberately NOT freed\n",
		       ctx->local_node, ctx->ops_active);
		return;
	}

	if (ctx->bast_mcast_sock) {
		mxfs_pal_udp_close(ctx->bast_mcast_sock);
		ctx->bast_mcast_sock = NULL;
	}

	if (ctx->stop_cond) {
		mxfs_pal_cond_destroy(ctx->stop_cond);
		ctx->stop_cond = NULL;
	}
	if (ctx->stop_lock) {
		mxfs_pal_mutex_destroy(ctx->stop_lock);
		ctx->stop_lock = NULL;
	}
	if (ctx->nudge_cond) {
		mxfs_pal_cond_destroy(ctx->nudge_cond);
		ctx->nudge_cond = NULL;
	}
	if (ctx->nudge_lock) {
		mxfs_pal_mutex_destroy(ctx->nudge_lock);
		ctx->nudge_lock = NULL;
	}
	/* sess128: safe here and only here — stop() above joined every
	 * dispatcher in phase 3, and the unsafe_to_free gate above already
	 * refused to free anything if an admitted operation never left. */
	caw_bastq_free(ctx);
	if (ctx->held.lock) {
		mxfs_pal_mutex_destroy(ctx->held.lock);
		ctx->held.lock = NULL;
	}
	if (ctx->mem_lock_mutex) {
		mxfs_pal_mutex_destroy(ctx->mem_lock_mutex);
		ctx->mem_lock_mutex = NULL;
	}
	if (ctx->slot_hints) {
		mxfs_pal_free(ctx->slot_hints);
		ctx->slot_hints = NULL;
	}
	if (ctx->slot_hint_lock) {
		mxfs_pal_mutex_destroy(ctx->slot_hint_lock);
		ctx->slot_hint_lock = NULL;
	}
	if (ctx->grant_meta) {
		mxfs_pal_free(ctx->grant_meta);
		ctx->grant_meta = NULL;
	}
	if (ctx->grant_meta_lock) {
		mxfs_pal_mutex_destroy(ctx->grant_meta_lock);
		ctx->grant_meta_lock = NULL;
	}
	if (ctx->orphan_clock) {
		mxfs_pal_free(ctx->orphan_clock);
		ctx->orphan_clock = NULL;
	}
	if (ctx->orphan_clock_lock) {
		mxfs_pal_spinlock_destroy(ctx->orphan_clock_lock);
		ctx->orphan_clock_lock = NULL;
	}
	/* sess112: drain the local request registry.  Any entry still chained
	 * here at destroy time outlived its resource — report it rather than
	 * free it silently, because a surviving tenure count means some
	 * release path never told the registry its bits were gone. */
	if (ctx->lreq) {
		uint32_t b;
		uint32_t leaked = 0;

		for (b = 0; b < MXFS_CAW_LREQ_BUCKETS; b++) {
			struct mxfs_caw_lreq *e = ctx->lreq[b];

			while (e) {
				struct mxfs_caw_lreq *next = e->next;

				/*
				 * sess151: name the survivors (first 8 — the
				 * cap bounds log volume on a mass leak).  The
				 * aggregate count below says THAT entries
				 * leaked; this says WHICH resource and in
				 * what state, which is the difference between
				 * a diagnosable report and a number.
				 */
				if (leaked < 8)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P248-LREQ-LEAK-ENT type=%c id=%llu tenure=%u/%u/%u/%u/%u/%u pub_seq=%llu attempts=%u writers=%u pin=%u clr_active=%u owed_pend=%d busy=%d oq=%d",
					    e->resource.type == MXFS_LTYPE_INODE ? 'I' :
					    e->resource.type == MXFS_LTYPE_AG ? 'A' : 'O',
					    (unsigned long long)(e->resource.type == MXFS_LTYPE_INODE ?
						e->resource.ino :
						(uint64_t)e->resource.ag_number),
					    e->tenure[MXFS_LOCK_NL],
					    e->tenure[MXFS_LOCK_CR],
					    e->tenure[MXFS_LOCK_CW],
					    e->tenure[MXFS_LOCK_PR],
					    e->tenure[MXFS_LOCK_PW],
					    e->tenure[MXFS_LOCK_EX],
					    (unsigned long long)e->pub_seq,
					    e->attempts, e->writers, e->pin,
					    e->clr_active,
					    lreq_owed_pending(e) ? 1 : 0,
					    e->owed_busy ? 1 : 0,
					    e->oq_queued ? 1 : 0);
				leaked++;
				mxfs_pal_free(e);
				e = next;
			}
			ctx->lreq[b] = NULL;
		}
		/* sess129 (blocker 4): the owed-ready queue indexes the very
		 * entries just freed.  Drop it wholesale HERE rather than
		 * unlinking per entry above — this runs after the collector has
		 * been joined, so there is nobody left to schedule. */
		ctx->owed_q_head = NULL;
		ctx->owed_q_tail = NULL;
		ctx->owed_q_n = 0;
		if (leaked)
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P248-LREQ-LEAK entries=%u guard=%llu defer=%llu owed=%llu exhaust=%llu nomem=%llu — registry entries survived teardown",
			    leaked,
			    (unsigned long long)ctx->lreq_guard_hits,
			    (unsigned long long)ctx->lreq_defer_hits,
			    (unsigned long long)ctx->lreq_owed_runs,
			    (unsigned long long)ctx->lreq_exhausted,
			    (unsigned long long)ctx->lreq_nomem);
		mxfs_pal_free(ctx->lreq);
		ctx->lreq = NULL;
	}
	/* sess120: the destructive-clear reserve.  Report a nonzero dry count —
	 * it means some clear on this mount failed closed for want of a spare
	 * registry entry, which is a sizing signal, not a normal event. */
	if (ctx->lreq_reserve_dry)
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P251-LREQ-DRY total=%llu reserve_left=%u — destructive clears refused for want of a reserved registry entry",
		    (unsigned long long)ctx->lreq_reserve_dry,
		    ctx->lreq_reserve_n);
	while (ctx->lreq_reserve) {
		struct mxfs_caw_lreq *e = ctx->lreq_reserve;

		ctx->lreq_reserve = e->next;
		mxfs_pal_free(e);
	}
	ctx->lreq_reserve_n = 0;
	if (ctx->lreq_cond) {
		mxfs_pal_cond_destroy(ctx->lreq_cond);
		ctx->lreq_cond = NULL;
	}
	if (ctx->lreq_lock) {
		mxfs_pal_mutex_destroy(ctx->lreq_lock);
		ctx->lreq_lock = NULL;
	}

	/* v5 sess33: free heap-allocated arrays */
	if (ctx->held.slots) {
		mxfs_pal_free(ctx->held.slots);
		ctx->held.slots = NULL;
	}
	if (ctx->mem_locks) {
		mxfs_pal_free(ctx->mem_locks);
		ctx->mem_locks = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: destroyed for node %u", ctx->local_node);

	mxfs_pal_free(ctx);
}

/* ─── Single-node bypass ─── */

/*
 * Flush all in-memory held locks to disk.
 *
 * Called when transitioning from single-node to multi-node.
 * For each lock held in-memory, claims a disk slot via the normal
 * CAW path (find_slot + CAS new slot or add holder bit).
 *
 * Returns 0 on success, negative errno on first I/O failure.
 */
static int caw_flush_held_body(struct mxfs_dlm_caw_ctx *ctx)
{
	int count;

	if (!ctx)
		return -EINVAL;

	/*
	 * v0.3.86 (sess25 root-cause fix): do NOT promote single_node
	 * in-memory locks to disk.  The original design OR'd our holder
	 * bit into each slot — but if peer is also transitioning
	 * single→multi and ran flush_held_to_disk concurrently, BOTH
	 * nodes' bits end up in the EX bitmap.  caw_lock's "already-held"
	 * fast-path then sees our bit and returns success without
	 * conflict detection; xfs cached i_dlm_mode and pag_dlm_cached
	 * stay set; both nodes proceed without coordination.  Sess24 P35
	 * captured this as 50s of dual-cached state on AG=0; sess25
	 * cross-node visibility test reproduced as `d?????????` on T2.
	 *
	 * After this change, disk slots stay empty post-transition, and
	 * the xfs side's mxfs_dlm_peer_joined_flush invalidates cached
	 * i_dlm/pag state, forcing every next acquire through proper
	 * CAW flow with conflict detection.  Any peer holding the
	 * resource won't see our prior single_node hold — but they have
	 * no concurrent acquires in flight (their first multi-mode
	 * acquire is what produces the BAST request), so nothing is
	 * lost.
	 */
	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
	count = ctx->mem_lock_count;
	ctx->mem_lock_count = 0;
	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);

	if (count > 0)
		mxfs_pal_log(MXFS_LOG_INFO,
			     "dlm_caw: dropped %d single_node in-memory locks "
			     "(no disk promotion to avoid OR-bug)", count);
	return 0;
}

/*
 * The v0.3.x single->multi disk-promotion flush (each in-memory
 * single_node hold written to disk on transition) was disabled by
 * sess25/v0.3.86 for the OR-bug described above; its dead body was
 * removed in 0.11.461 when caw_grant_epoch_update grew a compare-image
 * argument.  Git history (pre-0.11.461) has the original.
 */

int mxfs_dlm_caw_flush_held_to_disk(struct mxfs_dlm_caw_ctx *ctx)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	if (!caw_op_enter(ctx))
		return -ESHUTDOWN;
	rc = caw_flush_held_body(ctx);
	caw_op_leave(ctx);
	return rc;
}

void mxfs_dlm_caw_set_single_node(struct mxfs_dlm_caw_ctx *ctx, bool single)
{
	if (!ctx)
		return;

	if (ctx->single_node && !single) {
		/* Transitioning single→multi: flush held locks to disk
		 * so the new peer can see them. */
		mxfs_dlm_caw_flush_held_to_disk(ctx);
	}

	{
		bool was = ctx->single_node;
		ctx->single_node = single;
		if (was != single)
			mxfs_pal_log(MXFS_LOG_INFO,
				     "dlm_caw: single_node = %s",
				     single ? "true" : "false");
	}
}

/* ─── Callbacks ─── */

void mxfs_dlm_caw_set_bast_cb(struct mxfs_dlm_caw_ctx *ctx,
				 mxfs_dlm_bast_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->bast_cb = cb;
	ctx->cb_data = data;
}

void mxfs_dlm_caw_set_holders_alive_fn(struct mxfs_dlm_caw_ctx *ctx,
					bool (*fn)(void *data,
						   uint64_t slot_mask),
					void *data)
{
	if (!ctx)
		return;
	ctx->holders_alive_fn = fn;
	ctx->holders_alive_data = data;
}

/* sess374 (sess357 ruling part 1): wait-cancellation oracle — see dlm_caw.h. */
void mxfs_dlm_caw_set_wait_refuse_fn(struct mxfs_dlm_caw_ctx *ctx,
				     int (*fn)(void *data,
					       const struct mxfs_resource_id *res),
				     void *data)
{
	if (!ctx)
		return;
	ctx->wait_refuse_fn = fn;
	ctx->wait_refuse_data = data;
}

/* sess374 (sess363 ruling item B): survivor-side out-of-closure scrub oracle
 * — see dlm_caw.h. */
void mxfs_dlm_caw_set_closure_scrub_fn(struct mxfs_dlm_caw_ctx *ctx,
				       int (*fn)(void *data,
						 uint8_t blocking_slot,
						 const struct mxfs_resource_id *res),
				       void *data)
{
	if (!ctx)
		return;
	ctx->closure_scrub_fn = fn;
	ctx->closure_scrub_data = data;
}

/* sess374 (RULE-5 review items 2+3): skip-only candidate hint — see
 * dlm_caw.h.  Never consulted for authority. */
void mxfs_dlm_caw_set_closure_cand_mask(struct mxfs_dlm_caw_ctx *ctx,
					uint64_t mask)
{
	if (!ctx)
		return;
	ctx->closure_cand_mask = mask;
}
