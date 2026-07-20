---
name: net2-step2-gate2-user-green-0.11.1
description: NET2 §11 step 2 LANDED 0.11.1, gate-2 USER part GREEN (19/19 ×3 seeds + rt + ASan/TSan clean; 27s/45s). STOPPED at checkpoint A — Kbuild diff present…
metadata:
  type: project
tags: [net2, dlm-plan, gate2, midcomms, link, harness, checkpoint-a]
---

# NET2 step 2 landed user-mode — gate 2 USER GREEN (0.11.1, 2026-07-17)

Session 21de360a. Engine: net2_ctx.h, net2.c, net2_link.{c,h},
net2_overlay.{c,h} (mesh), net2_midcomms.{c,h}. Harness: vcluster.c +
scen_midcomms.c (15 scenarios = §13.1 matrix) + gate2_midcomms.sh.
Kernel module UNTOUCHED (srcversion still 5221BFFE305AF21A; net2 objects
not in Kbuild). Cluster stays 0.10.120.

## STOPPED AT CHECKPOINT A — user go-ahead required
Kbuild dlm block (after v5_mount.o) += net2.o net2_link.o net2_overlay.o
net2_midcomms.o net2_fault.o. ALSO proposed (§14 registry change):
mxfs_ports.h += MXFS_PORT_NET2_LINK_BASE 7610 (listen = base+slot;
7605 stays membership-only). Neither applied. gate2_midcomms.sh
--kernel-smoke REFUSES to run until Kbuild lists net2_midcomms.

## Load-bearing design decisions (as-built, in docs/net2.md)
- DELIVER-ON-RECEIPT rx — NO reorder-hold. An in-order hold buffer was
  built first and REMOVED: it lets a congested lower class delay a
  higher one end-to-end, defeating §7.A priorities (RELEASE > REVOKE).
  §7.A specifies only cum_ack + 32-bit SACK + msg_id dedup. rcvd_mask
  (64-bit) dedups transport; msg_id ring 1024 dedups caller retries.
- Coherence window/queue overflow ⇒ -ENOBUFS + COMM_AMBIGUOUS + freeze
  cb; op STAYS WITH CALLER (never silent). GRANT/DISCOVERY ⇒ -EAGAIN.
- Sessions refcounted (table/GC + link binding + every eqent); lock
  order ctx > link > sess > stats/fault; only the egress worker writes
  a live socket; sockets close only after their threads are joined
  (that makes send-outside-link-lock safe).
- Supersede folds session stats into stats.retired (abort-disposition
  evidence survives); EMBRYONIC sessions buffer pre-handshake sends;
  restart ALWAYS bumps inc+nonce (same-identity-empty-state cannot
  exist in prod, so harness cannot construct it either).
- Lower-slot-initiates ⇒ inbound links slot<self, outbound slot>self:
  peer.c's Bug-80 accept/connect cross-races are structurally gone.
- Egress DROP fault = pack-then-discard (models wire loss; tx counted).
- Ambiguity ages never-sent entries from enq_ms (unreachable peer is
  MORE ambiguous, not less).

## Bring-up refutations (engine was right, harness was wrong — 3×)
1. mc_loss_ack: cumulative ACKs SELF-HEAL ack loss in a fast stream
   (later ack covers earlier); retx only forced by a mid-stream pause +
   count-limited drop-all-acks rule.
2. Sender restart resets sender counters ⇒ invariants must count
   current-incarnation deliveries only (vc_unique_from filters src_inc).
3. Cross-cluster SYN aimed at the wrong node's port dies on dst_slot
   before UUID validation — aim at the target's own listener.
Also: send_burst must retry -EAGAIN (window backpressure IS the
contract; first matrix run "failed" 4 scenarios on a tight send loop).

## Verification record
gate2_midcomms.sh: 19/19 ×3 seeds (0xF422/0xBEEF/0x1234) + rt subset
(real tunables: mc_basic, mc_loss_data, mc_reset_framing) + ASan sweep
(0 errors/leaks). TSan (`setarch -R` needed on 6.8 ASLR): only
volatile running/pending_sock stop-latches flagged = peer.c idiom;
all mutexed state race-free. Budget: 45 s pinned (27 s actual);
gate1_wire.sh re-scoped to its 4 wire scenarios, still green (4 s).
make modules clean 262 s.

## Next after approval
Apply Kbuild → make modules (first __KERNEL__ compile of net2_*.c —
audited for snprintf/errno/types but never compiled) → design + run the
2-node kernel echo smoke → [x]2 → step 3 (dlm_shared lifts + CAW sanity
gate 3). Kernel-side open item flagged in docs: pal tcp_connect timeout
semantics for conn threads (user PAL blocks; localhost fine).
