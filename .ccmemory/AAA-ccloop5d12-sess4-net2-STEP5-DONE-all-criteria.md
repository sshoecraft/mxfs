---
name: AAA-ccloop5d12-sess4-net2-STEP5-DONE-all-criteria
description: ccloop 5d12 sess4 FINAL: GATE 5 GREEN 0.11.5, ALL success.md criteria met, YES written. Step 6+ = next interactive checkpoint. Port-stride + gate2-sc…
metadata:
  type: project
tags: [net2, mepoch, gate5, ccloop, membership]
---

# ccloop 5d123e7b — sess4 (FINAL): step 5 + gate 5 GREEN, run COMPLETE

## Outcome
0.11.5. Gate line [x]1-5. All success.md criteria met for every AUTHORIZED
item; COMMITS stays PENDING (recorded; nothing committed). YES marker
written. state.md rewritten once as the DONE bridge. Step 6+ (fence/freeze/
scsipr/seam) deliberately NOT entered per the hard boundary.

## What landed (details in CHANGELOG 0.11.5 + docs/net2.md membership section)
- net2_epoch.c first-ever build: compiled clean at -Werror after 3 review
  fixes made BEFORE compiling: (1) #ifndef __KERNEL__ around stdio/stdlib;
  (2) net2_mepoch_suspect stamps suspect_since only on the 0→1 transition
  (re-asserted suspicion would otherwise hold off the 2×probe proposer
  takeover forever); (3) self-fence moved OFF the raw disk scan INTO
  mepoch_adopt_committed: fires only on member→excluded-with-fenced-bit
  transition — covers rx-COMMIT and disk-scan uniformly, and bootstrap
  adoption (no prior view) never fences ⇒ a restarted+bumped incarnation
  REJOINS instead of dying; clean LEAVE keeps the bit clear (fence_ok is
  the removal-authorization proof; the BIT means real fence only).
- Epoch-0 records = incarnation-bump carriers; bootstrap + scan skip them
  as committed candidates (else a pre-join bump gets adopted as EMPTY
  membership and wedges proposals).
- pal/linux/user.c += mxfs_pal_crc32c (table; raw kernel crc32c semantics;
  verified vs std check value E3069283 and cross-validated against
  chk_mxfs's independent decoder on engine-sealed records).
- net2_membership.{c,h}: 3-observer votes, ≥2 missing → SUSPECT,
  same-{inc,nonce} within grace → ACTIVE, different inc NEVER resumes,
  grace → FENCING, DEAD only via fence_done(matching inc); inc_bump
  preserves record content incl. stale PREPARED; boot_nonce.
- scen_mepoch.c: 8 scenarios / 102 checks. Key mechanics: committed_cb →
  vc_view_node (view follows commits — links re-form/retire on adoption);
  check-3 determinism via drop-all-RX fault on the proposer (PROPOSEs go
  out, ACKs never land, voters' PREPARED polled ON DISK before the kill);
  check-6 zero-network proven by an own-recv-cb delivery counter (the vc
  log was a tautology — my cb replaced vcluster's logger; fixed).
- chk_mxfs: MEPOCH decode @456 (PREPARED labeled/not counted; epoch-0
  skipped; bad crc errs); loop-device verified + corrupt-byte negative.
  chk_mxfs.md + pal.md awareness updated.
- gate5_mepoch.sh: ×4 seeds + N2_DEBUG pass + full-suite ASan; 108s/120s
  pinned; run_matrix surfaces stderr diagnostics (CHECK-FAIL/ENV-FAIL) on
  failure — gate4's version discards them, which made the original flake
  opaque (improvement candidate for gate4 at next touch, not done: its
  gate is closed).

## Two root causes proven this session (RULE 4, measured)
1. **Harness flake (1-in-~10 ASan full-suite runs, last scenario dying
   with checks=0)**: `run all` creates 42 vclusters; old 256-port stride
   from 23000 put blocks ≥39 at 32984/33240/33496+ — INSIDE
   ip_local_port_range (32768-60999). A transient outbound source port
   (the harness's own link connects burn hundreds) owning the port makes
   listen bind fail EADDRINUSE (SO_REUSEADDR covers TIME_WAIT only, not
   live holders) → vc_create fails → env_start rc → scenario FAIL with
   zero checks. Proof: port extraction from saved full-run logs (117
   binds, max 33496). Fix: stride 16 (max port 23656). 9 clean ASan
   suites pre-fix never reproduced it — the proof is the measured port
   map, not statistics.
2. **gate2 budget blowout (203s > 45s)**: its "full matrix" was `run all`,
   which steps 4+5 grew 19→38 scenarios. Re-scoped to new harness group
   `run midcomms` (wire statics + §13.1 = exactly the 19 its budget was
   pinned for), mirroring how gate1 was re-scoped when gate2 took the
   matrix. 39s/45s green. TIMEOUT_BUDGETS rows updated (g2 note, g4
   actual 210s, g5 new row).

## Step-7 seam notes (for the next interactive session)
- mxfs_n2msg_is_lockplane() sniffs the shared N2MSG magic ONLY — the
  lockspace recv cb would swallow N2_MEPOCH_* into shard_dispatch; the
  seam must route by TYPE (15-17 → net2_mepoch_rx) before/instead.
- mepoch sends address dst.incarnation from its member_incs table;
  midcomms REJECTS stale-inc addressing (sess->peer_inc > dst->inc) —
  the seam must keep the incs table live (commits carry it).
- committed_cb → mxfs_net2_update_view is the consumer-contract wiring
  precedent (harness does exactly this).
- Kernel storage vtable backing: read_rec(slot)/write_rec(own) over the
  real disklock HB I/O path; offsetof(heartbeat, mepoch)=456 is
  static-asserted in scen_mepoch.c.

## Verification inventory (all this session)
- mepoch group: 8/8 × 4 seeds × {N2_DEBUG 0,1} (8 runs) + inside gates.
- Full suite 38/38 normal + ASan (≥10 ASan sweeps total, 0 reports).
- gate1 9s/30s, gate2 39s/45s, gate4 210s/300s, gate5 108s/120s — all
  re-run AFTER the stride fix.
- Kernel make modules clean srcversion 3E0347D1B1DBA8468BDA751 (no new
  kernel code in 0.11.5); make tools clean; harness final sanity 8/8.
- CAW criteria: cluster untouched the entire session (user-mode only).
