---
name: AAA-ccloop5d12-sess3-net2-progress
description: ccloop 5d12 sess3: GATE 4 GREEN 0.11.4 (11 scen ×4 seeds + ASan, 199s/300s pin). Step 5 ~60%: disklock.h MEPOCH layout + wire + net2_epoch.{h,c} land…
metadata:
  type: project
---

# ccloop 5d123e7b — sess3 final state

## GATE 4 CLOSED (criterion 3 of success.md DONE)
- All 11 shard scenarios GREEN ×4 seeds (default, 0xF422, 0xBEEF, 0x1234);
  full 30-scenario suite green; ASan sweep clean.
- tests/net2/gate4_shard.sh written, calibrated, PASS wall=199s budget=300s
  (pinned). TIMEOUT_BUDGETS row added. DLM_IMPL_PLAN gate line [x]4.
  VERSION 0.11.4, CHANGELOG entry, docs/net2.md "Lock plane (step 4)"
  section + history entry — ALL DONE.
- Engine fixes this session (details in CHANGELOG 0.11.4 + docs/net2.md):
  leader completeness (immutable committed, abdicate-on-NACK, term_proven
  gate, lazy-create pull-all), snapshot wire base+src_last (32B body) +
  96B log-suffix transfer, pull-found-nothing => recovery barrier,
  recovery leader self-report install, election term escalation
  (constant term+1 livelocked dual candidates), dispatch epoch bridge
  window (E-1/E+1 accepted; exact-match wedged barrier appends during
  the non-atomic epoch wave), delayed-ACK arming kick (in mxfs.ko!).
- Kernel builds clean; srcversion after disklock.h layout change:
  3E0347D1B1DBA8468BDA751 (0.11.4 tree). NOT deployed; t1/t2 on 0.11.3.
  make tools also clean.

## STEP 5 IN PROGRESS (~60% of code landed, NOTHING COMPILED YET)
Landed, NEVER BUILT — first action next session: cd tests/net2, add
net2_epoch.o to Makefile objs, make, fix compile errors:
1. dlm/disklock.h: EVICT_RING_ENTRIES 28→25 (416B ring), struct
   mxfs_mepoch_rec 44B packed (u64 epoch/member/fenced @0/8/16, u32
   magic@24 "MEPO" 0x4F50454D, u32 self_inc@28, u16 voter_slots[3]@32,
   u16 flags@38 (F_PREPARED 1, F_VOTERS5 2), u32 crc32c@40 over 0..39
   via mxfs_pal_crc32c), HB: 40+416+44+12reserved=512, asserts updated.
   KERNEL+TOOLS BUILD VERIFIED CLEAN with this.
2. dlm/net2_msg.h: types N2_MEPOCH_PROPOSE=15/ACK=16/COMMIT=17; n2msg
   fields mep_epoch/member/fenced/fence_ok, mep_voters[3], mep_flags,
   mep_incs[64]; bodies PROPOSE/COMMIT=296 (epoch,member,fenced,
   fence_ok,voters×3,flags,incs@40), ACK=12 (epoch,ack_ok@8,status@9=
   reason). Layout comment block NOT yet updated (do with docs pass).
3. dlm/net2_epoch.{h,c}: full §7.C single-decree engine — storage
   vtable {read_rec(slot),write_rec(own)}, bootstrap (max valid
   committed; fresh=epoch1 self-quorum), propose (proposer=lowest ALIVE
   voter of E, alive = !suspect>2×probe_interval), voter validate
   (NOT_VOTER/NOT_MONOTONIC/FENCED_SHRANK/NO_FENCE_PROOF/STALE_ROUND
   for different-value-same-epoch), PREPARED staged to own HB before
   ACK, majority-of-E's-voters commit (3 lowest of mask, 5 at pop>=16
   derived not stored), COMMIT broadcast to old∪new members, rx-COMMIT
   adoption, tick: round retry to unacked voters + periodic disk scan
   (catch-up adoption when best.epoch>mine, PREPARED takeover — own or
   found on disk — proposer re-proposes it, disk-visible SELF-FENCE cb
   when a committed rec names me in fenced_mask), lease self-freeze
   (freeze_cb, refresh on voter rx + adoption), round_status getter for
   NACK evidence. cb's fired OUTSIDE mp->lock via commit_fire struct.
   KNOWN ISSUE: net2_epoch.c has bare `#include <stdio.h>` + getenv —
   wrap in #ifndef __KERNEL__ like net2_shard.c does (compare its head)
   for dual-build hygiene even though harness-only for now.

## STEP 5 REMAINING
1. Build net2_epoch.c (Makefile: add to engine objs list next to
   net2_shard.o etc. in tests/net2/Makefile).
2. dlm/net2_membership.{c,h}: observer aggregation (MCAST/PROBE/DISK
   votes, ≥2 missing → SUSPECT cb → feeds net2_mepoch_suspect; same
   inc+nonce reconnect within grace → ACTIVE), persisted incarnation
   bump helper (read own HB rec self_inc → +1 → write → return; uses
   the same storage vtable), boot nonce via mxfs_pal_get_random_bytes
   (pal.h:685). Keep lean but real.
3. Harness: tests/net2/harness/scen_mepoch.c — file-backed disklock
   image (64×512B file; read_rec/write_rec via pread/pwrite of the
   mepoch offset within each 512B record: offsetof(struct
   mxfs_disklock_heartbeat, mepoch) = 40+416 = 456) + per-node ctx
   (vcluster) + own recv_cb routing N2_MEPOCH_* → net2_mepoch_rx,
   else drop. Tick thread or loop driving net2_mepoch_tick every 10ms.
   Gate-5 checks (success.md criterion 4): (1) bootstrap fresh →
   epoch1 self-quorum; (2) join increments (propose member+new →
   commit E+1; leave with fence_ok → E+2); (3) proposer crash mid-round
   (send PROPOSE then destroy proposer BEFORE commit — use a partition
   or kill between ACK-stage and commit; next proposer adopts PREPARED
   from disk, completes) ; (4) voter-minority stall: partition/kill
   majority of voters → propose can't commit + lease freeze_cb fires
   (visible), no commit; (5) whole-cluster restart: destroy all mp
   instances, recreate over same file image → bootstrap adopts max
   committed; (6) excluded-node disk self-fence with ZERO network:
   commit an exclusion among survivors (fence_ok supplied), excluded
   node has NO links (partition first), its tick disk-scan sees
   fenced_mask bit → self_fence_cb; (7) exclusion WITHOUT fence proof
   → voters NACK N2ME_NO_FENCE_PROOF, round dead, no commit
   (round_status). Register scenario in net2_harness tables as group
   "mepoch"/scenario names mep_*.
4. tools/chk_mxfs: decode MEPOCH rec per HB slot (offset 456 in each
   record; print epoch/member/fenced/voters/flags/inc + crc validity).
   chk_mxfs.c has the disklock region offsets already (~line 470).
5. tests/net2/gate5_mepoch.sh: RULE-0 header (provisional build+120s
   per success.md; calibrate → pin), pattern from gate4_shard.sh.
6. Bookkeeping: [x]5, VERSION 0.11.5, CHANGELOG, docs/net2.md
   (membership plane section + history), TIMEOUT_BUDGETS gate5 row,
   net2_msg.h layout comment for MEPOCH bodies.
7. Kernel `make modules` + `make tools` re-verify (disklock.h already
   proven; net2_epoch/membership NOT in Kbuild — harness-only).
8. Then per success.md: do NOT proceed to step 6. state.md rewrite once
   (exact stop point, PENDING items: COMMITS), final ccmemory, DONE
   protocol (echo DONE > resume file is WRONG — it's: all criteria
   green then `echo YES > /src/mxfs/.ccloop/runs/5d123e7b-.../criteria-met`
   per the wrapper preamble; success.md's "write DONE" refers to
   $CCLOOP_RESUME_FILE — follow the wrapper's actual mechanism).

## Facts (do NOT re-derive)
- Budgets: scenario 90s each; shard group ~50s; gate4 199s/300s pin;
  kernel incremental ~260s; full syn suite (run all) ~90s.
- Harness: --seed 0xNNNN; KP_ONLY=n; N2_DEBUG=1 traces (can MASK timing
  bugs — sh_reconfig@0xBEEF only failed without it; run both ways).
- mepoch msgs ride mxfs_net2_send directly (NOT net2_shard_send);
  envelope membership_epoch = committed.epoch; FENCE priority.
- Voters derived from mask (3 lowest, 5 at ≥16) — never stored beyond
  the informational voter_slots[3].
- CAW criteria intact; cluster untouched all session.
