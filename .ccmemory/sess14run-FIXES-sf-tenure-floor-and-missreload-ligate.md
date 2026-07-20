---
name: sess14run-FIXES-sf-tenure-floor-and-missreload-ligate
description: sess14: SF-TENURE-FLOOR (5A31CD27) tds 8-node 72s→41.7s PASS 8/8; FIX-F li_list gate in iget_miss_reload (360111F2) for ds got=0 P91-capture loop. In…
metadata:
  type: project
---

# sess14 (a9a03929) — tds fixed; ds got=0 root proven+patched

## FIX: SF-DIR TENURE FLOOR (build 5A31CD27, VERIFIED at 8 nodes)
tds 8/tcp root = 2.4 dir-EX handoffs/round × ~20ms (12.9ms holder release
P138: sa=1.6 b2=3.5 flush=1.6 sc=1.7 sd=4.3; ~7ms requester) — the eager
idle-release arms (mxfs_dlm_ilock_end + mxfs_inode_unpin CACHED&&bpend,
sess9-v3/sess11) hand off at EVERY syscall boundary; MHT never covered the
2-5ms shell-exec gaps. sess11's "19.6s PASS" was 4-NODE; 8-node bill =
2×rounds, window fixed → never passed on this lineage.
- `mxfs_dlm_sf_tenure_keep_delay/arm` (xfs_mxfs_dlm.c after dwork fn,
  decl in .h): keep EX at idle while tenure < dir_sf_mht_ms (SF dirs, EX
  only), leave bpend SET, arm dwork for remainder (bastq_src=12; igrab-fail
  = eviction releases). Both gates patched. dir_sf_mht_ms 2→15.
- RESULT: tds 41.3-41.9s all 8 (window 60), 150/150 ✓, 0 P73-WAITSTALL,
  201 P36-MHT-REARM (batching live). Regression iter r4: 12/12 tests PASS
  before harness truncation (cc/sc/posix/mmap/zsl/fairness/membership/
  sccurve/ds/rsync/crash 8/8) + drc FAIL (pre-existing face, see below).

## FIX-F: iget_miss_reload li_list gate (build 360111F2, UNVERIFIED)
r3 ds 7/8 node6 got=0 ROOT PROVEN: mkdir-race loser's cluster buf
(daddr=33491808) carries OTHER slots' inode log items (li_empty=0
has_bli=0) → FIX-D invalidate ret=1 (checks only bli/pin) → FUA re-read
P91-FUA-SKIP-LOGGED-captured → same stale image, no FUA_FRESH → ∞ loop
(P12-IGETMISS-RELOAD × P13-VISNUDGE alternating, lock_rc=0 nudges useless).
FIX-E slot patch gated on !ret → never ran. FIX: whole-buffer invalidate
now requires list_empty(&bp->b_li_list); li-present routes to FIX-E slot
patch (ret=2) or ladder escalation.

## drc 8-node status (the remaining 8/tcp blocker)
- First-view readdir misses PRE-EXIST the floor (same rate pre/post:
  ~7-8 new failround lines per 8-node run incl. PASSING runs r3/drc8_wall;
  denominators disambiguate: 800=8-node, 400=old 4-node lines).
- r4 round 11: ALL 100 node7 files LOOKUP_ENOENT+REREAD_MISS in ino=157
  — durable divergence, NOT transient. test7's journald+snapshots died
  after round 9 (small 6G disks on test5-8, 65-75% used).
- All nodes AGREE on dirino per round (8930624→25→26→157 advancing) — no
  cross-node DIRID divergence in r4's real (journald) data.
- drc FAIL = face-retry time + pace vs 800s budget; passes when lucky.
- LIKELY related to FIX-F class (mkdir-per-round + subdir race).

## Infra fixed this session
- suite_iter.sh timeout 1100→2600 (1100 truncated 8-node iters mid-drc,
  silently dropping last 4 tests — r4's "0/8 drc" verdict shape).
- drc script now rm's stale /root/drc_* at start (persisted across
  reboots, poisoned artifact pulls — r4 postmortem chased r3's files:
  ALWAYS check in-file boot fingerprint realns−uptime, not filename).
- Nodes' /root cleaned; mxfs_sshpass.sh <host> /tmp/.mxfs_pass "<cmd>".
- ds/tds artifacts only pulled on FAIL; PASS data lives in node dmesg.

## State at checkpoint
- Gap run live: /tmp/gap8_r1.log = ./run.sh 8 tcp drc fence netpart soak
  tds on 5A31CD27 (launched 17:12:43Z, ~25min). FIX-F build 360111F2 NOT
  yet deployed (deploys at next prep).
- Next: gap results → deploy 360111F2 → full iter (fixed suite_iter) →
  attack drc first-view face with FIX-F in place → 1/2-node columns.
