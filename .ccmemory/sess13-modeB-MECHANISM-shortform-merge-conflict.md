---
name: sess13-modeB-MECHANISM-shortform-merge-conflict
description: sess13 MECHANISM (dir-filtered P-LKT + P62 proof): MODE-B = shortform concurrent-modify MERGE CONFLICT — node RMWs/reloads a dir where in-core (own n…
metadata:
  type: project
---

## PROVEN MECHANISM (build CF359E6C, dir-filtered P-LKT via tests/tcp_lkt_dirtrace.sh + tcp_dlm_scaling.sh lkt_ino/dump hooks). The 2/tcp residual MODE-B is the shortform shared-dir concurrent-modify LOST-UPDATE / MERGE CONFLICT. NOT a double-grant (refuted [[sess13-doublegrant-REFUTED-serialized-stale]]).

## EVIDENCE at a tcp_dlm_scaling failure (leftover n1_r1,n1_r2 = test1's OWN files; dir ino=2097280; test2=master, owner ids test2=1917819590 test1=1354625623):
- **Grants SERIALIZED** (test2 master ring): GRANT-LOCAL/UNLOCK-GRANTED(test2) and GRANT-REMOTE/REMOTE-RELEASE(test1) strictly alternate PR/EX — no two owners GRANTED overlapping. DLM exclusion is correct.
- **test1 RMWs from a STALE base**: `P58-STALE-BASE-ADD add=[n1_r1.done] fmt=0 loaded_gen=3 dir_gen=11`, then `add=[n1_r2.done] loaded_gen=13 dir_gen=27`. loaded_gen always LAGS dir_gen.
- **test2 (master) reloads fresh**: `P34D-RELOAD-FRESHSRC ino=2097280 buf size=19 → fresh size=32 — adopting coherent on-disk`. So reload works for the master.
- **DECISIVE — test1 P62-RELOAD-FORK-SHRINK ino=2097280 shows in-core AHEAD of disk, CLEAN**: `incore_size=37 disk_size=33 in_ail=0 pin=0` then adopts 33; `incore_size=51 disk_size=32 in_ail=0 pin=0` then adopts 32. i.e. test1's in-core shortform is LARGER than disk but NOT dirty/pinned, and the reload SHRINKS it to disk.

## INTERPRETATION: test1's in-core = {its own n1_* entries} + {STALE n2_* entries test2 already removed}; disk = {test1's durable n1_*} + {test2's CURRENT n2_*}. NEITHER is a superset of the other. The reload's "adopt disk if peer_modified" heuristic shrinks to disk and can drop test1's not-yet-durable n1_* (in_ail=0 because the create destaged, then a peer's stale RMW reverted it on disk → in-core ahead of disk while clean). The P58 add then RMWs the stale base and the net effect durably reverts test1's own rename+rm → leftover n1_r1,n1_r2.

## WHY reload can't fix it alone: with in_ail=0/pin=0 the reload cannot tell (a) "disk is NEWER, adopt+shrink" from (b) "disk was REVERTED by a peer's stale-base RMW, do NOT adopt" — identical clean flags, opposite correct actions. This is the irreducible shortform merge conflict (whole dirent set in ONE dinode, two writers).

## FIX (converged, GPT Option A or 3-way merge — implement next):
- **Option A (strict tenure)**: a shortform-dir MUTATION must, within its EX tenure, (1) reload the CURRENT on-disk dinode synchronously right before the RMW (not heartbeat-gated — the EVICT-RING is laggy/bursty, proven 6 gens/10us), (2) apply its delta, (3) make it durable BEFORE releasing EX. Combined with the existing release barrier (already durable) this makes disk always a strict superset at the next acquire → no merge conflict. The gap today: the modify path reload is gated on the LAGGY MXFS_IF_DIR_RELOAD/dir_gen, so a node modifies in the lag window from a stale base.
- **Option B (3-way merge, GPT-endorsed for disjoint names)**: snapshot the shortform fork at load (base@loaded_gen); at RMW, merge base vs in-core (ours) vs disk (theirs) by NAME: our changed names win, else disk wins. Sound for the disjoint-name churn tests. Needs a base snapshot (new per-inode field).

## NEXT: implement Option A first (smaller): make mxfs_dlm_dir_modify_reload_prelock (sess13, xfs_mxfs_dlm.c) for a SHORTFORM dir reload UNCONDITIONALLY (not gated on MXFS_IF_DIR_RELOAD) by comparing in-core SF vs a coherent on-disk read (cf P9-SFREFRESH 6225), and ensure our own pending SF mods are durable first (flush) so the adopt is a clean superset. Validate full run.sh 2 tcp x3 clean-reboot. Build CF359E6C deployed. [[sess13-HEAD-status]] [[sess13-modeB-writeside-laggy-heartbeat-not-stale-read]] [[sess12-churn-resurrection-root-and-gpt-fix-A]]
