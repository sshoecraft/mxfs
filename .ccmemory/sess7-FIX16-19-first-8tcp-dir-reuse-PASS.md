---
name: sess7-FIX16-19-first-8tcp-dir-reuse-PASS
description: sess7(a9a03929) MILESTONE build CAE7BFBD: 8/tcp dir_reuse 24/24 PASS 8/8 (run93). FIX-16 noino land-scan, FIX-17 lock_impl orphan, FIX-18 demote-wait…
metadata:
  type: project
---

# sess7 (ccloop a9a03929) — four proven fixes → first full 8/tcp dir_reuse PASS

Builds: 36600ADF (sess6 head) → 89CBFF74 (FIX-16, run90) → 9ED89275 (+FIX-17, run91) → F265FEB5 (+FIX-18, run92) → **CAE7BFBD (+FIX-19, run93 = PASS 8/8, failrounds=0 on every node, ~460s wall)**.

## FIX-16 (PROVEN run89 r6): noino release blind to mxfs-seq dir blocks
node8's md5-tail block daddr=94197064 (lseq=168 wseq=0, dirty=0 pin=0 **in_ail=0** — this class NEVER enters the AIL) was unlocked-past by the noino work fn: its FIX-12 whole-AIL LSN fence saw an empty/covered AIL and unlocked in 1.5ms; test1 FUA-read the pre-add platter (758/800; RDMISS0 = one peer's md5-tail, LOOKUP_OK+REREAD_SHOWS). node8's own next acquire re-landed it 200ms later (P3R-RELAND). Fix: `mxfs_dir_noino_land_scan(mp, ino)` (xfs_mxfs_dlm.c ~560, after owner_scan) — per-AG bcache rhashtable walk, `mxfs_dir_buf_is_owned_dir3(bp,ino)` + `mxfs_dir_buf_is_undestaged(bp)` + !STALE → validate content → set DONE → bwrite; called in noino work fn (before AIL fence; extra coalesced flush when skip-arm taken) and inline OOM fallback. P-NOINO-LAND fired 30× in run93.

## FIX-17 (PROVEN run90 r10): dlm_lock_impl still_safe orphaned the resource
Local-master same-owner GRANTED re-request (phantom-NL window after ACQBAST-BATCH release left i_dlm_mode=NL while table held EX gen=16605): the Bug-51 `still_safe` check counted **other-node WAITING entries as staleness evidence** → freed the ONLY granted entry (P52-GRANT-FREE ret=dlm_lock_impl+0x560) → re-queued fairly BEHIND 6 EX waiters → zero granted, promotion only runs on release events → orphan → 184.5s timeouts (P34-ACQ-SLOW dur_ms=184500 rc=-110) → 6/8 nodes force-shutdown ("Corruption of in-memory data (0x8) at mxfs_dlm_ilock_begin:16975" = the shutdown POLICY flavor, not real corruption). Fix: WAITING/BLOCKED no longer distrusts our grant; only a CONFLICTING GRANTED does (mirrors the remote path's sess-tcp ALWAYS-RE-AFFIRM at process_remote_request, which was already correct).

## FIX-18 (PROVEN run91): demote-wait rescue arms were unreachable
run91 moved the wedge to a FILE ino (8388742): ghost ex_holder=1 (leaked at a P71-UNDERFLOW accounting tear ~182s) kept every bast_process in P15-REL-ABORT→re-arm limbo; state=BAST, work idle, master (test4) table showed test6 EX GRANTED held_ms=499427; P73-WAITSTALL every 30s for 500s; **zero P79 rescues cluster-wide** because the inner `while (wait_event_timeout(...)==0)` re-slept forever — the sess4 FIX-1 rescue below it was dead code on any permanent wedge. Fix: `if`-conversion (each 30s timeout falls through to the rescue arms: g2>=mode admit / g2<mode clear-to-NONE+slow-path, which now self-heals via FIX-17 local adopt or remote re-affirm) + FIX-18b re-drive arm (state BAST/DEMOTING + holders==0 + work idle → set DEMOTING, ihold, queue bast work; unlock around ihold/queue — xfs_irele can sleep). P-DEMWAIT-REDRIVE print. Zero fires in run92/93 (FIX-17 prevents formation); arms are the safety net.

## FIX-19 (PROVEN run92 r1): shrinker reclaimed committed-undestaged dir buffers
Round-1-only uniform loss (791/800 run91, 795/800 run92; LOOKUP_ENOENT+REREAD_MISS = durable cluster-wide): node7's md5-tail bp (daddr=4188352, lseq=15 wseq=0, all-clean flags, no BLI hold) — after the OTHER nodes finished their waves (no more BASTs → no release between 74.4s and verify), node7's own verify-phase `drop_caches` freed the undestaged buffer via the bt_lru shrinker (only landed copy = journal, which nothing replays without a crash) → every node FUA-read the pre-add platter. Proof: P13-NADD bp pointer changed mid-wave with lseq restart (…465f6c0 → …2c04540). Fix: `xfs_buftarg_isolate` (pal/linux/xfs_buf.c ~6560) rotates dir-class ops bufs (dir3 data/block/free/leaf1/leafn/da3) that are `mxfs_dir_buf_is_undestaged` — P-SHRINK-UNDEST-ROTATE (capped 2000) fired 74× in run93. Upstream-logged bufs don't need this (BLI/AIL hold); the mxfs-seq class had no reclaim guard at all.

## Verification state
- run93 (CAE7BFBD, clean 8-VM reboot cycle): dir_reuse_coherency 8/tcp **PASS nodes_pass=8/8**, failrounds=0 everywhere, no shutdowns, no wedges, wall fits 480s budget (round pace ~15.8s).
- Remaining for criteria ("full ./run.sh N tcp suite at 1/2/4/8"): reliability repeats of 8/tcp dir_reuse (sess49 plan: 3× clean-reboot), then FULL suite at 8, then 4/2/1. Historical suite landscape: sess20 = 16/17 at 8/tcp with only dir_reuse failing (pre these fixes).
- Cycle procedure: destroy+start all 8 → wait ssh → `find /root -maxdepth 1 -name 'drc_*' -delete` per node (NEVER rm-glob) → `nohup ./run.sh 8 tcp dir_reuse_coherency > $S/runNN.log` → foreground 280s polls on `pgrep -f "run.sh 8 tcp"`.
- Instrumentation gotchas: P7S/P7B/P37/P4L/P6U prints gated ino<=256; P70-BP cap 6000 exhausts ~170s into a run (12000 lines ENTRY+EXIT); P-LKTIMEOUT-HOLDER (uncapped) is the master-table dump; P73-WAITSTALL names the demote-wait wedge signature; grep /dev/kmsg BLOCKS (use dmesg).
