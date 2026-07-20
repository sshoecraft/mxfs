---
name: sess46-PROVEN-dir_reuse-leaf-hole-is-async-evictring-lag-stale-leaf-RMW
description: sess46 PROVEN root of dir_reuse_coherency 2/tcp leaf-hash hole: node1's EX re-acquire does NOT synchronously invalidate its clean-but-stale cached le…
metadata:
  type: project
---

## sess46 (ccloop 8ddb16a2, build EF006296 unchanged) — dir_reuse_coherency 2/tcp ROOT, PROVEN via dmesg capture

### STATE: clean full `./run.sh 2 tcp` is FLAKY, NOT 14/17. Two clean reboot+full runs this session:
- repro#1 (155702Z): 15/17 — FAIL crash_consistency(empty .md5) + dir_reuse(leaf-hash got=15..30).
- repro#2: 16/17 — FAIL **dir_reuse ONLY** (crash_consistency PASSED this time).
- sess45 was 14/17 with a DIFFERENT set (cache_coherency+dir_reuse+tcp_dlm_scaling).
- **dir_reuse_coherency FAILS 3/3 = the RELIABLE blocker.** crash_consistency + cache_coherency are FLAKY (timing). The criterion "100% successful" requires ALL reliably green.
- The "17/17" showstat.sh table the user sees = ACCUMULATED criteria.json (run.sh with 1 test arg re-preps+records only that test, leaving stale PASSes). NOT a single clean full run. Always verify with a no-arg `./run.sh 2 tcp` after clean virsh reboot.

### dir_reuse FAILURE SIGNATURE (test1/node1, round 1, FRESH dir — no reuse yet):
`mxfs-drc-FAIL round=1 rank=1 readdir=200 exp=200 lookup_fail=15 missing=[node2_f36.md5 .. node2_f50.md5]`
node1 readdir sees all 200 (DATA blocks fresh), but lookup of node2's LAST 15 .md5 entries ENOENTs = LEAF-hash hole (leaf block missing node2's tail entries). "Last few of a batch" pattern.

### PROVEN MECHANISM (dmesg capture, /tmp/drc_evidence_t1.log on test1; capture via `systemd-run --unit=dmesgcap --collect bash -c 'dmesg --follow > /tmp/dfollow.log'`):
1. node1 creates its entries under EX, leaf pinned. RELEASE → **P34-LEAF-DRAIN CACHED=1 needs_flush=0 done=1 dirty=0 in_ail=0 pin=0** = leaf is CLEAN/DESTAGED at release (mxfs_dir_flush_data_blocks works; release-side is NOT the gap).
2. node2 takes EX, adds f36-50.md5, destages → LUN leaf complete.
3. node1 RE-ACQUIRES EX. Its CLEAN cached leaf buffer (XBF_DONE, node1's OLD version) is **served, not invalidated** → node1 RMWs from the stale base → re-pins leaf MISSING node2's f36-50.md5 (DIR-STALE-SKIP blk=0x800000 buf_gen=0 inode_gen=3 **pin=1 undest=1** — now stale AND pinned, can't evict).
4. The peer-modify gen-bump arrives via **EVICT-RING-DIRMOD ino=N gen->3 (ASYNC heartbeat)** ~2s AFTER node1's creates — TOO LATE; and by then the buffer is re-pinned so even the gen-bump can't evict it (DIR-STALE-SKIP).
5. Verify (drop_caches; sleep 1; lookup): DATA block droppable→cold-read fresh (readdir OK); LEAF block pinned→DIR-STALE-SKIP→stale (lookup fails).

### ROOT: **the dir peer-modify invalidation is ASYNC (evict-ring), so node1's EX re-acquire does NOT synchronously invalidate its clean-but-stale cached leaf before RMWing it.** This is the sf→block→leaf "conversion/RMW divergence" sess43/44 named, at the BLOCK (not inode-format) layer. NOT P43/P43B (those gate on dip->di_format==LOCAL; a 200-entry dir is FMT_EXTENTS so P43 never fires). NOT the release drain (P34-LEAF-DRAIN proves leaf clean at release). NOT the existing write-side guards (mxfs_buf_xfsaild_skip_dir_write handles NL-released + ABA; this clobber is an ACTIVE EX-held RMW from a stale base, current incarnation, so neither arm fires).

### FIX DIRECTION (next, RULE 4 — instrument the acquire path first): make the dir-grant SLOW-PATH re-acquire (node1 regains grant after peer held EX) bump i_dlm_dir_gen + force-evict cached dir data-fork blocks (data+leaf) SYNCHRONOUSLY, instead of relying on the lagging async EVICT-RING-DIRMOD. Grep i_dlm_dir_gen bump sites + the acquire/reload path (mxfs_dlm_reload_inode / post_release reload ~xfs_mxfs_dlm.c:6080+, and mxfs_dlm_dir_consumer_refresh:2470 / modify_refresh:2630). Must NOT force-destage the stale buffer (that CLOBBERS the peer — at re-acquire the buffer is clean, just XBF_DONE-stale; clear XBF_DONE + cache-miss → FUA-reread node2's LUN version). Watch RULE 0 perf (tcp_dlm_scaling) + don't regress dlm_fairness/cache_coherency (the force_block=1 victims — keep force_block=0). User: FIX ROOT, no flag-flip. KEEP sess45 partial-iwrite fix. [[sess45-MILESTONE-full-suite-14of17-three-remaining]] [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]]</body>
