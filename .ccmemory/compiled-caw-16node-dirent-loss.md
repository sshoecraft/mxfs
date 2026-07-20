---
name: compiled-caw-16node-dirent-loss
description: Compiled: 16-node durable dir-block dirent-removal lost-update proven CASE B (post-release async clobber); Case A refuted; fix target + refuted tally.
metadata:
  type: project
tags: [compiled, caw, 16-node, dirent-loss, cache-coherency, dir-block, xfsaild, case-b]
---

## 16-node durable dir-block dirent-removal lost-update (dangling dirent) — compiled

ccloop 26c41354, sess1, 2026-07-06. Kernel build **591A76FB** (no kernel edits landed this session — only run.sh + scripts/caw_preflight.sh). All work on the CAW transport at 16 nodes. Sources: [[caw-16node-dirent-loss-current-state-sess1]], [[caw-16node-dirent-loss-gpt-design-plan]], [[caw-16node-dirent-loss-CASE-B-PROVEN]], [[caw-16node-dirent-loss-release-stale-refuted]].

### The bug
`cache_coherency` criterion at 16 nodes. 16 nodes each create 30 files + unlink all 30 in ONE shared dir (ino **2097305**). ~1 dirent of ~480 survives as a **DANGLING dirent**: the inode IS freed (inode-cluster guards P-IRESURRECT / P119 / P17B all WORK) but the parent dirent survives on disk → lookup finds the name → iget returns ENOENT: `P26-IGET-FAIL dp=2097305 name=nodeN_fileM inum=X err=-2`. Always the LAST-ish file in a node's batch (_file19 / _file30) — the final removal, released only via idle MHT-expiry/BAST with no subsequent op to re-flush it. Passes SOLID at 8 nodes; ~30-50% per-test FAIL at 16 (same residual race, ~2× more probable). Each individual test PASSES alone at 16 (cache_coherency 16/16 alone); the SUITE fails because SOME test hits the race.

### PROVEN: this is CASE B (post-release async clobber), not CASE A (drain-incomplete)
The decisive result — no rebuild, from [[caw-16node-dirent-loss-CASE-B-PROVEN]]: ran cache_coherency at 16 with `MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 dir_relverify=1"`. `dir_relverify` verifies disk==incore at EVERY dir-EX release, logging `P25-RELVERIFY-MISMATCH ino= daddr= incore_cnt= disk_cnt=` on divergence.
- **Result: 0 P25-RELVERIFY-MISMATCH cluster-wide (all 16 nodes).** Every dir-EX release leaves disk == in-core → the removal IS durably applied at release.
- **Case A REFUTED** (GPT root #1: drain never wrote the removal). The release drain `mxfs_dir_data_durable` (xfs_mxfs_dlm.c ~11237) is CORRECT. Do NOT add more release-side draining.
- **Case B PROVEN**: a write AFTER the correct release re-writes the dir block WITH the removed dirent. With `fua_always=1` a peer FUA-reads fresh on ACQUIRE, so the reintroducer is most likely an ASYNC **xfsaild destage of a STALE cached dir buffer** — the classic ABA writeback.
- Caveat: relverify=1 also TIMES OUT the test at 16 (per-release FUA-read latency, RULE-0) → DIAGNOSTIC ONLY, not shippable. But P25=0 is robust re: drain correctness regardless of timeout.

### Case-B narrowing: it is a PEER's stale buffer, not the demoting node's own
From [[caw-16node-dirent-loss-release-stale-refuted]]: tested `dir_release_stale=1` (GFS2 invalidate-on-demote: demoting node clears XBF_DONE|_XBF_FUA_FRESH on its own dir buffers at EX release).
- Result: FAIL 15/16, `test1: uv gone node8_file22 uv none remain got=1` — dangling dirent STILL leaks. Completed in 218s (NOT a timeout — invalidation is cheap).
- Conclusion: the reintroducing async write is NOT the demoting node's own stale buffer → it's a **PEER's** stale cached dir buffer being xfsaild-destaged (or a path release_stale's invalidation doesn't cover). 15/16 (not all-16) = the reintroduced dirent is visible to only SOME nodes = per-node cache divergence.

### Refuted-fix tally (RULE 5: ≥3 distinct approaches refuted with evidence)
1. **MHT increase** (`inode_mht_ms=600 dir_sf_mht_ms=120`): coherency WORSE — posix_multi PASS→0/16. Longer hold delays visibility. Defaults 300/40 tuned for 8 nodes.
2. **Release guards ON** (`dir_relverify=1 dir_release_stale=1 dir_wr_barrier=1`): cache_coherency TIMEOUT 0/16 (~300s), RULE-0. Heavyweight per-release FUA verify + write-barrier wait is TOO SLOW at 16-node handoff frequency. THE FIX MUST BE LIGHTWEIGHT (no per-handoff latency).
3. **`dir_release_stale=1` alone**: still leaks 15/16, but lightweight (218s, no timeout) → proves reintroducer is a PEER buffer, not self.

Also refuted: root #4 (BAST vs MHT-expiry drain non-equivalence) — `mxfs_dlm_bast_process` serves BOTH immediate-BAST and MHT-expiry dwork; they are equivalent.

### GPT-5.5 root-cause ranking (RULE-5 consult, from [[caw-16node-dirent-loss-gpt-design-plan]])
1. Release/drain doesn't sync-write the final touched dir DATA/LEAF buf before CAW unlock (last-file bias: earlier unlinks accidentally flushed by later ops; final unlink relies solely on idle-release drain). — **REFUTED by P25=0.**
2. **`_XBF_FUA_FRESH` is a timeless boolean, not tied to DLM/CAW generation → peer reuses stale cached xfs_buf across an EX handoff.** A "FUA read" wrapper around an already-XBF_DONE buffer submits NO bio → RMW of stale base reintroduces the removed dirent. FRESH must mean "fresh for THIS parent-dir lock generation only," invalidated on any EX handoff. — **The surviving lead, consistent with Case-B + peer-buffer narrowing.**
3. Drain enumeration misses dir buffer CLASSES (data/leaf/free/node) or pinned/late-logged bufs.
4. BAST vs MHT-expiry drain paths non-equivalent. — REFUTED (equivalent).
5. Write/flush ordering (submit→WAIT→flush→WAIT→release).
6. Actual SCSI FUA not honored (lower — inode cluster is coherent).

### THE FIX target (lightweight, zero handoff latency)
`mxfs_buf_xfsaild_skip_dir_write` (pal/linux/xfs_buf.c ~3327-3610) — the xfsaild dir-block ABA-writeback destage suppressor. Has MANY default-OFF, mostly-refuted arms: `mxfs_dataclobber`, `dir_ex_write_guard`, `dir_stale_incarn_skip`, `dir_subset_guard`, `dc_stale` (via `b_mxfs_dir_gen<dir_gen`). NONE catch "in-core write REINTRODUCES a dirent absent on current disk" within-tenure, nor a peer at NL/PR destaging a stale dir buf. Skipping a bad async write costs ZERO handoff latency (no RULE-0 risk). Note the `dir_ex_write_guard` not-held-EX gate MISSES the within-tenure clobber (stale-KEPT block destaged WHILE STILL HOLDING EX; proven clobber shape from ccmemory sess22/sess32-HEAD).

### NEXT (RULE 4 — write-side probe to NAME the peer reintroducer, then targeted skip)
1. Rebuild with a WRITE-SIDE probe at the xfsaild dir-block destage (pal/linux/xfs_buf.c, dir DATA/LEAF bio submit near `mxfs_buf_xfsaild_skip_dir_write` ~3327): for owner == shared test dir, before submit, raw-FUA read (bypass xfs_buf) the CURRENT disk block; if in-core image about to be written contains a dirent (name+inum) the fresh disk LACKS (= reintroduction), log: writer comm/daddr/owner, `b_mxfs_dir_gen` vs `i_dlm_dir_gen`, `b_mxfs_dir_incarn` vs `i_generation`, `i_dlm_mode`(EX? — expect NL/PR = a peer), the reintroduced inum, `XFS_LI_IN_AIL`, done/dirty/pin. Loop cache_coherency at 16 with BASELINE modargs (`dirwr=1 dirland=1`, NO relverify) until the dangling-dirent fail.
2. Fix = SKIP that specific destage (disk is authoritative). Gate against false-skips of legit ADDs: only skip when a real-FUA disk read proves the disk is a valid same-owner **SAME-INCARNATION** (`b_mxfs_dir_incarn==i_generation`) dir block AND the in-core buf would reintroduce an inum the disk lacks. Mirror sess26 `dir_subset_guard` but for the REINTRODUCE direction (in-core has EXTRA inum vs disk), same-incarnation gated so ghosts/fresh-blocks excluded. WARNING: xfsaild legitimately destages metadata; the skip must be dir-DATA/LEAF + not-EX-held + disk-proven-reintroduction, else it wedges the AIL.
3. Complementary (GFS2/OCFS2 pattern): tie cache validity to the LOCK RESOURCE generation, not a timeless boolean. INVALIDATE (clear XBF_DONE|_XBF_FUA_FRESH) a peer's cached dir buffer when it observes the dir's CAW slot generation advanced (peer modified it) — runs on the BAST-poll observing gen change, cheaper than per-release work, so the stale buffer never destages. On EX acquire (unless proven uninterrupted same-node tenure): invalidate dir DATA/LEAF/FREE/NODE bufs + real FUA read + stamp `bp->fresh_ex_seq=grant_seq`. GFS2 = go_sync (flush before demote) + go_inval (invalidate on demote).

### RULE-5 escalation status
Proven diagnosis + Case B pinned + ≥3 fixes refuted (MHT, release-guards, release_stale-alone). GPT-5.5 consulted ONCE. `ask_fable` MCP NOT connected this session (only ask_gemini / ask_gpt; GPT-5.5 was tier-1 fallback). A 2nd GPT call is justified ONLY after the write-side probe pins the reintroducer with data AND one more distinct fix is refuted.

### Infra (fixed this session — reuse)
- **`scripts/caw_preflight.sh N`** — ALWAYS run before `./run.sh N caw`. Teardown wedged mxfs + power-cycle + /src mount + mpath_up N + verify READY. Prevents run.sh mid-prep power-cycles (lose /src → PREP FAIL).
- **run.sh `power_cycle_node` PATCHED**: after a reboot it now remounts /src + re-logs BOTH iSCSI portals + `multipath` before the DEV wait (was losing /src + mpatha → PREP FAIL cascade). bash -n OK.
- Restore `/tmp/.mxfs_pass` from `/home/steve/.mxfs/pass` after reboots.
- Long runs: `nohup timeout <big> env MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 16 caw <tests> >log 2>&1 &` then foreground-poll `while ls -d /proc/$PID`. NEVER `pkill -f 'run.sh 16 caw...'` (matches own cmdline → exit 144); kill by captured PID.
- criteria.json 1/2/4/8 PASS intact. Marker NOT written.
- Separate known issue: 16-node CONVERGENCE is flaky ("did NOT converge to 16 within 170s") — disklock slot-table read undercount membership-stability issue, contributes to PREP FAILs (see caw-multipath-16node-instability-diagnosis-sess1).
