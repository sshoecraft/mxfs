---
name: caw-16node-dirent-loss-current-state-sess1
description: 16/caw HEAD (ccloop 26c41354 sess1): core bug = durable dir-block dirent-removal lost-update (dangling dirent, dir ino 2097305, last-file bias) at 16…
metadata:
  type: project
---

## 16/caw multipath — CURRENT STATE (ccloop 26c41354, sess1, 2026-07-06, build 591A76FB)

Continues [[caw-multipath-16node-instability-diagnosis-sess1]] + [[caw-16node-dirent-loss-gpt-design-plan]]. Marker NOT written.

### THE reproducible core bug (everything else is downstream/variance)
Durable **dir-block dirent-removal lost-update** → DANGLING DIRENT. 16 nodes each create 30 + unlink 30 in ONE shared dir (ino 2097305). ~1 dirent of ~480 survives: its inode IS freed (P-IRESURRECT/P119/P17B inode-cluster guards WORK) but the parent dirent survives on disk → lookup finds name → iget ENOENT (`P26-IGET-FAIL dp=2097305 name=nodeN_fileM inum=X err=-2`). **Always the LAST-ish file** in a node's batch (_file19/_file30 — the final removal, released via idle MHT-expiry/BAST, no subsequent op to re-flush it). Passes SOLID at 8 nodes; ~30-50%/coherency-test fail at 16 (SAME residual race, ~2x more probable). Individual tests PASS alone at 16 (cache_coherency 16/16 alone); the SUITE fails because SOME test hits the race.

### Release path is already very mature (why easy fixes fail)
`mxfs_dlm_bast_process` (used by BOTH immediate-BAST and MHT-expiry dwork — root#4 REFUTED, they're equivalent) → dir release loop (xfs_mxfs_dlm.c ~11237): `mxfs_dir_data_durable(ip)` checks EVERY cached dir block for dirty|in_ail|pinned|delwri|logged≠written (sess33/47/98/43/133 layers). `fua_always=1` default (every coherency read is a REAL SCSI FUA — root#2 stale-read mitigated). Three GPT-recommended guards EXIST but DEFAULT-OFF: `dir_relverify` (disk==incore at release), `dir_release_stale` (GFS2 invalidate-on-demote), `dir_wr_barrier` (P40, wait in-flight write bios).

### FIXES REFUTED THIS SESSION (RULE 4 evidence)
1. **MHT increase** (inode_mht_ms=600 dir_sf_mht_ms=120): coherency WORSE (posix_multi PASS→0/16). Longer hold delays visibility. Defaults 300/40 tuned for 8 nodes.
2. **Release guards ON** (dir_relverify=1 dir_release_stale=1 dir_wr_barrier=1): cache_coherency TIMED OUT 0/16 (~300s). The heavyweight drain (per-release FUA verify + write-barrier wait) is TOO SLOW at 16-node handoff frequency → RULE-0 timeout. THE FIX MUST BE LIGHTWEIGHT (no per-handoff latency).

### Proven clobber shape (from ccmemory sess22/sess32-HEAD) → the lead
The dir_reuse loss is **WITHIN-tenure**: a node destages a stale-KEPT dir DATA/LEAF block while STILL HOLDING EX (so the `dir_ex_write_guard` "not-held-EX" gate misses it) — a prior-tenure base kept in-AIL-undestaged at a modify-evict, RMW'd, flushed, erasing a peer's dirent. The xfsaild ABA-writeback suppressor `mxfs_buf_xfsaild_skip_dir_write` (pal/linux/xfs_buf.c ~3327-3610) has MANY default-OFF, mostly-refuted arms (mxfs_dataclobber, dir_ex_write_guard, dir_stale_incarn_skip, dir_subset_guard, dc_stale via b_mxfs_dir_gen<dir_gen). This is a LIGHTWEIGHT skip (no latency) — the right place for a fix IF the clobber is Case B.

### NEXT (RULE 4 — do NOT guess-patch the ABA arms; PROVE Case A vs B first)
1. **Decisive probe** (GPT design, [[caw-16node-dirent-loss-gpt-design-plan]]): at dir release after drain but BEFORE CAW unlock, raw-FUA-read (bypass xfs_buf) the modified dir DATA/LEAF blocks; log whether the just-removed name is ABSENT. Case A (present) = drain never wrote it. Case B (absent, reappears later) = a later write clobbers → capture the first subsequent physical write to that daddr (writer node, EX-held?, foreground-RMW vs xfsaild, dirent-count, whether a real FUA bio ran). Add a paired probe at the xfsaild dir-write (xfs_buf.c ~3327) logging owner/daddr/EX-held/name-present for EVERY dir-block write. Requires rebuild + loop cache_coherency at 16 until fail (~50%).
2. Given the mature release path + fua_always=1, STRONGLY expect Case B (within-tenure ABA destage). If so, the fix is a LIGHTWEIGHT xfsaild-skip: suppress the destage of a dir block whose in-core image would erase a dirent present in a real-FUA read of the current disk (disk_has_extra_inum) — the sess22/26 dir_subset_guard direction, but make it CORRECT (the refuted arms false-skipped ghosts/fresh blocks; gate on same-incarnation b_mxfs_dir_incarn==i_generation + disk-proven content).
3. Escalate to ask_gpt (2nd call, same issue) ONLY after the probe pins Case A vs B with data + one more distinct fix refuted. ask_fable MCP is NOT connected (only ask_gemini/ask_gpt available); GPT-5.5 was tier-1 fallback.

### INFRA (fixed this session — reuse)
- **`scripts/caw_preflight.sh N`** — ALWAYS run before `./run.sh N caw`. Teardown wedged mxfs + power-cycle + /src mount + mpath_up up N + verify READY. Prevents run.sh mid-prep power-cycles (which lose /src → PREP FAIL).
- **run.sh `power_cycle_node` PATCHED** (sess1): after a reboot it now remounts /src + re-logs BOTH iSCSI portals + `multipath` before the DEV wait (was losing /src + mpatha → PREP FAIL cascade). bash -n OK.
- Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass after reboots.
- Long runs: `nohup timeout <big> env MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 16 caw <tests> >log 2>&1 &` then foreground poll `while ls -d /proc/$PID`. Bash-tool self-match: NEVER `pkill -f 'run.sh 16 caw...'` (matches own cmdline → exit 144); kill by captured PID via `ls -d /proc/$PID`.
