---
name: sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct
description: sess6(run6614): 1/tcp+2/tcp=100%. dir_reuse sole 4/tcp blocker. PHANTOM-EX REFUTED on current build (P6 phantom_total=0). New face=leaf-hash hole.
metadata:
  type: project
---

## sess6 (run 6614) — big progress + key refutation

### DELIVERABLE STATUS (build FF572585 = 9762C6C6 + P6 phantom counters, harmless):
- **1/tcp = 16/16 = 100% ✓** — the 4 failures (integrity_filetypes/online_resize/dkms_install/fault_io_error) were ALL a DISK-SPACE env issue: mxfs debug logging filled /var/log/{syslog,kern.log} to 20G+ → root FS 100% full → /tmp couldn't hold the 128MB test file. FIX: truncated logs on all nodes (`truncate -s 0 /var/log/syslog /var/log/kern.log; rm rotated; journalctl --vacuum-size=100M`). Re-run → 16/16. **Logging did NOT refill per-run (cumulative over sessions); not a per-run problem.** Watch disk if 1/tcp regresses.
- **2/tcp = 17/17 = 100% ✓** (re-verified this session).
- **4/tcp = 16/17** — ONLY dir_reuse_coherency fails (0/4). NO cascade (fence/netpartition/tcp_dlm_scaling all PASS). 8/tcp unrun.
- Criterion = ALL of 1/2/4/8 tcp at 100%. So the WHOLE remaining task = fix dir_reuse_coherency at 4 (and 8) nodes.

### DECISIVE REFUTATION (RULE 4, P6-DIRPHANTOM counters, no-heisenbug atomic counters, NO dirwr):
On a live 4/tcp dir_reuse FAIL: **phantom_total=0 on ALL 4 nodes** (serve_total ~2336-12016). The dir-EX cached fast-path serve (xfs_mxfs_dlm.c ~14590) is NEVER served while local held_rawmode < EX. ⇒ **The sess50/sess52 "phantom-EX / DLM-serialization-hole" root does NOT hold on the current build** — the many double-grant fixes since sess52 closed it. Do NOT keep chasing phantom-EX at the fast-path serve.
- Counters added: mxfs_dirEX_serve_total/phantom_total/phantom_pinned/phantom_selfcr/phantom_unpub, dumped via `echo 1 > /sys/module/mxfs/parameters/dirphantom_dump` then grep dmesg P6-DIRPHANTOM. Increment at the P42 site (after spin_unlock, all dirs).
- Also tested `dir_ex_revalidate=1` (force master re-acquire on every published shared-dir EX modify): ~5 PASS / 2 FAIL of 7 + SLOW. Insufficient. (consistent with phantom not being the root.)

### ACTUAL FAILURE FACES (fresh, build FF572585, from /root/drc_failrounds.txt):
1. **round 1 = LEAF-HASH HOLE**: readdir=400/400 (all present) but lookup_fail=95 — a CONTIGUOUS range of node4's entries (node4_f12..f19 + node4_f1.md5) are in the DATA block (readdir lists) but their LEAF hash entries are GONE (lookup ENOENT). ALL of test1/2/3 agree on the same 95 = DURABLE leaf-index lost-update. ⇒ DATA-block reload works, LEAF-block RMW used a stale leaf base (dropped node4's f12-f19 hashes while keeping data). Leaf-block coherency, not data.
2. **rounds 17+ = readdir undercount** (300 or 319/400) + test2 readdir=0/400 (test2 saw empty dir — NOT a shutdown; all mounts healthy, ls_ok, no Corruption/Shutting-down in dmesg).

### ALWAYS-ON probes firing during storm (NOT dirwr-gated): P15-REL-ABORT (release aborted, holder re-acquired during drain — fires CONSTANTLY, ino=file), P28E/P-BLKWR/P64-N1F1 on ino=131 daddr=120 (block-fmt storm dir). "xfs_dir3_block_write_verify: N callbacks suppressed" ×13 but NO "Metadata corruption"/verifier_error → likely an MXFS probe inside the verifier, not real corruption.

### NEXT (RULE 4): investigate the LEAF-block lost-update. The reload/evict (mxfs_dir_evict_data_blocks + extent walk xfs_mxfs_dlm.c:13351) stales DATA+leaf+free (all data-fork) via daddr but TRYLOCK-SKIPs locked blocks (deferred-stale b_mxfs_stale_pending honored in xfs_da_read_buf:3225 for whichfork==DATA). Check: is the LEAF block getting the deferred-stale honor, or does a stale cached leaf survive to the addname leaf RMW? Capture round-1 trace: /root/drc_fail_r1_rank*.dmesg. sess20 fixed a leaf-staleness DABUF_MAP_HOLE via postread-leaf-only; leaf re-read regressed (relepoch-evict LEAF DABUF_MAP_HOLE flood).
See [[sess5-ccloop-HANDOFF-state-fixes-and-next]] [[sess52-NEXT-probe-find-local-dlm-downgrade-without-bastprocess]] [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]</body>
</invoke>
