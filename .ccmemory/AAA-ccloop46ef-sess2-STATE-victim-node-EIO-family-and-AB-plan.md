---
name: AAA-ccloop46ef-sess2-STATE-victim-node-EIO-family-and-AB-plan
description: sess2 MID: cache_coh@32 0/32 ×3 on 30E6BF7F = per-run VICTIM nodes go EIO-dead mid-test (test10 ICD-FAIL ino=131 6s → mount EIO forever, no shutdown…
metadata:
  type: project
---

# ccloop46ef sess2 — victim-node EIO family (cache_coherency@32 on 30E6BF7F)

## Refuted theories (evidence-cited, do NOT re-chase)
1. ~~Panic as driver~~ — run 024415Z + cap4 failed 0/32 with ZERO panics (serial capture live on all 32 VMs now: /var/log/libvirt/qemu/testN-serial.log append=on; guest console=ttyS0 all verified).
2. ~~node1_before_1 clobber~~ — cap4 P29 ledger: the "REGRESS" writes at 02:54:31+ were the RENAME phase legitimately removing before_N one per mv. before_1's 02:55:09 "miss" is the old-gone check working.
3. ~~Slot-table ghosts across mkfs~~ — full dump (scripts/caw_slot_dump.py, offset 67149824): all 1814 slots (789 LIVE/1025 TOMB) carry ONE vol=0x5483b603fc65f748; volume_id = FNV1a(sb_uuid) rotates per mkfs (xfs_super.c:2667). No foreign-vol entries.
4. ~~PR-fence as current blocker~~ — sg_persist shows all 64 keys; test10 HB failures=0. (PR conflicts DO occur ~10/node at prep teardown/CLEAR windows — old-mount collateral, e.g. test10 02:51:42 log EIO -52 was the PREVIOUS mount dying during next-run prep. Prior mount-time UA family fixed in v0.6.1.)
5. ~~run-2 torn-publish clobber (N7 11-over-23)~~ — REAL for run 021307Z but that run had test12 PANIC mid-create; crash-dependent. Runs 3/4 fail without any crash.

## CONFIRMED shape (cap4 run 025140Z, live harvest in scratchpad/cap4/)
- Failures concentrate on per-run VICTIM nodes: node9 (cwr size 901120/1048576 everywhere incl. own view), node10 (all 20 rv contents empty; size 0 ON LUN), node12 (uv 6 unlinks remain).
- test10 timeline: healthy through 02:55:36 → `P9-ICD-FAIL ino=131 rel=1 max_try=1500 clean=1 rerr=0 pin=0 in_ail=0` + `P13-SFPARENT-DURABLE-FAIL ino=131` + P106-EXREL ino=131 drain_ms=6118 → noino-BAST storm (500-1500/5s) 02:55:41-02:56:26 → **mount EIO forever** (statx on mountpoint root = instant EIO, NO shutdown message in 16M ring spanning the window, HB fine, PR fine). EIO source UNDIAGNOSED — shutdown-flag-set-without-message OR DLM/mount poisoned some other way. FIND THE EIO SOURCE if A/B doesn't moot it: check xfs_is_shutdown flag via crash/live probe; find what P9-ICD-FAIL's caller does on false return (xfs_mxfs_dlm.c:4655 loop; ICD loop at ~4400-4660; tenure-refuse at 4467 requires (rtry&31)==0 && inode_held==0).
- Victim's committed-in-core file state (13-byte contents, final cwr size) stranded when mount died: never destaged → LUN keeps size 0/901120 → every node incl. victim reads stale = ALL the "coherency" check failures. The file losses are DOWNSTREAM of the victim's death.
- ino 131 = .cache_coherency SF parent dir — the tenure machinery (sess1: keep-delay extended to ALL dir formats + BAST-state arm) now batches ITS tenures too; ICD-FAIL hit exactly ino 131 during a dwork release.

## THE A/B (next action, no rebuild — params are 0644)
- A: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1 dir_ex_tenure_floor=0" timeout 1400 ./run.sh 32 caw cache_coherency` → expect PASS (DDB9E83B equivalence) ⇒ tenure machinery confirmed as enabler.
- B (after A passes): same with crash_consistency → expect FAIL (starvation returns; floor exists for it).
- Then tenure v2 design: (1) ops_in_tenure>=2 gate for the grace (dir_gen delta since grant; single-op tenures release immediately — also fixes dlm_scaling rate-floor tax "ds nodeN rate>=floor"), (2) EXCLUDE the SF parent from long tenures OR fix the ICD/tenure interlock (ICD refuses when slot no longer ours — fair_handoff yield mid-release?), (3) keep crash_consistency batching via the holder-race abort bootstrap.

## Infra done this session
- run.sh prep: parallel power-cycle escalation (both loops) — 32-dirty-node prep converges ~6 min.
- scripts/setup_serial_capture.sh (idempotent; NOTE its fix_guest sed path mangled /etc/default/grub via mxfs_sshpass.sh CMD="$*" flattening — repaired via scp'd grub.fixed on 19 nodes; originals at /etc/default/grube. NEVER pass quoted scripts through the wrapper — memory infra-sshpass-wrapper-flattens-args).
- scripts/live_marker_harvest.sh start/stop/collect N [dir] — journalctl -f collectors, beat the ~85s dirwr rotation.
- Budgets: outer timeout for 1-test run.sh = 1400s (prep 360 + converge 65 + test 300 + artifact ~180 under dirwr).

## Scoreboard on 30E6BF7F
crash_consistency@32 PASS 32/32 (run 014650Z trio). cache_coherency 0/32 ×3. dlm_scaling 0/32 (rate-floor; no corruption/strand — P15H strike-escalation WORKS: 11-26 fires/node, zero rc=-110 in trio run).
