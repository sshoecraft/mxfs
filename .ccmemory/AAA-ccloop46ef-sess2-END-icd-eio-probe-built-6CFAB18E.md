---
name: AAA-ccloop46ef-sess2-END-icd-eio-probe-built-6CFAB18E
description: sess2 END: build 6CFAB18E (ICD lap counters + plain-read discriminator probe) BUILT NOT RUN. PROVEN: victim EIO-death = imap_to_bp -EIO ×1500 in ICD;…
metadata:
  type: project
---

# ccloop46ef sess2 END — state for sess3

## IMMEDIATE NEXT ACTION
Deploy+run build **6CFAB18E** (in tree, v0.10.2):
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 1400 ./run.sh 32 caw cache_coherency`
then read the NEW probe line in the victims' kernlogs (artifact dir /tmp/run_cache_coherency_<ID>/kernlog_test*):
`P9-ICD-MIDLOOP ino=… imap_rc=… plainrd_rc=… magic=… shutdown=…`
Discrimination:
- shutdown=1 → an UNLOGGED FS shutdown precedes; hunt what set the flag (no "has been shut down" line exists — check xfs_do_force_shutdown callers/flags, maybe message rotated or a flag-set path without message).
- shutdown=0 + plainrd_rc=0 + magic=0x494e ('IN') → device+content fine ⇒ buffer-LAYER refusal inside xfs_buf_read_map/mxfs gates (FUA path mxfs_buf_read_fua rc handling ~pal/linux/xfs_buf.c:6771+, read-skip arm at 6663 fakes success, P122 arm needs mxfs_suppress_stale_agwrite) — instrument mxfs_buf_read_fua error path next.
- plainrd_rc!=0 → real device-level read failure (check multipath/PR at that moment).

## PROVEN THIS SESSION (evidence-cited)
1. **cache_coherency@32 fails 0/32 with floor=1 (default), effectively PASSES with dir_ex_tenure_floor=0** (3020/3021, sole fail = self-inflicted /tmp artifact). Clean-disk A/B: floor=1 → 0/32 (run 032702Z), floor=0 → pass (run 031632Z). dlm_scaling@32 floor=1 clean-disk = 29/32 (victims quota=0 = dead mounts, not rate).
2. **Victim-death mechanism**: 1-3 nodes/run go mount-wide EIO mid-rv-phase. P9-ICD-FAIL ino=131/128/2097280 (SF parents + ROOT) max_try=1500 **imapf=1500 last_rerr=-5** (new counters, run 033921Z: test16/23/24 wedged on ino 131 SIMULTANEOUSLY 03:44:30; comm=kworker = the tenure dwork release). xfs_imap_to_bp returns -EIO every 2ms lap for 6s. NO sd-layer IO errors, NO P-FUA-READ-ERR (its 20-retry logger silent), NO verifier "Metadata corruption", NO "has been shut down" line — yet post-mortem statx(mountpoint)=instant EIO like a shutdown flag.
3. The tenure machinery (sess1 dir_ex_tenure_floor/grace, dwork releases) is the ENABLER: floor=0 avoids it entirely. dwork context (kworker) runs bast_process→RELFENCE→mxfs_inode_cluster_durable (ICD) on SF parents (ino 131 = .cache_coherency, stays SF forever, EX-hammered by subdir ops).
4. Infra fixed this session (keep!): node root disks (6.1G on test9-32) were FULL — triplicated kernel logging; scripts/node_disk_hygiene.sh applied (rsyslog masked, journald capped 200M, drc_* cleaned) — disk-full FABRICATES victim failures (memory: infra-node-root-disks-fill-and-fabricate-victim-failures). Serial capture live on all 32 VMs (grub console=ttyS0 + libvirt log append=on; panics now captured). run.sh prep power-cycles parallelized. mxfs_sshpass.sh flattens args — NEVER inline complex scripts (memory: infra-sshpass-wrapper-flattens-args).
5. Refuted en route: slot-table ghosts (all 1814 slots one vol; volume_id=FNV1a(sb_uuid) rotates per mkfs); PR keys currently all 64 present; sess-1 strand did NOT recur (P15H escalation works: 11-26 fires/node, 0 rc=-110 in trio); panic was an amplifier not driver (test12 panicked run 021307Z only; panics now serial-captured).
6. Run-2 (021307Z) torn-publish clobber (node7 11-over-23 at daddr 37678120 after test12 panic mid-create) — REAL crash-recovery gap (P15-abort drains publish blocks w/o dinode; no foreign journal replay) but SECONDARY: fails happen without crashes.

## AFTER the EIO root-fix (order)
1. Fix the victim-death (root cause via MIDLOOP probe). Re-run cache_coherency@32 ×2-3 clean.
2. dlm_scaling@32: with victims fixed expect near-32/32; add ops_in_tenure>=2 grace gate if rate-floor still misses (design in AAA-ccloop46ef-sess2-STATE memory).
3. crash_consistency@32 re-verify (floor must stay for it; it PASSED with floor+grace in run 014650Z).
4. dir_reuse@16 (2240s budget) + @32 (4480s) — run_in_background, poll output file.
5. FULL ladder on FINAL build: ./run.sh N caw for N=1,2,4,8,16,32 (~17 tests each; 16/caw currently 16/17 PASS on older builds needs re-sweep too).
6. All green → echo YES > /src/mxfs/.ccloop/runs/46efd8b6-3dd3-477c-b004-14362c80d8e8/criteria-met

## Build ladder this session
30E6BF7F (sess1 sliding grace) → 2A10F6B9 (ICD lap counters, run 033921Z) → **6CFAB18E (current: + MIDLOOP plain-read/shutdown discriminator; BUILT, NOT DEPLOYED/RUN)**. All params default-on except tests pass caw_fair_handoff=1.
