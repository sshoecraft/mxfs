---
name: compiled-caw-multipath-deploy-conditions
description: CAW deploy conditions: 3+1 condition script inventory, dm-multipath CAW+PR verified, caw-mpath ladder 1-8 PASS, infra fixes.
metadata:
  type: project
tags: [compiled, caw, multipath, scst, iscsi, test-infra, deploy-conditions, pr-fencing]
---

## CAW multipath deploy conditions — compiled

Covers the deployment-condition matrix MXFS must validate on the test VM cluster
(N=1..32, ONE shared LUN with N initiators — NOT one LUN per host), the infra
create/destroy/verify scripts, the dm-multipath CAW+PR proof, the CAW-on-multipath
test ladder, and the infra script bugs fixed along the way.

### The deployment conditions (user framing, 2026-07-05) [[caw-test-3-conditions-and-script-inventory]]
CAW = SCSI opcode 0x89, transport-agnostic (same over FC/iSCSI; == VMware VAAI ATS).
Transport never fakes CAW — the *target* does: SCST is real, LIO fakes it, vendor/QNAP
must be verified with `caw_verify`. The three original conditions:
1. **TCP DLM / commodity block (no CAW).** `force_transport=1`, rig = LIO/tcm_loop.
   DONE: 8-node = 100% (`showstat 8 tcp`).
2. **FC-fabric → physical hosts (CAW).** SCST + per-VM QEMU `device='lun'` passthrough:
   clyde is the initiator, distinct target per VM → N sdX on clyde → one passed to each
   VM. Per-VM host session gives REAL PR fencing (sess26). This is the "16/now 32 sdX on
   clyde" model; REQUIRED to simulate FC.
3. **Direct iSCSI mount, no fabric (CAW).** Each VM runs its own `iscsiadm` login to
   clyde's SCST target → own nexus/PR. 0 sdX on clyde. "Joe sysadmin mounts an iSCSI LUN."

Later added as the #1 real enterprise deployment:
4. **CAW over dm-multipath** — SAN (FC or iSCSI) with ≥2 paths + multipathd, mounting
   `/dev/mapper/mpathX`. [[condition4-multipath-caw-pr-works]]

### Script inventory (all in `scripts/`, RULE 3) [[caw-test-3-conditions-and-script-inventory]] [[caw-scripts-all-3-conditions-proven]]
- **`scst_setup.sh {setup|status|teardown}`** — host SCST target. `vdisk_fileio` device
  `mxfs` (async=1, o_direct=1) over disk.img; iSCSI target `iqn.2026-05.local.mxfs:shared`
  on 192.168.120.1:3260. `allowed_portal` = br0 ONLY (critical: clyde has ~9 IPs incl
  docker 172.17-20.0.1 + libvirt 192.168.122.1; without the pin, guests open 9 sessions →
  multipath chaos). Releases LIO first (guard). PORTAL_IP later made a space-sep LIST;
  allowed_portal reset each setup. A vdisk_fileio dev makes NO local sdX until an initiator
  logs in.
- **`scst_wire_passthrough.sh {attach|detach|status} [N]`** — condition 2 host side: per
  node K create distinct target `...:nodeK`, clyde loopback login → `/dev/disk/by-path` dev
  → virsh `device='lun'` into testK as sda. Distinct targets (not N ifaces) REQUIRED:
  per-nexus PR + by-path uniqueness.
- **`lio_tcm_setup.sh`** — condition 1 (TCP). Added `release_scst` guard (symmetric to
  scst_setup's `release_lio`); guard path `/sys/kernel/scst_tgt/devices/mxfs`.
- **`verify_infra.sh {tcp|direct|passthrough|multipath} [N]`** — INFRA-ONLY verifier.
  Replaced and DELETED `caw_cluster_up.sh` (which wrongly formed a cluster). Per node:
  device present + vendor + 50GiB size + raw readable + same SCSI serial. CAW modes do raw
  cross-node `caw_verify` (storage capability, not FS). Checks clyde footprint (direct 0/0;
  passthrough N/N; tcp 0/1). `multipath` mode: 2nd br0 alias 192.168.120.2, `find_multipaths
  yes`, dual-portal login → 2-path mpatha, retry-CAW + PR-across-paths.
- **`tools/prep_node.sh`** (iscsiadm → 192.168.120.1:3260, 32-aware; `fuser -km` before
  umount), **`tools/prep_tcm_node_scst.sh`** (SCST_FIO, sg_opcodes CAW, 180s timeout),
  **`tools/mxfs_sshpass.sh`** (ConnectTimeout=10). Fan-out via `tests/criteria/lib.sh
  fresh_cluster_mount`.
- Docs: `docs/test_infra_scst_caw.md`, `docs/iscsi_setup.md` (end-user),
  `docs/condition4_multipath_scope.md`.

### Infra verified at 32 nodes, all 3 base conditions, 2026-07-05 (infra-only, EXIT 0) [[caw-scripts-all-3-conditions-proven]]
SCOPE was corrected mid-task (user directive): these scripts ONLY create/destroy infra and
verify the shared LUN is presented — NO mkfs, mount, workload, or coherency. That is the
test harness's job.
- direct 32: 32/32, same LUN (serial 2e476d07), CAW PASS, footprint 0/0.
- passthrough 32: 32/32, same LUN, CAW PASS, footprint 32 sessions/32 sd*.
- tcp 32: 32/32, same LUN (LIO-ORG), footprint 0 sessions/1 sd*.
Then torn down to BARE (SCST+LIO gone, 0 sessions, 0 sd*, 0/32 VM configs ref LUN, disk.img
intact).

Verifier bugs found + fixed (RULE 4): (1) direct login raced iscsid at boot → session with
no attached disk; plain re-login no-ops → fix = full clean cycle per retry (logout+delete →
discover → login → session --rescan). (2) sg_inq serial parse flaky → false same_lun=no →
fix = retry + gate "same LUN" on the cross-node CAW proof for CAW modes. (3) footprint
`iscsiadm -m session` needs sudo (non-root returned 0 sessions).

Guest buildup applied to all 32 (should be baked into VM image):
`/etc/multipath/conf.d/mxfs.conf` `find_multipaths strict` (+ cleared wwids) so a single
iSCSI path is NOT wrapped into mpatha; multipath stays RUNNING (prod-correct).
`/etc/fstab`: removed /src NFS auto-mount.

**Honesty correction** (do NOT overstate as proven mxfs bugs — out of scope): CAW-through-
dm-multipath one caw_verify returned UNIT ATTENTION (sense 0x29, power-on/reset) on the
FIRST command; caw_verify didn't retry UA → NOT evidence of a bug. 32-node concurrent-mkdir
gave EUCLEAN + FS shutdown on ~20/32 amid churn — one observation, far past the validated
8-node ceiling, not a filed bug.

### Condition 4 — CAW over dm-multipath: BUILT + VERIFIED 2026-07-05 [[condition4-multipath-caw-pr-works]]
Characterizes whether CAW + PR work through dm-multipath at the raw storage layer (SG_IO +
sg_persist, NO mxfs). Both WORK; the earlier scare was wrong:
- **CAW through dm-multipath: PASS** cross-node, no-retry AND retry-aware. The earlier "CAW
  fails / UNIT ATTENTION 0x29" was ONE transient first-command UA + caw_verify not retrying.
  Does not reproduce. No CAW-multipath bug.
- **PR/fencing through dm-multipath: PASS (N=2)** — nodeA reserves WE-RO (sg_persist
  `--param-alltgpt`); nodeB sees reservation+key through its OWN mpath; nodeB non-registrant
  write BLOCKED.
- **Presentation scales 32/32** — 2-path `/dev/mapper/mpathX` each, same LUN. 32-node PR
  sub-check false-failed only from test1's degraded paths (i/o pending, prio=0) after
  session churn — fresh boot clears it, not a scale defect.

Built: `tools/caw_verify.c --retry-ua` (retry sense key 0x06; NOT in `make tools` — compile
`cd tools && cc -Wall -Wextra -O2 -o caw_verify caw_verify.c`); verify_infra.sh multipath
mode.

Gotchas: `sg_persist` ALL_TG_PT = `--param-alltgpt` NOT `--all-tg-pt`; multipath dev size =
`blockdev --getsz` (not /sys/block/<name>/size); `find_multipaths yes` + clean wwids →
single path stays raw sda, 2-path → mpatha.

**Kernel handoff (mxfs multipath work):** (1) CAW UA-retry most likely needed in
`pal/linux/kern.c :: mxfs_pal_bdev_compare_and_write` (~2600-2860, opcode 0x89 @2638/2753);
handles MISCOMPARE (~2844) + ILLEGAL_REQUEST (~612/654) but NOT UNIT ATTENTION — add bounded
UA (key 0x06) retry mirroring caw_verify --retry-ua; also check read path
`mxfs_pal_scsi_read_fua_bdev` / `mxfs_pal_bdev_read_prio`. (2) PR on multipath — VERIFY
before changing: mxfs kernel PR uses kernel `pr_ops` (`mxfs_pal_scsi_pr_register` →
get_pr_ops @2345 → `bdev->bd_disk->fops->pr_ops`; dlm/scsipr.c on top). dm-multipath's
pr_ops replicates PR to all paths, so kernel PR MAY work UNCHANGED — test first. The
ALL_TG_PT concern is for the RAW userspace SG_IO PROUT path (`pal/linux/user.c` 0x5F), NOT
the kernel pr_ops path. Deferred: real 2-network (2nd bridge+NIC) for path-FAILOVER testing.

### CAW-on-multipath test ladder — actual FS testing (2026-07-06)
Criterion: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh N caw`
all-tests-PASS at N=1,2,4,8,16,32 on ONE build. `criteria.json` is source of truth. Marker
file `/src/mxfs/.ccloop/runs/5bea4199-.../criteria-met` (NOT yet written).

**sess6 (ccloop 186320ae)** [[caw-multipath-matrix-progress]]: 2/caw formation failure was
100% infra, NO kernel bug. Live dmesg forensics found three root causes: (1) leftover
higher-rung nodes — a 4→2 transition left test3/4 mounted+announcing → test2 saw 4 active in
a 2-node run → converge gate never reached 2 → best-effort chaos + P131 self-fences; (2)
silent step-1 cleanup failure — prep teardown was fire-and-forget, test2's old mount survived
(busy), passed the srcversion readiness check, then test1 re-mkfs'd the LUN under it → test2
ENOENT-everything under OLD fs uuid, mutual invisibility; (3) converge gate was WARN+proceed
→ 17 garbage FAILs instead of one loud abort. Fixes (all in-tree): run.sh TEARDOWN snippet
(`fuser -km` + `umount -f` + rmmod), prep step 0 tears down ALL running test VMs outside
NODES + power-cycles dirty ones, step 1 verifies teardown per node and escalates via
`power_cycle_node()` (virsh destroy+start + ssh wait + DEV wait), converge gate now
HARD-FAILS (window 90+5N s). **iscsid + open-iscsi were disabled on ALL nodes** →
node.startup=automatic did nothing after power cycle → `systemctl enable iscsid open-iscsi`
on all 32, and mpath_up.sh now enables (not just restarts).

Build chain: `656E89B4` (v0.6.5, sess5): five fixes → 1/caw + 4/caw 17/17. `57773CBD`
(sess6): 656E89B4 + P124-ALLOC-REVERT probe re-gated instr-only (was dirwr||instr) — its
"no this-node-ahead content" premise is false for a sole-EX-holder under sustained load (no
release → no destage → AIL legitimately ahead of disk), and its dump_stack failed soak's
clean-dmesg criterion; LOG-ONLY change. P88 companion proved forward progression 33→34→35→36.

**ccloop 5bea4199 (build 591A76FB)** [[caw-multipath-ladder-progress-sess-5bea4199]]: ladder
1/2/4/8 caw all 17/17 PASS. 8/caw COMPLETED this session on 591A76FB — the 3 previously
missing (dir_reuse_coherency, fault_netpartition, soak) all PASS. dir_reuse fixed by P6L
leaf scan. 591A76FB is the candidate FINAL build — do NOT rebuild speculatively. `dirwr=1`
is LOAD-BEARING (not just diagnostic): the `dirwr||instr`-gated block in `pal/linux/xfs_buf.c`
(~3992) does a FUA read-back + dco "COHERENT" restore with a functional early-return
(`xfs_buf_ioend; return`) — part of dir coherency, keep it. Pure-diagnostic parts still
active under dirwr=1 (P-LEAFDROP, P-LEAFWRITE ≤50000 lines heavy, P-DIR-DELALLOC-TRIP) did
NOT break 8/caw — RULE 4: only strip if 16/32 shows a timing/log-volume/dump_stack FAIL with
proof; if stripped, keep pr_err counters as canaries. Method: `./run.sh N caw` self-preps
(teardown→mkfs→form→join→srcversion-assert→converge→run→record). Long runs: `nohup timeout
<big> env ... ./run.sh ... >log 2>&1 &` + foreground `while kill -0 PID; sleep` waiter (set
Bash tool `timeout` up to 570000; default 120s). Run 16-node dir_reuse SEPARATELY so a
dir_reuse timeout can't poison fence/fault/soak (run104 cascade). Watch RULE 0 timing at
scale: dir_reuse budget 140*N; 32 → 4480s.

### mpath_up.sh quoting regression — FIXED (2026-07-06, ccloop 5bea4199) [[infra-mpath-up-sh-quoting-regression-fixed]]
`scripts/mpath_up.sh status|up N` → `line 117: syntax error near unexpected token '('`;
script totally unusable → nothing could reassemble `/dev/mapper/mpatha` on nodes that lost
iSCSI sessions. THIS is why 16/caw formation failed: test9-16 had iscsid active but 0 iSCSI
sessions → no mpatha → mxfs mount "Can't lookup blockdev" → converge FAIL (test1-8 already
had healthy mpatha). Root cause: the `NODE_ENSURE='...'` single-quoted block (lines 73-134)
requires the `'"'"'` idiom for inner single quotes; a post-sess6 edit adding
"node.startup=automatic in iscsid.conf" introduced two raw-single-quote bugs — line 117
comment `iscsid.conf's default` (unescaped apostrophe closed the string early, `(manual ...)`
parsed as code) and line 119 `sed -i 's/^node.startup = manual/.../'`. Fix (log/quoting only):
removed the apostrophe on 117; line 119 sed switched to double quotes (pass through the
single-quoted block literally). `bash -n` → SYNTAX OK.

**Ladder lesson:** before EVERY `./run.sh N caw` at a node count whose upper nodes may have
lost sessions, run `scripts/mpath_up.sh up N` first — run.sh does NOT assemble mpatha, it
assumes it exists. This gates 16 and 32.

### NEXT / open items
- 16/caw Run1 (16 tests minus dir_reuse) → Run2 (dir_reuse) → 32/caw same split → final
  one-build full-ladder rerun 1..32 on 591A76FB → write `criteria-met` marker.
- Known non-blocker: `mxfs_ili` kmem-cache leak at rmmod ("Objects remaining" BUG line
  between runs).
- `lib.sh` DEFAULT_NODES still lists only test1..16 (stale) — worth fixing.
- verify_infra.sh multipath: PR reports B_sees_resv=0 but ENFORCEMENT works (registrant ok,
  non-registrant blocked) — fence tests are the oracle.
