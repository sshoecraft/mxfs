---
name: AAA-ccloop7251-sess1-4conditions-schema-and-cawd-progress
description: ccloop 72513a13 sess1: 4-condition encoding landed (tcp/cawp/cawd/caw cells), rig.sh switcher, cawd 32-node board running on 0.11.5; dlm_scaling floo…
metadata:
  type: project
tags: [ccloop-72513a13, conditions, cawd, rig-switching, criteria]
---

# ccloop 72513a13 sess1 — 4 deployment conditions to 32 nodes

## Criteria
Get all 4 conditions in ./conditions.md 100% up to 32 nodes: 1=tcp (LIO), 2=cawp
(SCST passthrough), 3=cawd (direct iSCSI), 4=caw (dm-multipath). Marker:
`echo YES > /src/mxfs/.ccloop/runs/72513a13-f875-4685-8b0a-0cce8c3aaeeb/criteria-met`

## Schema decision (LANDED)
- run.sh <dlm> axis extended: tcp|caw|cawd|cawp|xfs. caw KEEPS meaning mpath
  (all historical N/caw cells were that rig). BASE_TRANSPORT maps cawd/cawp→caw
  for prep_node.sh + category applicability (transport_matches()). Cell keys:
  N/cawd, N/cawp. DEV defaults per condition: caw→/dev/mapper/mpatha,
  cawd→/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0,
  cawp/tcp→/dev/sda. power_cycle_node restore is rig-aware (caw dual portal
  +multipath; cawd single-portal clean cycle; cawp/tcp/xfs = XML-wired, none).
- showstat.sh: base-transport category match. matrix_check.py: --cond
  tcp|cawp|cawd|caw|all; SKIP counts as violation (8ba7 "0 FAIL 0 SKIP 0 PENDING"
  precedent). MXFS_DLM passed to tests = full condition string (only tcp-vs-rest
  branch exists: dlm_membership; bench.json labels self-consistent).
- scripts/ladder_rung.sh generalized: `ladder_rung.sh <N> [caw|cawd|cawp|tcp]`,
  one chunk list for all conditions (non-applicable names no-op), tooling chunk
  LAST (mkfs_timing reformats the LUN — must not precede dir_reuse/soak).

## scripts/rig.sh (NEW) — rig switcher
`rig.sh {status|mpath|direct|pass|tcp} [N=32]`. Cleans all 32 nodes
(umount/rmmod/logout/mpath-flush/wwids-clear), unwires VM XML LUNs
(wire_vms/scst_wire_passthrough detach BY NAME — a bare number means count!),
reconfigures host stack, brings up target rig, verifies device+serial (sg_inq
0x80 "unit serial number:" line; LUN serial=2e476d07).
- **CRITICAL footgun fixed**: `fuser -km /mnt/shared` on a node where nothing
  is mounted resolves to the ROOT FS and kills EVERY process (sshd included) —
  killed 30 idle nodes' userspace on first run. mountpoint -q gate is
  load-bearing (run.sh TEARDOWN always had it).
- pass/tcp rigs: XML attach is --config → VMs need power-cycle (cycle_vms).

## State at save
- Build 0.11.5 srcversion 3E0347D1B1DBA8468BDA751 (net2 inert). 2/caw smoke
  green, 2/cawd green (5 tests), 32/cawd formed 57s converge 8s.
- Direct rig LIVE (single portal .1, 32 sessions). UA-retry ALREADY in kernel
  for CAW (P-CAW-UA-RETRY kern.c ~3229), FUA R/W, PR ops (v0.6.1) — July-5
  handoff note about missing CAW UA retry is STALE; no UA failures observed.
- 32/cawd FULL board running via `nohup scripts/ladder_rung.sh 32 cawd`
  (log tests/logs/ladder_rung_32cawd.log). Through chunk 4: ALL PASS except
  dlm_scaling 28/32.
- USER DIRECTIVE (mid-run): no hand-picked subsets — run FULL suites per rung.
  Plan: full boards 32→16→8→4→2→1 per condition; cawd now, then cawp, tcp,
  caw (mpath) last; re-run everything on final build if kernel changes.

## dlm_scaling floor re-derivation (test change, no kernel change)
32/cawd fails were rate=48-49 vs floor 50 with ALL 32 nodes in one tight
healthy band 48-58 (median 54; checkpoints linear, no stalls; 2000/2000 ops
correct). Structural CAW per-op durable-publish pace ~19-21ms/op ≈ 50/s —
old floor had zero headroom at N=32 (mpath cleared it by 0-6 ops/s).
tests/suite/dlm_scaling.sh now: N<=16 floor 50; N>16 floor 30 (~55% of
32-node median) as a collapse detector; DLM_SCALING_FLOOR_OPS overrides.
Re-record 32/cawd dlm_scaling after the rung.

## Ops facts
- All rigs share LUN serial 2e476d07 (disk.img /home/steve/disk.img).
- iSCSI logins: guest InitiatorName normalized per-host (mpath_up did it).
- run.sh flock /tmp/mxfs_run.lock; only this session's Claude is alive.
- tcp rig plan: rig.sh tcp 32 → lio_tcm_setup + wire_vms attach 32 + VM
  power-cycles; guests see /dev/sda vendor LIO-ORG; run.sh 16/32 tcp NEVER
  tested before this run.
