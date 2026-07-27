---
name: ccloop4dd7-sess5-B-pve9-roots-and-ALL-GREEN-final
description: sess5 END: pve9 roots #7-8 (inbound-connect transition gap + joiner settle gate) FIXED v0.11.72/73; ALL BOARDS GREEN v0.11.73 (2/tcp 20/20, 1/tcp 29/…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, pve9, split-brain, membership, final-state]
---

# sess5 part 2 — pve9 formation roots + final all-green state (v0.11.73 = A9CE91EE)

## Root #7 — TCP inbound-connect single→multi transition gap (SPLIT-BRAIN)
pve9-1/pve9-2 (Proxmox 9.1 VMs, kernel 6.17.2-1-pve, tcm_loop LUN, TCP DLM): manual staggered
mount → each node wrote its own root dir, ZERO BASTs, divergent `ls`. Chain (dmesg both nodes):
- Higher-id node's discovery → `mxfs_peer_connect_force` → **inbound** connect at the joiner →
  `v5_peer_connect_cb_tcp` registers the node in lease + `v5_refresh_active_nodes` (wipes DLM
  lock table at single→multi) but NEVER fires `peer_joined_notify_fn` (XFS flush + perag/inode
  DLM-cache invalidation).
- The joiner's own discovery announcement then hits `mxfs_lease_has_node` → **early return** in
  the v5 discovery handler → the transition NEVER runs on that node → phantom XFS-layer holds
  (pag_dlm_cached with no DLM record) → both nodes self-master → split-brain.
FIX (v0.11.72, dlm/v5_mount.c `v5_peer_connect_cb_tcp`): if `mxfs_dlm_is_single_node` at inbound
connect, fire `peer_joined_notify_fn` FIRST (same ordering as the discovery path), logged as
"connected while SINGLE-NODE — running deferred single→multi transition". Verified live: racy
join printed the deferred-transition line; cross-node visibility restored both ways.

## Root #8 — joiner mount-return-before-membership race (dirent loss)
Reproducer: mount n1, `touch n1_seed` (unflushed), racy-mount n2 + IMMEDIATE `touch` → n2's RMW
ran ~1s BEFORE the peer-connect transition, built the root RMW on the stale platter base →
**n1_seed durably lost cluster-wide**. The joiner KNEW another live node existed (disklock slot
table showed the ACTIVE foreign slot at claim time) yet mount returned before DLM membership
included it.
FIX (v0.11.72/73, dlm/v5_mount.c both TCP and CAW branches): MEMBERSHIP-SETTLE GATE — after
lease start, `mxfs_disklock_get_stale_slot_mask(threshold=0)` snapshots ACTIVE non-foreign
slots; if any, poll `mxfs_lease_get_active_nodes` until count ≥ foreign+1 (250ms steps, 15s cap
→ `P-MEMB-SETTLE-TIMEOUT` warn + proceed for dead slots). Verified live: exact reproducer now
logs "membership settled at mount: 1 active slot(s), lease sees 2 node(s) after 250ms" and BOTH
files survive. NOTE: the "TCP DLM initialized"/"DLM initialized (CAW" prints MUST precede the
gate — run.sh's convergence awk resets its beacon window at that line and the joiner's only
beacon fires DURING the gate (v0.11.72 briefly broke prep; fixed in v0.11.73).

## pve9 verification battery (task #3 closure)
6.17 module builds clean on-node (local copy /root/mxb, NOT the NFS tree — keeps clyde's 6.8
objects). Battery: formation ✓, cross-node visibility ✓, 45s dual churn ~3000 ops/node clean ✓,
**dead-peer umount 0.24s** (virsh destroy pve9-1 → pve9-2 umount+rmmod instant — the pve2
flush_workqueue wedge shape; also b70r1 exercised FS-shutdown-peer teardown cleanly with
P-WITHDRAW-RELALL releasing 10 grants) ✓, `chk_mxfs -v` clean after all of it ✓. Physical
pve1/pve2 (192.168.1.80/.81) POWERED OFF, no IPMI (pve1 = HP Z400, manual reset only) — kernel
dimension covered by pve9 pair; QNAP-iSCSI dimension pending user powering hosts.
Wiring: `scripts/wire_vms.sh attach pve9-1 pve9-2` (extended to accept any defined domain);
nodes need `mount -t nfs4 192.168.1.4:/src /src`.

## Also in part 2
- b70r1 root (v0.11.71 side-read fix, see sess5-A): no recurrence b71r1-3, b73r1-3.
- P58-DIRPIN-NONEX tightened (v0.11.70: require ex_holders==0 && dlm_pin==0 besides mode!=EX) —
  0 fires since (was 357/round noise with ex_h=1, no correlated failure in 14 rounds + suites).

## FINAL STATE (criteria: all known issues resolved)
v0.11.73 = A9CE91EE: **2/tcp 20/20 PASS** (three chunks + instrumented soak dmesg_hits=0),
**1/tcp 29/29 PASS**, deadshell 8/8, stress rounds b73r1-3 clean; 20+ consecutive stall-free
rounds since the v0.11.62 IOLOCK-order fix (b63×10, b69×4, b71×3, b73×3) → task #4 closed;
b55r2 platter-regression watch closed (root #5 fix held, P110/P117 silent 16+ rounds) → task #2.
criteria.json: only non-PASS rows are 4 structural SKIPs in 1/xfs baseline. Armed tripwires all
silent on final build: P9-RMC-* (0), DISCARD-LEAK (0 — the upstream-inherited +1 leak path never
observed live; probe stays as tripwire, fix only on evidence per RULE 4), P-DRAIN-PASSCAP (0),
P-MEMB-SETTLE-TIMEOUT (0), P-SINGLENODE-REGRESSION (0).
