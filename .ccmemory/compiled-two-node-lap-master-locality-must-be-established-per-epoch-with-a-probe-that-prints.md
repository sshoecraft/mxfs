---
name: compiled-two-node-lap-master-locality-must-be-established-per-epoch-with-a-probe-that-prints
description: Master locality is a hash, re-decided on cluster re-form; establish it first-hand per lap with a probe whose print condition covers the inode.
metadata:
  type: feedback
tags: [compiled, harness, dlm, locality, measurement-integrity, live_holder_wait]
---

# Two-node laps: master locality is a hash, per-epoch, and must be measured with a probe that actually prints

Shared topic: `tests/live_holder_wait.sh`-style laps that must know which node masters a candidate inode, because remote-master (wire) and local-master (queue, no wire) are different code paths with different waiter handling. Three notes, one failure family: locality was assumed, carried over, or read from a silent instrument, and the lap scored a pass on the wrong path.

## Facts

- Which node masters a DLM resource is a hash of the resource id. A harness that uses whatever inode it creates has a per-run coin flip over which path it exercises. [[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]]
- The hash's answer changes when the cluster re-forms. Measured on 2 nodes / TCP: ino 139 was mastered by test2 in one build, then after `scripts/module_swap_deploy.sh 2 tcp` (same fs, same inode numbers) by test1. A module swap is a re-form, so locality never carries across a deploy. [[trap-master-assignment-moves-across-a-module-reload-so-locality-is-per-epoch]]
- The blocking notification is fired by the MASTER, not the holder. For a locally mastered target the master is the requester, so counting on the holder reads 0. [[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]]
- `P7S-BAST-FIRE` (`fire_bast_records` in `dlm/dlm.c`) printed only for `MXFS_LTYPE_INODE` with `ino <= 256` (fresh-fs hot dirs). On an aged fs the candidates were inodes 3713..3720, nothing printed, all read `master=undetermined`, and the lap aborted with a false "none remote-mastered". The lap's own `otherfire == 0` check would also have passed vacuously for any ino > 256. [[trap-a-locality-probe-scoped-to-low-inode-numbers-goes-blind-on-an-aged-filesystem]]

## Failures that passed

1. Two laps on different mastering read as a before/after (238 vs 237 blocking notifications at the holder) and scored 9/9 PASS while measuring the path not under test. [[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]]
2. Budget gate `fires <= budget` scored a zero from the wrong node as a pass. A zero there is a broken instrument: the wait had a blocking holder, so something fired. [[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]]
3. A probe that armed the request-drop knob and called the candidate LOCAL when the knob did not fire read an absence as an answer. ino 140 was declared local; test1 fired 26 notifications, test2 (the node counted on) fired zero. Caught only by an earlier-added assertion that the fire count came from a node that actually fired. [[trap-master-assignment-moves-across-a-module-reload-so-locality-is-per-epoch]]
4. Unscoped `P7B-BASTNOTIFY` on the holder read 27 for a lap whose target was one of them; `ino=140` also matches `ino=1400`. `P36-RETRY` is `pr_warn_ratelimited`, so its line count is not a retry count. [[trap-master-assignment-moves-across-a-module-reload-so-locality-is-per-epoch]]

## Rules

- Establish locality inside the lap that uses it; never carry it across a deploy or any cluster re-form.
- Firing of a remote-path-only probe (e.g. `dl_drop_lockreq_ino` site) proves remote; its silence proves nothing. Make both branches first-hand: holder takes a conflicting grant, waiter reads, see which node LOGS the blocking notification. The master states it in its own log either way.
- Per candidate, scoped to the run's kernel-log mark: `grep -ac "P7S-BAST-FIRE ino=$ino " dmesg_testN.txt` on both nodes. Exactly one side non-zero is the master; both or neither is UNDETERMINED, skip the candidate, do not guess. After the lap assert the other node fired zero for that inode so a mid-lap remaster is loud.
- Scope every count with `ino=$ino ` including the trailing space.
- Derive the counting node from established locality, not from `H`/`W` role names (holder/waiter, not master).
- The lap declares which path it measures and ABORTS if it cannot get it.
- Any count that is zero only when the instrument is mis-pointed needs an explicit "instrument fired at all" assertion.
- Before scoring on a probe line, check the probe's print CONDITION (inode scope, budget, ratelimit), not just its existence. An inode-selective probe is fresh-fs-only unless it honours an explicit target knob. Fix in 0.84.0: `dbg_probe_ino` (0644) makes `P7S-BAST-FIRE` and `P7B-BASTNOTIFY` print for the named inode regardless of number; the harness arms it per candidate and for the chosen target. [[trap-a-locality-probe-scoped-to-low-inode-numbers-goes-blind-on-an-aged-filesystem]]
- Two laps are a before/after only if every axis but the change is pinned, including the inode number and the cluster epoch (build/re-form).
