---
name: technique-kill-a-vm-on-its-own-kernel-line-and-never-wait-on-the-corpses-ssh
description: TECHNIQUE (sess50/51, D-0965 kill arm): a fixed sleep before virsh destroy killed the node before its REGISTER; waiting on the corpse's ssh blocked 9…
metadata:
  type: feedback
tags: [harness, virsh, scsi-pr, d0965]
---

# Killing a VM mid-mount: key the kill on the node's own kernel line, and never wait on the dead node's ssh

Surfaced by `tests/d0965_successor_killed_after_register.sh` (sess50 first run, sess51 fixes). Two harness defects, each of which made the arm vacuous while every assertion still ran.

## 1. A fixed sleep before the kill lands wherever the ssh login and the slowed mount put it

`sleep 3; virsh destroy A` was meant to kill A after its PR REGISTER and before its settle. With a 1.5 s delay injected into every READ KEYS, the ssh login plus the mount's pre-observe bracket put the REGISTER at ~3.8 s, so the kill landed first: A's record read ABSENT on the peer, the key table was empty, and the peer mounted clean. The evidence directory had an empty `a_mount.txt` and an empty `keys_after_kill.txt`, which is the tell.

Fix: poll A's own ring over ssh for the line that marks the state you want (`P-PRKEY-REGISTERED 'mxfs' key=`) after the kmsg mark, bounded, and destroy the moment it appears. Report `registered_seen=1` and the ms into the mount as evidence.

## 2. `wait` on the ssh client that was talking to the dead VM blocks until TCP gives up

The mount was launched as `( ssh A mount ... ) & apid=$!` and the harness did `wait $apid` after `virsh destroy`. The client sat 96 s before the peer's mount started. In that window the state under test had already moved on (the key was gone), and the arm read as "the target dropped the registration" — which the sess51 poll then disproved: the QNAP iSCSI target kept the dead session's registration for the whole 10 s grace and it vanished only when the peer's PREEMPT AND ABORT landed (poll: last seen 11.1 s, first absent 12.1 s; fence certified at 11.6 s).

Fix: run the client under its own session (`setsid bash -c "..." & apid=$!`) and `kill -- -$apid` right after the destroy. The peer then mounts 0.7 s after the kill.

## 3. The first-sight line is state=UNKNOWN; the classification is the worker's result line

`P304-RETIRE-PENDING-SEEN ... state=UNKNOWN` is logged before the table is read; `P304-RETIRE-WORKER ... result=PRESENT` is the classification. A reach predicate on `SEEN.*state=PRESENT` read 0 on a lap where the grace, the withdraw and the fence all happened (s51kill2). Count the worker's result line, or the grace line itself.

## 4. A rebooted test VM has no /src

The tree is NFS; `prep_node.sh` lives on it. Running it before mounting `192.168.1.4:/src` reads as a prep failure ("No such file"). Mount with the retry loop the other harnesses use first (`tests/d0932_owner_depart_takeover.sh:193` has the shape).
