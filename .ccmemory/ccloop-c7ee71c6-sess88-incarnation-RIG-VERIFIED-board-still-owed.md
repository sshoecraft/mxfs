---
name: ccloop-c7ee71c6-sess88-incarnation-RIG-VERIFIED-board-still-owed
description: sess88: incarnation landing DEPLOYED + RIG-MEASURED. Epoch nonzero/distinct/per-incarnation, death path names victim exactly. Board + SUPERSEDED arm…
metadata:
  type: reference
tags: [sess88, disklock, incarnation, epoch, rig-verified, measured, proto-gen-3, board-owed, hb_slots-fix]
---

# sess88 — D-MOUNT-INCARNATION-CONSTANT-ZERO measured on the rig

Build **0.11.420**, srcversion `33018595D555FBE463F017B`, `MXFS_PROTO_GEN` 3,
DEPLOYED to all 32 nodes on a freshly mkfs'd gen-3 LUN. Prep 71s (budget 240s).

## DEPLOY TRAP — `make clean` deletes the userspace tools

sess87 ran `make clean`, which does `$(MAKE) -C tools clean`. That removed
`tools/mkfs_mxfs` and `tools/chk_mxfs`. `tests/setup/prep_fs.sh` hard-fails
with "mkfs tool not found/executable" — and `make modules` does NOT rebuild
them. **After any `make clean`, run `make tools` before prep_cluster.**
This matters doubly for a proto_gen bump: mkfs_mxfs stamps
`cluster_proto_gen = MXFS_PROTO_GEN` (tools/mkfs_mxfs.c:569), so a stale mkfs
binary would format a gen-2 volume that gen-3 code refuses to mount.

## What was MEASURED (all on the live 32-node caw rig)

1. **On-disk incarnations are real.** 32/32 live HB records nonzero, 32/32
   distinct, bit lengths 58-64 (consistent with the GPT-ruled random 64-bit
   construction). sess83's identical measurement returned `distinct EPOCH
   values: [0]`.
2. **The death path names the victim by its exact incarnation.** Killed test32
   (slot 20, node 2541769084, epoch 4152495875090453247) with `virsh destroy`.
   **All 31 survivors** logged
   `P163-RECOVERY-PENDING slot=20 node=2541769084 epoch=4152495875090453247` —
   the exact pre-kill on-disk value, not 0 and not a re-read. Detected t+70s
   against a derived budget of 134s (62s declare + 62s confirm + dispatch).
3. **The durable recovery descriptor is incarnation-bound** (sess83 item 2):
   `P234-RECOV-FENCED slot=20 victim=2541769084 epoch=4152495875090453247
   slice=0/4 owner=2583145845 gen=1 term=1`.
4. **Recovery completed cleanly**: stages 2->3->5, `P163-RECOVERY-COMPLETE
   slot=20 ... slice replayed, shared purges done, dead slot zeroed`,
   `P97-SWEEP-DONE slot=20 bucket=20 rc=0`.
5. **The incarnation actually changes across a remount** — the property that
   makes it an incarnation rather than a node id. test32 rejoined the SAME
   slot 20 with epoch 16225762881755121090 (was 4152495875090453247) and a new
   node_id. Cluster back to 32/32 beating.
6. **The must-not-appear probes are absent** cluster-wide: zero
   `P237-RECOV-INC-MISMATCH` (the fail-closed -ESTALE arm), zero
   `P237-PENDING-REARMED`, zero `P237-COMPLETE-REARMED`. No mxfs BUG:/WARN/call
   trace on any node (the one `WARNING:` per node is the boot-time
   `ITS: WARNING: ITS mitigation depends on retpoline` CPU notice — not mxfs).

## Instrument fixed — `tests/hb_slots.sh` was lying

It computed `age = wall_now_ms - timestamp_ms`, but `timestamp_ms` is
`ktime_get_boottime` (per-node UPTIME, documented in hb_guard_clobber_probe.sh
as comparable ONLY to itself). On a healthy 32-node cluster that yields ~1.79e9
seconds, so it printed **"live ACTIVE (age<62s): 0" with all 32 nodes mounted
and heartbeating** — a false negative on the one question the tool exists to
answer. Rewritten to the correct test: sample the region TWICE at least one HB
interval apart under **O_DIRECT** and ask whether `timestamp_ms` ADVANCED
(buffered re-reads come from the reader's page cache, which no peer write
invalidates, so a buffered second sample makes every live node read as dead).
Now also flags EPOCH-CHANGED / FLAGS-CHANGED / NODE-CHANGED between samples.

## New persistent instrument — `tests/incarnation_death_probe.sh`

`incarnation_death_probe.sh [victim=test32] [reader=test1] [watch_s=180]`.
Reads the victim's pre-kill incarnation O_DIRECT **from a survivor**, drops a
per-run kmsg marker on every survivor (sess27: unscoped windows are themselves
an evidence bug), `virsh destroy`s the victim, then polls survivors for P163
and asserts the logged epoch equals the pre-kill epoch AND is nonzero. It
distinguishes three failures: epoch=0 (defect present), epoch nonzero but
DIFFERENT (fabricated identity — the sess87 category error), and wrong node.
Leaves the victim destroyed; restart + rejoin afterwards.

Rejoin recipe used (7.4s): `virsh start`, mount /src, then
`MXFS_DEV=/dev/mapper/mpatha MXFS_KO_MD5=<md5> bash /src/mxfs/tests/setup/prep_node.sh caw`.

## STILL OWED before this defect can close under RULE 6

1. **Full board at 32/caw** — the regression gate for the proto_gen bump and
   the incarnation threading. Not run this session.
2. **The `P237-RECOV-SUPERSEDED` arm has never executed on the rig.** This
   session's rejoin happened AFTER recovery completed, so the slot was already
   zeroed and test32 made a fresh claim. SUPERSEDED only fires when the victim
   reclaims its slot while a recovery is still pending — it needs a rejoin
   raced into the ~124s detect+confirm window. Same for
   `P237-COMPLETE-SUPERSEDED` and `P237-SLOT-REOCCUPIED`. That is new,
   unexercised code on the path that decides whether to guard a LIVE member.

## Note on a census artifact

A whole-dmesg census shows `P163-RECOVERY-PENDING total=312 nodes=31`, which
is NOT 31 markers from this kill. 31 non-victim nodes never rebooted, so their
ring buffers still hold prior sessions' runs on the gen-2 volume. The
marker-scoped count for this kill is exactly 1 per node. Always scope to the
run marker.
