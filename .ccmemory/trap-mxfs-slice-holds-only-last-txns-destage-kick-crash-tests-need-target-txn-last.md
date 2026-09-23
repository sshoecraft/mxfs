---
name: trap-mxfs-slice-holds-only-last-txns-destage-kick-crash-tests-need-target-txn-last
description: TRAP (sess446): a victim's journal slice holds only its LAST 2-4 txns (mxfs_destage_kick pushes the AIL on every create) — a crash/replay test must m…
metadata:
  type: feedback
---

# Slice contents after a crash = the node's last 2-4 transactions only

Measured sess446 (chains 41 and 42, 0.53.0):
- bootstrap_full_restart NEG arm, 200 fsync'd 4 KiB creates + payload per node: P273-SHADOW-EVAL `buf=8 txn=2 icreate=0/0/0` on 31/31 slices, identical on lap 2 (chain 37) — the chunk ICREATE carved ~55 creates earlier was already covered.
- d0512_sf_to_block_replay, 24 sync'd creates + `sync`: replayed slice `txn=4 buf=14` (fix) / `txn=3 buf=10` (inject1); the sf->block txn (create ~8) was gone, so BOTH arms replayed COMPLETE without ever seeing the re-typed image (inject1's "expected REFUSED, got COMPLETE" was this artifact, not a replayer gap).
- chain 32 (one file + `sync -f`): 26/31 slices txn=0.

Cause (code): `mxfs_destage_kick_fn` (xfs/xfs_mxfs_dlm.c ~2341) = async log force + `xfs_ail_push_all` per debounce window on every create/unlink, so the log tail follows the workload within ms; per-file fsync does not hold anything in the log.

Rules for crash/replay harnesses:
1. The transaction under test must be the victim's LAST transaction: create one file at a time and stop the moment the producer-side probe fires (dmesg count grows), or stop on the allocation fact (`stat -c %i` returning ino % 64 == 0 = the create that carved the chunk). Never `sync`/`syncfs` afterwards; destroy immediately.
2. /proc/sys/fs/mxfs/ and /proc/sys/fs/xfs/ DO NOT EXIST on the nodes (xfs_sysctl.o is excluded from the build, Kbuild:157) — `echo N > /proc/sys/fs/mxfs/xfssyncd_centisecs` is a silent no-op; log covering was never the reason.
3. P133-ICLUSTER-SYNCINIT prints only for the first 20 carves per module lifetime (p133_n <= 20) — not usable as a per-carve signal after prep.

Harnesses fixed on this rule: tests/bootstrap_full_restart.sh (NEG: create-to-chunk-boundary, payload = the boundary file, per-node .payf), tests/d0512_sf_to_block_replay.sh (stop at the conversion, NCR entries, LASTF read).
