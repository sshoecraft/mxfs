---
name: ccloop-c7ee71c6-sess105-refusal-split-and-authtry-LANDED
description: sess105: ruling items 1-3 LANDED (0.11.437, builds clean, NOT deployed) — tagged grant status replaces the `valid` boolean, per-inode last-install-AT…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, instrument]
---

# sess105 — the sess104 ruling's items 1–3 are landed

**0.11.437, srcversion `CF3F5A492DC3B80F80761B3`, builds clean, NOT DEPLOYED
and NOT MEASURED.** Ruling: `ccloop-c7ee71c6-sess104-GPT-ruling-release-hook-and-install-retry`.

## Item 1 — the refusal is split at snapshot construction

`struct mxfs_grant_result.valid` (uint8_t boolean) is GONE, replaced by
`uint8_t status` carrying `enum mxfs_grant_auth_status`
(include/mxfs/mxfs_dlm.h): `UNSET / WRITE_EPOCH / NONWRITE_MODE /
WRITE_ZERO_EPOCH / NO_RESOURCE`. Two predicates now exist and are the ONLY
tests used anywhere:

- `mxfs_mode_can_write(mode)` — exact `EX || PW`. The tree previously mixed
  this with `>= MXFS_LOCK_PW` at three sites; they agree only by enum accident.
- `mxfs_grant_result_proving(g)` — `status == WRITE_EPOCH && grant_epoch != 0`.

Both fill sites classify: `caw_grant_result_fill` (dlm/dlm_caw.c) and
`mxfs_iclus_auth_snapshot_locked` (xfs/xfs_mxfs_dlm.c). The iclus one no
longer early-returns a fully-zeroed struct — it keeps mode/kind/resource on a
non-proving result, per the ruling's "do NOT discard the mode".

Consumer counters: `mxfs_auth_ref_notvalid_n` / `_noepoch_n` / `_shared_n` are
replaced by `mxfs_auth_ref_status_n[MXFS_GAUTH_STATUS_MAX]`. **The
structurally-unreachable `shared` bucket is gone by construction** — the
NONWRITE_MODE case is now decided at fill time, not after an early return.

`mxfs_common.h` gained `<stdbool.h>` on the user-mode branch (the new inline
uses `bool`; invariant 4 requires dlm/ + tools/ to build user-mode).

## Item 2 — the per-inode LAST INSTALL ATTEMPT

New on `struct xfs_inode` (xfs/xfs_inode.h): `i_mxfs_auth_try`,
`_try_mode`, `_try_line`, `_try_epoch`, `_try_gen`, with `MXFS_AUTH_TRY_*`
defines (STATUS_BASE=16 mirrors the grant-status enum one-for-one, MAX=24;
BUILD_BUG_ON guards the overlap). Written by
`mxfs_inode_authority_note_try_locked()` on EVERY exit of the install helper —
all 7 refusals and all 3 success paths. Aggregate in
`mxfs_auth_try_n[]`, printed as a `last_install_attempt` block by the
`inode_authority` debugfs file.

**Why `_try_gen` is the load-bearing field:** it snapshots `i_mxfs_auth_gen`
at attempt time. `try_gen < gen` at read time means a revoke happened AFTER
the last attempt and nothing retried — the ruling's "missing call/event" row —
without needing any new global sequence counter.

## Item 3 — P241-AUTHTRY, the dirty-point classifier

`mxfs_buf_owner_authority()` now fills a `struct mxfs_ownauth_snap` (replaces
4 out-params) and carries the try-record out of the SAME `i_flags_lock`
section as the state. At `oc == NONE && mxfs_mode_can_write(mode)` — the
exact 8346-image population sess104 proved is a recorder gap — it histograms
`mxfs_authtry_none[try]` plus samegen/stalegen, and emits a `printk_ratelimit`
sample line with the whole snapshot. Reported next to P240 in
`mxfs_authcap_report()`.

Reading the result: `never` → this acquire path never installs; `stalegen`
bucket via try_gen → missing post-revoke retry; `st_wrzero` → epoch
publication/restart gap; `st_nonwr` → **the ruling's leading hypothesis**
(installed against a read grant, no retry at the conversion); `install`/
`advance` → authority WAS installed and something revoked it (release-side).

## Also fixed en route

`mxfs_iclus_lock` zeroed `auth_epoch` on a failed stamp only for
`mode >= MXFS_LOCK_EX` (EX only), so a **PW** claim that failed to stamp kept
the previous epoch. Now both writing modes go through `mxfs_mode_can_write()`.
Safe: release zeroes `auth_epoch` (xfs_mxfs_dlm.c :44084, :44249), so a claim
after a release starts from 0 regardless.

## Next steps, in order

1. **Deploy + measure** — `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`,
   then the 4-criterion lap (rsync_paired / cache_coherency /
   dir_reuse_coherency / dirent_durability) and read P241 + the debugfs
   `last_install_attempt` block. This is a RULE-0-sensitive build: the P241
   arm is on the first-dirty path, but only on the NONE branch, so it should
   not move the wall — verify against the sess104 baselines (16s/23s/103s/64s).
2. Ruling item 4, the FINDING A fix: ONE centralized release-publication
   primitive requiring RELEASING before any peer-visible publication. Order:
   close local mutation gate → drain in-flight protected mutations → set
   RELEASING under the authority serialization → publish → lower i_dlm_mode
   last. Keep the backstop as a late-revoke diagnostic. **Hooking too EARLY is
   the opposite bug** — an already-authorized in-flight mutation that dirties
   after the clear gets stamped NONE.
