# sess35 H22 — invisible-release hypothesis

**Date**: 2026-05-08
**Builds on**: sess34 H17 (cache divergence confirmed) and the user's
correction of H21 (BAST is optimization; CAW is authoritative; the bug
is silent slot-bit clear leaving cache stale).

## H22 (falsifiable)

There exists at least one code path in the live kernel module that
clears test1's on-disk inode-DLM slot bit for ino 8388736
(`concurrent_mkdir/`) **without** going through `mxfs_dlm_bast_process`
and **without** setting the in-memory inode's `i_dlm_stale=true` /
calling `mxfs_dlm_reload_inode`.

Candidate sites (from sess34 state.md and a code grep to follow in
task #3):

- `caw_repair_slot` in `dlm/dlm_caw.c:295`
- `mxfs_v5_dlm_force_release_all` (unmount + error paths)
- Lease expiry / disklock heartbeat purge (`dlm/disklock.c`,
  `dlm/lease.c`)
- `mxfs_dlm_purge_node` (sess27 wired this from lease_expire on TCP
  path; check whether CAW path has equivalent)
- A `peer_joined_notify_fn` branch that clears more than intended
- `mxfs_dlm_caw_unlock` callers other than `bast_process`

## Falsification criterion

After adding P-H22 instrumentation to every site listed in task #3
and running `scripts/sess34_repro.sh 2`:

- **Proven** if at least one P-H22 site logs ino 8388736 BEFORE
  test2's first ACQ-FRESH on that inode, with `bast_process=0`.
- **Disproven** if none of the P-H22 sites fire for ino 8388736
  during the bug window — meaning the slot bit was never set by
  test1 in the first place. In that case form H23: test1's
  `FAST-PATH-DIR cached_mode=5` (sess34 state.md) decision is
  trusting an in-memory `i_dlm_state=ICACHED` that was set without
  the slot bit ever being claimed on disk.

## Don't repeat

- Do NOT patch a candidate site without P-H22 evidence pointing to it.
- Do NOT bundle this with any other change (RULE 4 forbidden shortcut:
  "fix both X and Y at once").
- Do NOT take a code-reading guess and build on it.

## Result (filled in after repro)

TBD.
