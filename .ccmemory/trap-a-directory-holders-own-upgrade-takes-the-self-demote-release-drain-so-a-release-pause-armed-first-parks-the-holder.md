---
name: trap-a-directory-holders-own-upgrade-takes-the-self-demote-release-drain-so-a-release-pause-armed-first-parks-the-holder
description: TRAP (sess595, D-0958 control): a dir holder still caching PR after a peer listing upgrades PR->EX via -EDEADLK self-demote through the release drain…
metadata:
  type: feedback
tags: [trap, harness, dlm, directory, release-pause, D-0958]
---

# A directory holder's own PR→EX upgrade goes through the release drain

## What happened (s595b, live_holder_wait.sh RW=create TARGET=dir, 0.84.11)
- The file form of the lap arms the release pause on H (`dbg_rel_pause_ino/stage=1/ms`) and THEN re-dirties the target with dd. Copied for a directory (arm, then `: > dir/held_by_h`), H's own create parked for the whole 240 s pause and the lap aborted at setup with an empty capture.
- Instrumented on H: after W's probe listing H still cached PR on the directory (state=2 mode=3). H's create asked EX; the master (H itself) answered `DLM inode lock failed: ino=38186 mode=5 rc=-35` (-EDEADLK), the upgrade path self-demoted (`P70-BP ENTRY mode=3 selfdem=1` from the `mxfs-ino-bast` worker) and the release drain hit `P-D512-RELPAUSE stage=1` — with H's create blocked in `xfs_create -> mxfs_ilock_fallible` under it (`P73-WAITSTALL demoter_comm=kworker/u12:0 acq_comm=bash`) and the digest `ls` queued behind that in getattr.
- A file never meets this: after W's probe read H holds nothing on the file, so its dd takes EX without releasing anything.

## Lesson
- For a directory target, re-dirty FIRST (H takes EX), THEN arm the pause. The harness now does that for `TARGET=dir` and keeps the file order.
- The release-pause knob fires on ANY release drain of that inode, including the holder's own self-demote; `clear_knobs` after the pause has started does not shorten it (the msleep already began) — wait for `P-D512-RELPAUSE-END` before the next lap, or the bast worker stays occupied and the next candidate probes read undetermined.
- Directory grants are cached PR/EX at the last holder; a listing from a peer leaves the previous EX holder at PR, not NL.
