---
name: design-the-mount-threads-retire-grace-lives-inside-the-admission-barriers-bound
description: DESIGN (D-0965, 0.87.11): a PRESENT key on a RETIRE_PENDING record may be a same-boot successor's fresh registration; the mount thread holds a 10 s g…
metadata:
  type: project
tags: [design, disklock, scsi-pr, d0965]
---

# The mount thread's grace on a PRESENT retire-pending key is its own constant, and it must leave room for the recovery it may trigger

D-0965 (0.87.11, design consult with Astra 2026-09-18). Two facts that a later change to `hb_retire_settle`, the admission barrier, or the per-boot PR key must respect.

## The key being PRESENT proves nothing about the departure

A clean unmount leaves its slot RETIRE_PENDING naming its per-boot PR key. A remount in the same boot re-registers the IDENTICAL key before it can settle its predecessor's record (P305-RETIRE-SETTLED-OWN comes ~40 ms after REGISTER unloaded, ~8 s with a 1.5 s READ KEYS delay). The target cannot distinguish "the departure never unregistered" from "the successor registered the same key", and the live-member guard cannot see a successor that has not claimed a slot yet. A peer's mount thread that withdrew a PRESENT key at once fenced the live successor (P303-FENCECAP-SELFABSENT) — measured 2/2 on 0.87.10.

Ruling: expiry authorises recovery and proves nothing. Safety requires only that the mount not go writable beside the registration, so the mount thread holds admission (P-ADMIT-RETIRE-PENDING-HELD; the barrier re-sweeps) for a grace that starts at first sight and is never reset by a barrier round.

## Why the mount thread's grace is 10 s and the monitor's stays 30 s

`MXFS_DISKLOCK_RETIRE_MOUNT_GRACE_MS` (10 s) vs `MXFS_DISKLOCK_RETIRE_GRACE_MS` (30 s). The mount thread's wait lives inside the admission barrier's 30 s bound, and a genuinely stalled record still has to be withdrawn, its key fenced and its clean slice replayed inside that same bound. Measured on the first build with a 30 s mount-thread grace: the withdraw landed at 29.3 s of the bound and the fence + replay took 12 s more; the mount succeeded only because the retire worker's first sight preceded the barrier's first poll. With 10 s, the withdraw lands at ~10.5 s, fence certified ~1 s later, mount admitted at ~22.7 s.

Anyone raising the barrier bound, the fence cost or the replay cost has to re-derive this split. Harnesses: `tests/d0965_remount_bracket_race.sh` (both interleavings), `tests/d0965_stalled_record_mount_thread.sh` (the withdraw still happens), `tests/d0965_successor_killed_after_register.sh` (dead successor with a live registration).

## The re-bracket half

`mxfs_scsipr_own_registration_proven` re-brackets when the bracket was disturbed (why=generation-moved or invalidated-during-bracket), bounded by `dbg_pr_own_proof_brackets` (default 4, 1 = the pre-fix single bracket for a control), 50 ms × attempt between attempts. A COHERENT bracket that lacks the key or the reservation still refuses; only a disturbed one is retried.
