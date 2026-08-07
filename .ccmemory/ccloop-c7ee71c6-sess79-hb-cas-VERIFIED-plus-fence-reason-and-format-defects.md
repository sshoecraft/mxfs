---
name: ccloop-c7ee71c6-sess79-hb-cas-VERIFIED-plus-fence-reason-and-format-defects
description: sess79: sess78 HB own-slot CAS fix VERIFIED on rig (HELD + self-fence + withdraw-refused). Plus 2 new defects fixed: false fence cause, P49 format mi…
metadata:
  type: reference
tags: [disklock, heartbeat, fencing, rule4-verified, log-honesty, format-string, sess79]
---

# sess79 — HB own-slot CAS VERIFIED on the rig; two new defects fixed

**0.11.418, srcversion `412957C596B75E582F3F676`, deployed to 32/caw, builds
with ZERO `-Wformat` warnings.**

## 1. sess78's fix is now FIXED AND VERIFIED (rig-measured, both builds)

Deployed 0.11.417 then 0.11.418 and re-ran `tests/hb_guard_clobber_probe.sh
test2 test1`. Both runs met the full sess78 PASS condition — `HELD` alone
would have been a failure:

```
VERDICT: HELD for 12s — flags stayed RECOVERY_GUARD
P236-HB-FOREIGN-WRITE slot=25 ... own-slot CAS MISCOMPARE
P236-SELF-FENCE ... stopping heartbeat, forcing shutdown
XFS (dm-1): ... forcing shutdown
P236-WITHDRAW-REFUSED slot=25 ... would destroy it
```

vs 0.11.416, where the guard died at t+0.8 s and the victim logged nothing.
Call site 3 (`withdraw`) is confirmed too — it refused to stamp WITHDRAWN over
the guard. Call site 2 (`release_slot`) is NOT exercised by this probe; it
needs an unmount with a guard present. Detection latency is ~1.8 s (one HB
interval) — anything assuming instant effect is D-VICTIM-REPLAY-WITHOUT-
PROVEN-EXCLUSION, still open.

`P-HB-SLOW`: zero under the new build (test1's two predate the deploy, and both
are `write_ms=0` with multi-second `lockwait_ms` — lock wait, not the CAS).
Cadence did not regress.

## 2. NEW DEFECT (fixed) — the self-fence named a cause that had not happened

Four detectors fire a self-fence; all four printed the sess131 message
`P131-SELF-FENCE: device reformatted under live mount`. **Three were false.**
`fence_cb` / `fence_notify_fn` carried no reason, so the XFS layer hardcoded
one. This is MXFS's most severe operator message — it force-shuts-down a live
mount — and 3/4 of the time it told an admin their shared LUN had been
destroyed, a data-loss panic response, when the truth was ordinary cluster
fencing and the device was intact.

Fixed by plumbing `enum mxfs_self_fence_reason` (new, in
`include/mxfs/mxfs_common.h`, with `_name()` + `_desc()` kept beside it so a
new detector cannot be added without writing an operator explanation):
- `MXFS_SELF_FENCE_FS_IDENTITY` — disklock, re-mkfs'd device (the only one the
  old text was right about)
- `MXFS_SELF_FENCE_SLOT_TAKEOVER` — disklock, own-slot CAS miscompare
- `MXFS_SELF_FENCE_PR_KEY_LOST_FENCING` — v5_mount.c:739, our PR key gone while
  fencing a peer
- `MXFS_SELF_FENCE_PR_KEY_PREEMPTED` — v5_mount.c:991, self-check found it
  preempted

Both typedefs (`mxfs_disklock_fence_cb`, `mxfs_v5_fence_notify_fn`) now take
`int reason`. Rig-verified: `P131-SELF-FENCE [SLOT_TAKEOVER]: a surviving peer
declared this node dead and is replaying its journal slice — this mount has
been fenced by the cluster, the device is intact`.

Note the two PR paths never went through the disklock log at all — they call
`fence_notify_fn` directly, so they only ever produced the false XFS line.

## 3. NEW DEFECT (fixed) — P49-STALEBASE printed garbage from a bad va_arg

`xfs/libxfs/xfs_dir2_data.c` `P49-STALEBASE` had **16 format specifiers and 15
arguments**: the trailing prose `missing %d durable peer dirent(s)` had no
argument, so `vsnprintf` read an uninitialised `va_arg`. A probe whose own
summary line prints garbage is exactly the failure mode that has cost this
project sessions. `missing=%d` already carries the count; the tail no longer
takes one.

**`mxfs_pal_log` IS `__printf(2,3)`-annotated** (pal.h:566-571), so the whole
`dlm/` layer is format-checked — this was the only mismatch in the tree. Full
rebuild after the fix: `grep -c Wformat` = 0.

Method note: the warning only surfaces on a FULL rebuild, and `grep -iE
"error|warning"` hides which file it came from — the file name is on the
`note: in expansion of macro` lines. Capture the whole build log and grep with
context.

## 4. REFUTED — "kmsg visibility lags its timestamp"

Twice this session a grep for `P236-WITHDRAW-REFUSED` returned nothing and a
later grep found the same line carrying an EARLIER printk timestamp. Built
`tests/kmsg_visibility_latency.sh` (in-tree, RULE 3) to measure it: emit a
marker to `/dev/kmsg`, poll `dmesg` over one SSH session, compare the printk
stamp to `/proc/uptime` read on the node.

**Result: worst lag 15.4 ms, 0/10 never-visible.** Hypothesis refuted — a
single dmesg snapshot IS sound on these nodes.

So the missed greps have some OTHER cause and it is still unexplained. Do not
let this go: a grep that false-negatives on evidence that exists silently turns
real failures into PASSes (sess27 found three of that family). Next session
should reproduce it deliberately — re-run the guard probe and poll for
`P236-WITHDRAW-REFUSED` from the moment of the write, logging every poll, so
the miss window is captured rather than inferred.

## State / next steps

- test2 is fenced+shut-down by the probe (by design). **Re-prep before boarding.**
- Full board `./run.sh 32 caw` + `./showstat.sh` NOT yet run on 0.11.418.
- **There is no OPEN_DEFECTS.json entry for this defect** — 46 entries, none
  matching HB/BLIND/CLOBBER/GUARD. sess78 never added one. Add it, then close it
  as FIXED AND VERIFIED citing the probe output above. The two defects found
  this session need entries too (both fixed; the fence-reason one is rig-
  verified, the P49 one is build-verified).
- `tools/` binaries were MISSING from the tree (only `caw_verify` survived) and
  `prep_cluster` fails with `FS_PREP_FAIL: mkfs tool not found`. Fixed by
  `cd tools && make`. If prep dies that way again, that is the cause.
