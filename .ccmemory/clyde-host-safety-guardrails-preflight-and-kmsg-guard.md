---
name: clyde-host-safety-guardrails-preflight-and-kmsg-guard
description: The guardrails that now stand between the rig and a third clyde wedge: clyde_preflight.sh gate (run.sh calls it), mxfs-clyde-guard.service kmsg watch…
metadata:
  type: reference
tags: [clyde, rig, rule2, rule2c, rule2d, host-safety, preflight, watchdog, scst, infra]
---

Full write-up: `docs/host-safety.md`. Rule text: CLAUDE.md **RULE 2d**.

## What exists now

| Thing | Does | Fails how |
|---|---|---|
| `scripts/clyde_preflight.sh` | gate: halt flag, kernel taint (BAD_PAGE/oops/softlockup/MCE), D-state count, SCST version >= `.4`, SCST trace mask, kernel-log rate, fs headroom, journald caps | exit 1 -> `run.sh` aborts exit 3 |
| `tools/clyde_kmsg_guard.sh` + `mxfs-clyde-guard.service` (enabled) | tails /dev/kmsg; halts rig on CORRUPTION / PRECURSOR / FLOOD | writes `.rig_halt`, snapshots to `/src/mxfs/.evidence/`, bound-pauses guests on CORRUPTION only |
| `scripts/scst_setup.sh::reset_trace` | resets SCST trace mask to build default on every rig build | n/a |
| `tests/scst_pr_bounds_check.sh` | proves the PR overflow fix present in the INSTALLED modules | exit 1 |
| `/etc/systemd/journald.conf.d/50-mxfs-rig.conf` | SystemMaxUse=4G, SystemKeepFree=100G, RateLimitBurst=2000/30s | n/a |

`run.sh` calls the preflight just before `marker_read`. Override
`MXFS_PREFLIGHT_SKIP=1` exists only for when the gate itself is broken.

## Measured numbers to calibrate against (do not re-derive blindly)

- clyde's own kernel log during a full 32-node campaign: **~1 line/s**
  (25,130 lines over 6.7h). The 2026-08-20 flood: **~182/s for 98 min**
  (1,074,700 lines; 92% from SCST's `scst_check_scsi_atomicity` TRACE_BLOCKING).
- Guard flood trip: >60 lines/s for 2 consecutive 5s windows. Verified tripping
  at 796/s in ~11s. A single long fixed window does NOT work — a flood that
  starts mid-window dilutes below threshold and escapes (observed).
- Preflight fs floors: <90% used AND >=60G free. 2026-08-20 wedge was at 92%.
- D-state ceiling 20. The 2026-08-20 wedge reached 875.

## Traps found while building this

- `kernel.dmesg_restrict=1` on clyde: `dmesg` needs root. A log-rate check that
  silently reads nothing looks exactly like a quiet host — the preflight now
  FAILS rather than passing when it cannot read the log.
- Parse `/proc/<pid>/stat` state as the field after the `)` that closes comm,
  never by whitespace index (comm can contain spaces and parens).
- The guard matches with bash `[[ =~ ]]` and `$SECONDS`, never `grep`/`date`
  subshells: a fork-per-line watcher under a 182 lines/s flood adds hundreds of
  processes per second to a host that is already in trouble.
- Evidence goes to `/src` (NFS, another server), never clyde's root ext4 —
  that filesystem is usually what the wedge is about.

## What the guard deliberately never does (RULE 2 / 2c)

No reboot/sysrq. No `virsh destroy` (measured 2026-08-20: every one timed out;
`virsh suspend` = QMP stop is used instead, bounded, never retried). No rmmod of
SCST. No dmsetup. No global `sync`. Reads only `/proc/<pid>/stat`, `comm`,
`stack` — never `cmdline` or `maps`.

## Still open, user's call

1. Move the LUN and guest images off the root ext4 (separate devices). The only
   change that makes the jbd2 wedge impossible rather than unlikely.
2. `kernel.panic_on_oops=1` (with `panic_timeout=0` to crash-and-hold) —
   argued both ways in docs/host-safety.md. `panic_on_warn` stays off.
3. Upstream the SCST PR fix.
