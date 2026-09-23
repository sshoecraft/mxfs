---
name: trap-scsi-logging-level-is-a-packed-three-bit-field-and-a-plausible-hex-constant-turns-on-per-command-logging
description: TRAP (s84): 0x1F80 in /proc/sys/dev/scsi/logging_level reaches MLCOMPLETE (shift 12) and logs every command completion; error recovery alone is 63.
metadata:
  type: feedback
---

# `/proc/sys/dev/scsi/logging_level` is ten packed 3-bit fields, not a bitmask

Session 84 wrote a harness that armed SCSI error-recovery logging on a node
about to be hit with a LU reset, and chose `0x1F80` because it "looked like the
error bits". It is not a bitmask. From `drivers/scsi/scsi_logging.h`, each
class gets three bits:

```
SCSI_LOG_ERROR_SHIFT       0
SCSI_LOG_TIMEOUT_SHIFT     3
SCSI_LOG_SCAN_SHIFT        6
SCSI_LOG_MLQUEUE_SHIFT     9
SCSI_LOG_MLCOMPLETE_SHIFT 12
SCSI_LOG_LLQUEUE_SHIFT    15
SCSI_LOG_LLCOMPLETE_SHIFT 18
SCSI_LOG_HLQUEUE_SHIFT    21
SCSI_LOG_HLCOMPLETE_SHIFT 24
SCSI_LOG_IOCTL_SHIFT      27
```

`0x1F80` sets SCAN=3, MLQUEUE=7 and **MLCOMPLETE=1** — a line for every SCSI
command completion, on a node running continuous O_DIRECT writes. That is the
shape of the incident this project already has a standing rule about: a trace
flag left on once produced 1.07M host kernel lines in 98 minutes and deadlocked
jbd2 on the filesystem holding the log, the guest images and the journal.

**What to use instead:** error recovery and timeouts at full verbosity, nothing
else, is `(7 << 0) | (7 << 3)` = **63**. Derive it from the shifts and write the
derivation in the harness; never pick a hex constant that looks about right.

Two companions worth arming at the same time, and both are OFF by default —
which is why "the node's kernel logged nothing" is weak evidence about error
recovery:

- `/sys/module/libiscsi/parameters/debug_libiscsi_eh` = 1 makes
  `iscsi_eh_cmd_timed_out()` narrate every decision, including the two that
  matter: `return timer reset` (the command is given another 30 s) versus
  `return shutdown or nh` (the SCSI error handler is finally let in).
- `scsi_logging_level` 63 makes `scsi_error.c` narrate the abort / device-reset
  ladder.

Disarm both in an EXIT trap, every time.
