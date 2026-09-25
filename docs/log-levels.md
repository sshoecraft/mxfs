# MXFS Log Level Policy

## What goes in the kernel log by default

An operator reading `dmesg` on an MXFS node sees:

- **errors** (`pr_err`, `xfs_alert`, `xfs_err`, `mxfs_pal_log(MXFS_LOG_ERR)`):
  I/O failures, refused recoveries, invariant breaches, forced shutdowns;
- **warnings** that report a condition someone must act on or know about: a
  loss, a corruption, a withdrawal or shutdown, a fence or a node's death, a
  refusal, a wedge;
- **lifecycle** (`pr_info`, `xfs_notice`, `MXFS_LOG_INFO`): mount and unmount,
  joins and departures, recovery started and completed, the per-mount DLM
  cache statistics.

Everything else is a **diagnostic probe** and is silent unless enabled.

## Probes

A probe is an instrumentation line whose text starts with a tag:
`mxfs: P12-DLMTR ...`, `mxfs: P-AGIFC-MOD ...`, `tauth: P-TAUTH-PREPARED ...`.
The project's test harnesses read them back out of the kernel log to decide
what the module did, and they are the reason the log used to be unreadable:
one 2-node suite run printed 76,541 kernel lines on one node, 98.2% of them
probes (`P-AGIFC-MOD` alone, 9,214; the TAUTH ledger, about 20,000).

Probes are dynamic debug.  They are written with `mxfs_probe()`,
`mxfs_probe_ratelimited()` and `mxfs_probe_once()` (`pal/mxfs_probe.h`), or
`mxfs_pal_log(MXFS_LOG_DEBUG, ...)` in `dlm/`, and when disabled they print
nothing and do not evaluate their arguments.  Enable them:

```bash
insmod mxfs.ko dyndbg=+p                                   # all, from load
echo 'module mxfs +p' > /proc/dynamic_debug/control         # all, at run time
echo 'module mxfs format "P-AGIFC" +p' > /proc/dynamic_debug/control   # one family
echo 'module mxfs -p' > /proc/dynamic_debug/control         # all off
```

`options mxfs dyndbg=+p` in `/etc/modprobe.d/` does the same for a module
loaded by `modprobe`.  The `dlm/` probes pass through one `pr_debug` in the
kernel PAL, so they are enabled together rather than by format.

The test rig enables every probe at every module load
(`tests/setup/prep_node.sh` and each harness that loads the module itself pass
`dyndbg=+p`), so what the harnesses assert on is unchanged.  A harness that
loads the module without it will find its probe lines missing, not failing.

## Which probes stay visible

A tagged message keeps its level, and so stays in the default log, when both
hold:

- its text names an event an operator must see: a loss, a corruption, a
  shutdown or withdrawal, a fence, a death, a refusal, an invariant, a wedge,
  a recovery or replay, a join or departure;
- it is rare: it fired at most 20 times in the measured suite run.

An ERR-level probe keeps its level unless it fired more often than that, which
would make it a routine diagnostic mislabelled as an error.

The split was made by `scripts/log_probe_levels.py` from a measured count of
every tag in a node's kernel log; running it again against a fresh
measurement re-applies the same rule.  On the run it was measured from, the
probes left visible printed 131 of the 75,165 probe lines.

The rule alone is not enough, for two reasons:

- A message can be rare in one run and routine in another.
  `P-TAUTH-RETARGET` names a "recovery-purged" incarnation, fired rarely in
  the first measurement, and printed 5,768 lines in a later suite run.
- Wording is a poor guide to what an operator acts on.  The counter dumps
  at unmount and replay (`*-REGISTRY-TOTAL`, `P291-AUTH-TAIL`,
  `P273-SHADOW-EVAL`, ...), and the internal steps of a join or a fence
  (intent, arm, seal, manifest, freeze, thaw), use words like "replay",
  "refuse" and "orphan", but nobody acts on them.

So a second pass works from what actually printed.
`scripts/log_demote_sites.list` names, message by message, the
default-level prints seen in a measured log that are not operator events,
and `scripts/log_demote_sites.py` moves exactly those call sites to dynamic
debug.  A fragment names one message variant, not a tag family: the success
line of `P303-FENCECAP` moves and its `-NOPERSIST` refusal stays.  Where a
level is chosen by a condition (`rc ? MXFS_LOG_WARN : MXFS_LOG_INFO`), only
the less severe arm, the routine outcome, is demoted.  Error-level prints
(`pr_err`, `xfs_alert`, `MXFS_LOG_ERR`) are never demoted: an error that
fires routinely is a defect to fix, not a line to hide.

What stays visible for a node's life: the mount and its slice and domain,
peers connecting and disconnecting, the join installed, a clean departure
received, a death, the fence's kind and certification, a fence that could
not be proved, recovery pending, the replay and recovery complete, open
obligations or residue at teardown, and every error.

To measure again: run the suite, then read each node's kernel journal at
`-p info` (which excludes `pr_debug`) over the window the build was loaded.
Discard `callbacks suppressed` lines and probe-gated stack dumps; with
probes on they are artifacts of the probes themselves.

## Adding a message

- Something the harness needs to see, or that helps diagnose one mechanism:
  a probe.  Use `mxfs_probe*`, never `pr_warn`.
- Something an operator must see: `pr_warn`/`pr_err`, rate-limited if it can
  repeat, with text that says what happened and what it means.
- Never rely on `mxfs_instr_enabled` alone to keep a probe out of the log;
  it gates the work a probe does, not where its line goes.

## Trailing newline: the kernel PAL appends it (0.59.3, sess452)

`mxfs_pal_log()` formats may omit the trailing `\n`; the kernel PAL
(`pal/linux/kern.c`) appends one when it is missing, exactly as the
user-mode PAL (`pal/linux/user.c`) always did.  Until 0.59.3 the kernel
side printed `"mxfs: %pV"` verbatim, and a printk whose text does not end
in a newline is stored `LOG_CONT` with its ringbuffer record committed but
**not finalized** (`kernel/printk/printk.c` `vprintk_store`: `prb_commit`
vs `prb_final_commit`).  `dmesg`, `/dev/kmsg` and journald cannot read an
unfinalized record; it becomes visible only when the *next* printk on the
system reserves a record.  Every PAL marker that ended a quiet period was
therefore invisible to a `umount; sleep 1; dmesg` capture and read as
"absent" by the harness.  `xfs_alert`/`xfs_warn` were never affected
(`xfs_printk_level` appends the newline itself).  Do not "fix" individual
formats by adding `\n` at call sites; the chokepoint handles it and a double
newline would split the record.
