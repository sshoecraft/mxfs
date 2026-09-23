---
name: compiled-rig-harness-measurement-traps
description: sess565-571: 16 rig/harness measurement-integrity traps — substring greps, ring-buffer scoping, knob-vs-reload, A/B contamination, silent probes, tai…
metadata:
  type: project
tags: [compiled, rig, harness, measurement, instrumentation, traps]
---

# Rig/harness measurement integrity, sess565-571

Seven sessions of A/B and board-run work on the 2-node TCP rig kept producing
the same shape of failure: an instrument reports a clean or plausible result
while the thing it claims to measure never happened, or happened under a
different configuration than the one recorded. Every case here failed silently
and in the direction of good news — no error, no missing field, a number that
looked right. None was caught by re-running; all were caught by going to a
different source of truth (the node's own dmesg window, a probe that fires on
both arms of a knob, the process tree instead of an exit code).

## Unanchored substring match on a field name

`grep -o 'mount_rc=[0-9]*'` against harness stdout matched **inside**
`umount_rc=0`, printed earlier in the same log line block — 5 of 7 control laps
that had actually failed to rejoin at `mount_rc=32` were scored as
`mount_rc=0` clean
([[trap-bare-mount-rc-grep-matches-inside-umount-rc-and-reports-every-lap-as-success]]).
Same shape one session later: `grep -q "PENDING"` against `showstat.sh`'s own
totals line (`0 PENDING`) can never go false, because the word is present
whether or not anything is pending — a 420s wait loop burned its whole budget
on a board that had finished minutes earlier
([[trap-grep-q-PENDING-matches-the-summary-lines-own-zero-pending]]). Rule:
anchor extraction to the owning line (`sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p'`),
or parse a number and compare it, never match on the presence of a word that
the "all clear" message also contains.

## dmesg is a ring buffer scoped to the boot, not to the lap or the build

Counting a probe over live `dmesg` attributes every prior lap's and every prior
build's lines to the current one, because `rmmod`/`insmod` does not clear the
ring and a module reload does not reset it. 45 hits of a refined probe read as
"the uncovered route fires constantly"; they were all the *previous* build,
printed 600s earlier in the same boot — the only thing that discriminated the
builds was that the newer one had grown a `why=` field the older one lacked.
Rule: change a probe's printed fields whenever you change its firing condition,
so a later harvest (yours or a subagent's) can separate old lines from new
without knowing the reload time
([[trap-a-probe-format-change-is-the-only-way-to-tell-which-build-a-dmesg-line-came-from]]).
The same ring-buffer fact bit a harness driver counting `ATOMIC-SKIP` from a
node's whole dmesg (cumulative since boot, not since lap start) — one of four
independent vacuous-success mechanisms found in one session; the other three
were a stale module silently still running after a rebuild (compare
`/sys/module/mxfs/srcversion` against `modinfo` on every node before every
lap, not just when a node was unmounted or a knob differed), the mount_rc/
umount_rc substring collision above, and a stage that reported PASS because
its precondition workload silently failed to create anything at all
(40 symlinks all rejected ENAMETOOLONG, so "no unauthorized image logged" was
vacuously true) — the fix in all four cases is the same: a stage must report
what it actually **produced** (`made=`, `links=`, counts), not that it ran
clean ([[trap-four-ways-a-harness-reported-a-lap-that-never-happened]]).

## A knob's read-back does not prove it was in force when the operation ran

Verifying `MXFS_EXTRA_MODARGS='dir_datascan_heal=0'` immediately after a
standalone prep, then launching the board separately, is not evidence about
the board: the knob was back at its compiled default by row 5, mechanism
unconfirmed (candidates: precond re-mount, a re-prep on a stale marker, the
modarg never persisting past the first module load). Verified via a probe
that is structurally gated to be silent when the knob is 0 but fired anyway
([[trap-the-board-prep-row-resets-mxfs-extra-modargs-so-a-knob-off-board-runs-knob-on]]).
The same fact recurred with sharper cause one session later: a knob written to
the sysfs param on the *live mount* survives right up until the lap's own
`rmmod`+`insmod`, which resets every module parameter to its compiled default
— so ten laps testing durability of a free-publication path ran the actual
operation under test (a later `rm -rf` in the same lap) at the untested
default the whole time, and "read back = 1" only proved the write landed, not
that it was in force when the relevant code ran. Rule: any knob that must span
a module reload goes on the **insmod line**
(`MXFS_EXTRA_INSMOD_PARAMS`), not just the prechurn write; an operation with no
dmesg window of its own is unfalsifiable, so give it one
([[trap-a-knob-set-before-the-churn-is-gone-by-the-rmmod-insmod-later-in-the-same-lap]]).
Family name for all three: **the arm you believe you are running is not the
arm that ran.**

## A/B control contamination

A second, later fix for a different root cause was added *outside* the
existing `poison_retire_wait` A/B knob because it lived in a different code
block. Result: the control arm (`retire_wait=0`) silently stopped reproducing
the defect between two builds — not because the defect was fixed, but because
the control had quietly become a second treatment arm. An A/B whose control
contains the treatment reports success no matter what the treatment does.
Rule: every change that alters the outcome, including a later unrelated fix
found by the same investigation, goes behind the knob; a control arm that goes
clean after a code change is the first thing to distrust, not the last
([[trap-a-fix-outside-the-ab-knob-turns-the-control-arm-into-a-second-treatment-arm]]).

## Silent instruments: zero is ambiguous between "absent" and "never exercised"

A gate that prints only on refusal makes "the gate never refused" and "the
gate was never reached" the same log output — a defect went unreproduced for
a whole session because every run was consistent with both its presence and
the absence of the opportunity to see it. A choke-point census that came back
zero across ten laps looked like "class closed" but a wrong `cb_data`, an
unregistered callback, or an untaken branch all produce the same confident
zero. Fix in both cases: a probe that fires on **both** arms of a knob
(`gated=0|1`) so the failing arm prints its own failure and a lap that never
took the route says "not exercised" rather than scoring clean; a positive
control (a knob whose two settings have a known right answer) proves the
instrument can produce a non-zero count before a zero is trusted as evidence
([[trap-a-silent-instrument-and-a-clean-system-are-the-same-observation]]).
Adjacent failure, same family: `pr_warn_ratelimited` hitting exactly 10 is
`DEFAULT_RATELIMIT_BURST` (10 per 5s), not a count of anything — a 24-vs-10
gap between a plain `pr_warn` and a ratelimited one was about to be read as
evidence of state carried forward from an earlier lap; it was an artifact of
the ratelimiter ceiling. Never compute a ratio between a ratelimited probe and
an unratelimited one; when a count matters, cap the *printing* with an
atomic counter but log the true total
([[trap-a-ratelimited-pr-warn-count-is-not-a-measurement-burst-is-10-per-5s]]).

## Harness process control: timeout/pipe hides the real state

`timeout N ./run.sh ... | tail` reports the pipeline's exit code, which is
`tail`'s, not `run.sh`'s — `run.sh` survives the signal and keeps running rows
after the tool reports done, and the orphan holds `/tmp/mxfs_run.lock`, so
every later `run.sh` invocation refuses and a driver that reads "newest
evidence dir" re-scores the previous lap's artifacts across multiple A/B laps.
Rule: redirect to a file and check `.last_run.json` + zero PENDING rows in
`showstat.sh`, never a wrapper's exit code, to decide a run is finished
([[trap-timeout-around-run-sh-piped-to-tail-kills-the-reader-not-the-run-and-orphans-the-cluster-lock]]).
Companion trap on the backgrounding side: a `run_in_background` command ending
in `| tail -N` buffers its entire input and writes nothing to the task's
output file until the pipeline exits at EOF — an interim `Read` mid-run
returns empty for the whole duration, costing real decisions (whether prep
finished, whether a rebuild is safe) that had to be deferred with no signal.
Never pipe a backgrounded top-level command through `tail`/`head`/`grep`;
filter when reading the output file, not when writing it
([[trap-piping-a-background-run-through-tail-hides-all-progress-until-it-exits]]).

## Rig/build state that must not move mid-run

`make modules` during a live harness run changes the tree's srcversion
underneath laps still in flight; the harness's own precondition check (compare
`modinfo mxfs.ko` srcversion against each node's loaded module) correctly
refused to record a verdict on the mismatched lap rather than silently scoring
a stale build — but the lap was still lost. Rule: source edits are fine while
a run is live; `make modules` is not — stage, wait for completion, then build
([[trap-never-rebuild-mxfs-ko-while-a-rig-harness-run-is-in-flight]]). Related:
a prep run that starts while a node is still booting can read pam's nologin
banner over ssh in place of the srcversion, **persist it into
`.cluster_marker.json`** as the cluster's identity, and report `prep_cluster
OK` — every subsequent row then dies silently (no PASS, no FAIL, no verdict
line) on a marker mismatch, which reads like a broken harness rather than a
stale marker. Gate readiness on a value that looks like a hex srcversion
before persisting it
([[trap-nologin-banner-gets-persisted-into-cluster-marker-srcver-and-poisons-every-later-row]]).
Related again: a harness's own header prose describes the workload shape, not
what it actually preps — `sess493_d0492_crash_durability.sh` reads as a
2-node harness but hardcodes `run.sh 32 caw prep_cluster`, booting all 32 test
VMs (out of the 2-node-TCP directive's scope), driving clyde to 0GB free, and
leaving the 2-node rig unmounted with the module unloaded, for zero
measurement. Before running any unfamiliar harness, grep it for the actual
`run.sh <N> <dlm>` invocation and node-list defaults, not the comment block
([[trap-a-harness-header-describes-the-shape-not-the-prep]]).

## Ledger-tooling traps (adjacent failure family, same sessions)

Backticks inside a `ledger_set.py prepend` value are command-substituted by
bash before the tool ever sees them — the enclosed word runs as a (failing)
command and is silently replaced with an empty string in the stored ledger
text. Every guard passed (`ok:` from the writer, `ledger OK` from the
date-schema validator) because neither checks semantic content; the sentence
simply lost the words it was about. No backticks (or `$(...)`, `$VAR`, `!`
inside double quotes) in any value passed to a shell-argument tool; read back
what was written
([[trap-never-put-backticks-in-a-ledger-set-value-bash-eats-the-word-silently]]).
Separately, the defect ledger stores "next step" under three possible field
names (`next`, `next_step`, `next_steps`); `defects.sh`'s summary view showed
only the first non-empty one, hiding ~130K characters of guidance across 18
open records (some hidden fields larger than the shown one) — including from
the session-start state hook, so every session opened on a partial view of its
own queue. Fixed by showing every populated variant labelled by field name;
check which field a record already uses before writing to it
([[trap-ledger-next-vs-next-step-two-fields-and-the-reader-showed-only-one]]).

## The general shape

Every trap above reduces to the same question, asked too late: **did this
lap/probe/wait/write actually do the thing it claims to report on, under the
configuration it claims?** The recurring fix is never "trust harder" — it is
either (a) give the operation under test its own unambiguous evidence window
(a build-discriminating probe field, a per-lap dmesg marker, a knob set on the
insmod line), or (b) prove the instrument can produce the *other* answer
before trusting the one it gave (a positive control, a probe that fires on
both arms, a process-state check instead of an exit code).
