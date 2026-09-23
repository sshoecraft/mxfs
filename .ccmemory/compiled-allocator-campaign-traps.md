---
name: compiled-allocator-campaign-traps
description: sess572-575: D-0946..D-0950 campaign traps — ruling-hazard compliance, inference fallacies, harness/tooling false-clean results, netconsole gap, defe…
metadata:
  type: project
tags: [compiled, rig, harness, measurement, instrumentation, traps, allocator, defects]
---

# Sole-survivor allocator campaign (D-0946..D-0950): investigation-integrity traps

sess572-575, chasing the D-0946/D-0947/D-0948/D-0949/D-0950 family on the
2-node TCP rig (deferred-deadshell recycle, inode-chunk free/carve races,
sole-survivor validator gaps). Continues the failure family in
`compiled-rig-harness-measurement-traps` (sess565-571: an instrument reports a
clean or plausible result while the thing it claims to measure never
happened). This batch adds three more shapes of the same root problem: acting
on a ruling's letter while missing its intent, treating an individually-true
inference chain as proof, and closing a defect's record without closing the
defect's class.

## Ruling compliance: the hazard clause is part of the procedure, not commentary

The D-0946 RULE-5 ruling gave a progress rule for transient allocator refusal
and named its hazards explicitly, including "do not hold the cluster AG grant
across a synchronous flush — that is cluster-wide head-of-line blocking."
`mxfs_pubob_drive_publication()` was built with exactly that shape:
`xfs_log_force(mp, XFS_LOG_SYNC)` + `xfs_ail_push_all()` + up to 200ms of
polling, called with the AG EX held. The correctness half of the ruling
(drop the AGI, keep cursors clean) was satisfied; the cost half was not. Next
board run: `node_responsive` FAIL (inode-BAST worker blocked) and `soak` FAIL
(inode acquire timeout) on a build that had passed before. Fix: kick
publication asynchronously (`xfs_log_force(mp, 0)`), refuse the candidate
transiently, let the existing reservation cooldown be the retry delay —
progress is still guaranteed without waiting under the grant. Lesson: when a
ruling gives a procedure and a hazard list, re-read the hazards against the
diff line by line before building, not after a board row fails
([[trap-i-built-the-synchronous-flush-under-the-ag-grant-the-ruling-warned-against]]).

## An individually-true inference chain is not proof; act and re-observe

The inode allocator's candidate validator conflated "platter read failed" with
"read succeeded, no dinode magic present." Splitting them, the fix reasoned:
a dinode keeps its magic once written even after free, a peer must publish
every owed image before releasing the AG EX, therefore absence of magic proves
nothing was ever durably written at that home and it's safe to allocate. Every
clause was true; round 14 of 11,700 creates allocated onto a home holding a
live `XDD3` directory data block, producing 8 `xfs_inode_buf_verify` failures
and a forced shutdown. The chain conflated "no dinode was ever written here"
with "nothing was ever written here" — an uninitialized own-cluster home and a
foreign home produce identical bytes, and no read distinguishes them. Working
fix: where inference can't separate two causes, act and re-observe —
`xfs_log_force(SYNC)` + `xfs_ail_push_all`, then re-read; ours now carries
magic, not-ours still doesn't, so refuse transiently instead of picking one of
the two terminal blanket answers
([[trap-no-inode-magic-does-not-mean-nothing-was-ever-written-there]]). The
identical fix (drive publication, re-check) is the async version from the
ruling trap above — same investigation, same correction landing twice for the
sync/async reason and the inference reason independently.

## Measurement: two independently truncated counts can't be divided

`2` `P133-ICLUSTER-SYNCINIT` lines against `53` `P-AGIFC-MOD` lines read as
"51 chunk carves skipped durable init" — a phantom defect written into a
ledger record and retracted the same session. Both counts were truncated:
the probe prints only its first 20 occurrences per module load (a hard cap,
not a sample), and the dmesg ring buffer had already rolled past the mount
banner, so even the capped 20 weren't all present. Rule: `dmesg | head -1`
before trusting any whole-log count — if the first retained line isn't the
boot/mount banner, every total is a lower bound; read a probe's own print
condition (`<= N`, `% 500`, ratelimited) before quoting its count; never
divide two counts truncated by different rules
([[trap-a-probe-count-is-meaningless-when-the-print-budget-and-the-ring-buffer-both-truncate-it]]).
The detour this produced led to the real finding
([[trap-no-inode-magic-does-not-mean-nothing-was-ever-written-there]]).

## Reproduction technique: the captured object's own fields name it

Three D-0946 harness modes scored `DEADSHELL=0` for 16+ rounds — reading as
"the defect doesn't reproduce" when the gate that carries the defect had
never fired. The one prior captured failure already held the answer:
`P-CR63-SHELL ino=0x84 mode=00 nlink=0 nblk=11` — `nblk=11` didn't match the
8MB (2048-block) file the workload was churning at all. Eleven blocks is a
directory that outgrew shortform, not a file — the object being raced was the
churn *directory*, removed by `rm -rf`. Reading that one field converted the
reproducer from a 150s-per-attempt death/rejoin harness (3 hits in 16 laps)
into a bare `mkdir`/fill/`rm -rf` loop with no fault injection at all
([[technique-read-the-shell-dump-fields-to-identify-what-object-the-defect-needs]]).
Once the object was known, closing the reproduction gap required scoring the
harness's own gate-fire count, not just its outcome: `sync -f` between passes
was publishing every owed free before the next round could race it, and
zero-length test files (`mode=00, nblk=0`) could never satisfy the recycle
path's entry condition (`i_mode != 0 || i_nblocks != 0`) even with sync
removed. A round with zero gate-fires is VACUOUS, not "not reproduced" —
report `PUBPEND=n PUBALLOW=n ... DEADSHELL=n` alongside every verdict. A
second-order version of the same bug hid inside one fix: both A/B arms shared
one rate-limit counter, so the treatment arm burned all the slots in round 1
and the control arm's real, frequent firing printed nothing — one rate-limit
counter per arm, or the louder arm silences the other and the A/B reads
backwards
([[technique-a-vacuous-clean-run-is-detected-by-counting-the-gate-not-the-outcome]]).

## Harness/tooling bugs that faked clean or null results

- **Deploy script dropped a field it depended on.** `module_swap_deploy.sh`
  resolved the LUN from `MXFS_DEV` or else `.cluster_marker.json`'s `dev`
  field, but rewrote the marker at the end of a successful run without that
  field — so the *second* swap fell through to a nonexistent
  `/dev/mapper/mpatha`, and by the time the missing device was detected the
  script had already unmounted and rmmod'd every node with no way back. The
  failing run is never the one that looks broken; a script that reads a
  field from a state file and rewrites that file must write the value back
  ([[trap-module-swap-deploy-dropped-dev-from-marker-and-killed-the-rig-on-its-second-run]]).
- **A mount entry in `/proc/mounts` proves presence, not usability.** A
  precondition of `grep -c ' /mnt/shared mxfs '` = 1 passed against a
  filesystem already self-fenced (`P305-RESV-SELF-GONE`) and EIO on
  everything; the workload then created 0 of 12000 files and the harness
  scored `verdict=VACUOUS` — one careless read away from "the defect didn't
  reproduce." Probe usability (`mkdir`+`rmdir` a probe path, exit 2 on
  failure), not presence. Same session: `grep -c` prints `0` and still exits
  1 on no match, so `grep -c ... || echo 0` doubles the output into garbage
  (`"0\n0"`); and `df --output=itotal` reports XFS's dynamic `maxicount`
  ceiling, not `sb_icount` — it read the same 25991808 before and after
  12000 creates. The counter that actually reports allocated inodes is
  `tools/chk_mxfs -v <dev>`'s `Superblock icount` / inobt sum
  ([[trap-a-mount-in-proc-mounts-is-not-a-working-mount-and-two-shell-counter-bugs]]).
  That same counter turned out to have its own staleness trap one session
  later: MXFS keeps `sb_icount`/`sb_ifree`/`sb_fdblocks` lazily and only
  writes them to platter at unmount, so three live-mount `chk_mxfs` samples
  around a 187-chunk-carving workload all read the *previous* unmount's
  value (`64`, unchanged) and the harness scored the whole run
  `verdict=VACUOUS`. A cold read with every node unmounted showed `12032`.
  Never gate a verdict on a live-mount superblock counter or diff two of
  them; gate on what the workload itself produced (a created-file count) or
  a cold post-unmount read
  ([[trap-chk-mxfs-superblock-icount-lags-a-live-mount-by-one-unmount]]). Third
  instance of the same shape as the truncated-probe trap above: `df
  --output=itotal` (wrong metric), `P133-ICLUSTER-SYNCINIT` (print budget),
  and now `chk_mxfs` live icount (write-at-unmount only) are three different
  mechanisms all producing a confident null. Before trusting any carve/free
  counter, ask what writes it and when.
- **A state snapshot is evidence about the instant it was taken, and SCSI PR
  says which instant.** A correct persistent-reservation hypothesis for an
  unmountable volume was disproven with a capture at PR generation 2765; the
  failure had logged its own state at generation 2757 (`P304-PREOBSERVE
  held=1 type=0x7 (WE-AR) holder_key=0x0 gen=2757`) — eight generations of PR
  OUT commands (the investigator's own remount attempts) had cleared the
  reservation before the capture. Any "I looked and it was clean" disproof of
  transient state needs a stamp tying the look to the event (generation,
  epoch, LSN, boot id); without one, "clean now" and "clean then" are
  indistinguishable, and the failure mode is the dangerous direction — it
  retires a true hypothesis. Time-shifted twin of
  [[trap-a-silent-instrument-and-a-clean-system-are-the-same-observation]]
  (a loud instrument read at the wrong moment, instead of a silent one read
  at the right moment). The PR key itself is derived from `{host, boot,
  LUN}`, not incarnation, so a fence aimed at a dead incarnation's key lands
  on the live successor's identical registration — observed as a mounted
  node logging its own key as unregistered and self-fencing
  ([[trap-a-pr-snapshot-only-proves-anything-about-the-generation-it-was-taken-at]]).
- **A probe guarded by the complement of its enclosing branch cannot fire.**
  `P103-CHUNKFREE` sat inside a `!D || S` (not-multi-node) branch but itself
  required `D && !S` (multi-node) — the exact complement — so every
  inode-chunk deletion the filesystem ever performed was silent, in no
  evidence directory anywhere in the tree. Both the probe and its enclosing
  comment read as multi-node instrumentation, which is why it passed review:
  the mismatch is 30 lines up, not local. General check: evaluate a probe's
  guard conjoined with every enclosing guard before trusting silence; a probe
  that has never once appeared in captured evidence despite its path
  plausibly running is a standing candidate for this bug — worse than the
  merely-unexercised silent-instrument case because no workload could ever
  have fired it
  ([[trap-a-probe-whose-condition-is-the-complement-of-its-branch-never-fires]]).

## Host observability: silence is not evidence the host stayed healthy

test1 rebooted mid-mount with no record in any of four channels: empty
pstore (these guests may carry no pstore region at all), journald's boot
list skipping the crashing boot entirely, no libvirt destroy/start event
near the crash, zero host `journalctl -k` entries. The *absence* of a
libvirt event is itself a positive finding — it means the reboot originated
inside the guest (panic, triple fault, guest-initiated reset), not from the
hypervisor. The actual gap: every node has netconsoled to clyde since the
rig existed (`netconsole: remote port 6666` in every boot log) and nothing
had ever listened — `ss -lunp | grep 6666` returned nothing. A guest panic
and a guest that "just rebooted" have been the same observation in every
prior session. Fixed with `tools/netconsole_listen.sh start|stop|status|tail`
(documented in `docs/host-safety.md`), run whenever the rig might kill a
node. Guest `console_loglevel=1` means ordinary probe output won't reach
netconsole (so it can't flood) and a plain `echo x > /dev/kmsg` (level 4)
also won't show — verify with `<0>` level explicitly, not by echoing an
arbitrary line and seeing nothing
([[trap-nothing-ever-listened-to-the-nodes-netconsole-so-every-guest-panic-was-discarded]]).

## Defect-record discipline: the record can be closed while the defect isn't

D-0904 was closed FIXED AND VERIFIED after `mxfs_v5_dlm_sole_survivor()` was
added at one call site and rig-verified on a 2-node TCP death chain — correct
fix, wrong scope. The defect was that dynamic-membership checks
(`is_single_node`) are wrong for a sole survivor generally; a census on
0.75.124 found ~369 real call sites of the unsafe predicate against 5 of the
safe one. Nine months of sessions read the ledger as "handled" because the
record said FIXED AND VERIFIED. Two of the ~364 unaudited sites sit on paths
a later campaign got stuck on, including the same chunk-delete guard pattern
in the finobt path and the D-0946 candidate validator being skipped entirely
when single-node — precisely the post-death window at risk. Rule: when a
defect's root is a predicate or idiom rather than a line, closing it needs a
census of every use (`grep -rc` the unsafe and safe forms, compare counts —
369:5 is itself the finding), not a fix at the one reported site; a
class-level record stays open naming the census until the sweep is done
([[trap-closing-a-defect-on-one-call-site-leaves-the-class-open-368-to-5]]).

Related discipline failure on the same tooling: `tools/defects.py`'s
`nodes`/`dlm` fields (fail-closed default `1`/`any`, blocking every release
until narrowed) were touched on a live record — `D-READDIR-PEER-CACHED-DIR-
PACE` — purely to smoke-test the `update` CLI's `-N`/`-D` flags, setting
`2/caw` on a record whose own evidence field said "MEASURED 32/caw." The
wrong value happened not to change the 2-node-TCP gate count (both `2/caw`
and `32/caw` are excluded from a 2/tcp gate), but would silently have
dropped the defect from a 2/caw gate on no evidence. There is no such thing
as narrowing a configuration field "just to see if the flag works" —
exercise CLI flags on a throwaway record, and read a record's own evidence
field (never its id, summary prose, or a keyword sweep) before ever setting
its narrowest reach
([[trap-i-narrowed-a-defects-configuration-while-smoke-testing-the-flag]]).

## The shape, again

Same question as the prior compiled batch — did this action/read/closure
actually establish what it claims, under the state it claims — plus two new
angles specific to this campaign: a ruling's hazard clause binds as hard as
its procedure, and a defect record's scope is only as wide as its census, not
its fix.
