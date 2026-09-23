---
name: trap-a-per-second-poller-whose-command-blocks-through-an-outage-reports-one-unanswered-second-for-the-whole-outage
description: TRAP (s65): a 1 s sg_persist poller across an iSCSI target restart counted ONE unanswered line for a 16 s outage — the in-flight command is queued th…
metadata:
  type: feedback
tags: [harness, measurement, iscsi, scsi-pr, poller]
---

# A per-second poller whose command blocks through an outage reports one unanswered second for the whole outage

Run 98c3ef65 session 65, tests/target_restart_pr.sh on the liovm bench target.

## What happened

The lap's poller ran `sg_persist --in --read-reservation` once a second on the
survivor across a restart of the iSCSI target and printed "the poller saw 1
unanswered second(s)" and "BACK_AFTER=1" for BOTH a 2 s service restart and a
16 s crash-and-reboot of the target VM. Read literally, the LUN answered one
second after a VM crash, which is impossible.

## Why

When the sessions drop, the initiator does not fail the command in flight: the
iSCSI layer holds it through session recovery (up to replacement_timeout) and
issues it as soon as the session logs back in. So one poll line spans the whole
outage and completes as the FIRST command into the reopened LUN; the next poll
runs a second later. The reconnect loop's `for i in 1..N; sg_persist && break`
likewise reports i=1 whatever the outage was.

The poll timestamps carry the truth: the gap between consecutive lines was 2 s
(service) and 16-17 s (host crash), matching the target VM's own boot record
(kernel up in <3 s, target.service restored ~5 s after boot).

## What to do

- Measure an outage as the largest gap between consecutive poll timestamps,
  never as a count of polls that returned an error.
- The blocked poll is a BETTER instrument than 1 s sampling for "is there an
  unreserved window when the LUN reopens": it is the first command the target
  serves. Say that, not "1 s resolution".
- A reconnect bound for an iSCSI initiator is replacement_timeout (120 s):
  past it the session is torn down and no in-loop command can succeed, so a
  larger bound is slack, not coverage.
