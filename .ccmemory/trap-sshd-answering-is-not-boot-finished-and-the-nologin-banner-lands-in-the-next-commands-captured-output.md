---
name: trap-sshd-answering-is-not-boot-finished-and-the-nologin-banner-lands-in-the-next-commands-captured-output
description: TRAP (s116): a lap waited for ssh `true` and returned; the next prep_cluster's srcversion probe read systemd's "System is booting up" banner and abor…
metadata:
  type: feedback
tags: [rig, harness, prep, measurement-integrity]
---

# sshd answering is not boot finished, and the banner is charged to the next command

## What happened

`tests/tcp_death_replay.sh` restarts the victim VM at the end of a lap and waits
for the guest to be reachable:

```sh
while [ $i -lt 120 ]; do
    if timeout 8 $SSH "$V" "true" >/dev/null 2>&1; then up=1; break; fi
    sleep 5; i=$((i+5))
done
```

That succeeds well before the guest has finished booting. systemd keeps
`/run/nologin` until the boot transaction completes, and `pam_nologin` prepends

```
"System is booting up. Unprivileged users are not permitted to log in yet.
 Please come back later. For technical details, see pam_nologin(8)."
```

to the captured output of whatever runs next. The next `prep_cluster`'s
srcversion probe got the banner ahead of the value it was parsing and reported

```
PREP FAIL: bad nodes: test2(no usable srcversion — still booting?)
ABORT: cluster prep failed
```

on **two preps of three**, while both nodes were in fact healthy, on the right
build, and the laps that ran afterwards passed with **zero** failures — the
`NODE_PREP_OK … srcversion=<correct value>` line was printed immediately below
the FAIL.

## Why it matters more than a spurious FAIL

Two separate costs, and the second is the dangerous one:

1. A prep that says FAIL about a healthy cluster is how a **real** prep failure
   gets waved through, because the message has been seen and dismissed before.
2. It leaves the following lap's **build identity unverified**. The probe is
   exactly the step that proves the fleet is running the module you just built;
   when it aborts, nothing else in the lap re-checks it, and a measurement gets
   attributed to a build nobody confirmed.

## The fix, and where it belongs

In the lap, not in the prep parser — the lap's own postcondition is "the victim
is back and the next prep can form a cluster", so the lap owes the wait:

```sh
if [ "$up" = 1 ]; then
    j=0; booted=0
    while [ $j -lt 90 ]; do
        if timeout 8 $SSH "$V" "test ! -e /run/nologin" >/dev/null 2>&1; then booted=1; break; fi
        sleep 3; j=$((j+3))
    done
    echo "  INFO $V boot transaction complete=$booted after ${j}s (/run/nologin cleared)"
fi
```

## Generalise it

Any readiness probe that only asks "does the transport answer" will hand the
next step a guest that is still emitting boot-time noise into stdout/stderr.
When the next step **parses** that output, the noise is indistinguishable from a
missing value. Wait on a state that means *finished* — `/run/nologin` gone, or
`systemctl is-system-running` returning — and print which it was, so a lap that
proceeded on a half-booted guest says so in its own log.
