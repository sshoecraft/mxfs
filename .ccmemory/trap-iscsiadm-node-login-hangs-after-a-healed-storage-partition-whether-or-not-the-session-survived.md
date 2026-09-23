---
name: trap-iscsiadm-node-login-hangs-after-a-healed-storage-partition-whether-or-not-the-session-survived
description: TRAP (s123a/s124a): `iscsiadm -m node --login` never returns after an iptables storage partition is healed; bound it and skip it when the LUN already…
metadata:
  type: feedback
tags: [rig, iscsi, harness, timeout]
---

# `iscsiadm -m node --login` hangs after a healed storage partition

`tests/fence_partition_reconnect.sh` ARM=storage drops B's iSCSI portal traffic
with node-local iptables, holds it past `replacement_timeout`, then heals and
drives the reconnect. Its comment claimed:

> a session that survived makes the login a no-op

**That is false, and it cost a whole arm.** Measured twice on the QNAP LUN:

- **s123a**: `SESSIONS_BEFORE=1` (the session had survived), the unbounded
  `iscsiadm -m node --login` never returned, and the arm died at the enclosing
  90 s `measure` bound with **rc=124 at `stage=capture`** — after every MXFS
  verdict in the lap had already PASSed (key gone at the certificate,
  reservation `WEAR → WEAR`, PR generation unmoved, a durable
  `LU_RESET_WITNESSED_V1`, `P163-RECOVERY-COMPLETE`).
- **s124a**, with the login under `timeout 30`: `SESSIONS_BEFORE=1`,
  `login rc=124` — it hung again — and yet `DEV_READABLE=1` immediately after.
  So the login is **both** unnecessary and non-returning.

## What to do instead

Probe the LUN first and only log in if it does not answer, and bound every
call node-locally:

    s0=$(timeout 15 iscsiadm -m session | grep -ac tcp || true)
    if timeout 10 dd if=$DEV of=/dev/null bs=512 count=1 iflag=direct >/dev/null 2>&1; then
        echo LOGIN_RC=0           # skipped: the LUN already answers
    else
        timeout 30 iscsiadm -m node --login > /run/login.txt 2>&1; echo LOGIN_RC=$?
        sed 's/^/LOGIN /' /run/login.txt; sleep 8
    fi

Take the rc from the command, not from a pipeline — `iscsiadm ... | sed` yields
`sed`'s status. Print `LOGIN_RC` so which of the two paths ran is on the record
rather than inferred.

## The general shape

An outer harness bound (`measure`'s 90 s) turns a node-local hang into an
**arm-wide ABORT that discards verdicts already earned**. Bound the individual
remote command so the hang is one recorded field, not the end of the lap.
