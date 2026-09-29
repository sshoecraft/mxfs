---
name: trap-log-tail-never-equals-log-head-on-a-covered-idle-log-measure-the-tail-against-the-burst-end-head
description: TRAP (0.90.16 tail-pin): sysfs log_tail_lsn is the START of the last record and log_head_lsn its END; on a covered idle log they sit 3 blocks apart f…
metadata:
  type: feedback
tags: [xfs-log, measurement, tail-pin, harness]
---

# The log tail never equals the log head on a covered idle log

**What bit us (tests/alloclist_tail_pin.sh, first version, 0.90.16, evidence
tests/evidence/alloclist_tail_pin/20260929T020119Z):** the verdict was "PASS
when the tail reaches the head".  Measured on a 4/tcp cluster after a 3000-file
burst: tail 10 blocks behind the head for 20 s; at the first 30 s log-worker
tick the tail jumped to the burst-end head (every item the burst logged was
written); then two log-covering records moved BOTH marks together, and for the
rest of the 120 s window the tail sat exactly 3 blocks behind the head.  The
script called that a FAIL.

**Why:** `/sys/fs/xfs/<dev>/log/log_tail_lsn` is the AIL minimum, and with an
EMPTY AIL it is `last_sync_lsn`, the START of the last record written;
`log_head_lsn` is the current write position, the END of that record.  A
covered idle log therefore shows tail = head minus the last record's length,
and equality is unattainable.

**Measure instead:** record the head at the end of the burst and PASS when the
tail reaches or passes it (`lsn_ge` on cycle:block) — that is the statement
"everything the burst logged has been written".  A tail that does not move at
all is the pinned tail; a tail that moves but stays below the burst-end head
is something else pinning the AIL.
