---
name: trap-journald-files-a-name-colon-prefix-written-to-dev-kmsg-as-the-identifier-so-o-cat-drops-it
description: TRAP (0.90.57): echo '<5>mxfs-test: run X start' > /dev/kmsg shows in `journalctl -k -o cat` as 'run X start'; a sed range on the full text matched n…
metadata:
  type: feedback
tags: [journald, kmsg, harness, measurement]
---

**What happened:** `tests/drbd_vmimage_contention.sh` marked each run with
`echo '<5>mxfs-test: vmimage-contention <RUN> start' > /dev/kmsg` and counted tags with
`journalctl -k -o cat | sed -n '/mxfs-test: vmimage-contention <RUN> start/,$p'`.  Every count came back empty
although `dmesg` held the mark and the tagged lines after it.

**Why:** journald parses a `/dev/kmsg` record's leading `word:` as its syslog identifier, stores the rest as
MESSAGE, and `-o cat` prints MESSAGE only.  `dmesg` keeps the full text.  (Kernel `pr_*` lines such as
`mxfs: P912-...` keep `mxfs:` in MESSAGE in practice because the rest of the harness greps found them; a
userspace-written mark is the case that loses its prefix.)

**How to apply:** match a /dev/kmsg mark in journal output without its `name:` prefix (or read `dmesg`), and test
the range extraction once by hand before trusting a count of zero from it.
