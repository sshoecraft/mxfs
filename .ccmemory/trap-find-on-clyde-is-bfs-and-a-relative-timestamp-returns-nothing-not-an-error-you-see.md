---
name: trap-find-on-clyde-is-bfs-and-a-relative-timestamp-returns-nothing-not-an-error-you-see
description: TRAP: `find` on clyde is bfs, which rejects `-newermt '3 hours ago'`. With stderr suppressed it prints nothing, and an empty capture reads as "no fil…
metadata:
  type: feedback
tags: [clyde, find, bfs, evidence-integrity]
---

# `find` on clyde is bfs, and a relative timestamp fails silently

2026-09-17. Verifying which files a session had written, this looked conclusive:

    find /src/mxfs -newermt '3 hours ago' -type f -not -path '*/.git/*' ... 2>/dev/null
    # (no output)

and it was about to be reported as "nothing in the repo was modified" — while a
file written twenty minutes earlier sat in `tools/`.

`find` on this host is **bfs**, not GNU findutils. It accepts only ISO-8601-like
timestamps and rejects relative ones outright:

    bfs: error: ... -newermt "3 hours ago"
    bfs: error: Invalid timestamp.
    Supported timestamp formats are ISO 8601-like, e.g.
      - 2026-09-17
      - 2026-09-17T17:40:13
      - 2026-09-17T22:40:13Z

exiting 1 having printed nothing to stdout. With `2>/dev/null` on the call the
diagnosis is invisible, and the empty result is indistinguishable from a real
negative.

## Rules this earns

- **Use an absolute timestamp**: `-newermt '2026-09-17 17:00:00'`. It works on
  both implementations.
- **Never suppress stderr on a command whose EMPTINESS is the evidence.** The
  same shape has bitten this project before with an ssh helper sending remote
  stderr to `/dev/null`, turning a failed command into an empty capture that
  `grep -c` then reported as a count of zero.
- A negative that is about to become a conclusion gets a positive control: check
  one file you know changed, by name, in the same command.
