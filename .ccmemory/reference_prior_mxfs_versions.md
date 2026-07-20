---
name: Prior mxfs version directories — load-bearing context for v5 work
description: Pointer to ~/src/mxfs.{1,2,3} which contain extensive scaling benchmarks, bug history, and populated awareness docs that v5 (/src/mxfs) did NOT inherit. Sess20-27 went in circles partly because this corpus was not consulted.
type: reference
originSessionId: 577f8f30-2496-458a-8b8e-8c2966f4ae36
---
`~/src/mxfs.1/`, `~/src/mxfs.2/`, `~/src/mxfs.3/` contain the prior
project iterations. v5 (current `/src/mxfs`) was started fresh against
kernel XFS source and did NOT carry forward the awareness docs, bug
journals, or scaling benchmarks from these directories.

**Why this matters:** Sess20-27 of v5 kept "discovering" issues that are
already characterized in mxfs.1 prior art — TCP DLM scale limits, BAST
delivery semantics, lease-vs-disconnect interaction, peer reconnect
cooldowns, membership stabilizer, etc. v5's empty `.claude/awareness/`
directory is a major contributing factor to the circular debugging.

**How to apply:** Before debugging a v5 cluster-coordination issue, check
whether the same class of issue was already analyzed in prior art. Use
these as starting points:

- `~/src/mxfs.1/.claude/awareness/structural-map.md` — populated structural
  map (functions, calls, types). v5's equivalent does not exist yet.
- `~/src/mxfs.1/.claude/awareness/subsystems/cluster.md` — DLM/lease/peer/
  disklock subsystem doc.
- `~/src/mxfs.1/.claude/awareness/subsystems/dlm.md` — DLM-specific deep dive.
- `~/src/mxfs.1/.claude/awareness/subsystems/platform-vfs.md` — PAL/VFS deep
  dive.
- `~/src/mxfs.1/handoff.md` — last-session handoff at end of mxfs.1.
- `~/src/mxfs.1/README.md` — top-level architectural summary, transport
  comparison table.
- `~/src/mxfs.1/docs/architecture.md` — DLM Transport Scalability section
  (line ~440), serial-bottleneck explanation.
- `~/src/mxfs.1/docs/dlm-protocol.md` — protocol spec.
- `~/src/mxfs.1/docs/perf.md` — performance characterization.
- `~/src/mxfs.1/bench.json` — actual benchmark numbers (1.01x CAW vs 7.7x
  TCP write spread).
- `~/src/mxfs.1/scale_tests_session10.txt` — 6/8/16-node CAW test logs.
- `~/src/mxfs.1/scale_test_6node.txt` — 6-node CAW BAST delivery failure
  evidence.
- `~/src/mxfs.1/libmxfs/*.md` — per-module changelogs (peer.md, dlm.md,
  mount.md, inode_cache.md, lease.md, dir_cache.md). Contains hundreds of
  bug fixes with root-cause writeups.
- `~/src/mxfs.1/pal/pal.md` — PAL TCP tuning history (TCP_USER_TIMEOUT,
  buffer sizes, sndtimeo).
- `~/src/mxfs.2/NEWSYS.md` — mxfs.2 redesign notes.
- `~/src/mxfs.3/journal.md`, `~/src/mxfs.3/project.md` — mxfs.3 design.

**Plan:** User said (sess28) "we will run awareness here but not yet — for
now research this." Meaning: read the prior-art corpus first, build the
mental model from documented evidence, then later bootstrap v5's own
awareness with the carry-forward facts.
