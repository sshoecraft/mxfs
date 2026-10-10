---
name: compiled-user-conventions-handoff-state-claude-md-text-host-names-mount-path-find-and-build-kills
description: Assorted user corrections: state.md fresh not history, clean CLAUDE.md rule text, no find /, test1/test2 names, /mnt/shared, SIGTERM builds.
metadata:
  type: feedback
tags: [compiled, feedback, conventions, handoff, claude-md, find-root, mount-path, builds]
---

Assorted group (the clusterer could not fit these to one topic): six independent user corrections, each a standing convention. Organised by the artifact they govern.

## Where text goes

- **`state.md` is a fresh snapshot, never a history log.** On every context handoff, overwrite it completely with only: what this session did, current code/deploy state, open bugs, next steps, gotchas. Never prepend a new section over the old one. The failure: it had grown to 865+ lines by prepending each session's state. The context-handoff skill's default "prepend/keep history" behaviour must be overridden here. Any history worth keeping goes in `CHANGELOG.md`. User, emphatic: history belongs in the changelog. [[convention-statemd-fresh-history-in-changelog]]
- **When asked to reword a CLAUDE.md rule, write only the clean rule text.** No "(user directive, DATE)" tag, no "reworded on..." parenthetical, no change-history note. The failure: a RULE heading was rewritten with both, and the user had to edit them out. Provenance belongs in ccmemory (description field), not in a rule read every session. Older rules already carrying "(User directive, sessNNN)" tags stay as they are unless asked; just do not add new ones. [[feedback-claude-md-rules-no-provenance-clutter]]

## Naming and paths

- **Name the test cluster nodes `test1` and `test2`** (the real hostnames, as in `bench/rsync_bench.sh` output, ssh prompts, `mount` listings), never `T1`/`T2`. Applies to state files, lessons, dmesg commentary, bench summaries and chat. Existing T1/T2 text may stay, but rename when the surrounding text is being rewritten anyway. [[Use test1/test2, not T1/T2]]
- **Mount MXFS on `/mnt/shared`**, never `/mnt/bench` or another path, for every MXFS or benchmark mount. [[MXFS mount path]]

## Commands never to run

- **Never run `find /` on clyde, for any reason.** Absolute and unconditional, not a "scope it better" guideline. `/src` and `/data` are QNAP NFS mounts, so a root crawl is slow and hammers the NFS server for the whole cluster, but the rule holds regardless of the reason you think you have. Origin: a `find /` hunting for an `fsx` binary. Alternatives that accomplish the goal: `command -v`/`which`/`dpkg -L <pkg>` for an installed binary; an exact known local directory; or check inside the test VM when the tool runs there. [[never-find-root-nfs-mounts]]
- **Kill mkosimage/packer builds with plain `kill` (SIGTERM), never `kill -9`.** Their cleanup handlers remove temp files and destroy partially created VMs only on graceful termination; SIGKILL leaves orphaned VMs and temp files for manual cleanup. Send SIGTERM and wait for the process to exit. [[feedback_kill_builds]]
