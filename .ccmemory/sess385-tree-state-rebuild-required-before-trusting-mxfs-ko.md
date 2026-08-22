---
name: sess385-tree-state-rebuild-required-before-trusting-mxfs-ko
description: sess385 END STATE: source is 0.19.22 but its build was INTERRUPTED by the clyde wedge — run `make clean && make modules` before trusting mxfs.ko.
metadata:
  type: project
tags: [build, sess385, rig, clyde, handoff]
---

## FIRST ACTION for the next session

    make clean && make modules && modinfo mxfs.ko | grep srcversion

**Do not trust the `mxfs.ko` on disk.** The tree's `VERSION` says **0.19.22**,
but that build was cut off when clyde degraded to the point where `make` ran
past 600 s (it had been taking ~90 s) and even `ls; date` timed out at 25 s. The
`.ko` is therefore either the previous good build (**0.19.21**, srcversion
`C6C38A5F0D470605779764E`) or a partially linked artifact. Project convention
already says to `make clean` first when changes span multiple files.

## Source state — all edits are ON DISK and complete

`/src` is NFS (`192.168.1.4:/src`), NOT clyde's wedged ext4, so every source
edit, ledger update, awareness-doc update and ccmemory note landed safely and is
intact. Only the compiled artifact is in question.

Last change applied (0.19.21 -> 0.19.22) was small and self-contained: escalating
2/4/8 ms backoff between the bounded repair retries in
`mxfs_p86_agi_unlinked_publish_audit`, because retrying back-to-back gives the
ILOCK holder no chance to release — which is the only reason a retry can succeed.

## Build lineage this session (all clean unless noted)

| version | srcversion | what |
|---|---|---|
| 0.19.16 | `86580ED23708F236FB1E5FD` | the build the A/B actually ran on |
| 0.19.17 | `EEBC0F69C128B81468B4B47` | probes anomaly-gated |
| 0.19.18 | `9DD66F4F011D27AA08AFB4C` | stale param description fixed |
| 0.19.20 | `50B07EF2D616706B3733F34` | Part D publication enforcement |
| 0.19.21 | `C6C38A5F0D470605779764E` | RCU identity re-check + reclaim guard |
| 0.19.22 | **build interrupted** | retry backoff |

## Then

1. Host reset is required first — see
   `sess385-clyde-ext4-jbd2-wedge-shared-lun-on-root-fs`.
2. Re-prep, deploy, and run `tests/d385_publication_verify.sh` — the scripted
   closing run for the AGI publication defect. It fails deliberately on low
   exposure rather than reporting a green run that proved nothing.
