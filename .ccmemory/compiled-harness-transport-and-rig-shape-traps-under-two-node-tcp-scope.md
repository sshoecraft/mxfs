---
name: compiled-harness-transport-and-rig-shape-traps-under-two-node-tcp-scope
description: Harness/rig transport traps: caw* names, module reload dropping force_transport, 2-node TCP scope, harness prep vs header, defect nodes/dlm narrowing.
metadata:
  type: feedback
tags: [compiled, harness, transport, tcp, caw, rig-safety, defects]
---

# Harness transport and rig-shape traps, and the two-node TCP scope they violate

Common thread: a harness, a prep call, or a CLI flag silently measures or claims a different configuration (transport, node count, reach) than the one the operator believes it did. Nothing fails visibly; the result is a non-measurement or a false claim.

## Scope directive (user, 2026-09-05)

[[feedback-scope-is-two-node-tcp-only]]: the only objective is two-node TCP working 100%. The user interrupted twice after a session inherited test3/test4 VMs from 4-node laps, delegated a chain that re-prepped the rig on CAW for a CAW verification leg, and planned a 32-node TCP campaign because open ledger records name 32/tcp or CAW legs as closure conditions.
- Rig is test1 + test2 on the QNAP LUN, TCP transport. `virsh destroy testN` any other running VM.
- Never prep CAW, run a CAW leg, or plan 32-node/4-node work, even when a record's closure condition names one. Note the owed leg in the record as out of scope and move on.
- The open_defects board cell counts every open record including 32-node/CAW-only ones; say so instead of chasing them. Prioritize records reachable on the 2-node TCP shape.

## Harness traps (chronological)

1. Module reload without an explicit transport ([[trap-sameboot-remount-harness-reloaded-module-without-force-transport-measured-caw-not-tcp]], sess510, 2026-09-04). `tests/sameboot_remount.sh` did `rmmod` + `insmod $KO $MODARGS` with MODARGS = `target_cache_protected=1` only. The last leaver forms a new cluster, which tries CAW first; the peer conforms (`P-TRANSPORT-CONFORMED caw`). All 5 joins in the s509d evidence read `transport=caw`, so the sess509 "0.75.3 TCP same-boot port verified" claim was a CAW measurement. Fix: MODARGS default carries `force_transport=1`; every join asserts `DLM init: node_id=N transport=$MXFS_TRANSPORT`. Rule: any harness that rmmod/insmods must pass the transport explicitly and assert the per-mount `DLM init: ... transport=` line; a prep's `force_transport=1` does not survive the harness's own reload. INFO lines in a PASS lap (the lone `P-TRANSPORT-CONFORMED caw`) are worth one read.

2. Exact-match on a transport name that has variants ([[trap-a-harness-that-matches-transport-caw-exactly-puts-a-cawd-node-back-on-tcp]], 0.90.4/0.90.5). Rig transport names are `caw` (dm-multipath), `cawd` (direct in-guest iSCSI, SCST 2-node rig), `cawp` (passthrough). `tests/lib/rig.sh mxfs_rig_modargs` chose `force_transport=0` only for `caw` exactly; with `MXFS_TRANSPORT=cawd` every reload after a whole-cluster outage got `force_transport=1`, and the mount died with `P-TRANSPORT-MISMATCH-REFUSED forced=tcp platter=caw`. `tests/bootstrap_takeover_2n.sh` graded that VACUOUS, hiding a setup failure as a non-measurement. Fix: `case caw*`, and the harness grades a DLM-init refusal ABORT. This is the same bug fixed once before for `caw` vs always-TCP; renaming the rig re-broke it. When a transport/rig name set changes, grep every exact comparison against the old name. `run.sh`'s own `caw)` arms mean the multipath rig specifically and are correct.

3. Header describes the shape, not the prep ([[trap-a-harness-header-describes-the-shape-not-the-prep]], sess565). `tests/sess493_d0492_crash_durability.sh` opens with a two-node workload description but hardcodes `run.sh 32 caw prep_cluster` and defaults `A=test3 B=test2 C=test4`. Running it started all 32 VMs, run.sh power-cycled test3..test32, clyde hit 0 GB free, test1/test2 were left unmounted with the module unloaded; ~5 min of rig time for zero measurement. Before running any not-yet-run harness from `tests/`: `grep -n 'run\.sh [0-9]* \(caw\|tcp\)\|MXFS_NODE_LIST\|^A=\|^B=\|^C=' tests/<harness>.sh`; either signal alone rejects it. Same harness's other landmines: `KO` defaults to a frozen build (measures a five-day-old module); `cp "$KO" mxfs.ko` is a same-file copy if KO is the tree path; `RESTORE_KO` defaults to a nonexistent path so the abort-path restore fails silently; the whole body is wrapped `{ ... } >> "$LOG" 2>&1`, so "no output" is not a hung run, read `tests/evidence/<name>_<label>.log`. Harnesses were mostly written in the 32-node era; under a narrowed directive verify the harness's prep, not its prose.

## Defect-queue reach is a claim ([[trap-i-narrowed-a-defects-configuration-while-smoke-testing-the-flag]], sess575)

`tools/defects.py update <id> -N 2 -D caw` was run on a real record only to see the flags take; its evidence said "MEASURED 32/caw", so the correct value was `32/caw`. The 2/tcp count did not change (2/caw and 32/caw both fall outside a 2/tcp gate), but the record would have silently dropped out of a 2/caw release gate on no evidence, defeating the fail-closed `1/any` default.
- Never write `-N`/`-D` on a real record to test the tool; add a throwaway record, exercise the flags, remove it.
- Every narrowing is preceded by reading that record's own `evidence` field and taking the smallest cluster/transport it states. Not the id, not the summary prose, not a keyword sweep.
- A heuristic bucket estimate (a subagent sweep said 40 of 95 were 2-node-TCP-reachable) is a destination estimate; the gate reading (93) is today's state. Never present the estimate where it can be mistaken for a gate reading.
