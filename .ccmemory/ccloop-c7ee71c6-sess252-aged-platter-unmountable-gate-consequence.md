---
name: ccloop-c7ee71c6-sess252-aged-platter-unmountable-gate-consequence
description: sess252: aged mass-crash platter UNMOUNTABLE fleet-wide — all 31 slice replays -117 (ATOMIC-SKIP/TORN-UNPUBLISHED), mount aborts; #1 tokenization is…
metadata:
  type: project
---

# sess252 — aged platter remount refusal (consequence of #21 fail-closed gate)

## What was done
- Found SCST dead on clyde (host was manually reset Aug 13 22:07 local; systemd scst.service fails on its own stale /etc/scst.conf — IRRELEVANT to the rig, which uses scripts/scst_setup.sh via `scripts/rig.sh mpath 32`).
- `scripts/rig.sh mpath 32` restored the full dual-portal rig: 32/32 nodes have 2-path /dev/mapper/mpatha (serial=2e476d07). Took ~5 min, worked first try.
- Platter verified intact (volume_id 0x22254921d1895f9b, same node_ids as sess249 archive).
- Attempted sess251's plan: form cluster WITHOUT mkfs on test1 (`MXFS_DEV=/dev/mapper/mpatha MXFS_KO_MD5=<md5> MXFS_EXTRA_MODARGS='ailstuck_probe=1' bash /src/mxfs/tests/setup/prep_node.sh caw`).

## Decisive result — the aged platter is UNMOUNTABLE by ANY node
test1 (slot 30) mounted, fenced+certified every dead slot correctly (P236 intent→certified ladder, P234 takeover of a mid-recovery dead owner — all worked), then foreign replay of ALL 31 slices failed -117:
- Every victim txn contains untagged inode images → P227-FR-ATOMIC-SKIP (whole-txn) → P227-FR-TORN-UNPUBLISHED refusal ("needs repair or token-authorized redo" — NEITHER EXISTS).
- After 4 inline rounds / 30s: "MXFS mount ABORTED: slot mask 0xbfffffff still requires recovery" — clean teardown, slot released.
- P273-SHADOW-EVAL slot0: capable=1 ENFORCEABLE_WOULD_APPLY=1 — the shadow evaluator names txns it COULD have applied with #1 tokens enforced.
- Evidence archived: tests/forensics/sess252_aged_platter_remount_refusal_test1_dmesg.txt (124 refusals = 31 slices × 4 rounds). Ledger #21 updated with field remount_refusal_sess252.

## Meaning
The #21 interim gate (0.11.482) converts a mass crash into a PERMANENTLY unmountable cluster. Production consequence: site-wide crash → no recovery. The unbrick is #1 D-FOREIGN-REPLAY-UNGATED-IMAGES tokenization (plan of record, sess175 rulings) so replay APPLIES victim txns. This raises #1's urgency: it now blocks BOTH corruption-free replay AND basic post-crash availability.

## Rig state for next session
- 32/32 nodes: mpatha present, /src mounted, module UNLOADED everywhere (test1 tore down after abort). SCST healthy.
- Platter STILL aged+dirty (nothing published, nothing zeroed — gate held). Re-running prep_node.sh on test1 reproduces the refusal in ~4.5 min (fence ladder ~60s + 31 slices × ~6s × 4 rounds; NB most of the 4m32s is replay-round serialization).
- The #18 repro (sess251 plan) now requires mkfs first: `./run.sh 32 caw rsync_paired` after prep_cluster (or just let run.sh prep do it). Aged-platter angle is exhausted — its wedge state is fully archived (sess249 slotdump + sess252 dmesg).

## Next step options (in ledger order)
1. #1 tokenization plan-of-record (sess175 rulings ccloop-c7ee71c6-sess175-GPT-ruling-*): now demonstrably load-bearing for availability, not just correctness.
2. #18 live repro on fresh fs with dmesg capture (scripts/collect_incident_dmesg.sh) + P12-HOLDERTASK stacks — rig is hot, one prep_cluster away.
