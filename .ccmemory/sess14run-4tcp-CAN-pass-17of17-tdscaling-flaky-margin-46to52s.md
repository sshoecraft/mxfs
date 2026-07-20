---
name: sess14run-4tcp-CAN-pass-17of17-tdscaling-flaky-margin-46to52s
description: sess14(ccloop) 4/tcp FULL suite = 17/17 PASS achieved (build 70F91E1B). tcp_dlm_scaling FLAKY at 60s margin: elapsed ~46-52s typical (one node ~17s),…
metadata:
  type: project
---

## sess14 (ccloop) — 4/tcp reaches 17/17, tcp_dlm_scaling is the flaky margin

Full `./run.sh 4 tcp` (defaults, build 70F91E1B) run 2 = **17/17 PASS** (clean cluster). tcp_dlm_scaling elapsed this run: rank1=52.6s, rank2=17.3s, rank3=52.2s, rank4=46.1s — all <60s. A PRIOR full run had tcp_dlm_scaling 2/4 (2 nodes >60s). So tcp_dlm_scaling is FLAKY right at the 60s window: typical ~46-52s for the slow nodes, one node always finishes fast (~17s, DLM unfairness), and in-suite (after soak) it sometimes tips 2 nodes over 60s.

### Criterion status (1/2/4/8 tcp FULL suite 100%)
- 1/tcp 16/16 ✅, 2/tcp 17/17 ✅ (RELIABLE).
- 4/tcp: CAN be 17/17 but NOT reliable — tcp_dlm_scaling margin. To make reliable, cut the dir-EX handoff latency (~46-52s for 150 rounds × 3 ops × 4-way contention; per-release Invariant-#1 drain at xfs_mxfs_dlm.c ~5788-5818 is the cost; FUA is NOT — gated same speed). Need ~30s to have comfortable margin.
- 8/tcp: far off — DABUF_MAP_HOLE shutdowns (create/lookup paths, reload trylock-bail) + empty-content reg-file coherency. Separate big effort.

### INFRA REMINDER
A failed/killed run leaves nodes mounted → next `./run.sh` prep_fs mkfs hits "device busy". ALWAYS clean first: `for n in test1..testN; do ssh $n 'umount /mnt/shared; sleep 0.3; rmmod mxfs'; done`.

Build 70F91E1B deployed (run.sh prep redeploys /src/mxfs/mxfs.ko). Criterion NOT met. See [[sess14run-HANDOFF-final-1and2tcp-100pct-4tcp-16of17-8tcp-needs-hole-and-content-work]].
