---
name: sess24-gpt5.5-dlm-fairness-and-demand-reread-design
description: sess24 GPT-5.5 design for 8/tcp dir_reuse: fix PR-reader starvation via persistent waiters + REAFFIRM fairness barrier + local revoke_pending + no-sh…
metadata:
  type: project
---

## sess24 GPT-5.5 consult — the converging design for 8/tcp dir_reuse

Builds on [[sess24-BREAKTHROUGH-storage-coherent-datablock-reread-safe-residual-dlm-starvation]]. GPT confirmed: TWO separate bugs — (1) DLM fairness isn't real (retries lose queue position + REAFFIRM bypasses fairness); (2) dir coherency is too coarse (leaf_only=0 rereads EVERY stale data block per handoff = ~8.7s/handoff = ~10x over budget). Minimal correct patch series, in order:

### Patch 1 — Persistent idempotent waiters (master)
A timed-out remote retry must NOT remove+recreate the master WAITING entry (resets queued_at -> FIFO loss + absence window). Keep the entry continuously present; on retry refresh last_seen, PRESERVE queued_at. Remove ONLY on grant / explicit cancel / node death / unmount / resource destroy. (My sess24 queued_at-preserve was partial — the entry must STAY enqueued across the requester's wait-timeout, not be deleted then re-added.)

### Patch 2 — REAFFIRM must obey the fairness barrier (master) — THE KEY MISSING PIECE
Today a remote re-request of an already-held sufficient mode hits REAFFIRM: keeps GRANTED entry, bumps grant_gen, re-sends grant, fires BAST if waiters — but BYPASSES compat/queue, so an EX holder keeps its cached EX while a PR waiter starves. FIX: in REAFFIRM, if an incompatible waiter from another node exists -> mark holder `revoking`, send BAST, and reply "revoke-pending/wait" — do NOT bump grant_gen, do NOT issue a fresh successful grant. KEEP the GRANTED entry visible (prevents the double-grant the REAFFIRM was built to stop). Threshold ≈ 0 (strict): first incompatible waiter => block incompatible new+reaffirmed grants immediately.

### Patch 3 — Local BAST disables the cached fast-path (client)
On BAST set `lock->revoke_pending=1`. Local acquire fast-path: `if (cached_mode>=req && !revoke_pending) grant`; else block/go-to-master. So a node can't start a NEW dir critical section on cached EX after a BAST. Drain current users -> EX durability fence (log_force+iflush+blkdev_flush) -> RELEASE -> recompete. Without this the master fix is defeated by local cached-EX reuse.

### Patch 4 — Don't shutdown on DLM wait timeout (EASY, do FIRST)
rc=-110 (ETIMEDOUT) from a contended lock wait is NOT in-core corruption. Today it does xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE) at xfs_mxfs_dlm.c:12394 -> cluster cascade. Change to retry/refresh same request + keep waiting (optionally a large diagnostic deadman). This stops the cascade by itself.

### Patch 5 — Demand-driven data-block reread (fixes the 10x latency)
Keep dir_postread_reread=1 + leaf_only=1 (leaf/node/freeindex stale -> reread before use; cheap). Do NOT reread every stale DATA block in xfs_da_read_buf. Instead reread the SPECIFIC data block on demand at authoritative sites: before xfs_dir2_data_use_free / addname RMW / removename RMW / live<->stale dirent convert; before returning readdir entries from a stale block; before returning lookup positive/negative from a stale block; before using freeindex to choose a block. Add helper mxfs_dir_buf_ensure_current(dp,bp,ctx). CORRECTNESS HOLE to avoid: readers must NOT return stale results (a stale negative lookup after a peer create is wrong) — lazy reread OK, stale RESULTS not OK. So it's "reread before authoritative use", not "writers-only".

### Patch 6 — Bounded EX batching quantum (perf, after fairness correct)
Once EX, allow a bounded batch (e.g. max_ops=16 or max_ms=10) before release IF only EX waiters exist; but if a PR waiter is oldest, hard barrier immediately (drain current op, fence, release, grant PR). Cuts handoff/fence/reread count toward budget.

### (d) Bigger architecture (NOT now): dir delegation/combining (one node owns the hot dir, peers forward create intents) or hash/range-partitioned dir locking. Larger surgery; do the 6 patches first.

### Implementation note
process_remote_request REAFFIRM is at dlm/dlm.c ~2759-2856; fresh compat path + my (non-firing) FAIRGRANT at ~2936; local path check_compat ~1223. Shutdown-on-timeout at xfs/xfs_mxfs_dlm.c:12394. addname data read at xfs/libxfs/xfs_dir2_node.c:1959 (xfs_dir3_data_read) right before the use_free at xfs_dir2_data.c:1740. Build/test: reboot all 8 VMs CLEAN each trusted run (`virsh destroy+start test1..8`), then `./run.sh 8 tcp dir_reuse_coherency`.
</body>
