---
name: sess31-mht800-mitigation-passes-but-wedges-under-load
description: sess31: inode_mht_ms=800 passes dir_reuse 8/tcp 3/3 short runs but WEDGES bast_work_fn under sustained 8-node load (runs 3-5). Not a reliable fix; tu…
metadata:
  type: project
---

## sess31 — mht mitigation explored and ruled out as the answer

### inode_mht_ms=800 (node-format dir min-hold-time; default 300)
Hypothesis: longer EX hold batches more adds per tenure → fewer handoffs → smaller stale-base async-destage TOCTOU window [[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]].
Result: dir_reuse 8/tcp (8 rounds) PASSED 3 consecutive short runs (wall 113s, then 2 more) — promising. BUT runs 4-5 in the same mount WEDGED: test4 `mxfs_dlm_bast_work_fn` stuck in stack traces, test4 dropped its mount → subsequent prep aborts. So a longer hold defers peers' BASTs enough that the bast drain wedges under sustained 8-node contention.

### Verdict
mht=800 trades the dir loss for a BAST-drain wedge — NOT reliable. And mht tuning is probabilistic (shrinks the window, doesn't close it), so it can never give the criteria's 100%. tcp_dlm_scaling uses SHORTFORM dirs (dir_sf_mht_ms=100, separate) so it wouldn't regress from this, but the wedge kills it anyway. A moderate value (400-500) might reduce the loss rate without wedging, but still can't reach 100%.

### Conclusion for the residual
The ONLY reliable fix is architectural: stop the async xfsaild destage of a stale multi-node dir DATA block (write dir DATA blocks synchronously at EX release with full in-AIL drain, OR defer the destage to a transaction-context worker that re-applies our delta onto the fresh disk base). See [[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]] for the full design options. Default config (inode_mht_ms=300) restored; cluster rebooted clean.
</body>
