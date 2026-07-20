---
name: ccloop8ba7-sess7-printk-volume-is-a-perf-criterion
description: sess7: un-ratelimiting P56-CORESIDENT-DIR-SKIP (~75 lines/s/node in unlink storms) alone dropped dlm_scaling@32 below its 50 ops/s floor. Diagnostics…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7, rule0, printk]
---

# printk volume is a RULE-0 perf criterion (sess7 proof)

0.10.118 changed P56-CORESIDENT-DIR-SKIP from pr_warn_ratelimited to capped-20000 pr_warn for the iter_13/14 forensics. In the dlm_scaling create/unlink storm it fires on EVERY partial inode-cluster write that skips a dir slot → 17,964 lines/4min on test17 (~75/s/node, 42.7K total mxfs lines in the window). Effect: per-node op rate fell from ~50-66 to 44-52 ops/s → dlm_scaling@32 floor=50 FAILed (30/32, then 27/32). Reverting to ratelimited (0.10.120, srcver F2443A0C) restored PASS 32/32 @49s.

Rules going forward:
- Any print that can fire per-buffer-write / per-op in a storm MUST be pr_warn_ratelimited or gated (mxfs.instr/dirwr) — a 20000 cap is NOT protection (it resets every module reload and lasts ~4min of storm).
- Before recording criteria rows, sanity-check `journalctl -k | grep -c 'mxfs:'` volume in the test window; >~30/s/node means a probe is taxing the run.
- P146-RELDUR / P147-PREUNLOCK (per dir-inode DLM release) measured LOW volume in these workloads — safe as-is. P150-RDPRESERVE/RDRESTORE fire on rare clobber-risk reads only (0 in dlm_scaling, ~2/node in pm) — safe.
- Big pre-existing spammers in storms (not mine, present in passing runs): P25-INSTR ~17/min/node, P61-ADOPT-CHK, P19-B3DEC, P82-ADD, P140-RECLAIM-COMMIT, P2L-*. If future criteria runs sit at a floor edge, trimming these is the next margin lever.
