---
name: ccloop-c7ee71c6-sess32-relbar-281-both-arms-hot-dir-defer-shape
description: 0.11.281: enforcement on BOTH unlock arms (helper mxfs_relbar_close_or_defer); board green; 119/70950 defers ALL ino=131 anchored — the hot-dir repea…
metadata:
  type: project
---

# sess32 addendum — 0.11.281 (8C32B2A02C5793950CF7D4A), both arms enforced

- Refactor: the anchored inline enforce block became
  `mxfs_relbar_close_or_defer(ip, arm)` (defined right above
  mxfs_dlm_bast_process, after the relbar dump ops); the NOANCHOR
  unconditional-unlock path now calls it too (`else if` before its unlock
  branch → `stranded = true` defer). P228 print carries arm=.
- Board on 0.11.281 (enforce default ON): cache 27s, crash 76s, dir_reuse
  104s, dirent_durability 65s — all PASS 32/32, walls unchanged.
- Totals across the board: unlocks=70950 obligation=0 closed=3
  **deferred=119 (0.17%)** — ALL 119 on arm=anchored, ALL ino=131 (one hot
  shared dir; plus 3× ino=150 earlier), all isdir=1. noanchor arm: 0 events.
- INTERPRETATION: the hot-dir repeated-defer shape is exactly GPT's predicted
  cost of the MISSING ADMISSION INTERLOCK — under continuous commits the
  ledger is perpetually ~+1 at the check instant, so the release defers a
  BAST cycle at a time until a lull. SAFE (an open grant is never handed
  away; criteria walls unchanged) but the peer's acquire pays the defer
  latency. The next increment is the interlock: RELFLUSH as a real admission
  gate (block new protected mutations during the closing drain, wait
  admitted ones out, snapshot, close, unlock) — see the GPT design in
  ccloop-c7ee71c6-sess32-RELBAR-ledger-numerator-and-GPT-fix-design.
- closed=3: the in-place durable passes do close some windows; the defer does
  the protective work for the rest.
