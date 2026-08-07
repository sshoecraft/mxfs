---
name: ccloop-c7ee71c6-sess130-MEASURED-bastq-fix-valve-gone-pace-still-open
description: sess130: BAST-queue fix VERIFIED (valve firings 0/567, tail waits 172->0, crash_consistency 5/5) but create pace still 24x in N — new root is mount-g…
metadata:
  type: project
tags: [bast-dispatch-queue, create-pace, crash-consistency, rule6, measurement, gpt-review]
---

# sess130 — what the BAST dispatch queue actually fixed, and what it did not

Build 0.11.453 / `F20024E38213A9E64DB6718`, fleet-confirmed on all 32 nodes.
All measurements on a VIRGIN fs at console loglevel 1 (see
`ccloop-c7ee71c6-sess130-CONFOUND-dmesg-n-8-console-fails-pace-criteria`).

## FIXED AND MEASURED — the yield-ticket convoy is gone

| discriminator | sess126 (0.11.452) | sess130 (0.11.453) |
|---|---|---|
| UDP RcvbufErrors delta / run | 8085 | **0** (614,803 datagrams, 32/32 nodes) |
| P204-YT-DEFER ticket age p50 | 2873 ms | **10 ms** |
| ... p90 / max | 4588 / 4994 ms | **69 / 283 ms** |
| defers within 500 ms of the 5 s valve | dominant | **0 of 567 (0.0%)** |
| P139-TAILCENSUS (waits > 800 ms) | n=172 | **NONE cluster-wide** |
| ino-128 grant waits > 5 ms | 202, mean 3533 ms, sum 713,681 ms | 8, mean 62.8 ms, sum **502 ms** |
| crash_consistency, virgin fs | FAIL 0/32 90s/90s 3/3 | **PASS 32/32 5/5** (79,79,77,79,82 s) |

Yield tickets are now retired by holders RELEASING, not by the
`MXFS_CAW_YIELD_TIMEOUT_MS` valve. That was the sess126 pathology and it is gone.

Queue conservation closes exactly (GPT demanded this):
`submitted 232310 = new 210078 + merged 8317 + rearmed 13915`;
`dispatched 220373 = new 210078 + 10295 requeues` (13915 rearm *submissions*
collapse to 10295 requeues); `overflow=0 inline=0 hiwater=1`.
Coalescing is only **1.05x** — merging carries ~5% of the load. The fix works by
DECOUPLING the socket drain from the synchronous shared-LUN read, not by
deduplicating hints. Do not tune the coalescing table expecting it to matter.

One bar item NOT formally met: ino-128 mean grant wait 62.8 ms vs a stated
`<50 ms` (n=8). The summed wall fell 1422x, so this is a small-sample technicality,
but it is over the line and should be stated as such.

## NOT FIXED — and the headline was wrong

`tests/create_scale_curve.sh 8 caw`, per-create mean ms by participants
[1,2,4,8,16,32] on 0.11.453:

    PRIVATE  4.2  10.9   5.9  19.8  35.2 100.3     (was 5.2 9.2 10.8 26.0 71.7 191.8)
    SHARED   3.6  10.2  24.1  35.8  80.7 162.5

- SHARED-vs-PRIVATE at 32 nodes is now **1.62x**, not the ledger's headline **42x**.
  The shared-dirent term has largely collapsed.
- But PRIVATE still degrades **24x** from 1 to 32 participants. The defect summary's
  "per-node private directories, which scale flat" is **FALSE** on this build.
- Grant waits are no longer where the wall is: 19 waits >5 ms cluster-wide totalling
  2026 ms, against a 79 s run. **The next root is NOT the CAW inode lock.**
  Candidates: AG-DLM inode allocation, log/journal serialisation, CAW transport
  bandwidth. Re-run `tests/cc_stackprof.sh` FOCUS at loglevel 1 and re-rank — that
  is the one outstanding PASS-bar measurement.

## GPT RULE-5 review (done sess130) — code hazards still to close

1. **UAF on teardown timeout.** `caw_bastq_join_workers()` uses
   `caw_join_bounded()` with an escalation deadline, then the caller runs
   `caw_bastq_free()`. A dispatcher still inside `ctx->bast_cb` or in
   `cond_timedwait` when the bound expires means freeing the queue is a UAF (PAL
   cond destroy is a bare `kfree`, `pal/linux/kern.c:1943`). "Timed out, log, then
   free" is not acceptable. **Audit `caw_join_bounded`'s timeout branch.**
2. **`ctx->running` is cleared before the producers are joined**, so a producer can
   submit into a queue whose dispatchers already exited — that last hint is lost
   with no backstop. Needs separate producers-stop / admission-closed /
   dispatchers-stop states.
3. **Recursive-PR self-deadlock** to disprove: a node holding PR that requests PR
   again while a foreign EX ticket exists must not block on the ticket. The
   `node_held_mode(...) == MXFS_LOCK_NL` guard at `dlm_caw.c:5665` looks like it
   covers this — prove it.
4. `MXFS_CAW_BASTQ_FASTPOLL_MS` 2000 is a fixed post-overflow window; draining 2048
   entries through 2 workers can take longer. Should hold FAST until depth falls
   below a low-water mark. (latent — overflow=0 so far)
5. Wants a **same-build forced-inline A/B** before crediting the queue, and a
   shutdown test under a deliberately blocked callback.

## Tree changes this session (no C code changed, so no rebuild needed)
- `tests/quiet_console.sh` (new) — `$QUIET_CONSOLE`, re-asserts `printk='1 4 1 1'`.
- `tests/cc_grantwait.sh` — new `mark` mode (no instr); `dmesg -n 8` removed from
  `mark` and `arm`.
- `tests/cc_bastcensus.sh` — `dmesg -n 8` removed from `mark`.
- `tests/cc_yieldcensus.sh` (new) — P204-YT-DEFER + P139-TAILCENSUS census;
  `MXFS_YC_MARK` env reuses another harness's boundary.
- `tests/criteria/OPEN_DEFECTS.json` — both entries updated with all of the above.
