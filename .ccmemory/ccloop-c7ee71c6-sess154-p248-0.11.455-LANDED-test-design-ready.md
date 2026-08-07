---
name: ccloop-c7ee71c6-sess154-p248-0.11.455-LANDED-test-design-ready
description: sess154: P248 fix 0.11.455 FULLY LANDED+builds (srcversion A559A52088F7FC1BF400138). p248_inject.sh design finalized incl case-5 analysis. NOT deploy…
metadata:
  type: project
---

# sess154 — 0.11.455 landed; tests/p248_inject.sh designed, NOT yet written

## LANDED (all sess153 edit-list items 2-10 + VERSION). Builds clean: kernel (no new warnings) + tools. srcversion **A559A52088F7FC1BF400138**. NOT deployed to any node. No docs yet (item 11 pending: dlm/dlm_caw.md + awareness dlm.md; pal awareness also flagged stale at session start).
- Params + `caw_inject_take` (consumable dec-and-true) after caw_epoch_free_reset (~dlm_caw.c:380): caw_inject_ra_casfail K1, caw_inject_owed_enoent K2, caw_inject_dow_casfail K5, caw_inject_pubfreeze_bump K4, caw_drain_budget_ms K3. User-mode #else: `caw_inject_take(k) (false)` + `mxfs_caw_drain_budget_ms 0`.
- lreq_finish: `ctx->lreq_finish_gen++` after `e->pub_seq++`. stop() phase 4: stop_finish_gen snapshot under lreq_lock immediately before caw_release_all_body (release_now arm only).
- caw_owed_release: fix A block between `resource = e->resource;` and `if (pending && !attempted)`. Condition `attempted && !pending && ctx->ops_closed && ctx->release_all_done`; tripwires (attempts!=0 || gen mismatch) → P266-RETIRE-REFUSED pr_err_ratelimited, else tenure scan → P263-OWED-TEARDOWN-RETIRE + lreq_teardown_retired++ + memset tenure. Prints UNDER lreq_lock (teardown-only frequency, deliberate).
- release_all body: `int io_retry` local w/ comment; K1 inject before CAS; B retry `rc==-ESHUTDOWN && io_retry<1 → io_retry++, ctx->lreq_rel_ioretry++, continue` before the `!= -EAGAIN` break; P268-RELEASEALL-IORETRY (cumulative) after P257 else.
- dispatch: K2 after caw_owed_resolve (`rc==0 && take → -ENOENT`). drop_own_waiter CAS: K5 → -EIO. Worker: budget_ms fn-scope var (K3, `>0 ? knob : MXFS_CAW_OWED_DRAIN_MS`) used in deadline+P254; K4 bump inside the drain_armed wait's lock section; P267-RETIRE-SUM after P254 block.

## Verified this session (do NOT re-derive)
- **untrack-on-proof holds everywhere mid-run**: unlock 8586 (CAS committed) / 8193 (bit already absent) / force-rel 9415+9446 (absent/committed) / 7058 (rc==0 only). ONLY unconditional untrack = release_all 10129 (fix A's target). ⇒ a mid-run worker discharge leaves the resource TRACKED; teardown release_all revisits → lreq_release_all retires tenure normally → case 5 may assert NO P248.
- Owed constants (dlm_caw.h:1119-28): BACKOFF_MS=4 (first-fail 4<<1=8ms — case-4 second pass fits 2000ms budget), MAX=500, ESCALATE=32, DRAIN_MS=2000, STEP=20.
- Node mechanics: knobs at /sys/module/mxfs/parameters/caw_inject_* (0644). prep_node.sh copies NFS /src/mxfs/mxfs.ko → /root/mxfs.ko.prep, insmods LOCAL copy (md5-guarded vs NFS staleness); mount -t mxfs $MXFS_DEV /mnt/shared; dmesg → /root/dmesg.stream via setsid. run.sh prep_cluster passes MXFS_DEV + KO_MD5. SSH: `tools/mxfs_sshpass.sh <node> <passfile> <cmd>` (3-arg; passfile via tools/mxfs_secrets.sh passfile).
- Knobs PERSIST across umount/mount (rmmod only between preps) — test must zero ALL 5 after every case.

## tests/p248_inject.sh design (write next session; RULE 3, RULE 2b — mktemp -d, no rm-glob)
Prep once: `MXFS_FORCE_PREP=1 timeout 580 ./run.sh 2 caw prep_cluster`; test1 departs/remounts per case (plain `mount -t mxfs` — module stays loaded), test2 anchors. Delimit windows with `echo 'P248TEST caseN <phase>' > /dev/kmsg` on the node; census = ONE dmesg/stream pass with awk multi-pattern (sess152: per-pattern greps time out). Per case: fresh subdir workload on test1 (~20 creates + sync) so tenure exists; arm knobs; umount test1; assert on window.
- **c1** K1=2: expect P257-RESIDUE owed>=1, P263>=1, P267 retired>=1, P268 n=1; NO P248/P266/P254. (K1=2 kills attempt+retry on FIRST slot only → owed → drain discharge → retire.)
- **c4** K1=2,K5=1: transient -EIO discharge → requeue → 2nd pass real → P263+P267; NO P248/P254.
- **c6** K1=2,K4=1: gen bump post-freeze → P266>=1 + P248 leaked>=1; NO P263. LUN left CLEAN (discharge succeeded).
- **c5** (2-node churn, K5=1 armed mid-run — NOT K2: the -ENOENT lie erases a live obligation; K5's -EIO merely delays a genuine discharge): teardown_leak_repro-style hot-shared-dir create/rm churn both nodes ~45s; arm at t~10s; non-vacuity = knob readback 0 (consumed ⇒ a mid-run dispatch completed); assert ZERO P263/P266 during run window both nodes; clean unmount both; NO P248. If unconsumed, extend churn (≤3 rounds) — mid-run owed needs a natural in-line clear failure (CAS contention), scarcer at 2 nodes than sess152's 32.
- then re-prep → **c3** K1=2, drain_budget_ms=1: P254 left>=1 + P248 leaked>=1; NO P263/P267; departure refused (grep exact verdict line at dlm_caw.c ~12409 first); reset budget to 0. LUN DIRTY after.
- re-prep → **c2** K1=2,K2=1: terminal -ENOENT retract → P263+P267, NO P248. LUN DIRTY after (bits remain; obligation erased by the lie) — LAST case; fleet prep re-mkfs anyway.
- Before writing assertions: grep dlm_caw.c for exact P248 ENT/aggregate print text (~12348/12381 pre-sess154 numbering; shifted ~+150 now).

## Remaining bar (sess153 ruling): after deterministic 6 → 3× `./run.sh 32 caw prep_cluster` + fleet census: zero P248 agg+ENT, kept=0, P253/255/257-262 deltas zero, 32/32 clean departures, P268 consistent w/ one-shot. Then ledger disposition, docs, memory compaction (193 unfolded, overdue).
## Clyde: ps/pgrep may hang (2 D-state ext4 mounts, NOT MXFS) — scan /proc/[0-9]*/stat.
