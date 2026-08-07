---
name: ccloop-c7ee71c6-sess153-p248-RULING-and-edit-plan
description: sess153: P248 RULE-5 ruling received (A approved+tripwires, B scoped to release_all -ESHUTDOWN retry x1). Exact edit list; dlm_caw.h fields LANDED.
metadata:
  type: project
---

# sess153 — P248 (D-RELEASEALL-LREQ-RETIRE-MISSING) GPT ruling + implementation plan for 0.11.455

## RULE-5 consult DONE (gpt-5.6-sol, sess153 transcript, task k798fvv3c). Ruling digest
- **A approved**: retire tenure in `caw_owed_release` under lreq_lock, condition `attempted && !pending && ctx->ops_closed && ctx->release_all_done`, BEFORE lreq_oq_sync/lreq_gc. Explicit disposition required (attempted excludes deadline handback; !pending excludes requeues). Do NOT require drain_armed (mid-sweep worker can complete after release_all_done, before phase 5).
- **Tripwires fail CLOSED** (keep tenure → P248 report is the evidence; never warn-and-proceed): (1) `e->attempts != 0` → refuse; (2) context-wide publication generation `ctx->lreq_finish_gen != ctx->stop_finish_gen` → refuse. Global gen beats entry pub_seq (catches illicit publication on ANY entry, incl. between release_all and claim). No pub_seq anchor needed (phases 2+3 join all publishers pre-release_all — phase 3 joins BAST threads precisely because releases publish; snapshot must be in phase 4 right before caw_release_all_body, NOT at phase-2 exit).
- **B approved, scoped**: release_all body loop ONLY. KEY CATCH: observed UA reaches body as **-ESHUTDOWN** (caw_slot's !running check swallows the original errno at attempt 1). So B = on CAS rc==-ESHUTDOWN, allow ONE extra iteration per slot (io_retry cap 1, no sleep; iteration re-reads slot which eats pending UA, then fresh CAS attempt-0 does real I/O). Conflation with semantic -ESHUTDOWN acceptable at bound 1 (dying queue fails fast). Do NOT touch caw_slot global behavior (phase-2 quiesce fast-abort + dead-LUN unmount budget).
- **Verification requires POSITIVE observation + deterministic injection**: zero-P248 fleet runs insufficient (B may eliminate natural owed traffic). Need retire counter+P-line, and 6 deterministic tests: (1) forced RA CAS fail ×2 → owed → drain discharge → retire fires, no P248; (2) drain resolve -ENOENT terminal → retire; (3) drain budget ~0 → attempted=false handback → NO retire, P254, leak stands, departure refused; (4) drain transient fail → requeue → retire only on later terminal completion; (5) mid-run owed completion (release_all_done=false) → NO retire; (6) pubfreeze gen bump → tripwire refuses, fail closed. Then fleet: ≥3× 32-node prep_cluster cycles, zero P248 agg+ENT, kept=0, P253/255/257-262 deltas zero, 32/32 clean departures, ioretry counter consistent with one-shot.

## Edit list for 0.11.455 (LANDED: only #1)
1. **DONE** dlm/dlm_caw.h ctx (after lreq_rel_kept): lreq_finish_gen, stop_finish_gen, lreq_teardown_retired, lreq_rel_ioretry (+block comment).
2. dlm_caw.c kernel section (~line 70, after mxfs_caw_gen_verify): 5 module params, default 0: caw_inject_ra_casfail (K1), caw_inject_owed_enoent (K2), caw_inject_dow_casfail (K5), caw_inject_pubfreeze_bump (K4), caw_drain_budget_ms (K3, semi-op override). Plus `static inline bool caw_inject_take(int *knob)` (dec-and-true if >0). User-mode #else (~line 391): `#define caw_inject_take(k) (false)` and `#define mxfs_caw_drain_budget_ms 0` (do NOT define the inject symbols — macro drops args).
3. lreq_finish publication branch (line ~4614, after `e->pub_seq++;`): `ctx->lreq_finish_gen++;`.
4. stop() phase 4 (~12075, before caw_release_all_body in `if (release_now)`): snapshot `ctx->stop_finish_gen = ctx->lreq_finish_gen` under lreq_lock (fallback unlocked if !lreq_lock).
5. caw_owed_release (~4160, between `resource = e->resource;` and `if (pending && !attempted)`): fix A block — condition above; tripwire branch prints **P266-RETIRE-REFUSED** (pr_err_ratelimited, type/id/attempts/gen pair); else scan tenure[], if any nonzero: `ctx->lreq_teardown_retired++`, print **P263-OWED-TEARDOWN-RETIRE** (pr_warn_ratelimited; type/id/tenure 6-tuple/pub_seq), memset tenure. NO WARN_ON (file builds user-mode; none available in dlm/).
6. release_all body (~9893): K1 inject before CAS (`if (caw_inject_take(&mxfs_caw_inject_ra_casfail)) rc = -ESHUTDOWN; else rc = caw_slot(...)`); B after `if (rc==0) cleared=true;`: `if (rc == -ESHUTDOWN && io_retry < 1) { io_retry++; ctx->lreq_rel_ioretry++; continue; }` before `if (rc != -EAGAIN) break;`. `int io_retry = 0;` in per-slot locals (pub_seq0 block ~9823). Body end (after P257 else): if lreq_rel_ioretry print **P268-RELEASEALL-IORETRY n=** (pr_warn).
7. caw_owed_dispatch (~4038, after caw_owed_resolve): `if (rc == 0 && caw_inject_take(&mxfs_caw_inject_owed_enoent)) rc = -ENOENT;`.
8. caw_drop_own_waiter CAS site (line 3813): K5 `if (caw_inject_take(&mxfs_caw_inject_dow_casfail)) rc = -EIO; else rc = caw_slot(...)` (committed=true via caw_may_have_written(-EIO) is the conservative direction — fine).
9. caw_owed_worker_fn drain section (~4508-4560): K4 after drain_armed wait (inside if(lreq_lock) guard): inject_take → lock, lreq_finish_gen++, unlock. K3: `budget_ms = mxfs_caw_drain_budget_ms > 0 ? ... : MXFS_CAW_OWED_DRAIN_MS`, use in deadline AND P254 print. After P254 block: if lreq_teardown_retired print **P267-RETIRE-SUM node= retired=** (pr_warn — the positive observation).
10. VERSION → 0.11.455 (patch rev; do NOT touch Makefile).
11. After build: dlm/dlm_caw.md + .claude/awareness/subsystems/dlm.md updates.

## P-tag allocation (P264/P265 TAKEN by BASTQ): P263 retire event, P266 tripwire refused, P267 retire summary, P268 RA ioretry summary.

## Verified code facts (this session, don't re-derive)
- caw_release_all_body callers: stop() phase 4 (line 12076) + mxfs_dlm_caw_release_all → dlm/mount.c:2731 (pre-stop path, ops_closed=false there → retire condition can't fire; stop() election resets release_all_done=false before phase 4). `ops_closed && release_all_done` co-hold ⟺ stop() phase ≥4-end. Both written under lreq_lock.
- pub_seq++ single site = lreq_finish line 4614 (tenure publication branch, under lreq_lock).
- caw_owed_release already has `bool attempted` param; early-return `!mask&&!w&&!wx` in dispatch returns true (attempted) — at teardown unreachable (no other discharger), and retiring there would still be correct (obligation gone).
- Constants: MXFS_CAW_IO_MAX_RETRIES=5, backoff 10→200ms; MXFS_CAW_OWED_DRAIN_MS=2000 (dlm_caw.h:1109, used dlm_caw.c:4516+4553).
- P248 destroy report: ENT dump line ~12348 (cap 8), aggregate ~12381 (prints only when leaked>0 — census semantics unchanged).
- No WARN_ON anywhere in dlm/ or compat/; pr_warn_ratelimited/pr_err_ratelimited used unconditionally (compat covers user-mode).

## Test plan after build+deploy
- Deterministic set on test1(+test2 for case 5) via knobs, script **tests/p248_inject.sh** (to write; RULE 3). Cases 1-6 above; case 5 needs 2-node contention (dir workload) + K5 mid-run.
- Then fleet: 3× `./run.sh 32 caw prep_cluster` + census (ONE dmesg pass + awk multi-pattern — census_p.sh per-pattern greps time out at 32-way, sess152 gotcha).
- Clyde host: ps/pgrep may hang (2 D-state ext4 mounts since Aug 5, NOT MXFS) — scan /proc/[0-9]*/stat instead.
