<!-- sess453 RULE-5 review -->
# sess453 RULE-5 review #3 — 0.59.2/0.59.3 (sv 9727DA88) — NO-GO

Prompt file: scratchpad review3_prompt.txt (88k chars; excerpts scsipr.c 406-737, disklock.c 800-1038 + 4375-4514, v5_mount.c 1676-1899 + 4440-4549 + 11360-11606, xfs_super.c 1458-1483 + 1700-1912 + 3780-3810, xfs_buf.c 2606-2640 + 6303-6335, kern.c knobs). GPT's line cites are excerpt-relative.

## Grades vs the sess451 STOP-SHIP #2 blockers
1. Absence proof coherent — PARTIAL: bracket A/RESV/B + gen check + discard-on-invalidation exist, but ABSENT is served from a snapshot up to 5 s old (`scsipr_answer` ABSENT_FRESH_MS) and hb_retire_settle publishes EMPTY from that cached answer with no re-validation adjacent to the CAS; detach abandons the scsipr ctx BEFORE the late unregister in put_super, so the unregister cannot invalidate the snapshot.
2. Clustered no-PR — PARTIAL: key0→UNKNOWN and gated self-clear done; but admission does not mechanically require REGISTER/READ KEYS/READ RESV/RESERVE/P&A, and `fence_capability_override` still authorises self-retirement (self_retire_ok).
3. OWN too broad — PARTIAL: enum OWN gone, exact tuple + full 64-slot enumeration done; but `mxfs_disklock_retire_settle_own` only checks proof != NULL (convention, not capability), departure mutex not asserted, proof-to-CAS window open, P305-RETIRE-MULTI only logs (duplicates not treated as conflicts).
4. HB starvation — MET (probe thread; monitor callback is a table read; sync bracket only on the mount thread).
5. Enforced freeze — UNMET: FROZEN only logs (P304-RETIRE-IO-AFTER-FREEZE) and still submits; check/use race between mxfs_departure_quiesced()==true and slot_release_commit; xfs_shutdown_devices' raw flush runs AFTER the release; inc/dec pairing of m_mxfs_buf_io_inflight not proven on all paths (partial-inode early return after the increment; underflow clamp hides corruption).
Minimum-for-GO: 1 PARTIAL, 2 PARTIAL, 3 PARTIAL, 4 MET, 5 UNMET, 6 MET (but CAW -EOPNOTSUPP → plain FUA write fallback in both settle paths defeats the exact-record protection), 7 PARTIAL (missing: clustered no-PR rejection, SIMULTANEOUS duplicate same-boot records, invalidation after unregister/preempt, P305-vs-peer CAS race both orderings, counter error paths, freeze/check/submit race).

## New hazards (ranked)
C1 stale ABSENT → EMPTY (5 s TTL; single-use ring limits reuse not staleness). C2 freeze/check/release TOCTOU. C3 buf-io counter leak/undercount corrupts every departure verdict. H4 detach/unregister outside snapshot-invalidation lifetime. H5 OWN proof is a string. H6 probe_stop joins unconditionally → unbounded teardown hang if a PR IN hangs. H7 probe_stop/probe_thread fields unsynchronised. H8 CAW fallback = unconditional overwrite. M9 ABSENT-use ring eviction can permit reuse; ABSENT consumed on return even if CAS never happens. M10 PRESENT 2 s / ABSENT 5 s asymmetry is the unsafe direction. M11 probe thread failure has no watchdog/restart (fail-closed but holds barriers). M12 dbg counters decremented non-atomically; knobs are 0644 in production.

## Conditions for GO (9)
1. No cached ABSENT for destructive settlement: single-use proof token validated adjacent to the EMPTY CAS; revoke on every local PR mutation, reservation loss/UA, detach, late unregister.
2. Close proof→CAS window (settlement API runs/consumes the bracket internally) or document + test the fencing invariant covering the residual interval.
3. Real departure I/O gate: reject/prevent mount-attributable I/O after FROZEN; drain+gate share synchronisation with the release publication.
4. Prove buf-io inc/dec pairing on every path; fault-injection tests returning the counter to zero exactly once.
5. All teardown I/O (incl. xfs_shutdown_devices flush) before the release point, or inside the quiescence protocol.
6. Mechanically prohibit clustered no-PR admission (all PR ops + nonzero key); fence_capability_override must not authorise clustered self-retirement.
7. P305-only OWN: assert departure mutex, opaque proof token, define duplicate same-boot records (independent or fatal).
8. Remove the -EOPNOTSUPP plain-write fallback in settlement CAW (fail closed).
9. Tests: clustered no-PR rejection; simultaneous duplicate same-boot records; invalidation after unregister/preempt/reservation loss; P305-vs-peer CAS race both orderings; counter error paths; freeze/check/submit race injection.

Rig note: probe knobs are reachable in production (0644); dbg_pr_read_keys_delay_ms is sticky and can hang admission.
