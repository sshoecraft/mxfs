<!-- sess435 RULE-5 ruling D-0359 (CAW-less device lone mount): option (a) as a separate non-joinable SNLOCAL_EXCLUSIVE authority mode; (b) R/V/W for all… -->
# D-0359 ruling (gpt-5.6-sol, sess435)

**Choose (a) with two qualifications:** SNLOCAL_EXCLUSIVE is a SEPARATE authority mode (not a weaker CAW grant), and a single FUA write is NOT a crash-durable authority record (torn-write stop-ship). (b) read/verify/write for all mounts REJECTED: not a CAS under contention → two initiators can both grant the same epoch. (c) unnecessary.

Transport rule: disk/CAW DLM requires a successful OPERATIONAL CAW probe; TCP per its own rules (never uses the non-CAW slot fallback); SNLOCAL_EXCLUSIVE only with single_node_exclusive=1 and only as a non-joinable single-initiator domain.

## Invariants
- I1 no ordinary clustered grant without atomic exclusion; a non-CAW R/V/W must never produce a token mistakable for a CAW-proven grant.
- I2 grant-before-image: nonzero incarnation+epoch selected, authority record durably committed, mode durably identified (CAW_GLOBAL / TCP_GLOBAL / SNLOCAL_EXCLUSIVE) BEFORE any token-bearing image commits. No epoch 0.
- I3 authority mode bound into token validation (fs id, resource, writer slice, incarnation, epoch, MODE, format, checksum); if no mode field, a disjoint feature-bitted namespace.
- I4 SNLOCAL_EXCLUSIVE not joinable (no disk-DLM join, no TCP/CAW conversion while live or dirty; foreign replay must not treat its tokens as globally proven). Transition only after recovery + drain + re-incarnation.
- I5 invalid/torn/contradictory authority records fail closed.

False assertion: cannot be made safe; still REFUSE on positive contrary evidence (live foreign HB, incompatible PR holder/reservation, joinable cluster record, dirty non-snlocal foreign slice, different live snlocal owner). Exclusive PR if available = defense in depth.

Migration to CAW SAN: acceptance matrix — dirty SNLOCAL slice + ordinary clustered mount → refuse/quarantine; explicitly authorized exclusive recovery → validate under snlocal rules, replay, clean, reinit slots under CAW, mint fresh global incarnation.

**Stop-ship torn writes:** need atomic-sector guarantee documented+enforced, OR alternating redundant copies with generation+checksum, OR a separate redundant snlocal grant ledger the replayer can use.

## Admission probe
Real operational CAW on an MXFS-reserved probe sector via the same PAL path: read/validate, CAW with matching compare that advances a gen/nonce, verify readback, then a deliberately mismatching CAW must miscompare and not install. Check alignment, transfer length, block size, FUA semantics. Classify: definitive unsupported (-EOPNOTSUPP/ILLEGAL REQUEST) → fallback allowed; transient/ambiguous → fail this admission (no silent non-CAW classification); semantic violation → hard refusal, path unsuitable. NO runtime downgrade: probe OK then runtime CAW unsupported → stop token-bearing metadata, withdraw/fence. Multipath: every CAW-eligible path verified or failover to a non-capable path fatal. Do not print 'DLM initialized (CAW' before the probe succeeds.

## Interactions
- snlocal marker = authority provenance: stamped before any token-bearing image, bound to incarnation+slice+mode+format, preserved across dirty shutdown, cleared only after replay+cleanup; clustered mount may not ignore/overwrite a dirty marker.
- purge_cas_zero stays fail-closed; lone dirty remount must use owner-local recovery (no foreign publication) or a separately named exclusive-only publication op. If the current lone-remount path inevitably calls foreign publication, (a) is incomplete.
- Lone dirty remount barrier: admitted as SNLOCAL, no cluster evidence, prior incarnation+marker validated, withdrawn slot reclaimed via the non-CAW durable path (not the CAW fn failing 6x), slots valid/reconstructed, replay with matching SNLOCAL tokens only, cleanup durable, new incarnation minted before writes.

## Exact refusal conditions (disk-DLM mount)
probe fails && !single_node_exclusive (unless deliberate TCP); joining a CAW cluster with a failed probe; snx set but positive foreign evidence; dirty foreign/non-snlocal slice on CAW-less target; dirty snlocal slice without explicit authorization; marker/incarnation/token/records disagree; torn authority records without redundancy; format cannot distinguish SNLOCAL tokens; grant-before-image not guaranteed; CAW intermittent/semantically wrong; snlocal→CAW/TCP transition before clean+new incarnation.

## Verification arms (24) before closing D-0359
1 loop no param: no false CAW msg, refused (or deliberate TCP), no metadata write before refusal. 2 loop + snx=1: mount reported SNLOCAL_EXCLUSIVE; mkdir/rename/unlink/fsync/umount; all images nonzero epoch + local provenance. 3 clean remount incarnation monotonic. 4 fsync+kill+exclusive remount: slot reclaimed, barrier closed until replay, metadata survives, no epoch 0. 5 crash at each ordering point (before/during authority write, after authority before image, after image before commit, after commit, during cleanup). 6 torn-write injection on every non-CAW authority update → redundant record recovered or fail closed. 7 dirty snlocal image moved to CAW target: clustered mount refuses; authorized recovery replays; fresh incarnation; stale local tokens rejected. 8 corrupt/mix marker, mode, incarnation, epoch, resource, checksum independently → fail closed. 9 no CAW validator accepts a non-CAW token. 10 live foreign HB / conflicting PR with snx set → refuse. 11 second join while SNLOCAL live/dirty → refuse. 12 simultaneous-start race documented (not proof). 13 probe + mismatch semantics on real LUN. 14 -EOPNOTSUPP selects fallback. 15 success-with-wrong-data / mismatch-that-writes hard fail. 16 timeout/reset during probe fails admission. 17 probe OK then runtime unsupported → withdraw, no downgrade, no further token commits. 18 multipath failover to non-CAW path rejected/withdrawal. 19 dirty own snlocal slice on loop remounts without foreign purge_cas_zero. 20 dirty foreign slice on non-CAW fails closed. 21 CAW cluster + non-CAW joiner refuses (no TCP split). 22 TCP cluster stays TCP. 23 CAW→TCP formation fallback + dirty-recovery refusal. 24 full vergate on loop in the intended mode + 32-node CAW board + foreign-replay suite.
