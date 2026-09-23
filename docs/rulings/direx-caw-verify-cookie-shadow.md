<!-- sess402 design-consult ruling D-400 term (c): the un-throttled dir-EX CAW verify (149 reads/100 iters) may be skipped only via a generation-cookie predicate… -->
# sess402 design-consult ruling — cheaper predicate for the un-throttled dir-EX CAW verify

Measured (0.23.16 per-site counters, test8, 100 tmpfile iterations, 5.2 ms/iter):
verify_site_direx_n 0->149, p108 0->1, s6 0->6, s7 0. The ~0.3 ms/op term (c) of
D-TMPFILE-CHURN-RULE0-PERF-400 is the sess8 (12e0d157) un-throttled dir-EX verify at
xfs_mxfs_dlm.c ~30071 (every idle dir-EX ilock cache hit with no holders/pins = one 512B
FUA slot read; self_created deliberately NOT skipped because the sess8 phantom came from
"our own demote racing a re-grant").

## Ruling (gpt-5.6-sol)
1. No purely local skip predicate is sound if another node may clear this node's holder
   bit without a reliably observed local event. A or C are sound only under the protocol
   invariant: while a node serves cached EX, its on-disk EX bit can disappear only through a
   locally serialized release/demote or a membership/fencing transition that stops it from
   serving. If survivor purge / lineage replacement / peer CAS can remove the bit while the
   node is live and unaware, only a fresh observation per serve (D) or acknowledged
   notification closes the hole.
2. A (virgin skip: self_created && never BASTed && no demote in flight && no recovery
   transition): misses lost BAST, survivor purge of a live node, external lineage change;
   "virgin" must be cleared at release START (not completion). Good benchmark optimization,
   not independently sound; the publish-skip predicate is not strong enough for
   lock-authority validation (different failure consequences). OK only as a subset of C.
3. B (1 s jittered throttle without the self_created skip): bounds latency, does NOT preserve
   mutual exclusion — the sess8 corruption was a sub-second window. REJECT as correctness
   mechanism.
4. C (verify only after a local release/demote or generation change) — RECOMMENDED in a
   strengthened GENERATION-COOKIE form: {grant_instance, relbar_generation,
   local_release_started_generation, membership/recovery incarnation, lineage/incarnation,
   observed peer-request/BAST generation}; the fast path may skip the read only while all
   components match the cookie validated at grant; a boolean release_attempted is too weak;
   on any cookie change prefer stop-serving+reacquire over verify-and-continue.
5. D (coalesce with the s6/s7 snapshot): safe cleanup (same read, no new holes) but one FUA
   per serve still misses the 0.14 ms ceiling.
6. Is the sess8 own-demote/re-grant phantom structurally excluded now? Only if ALL hold:
   release marked before any unlock can issue; no serve/re-grant crosses the release barrier;
   every unlock CAS conditional on the exact grant instance/epoch+lineage it releases; an
   older-epoch unlock cannot clear a newer holder; acquire/release ordering between barrier
   clear and fast-path admission; reclaim/retry/timeout/recovery cannot replay an old unlock
   after re-grant. Epoch bump + fast-path relbar check ALONE is not enough (old unlock I/O
   completing after a new grant). Invariant 1 is orthogonal.
7. Shadow program: implement C's skip decision but keep 100% of per-op verifies; for every
   read C would have skipped record inode, cached vs slot mode/epoch/lineage, grant-instance
   and relbar generations, release start/complete generations, BAST rx sequence,
   membership/recovery incarnation, purge/fence/rejoin state, would-demote; primary counter
   C_skip_would_find_not_EX (+ subcounters absent-holder / epoch-mismatch / lineage-mismatch
   / pending-peer-request); also verify_after_{local_release,BAST,membership_change,
   lineage_change}, stale_unlock_CAS_rejected, old_release_completed_after_new_grant.
   Exercise: 32-node rename storm, forced UDP BAST loss/reorder, delayed/reordered unlock
   completion, demote-then-immediate-regrant, crash + survivor purge, fence/rejoin during
   cached EX, lineage replacement, reclaim/reload. Acceptance: zero C_skip_would_find_not_EX
   incl. under deliberate old-release-after-new-grant schedules — supports deployment but
   does not replace the state-machine proof about unobservable external stripping.
8. Hard gate: prove peer CAS/purge cannot silently remove a live serving node's grant;
   otherwise keep per-serve validation or add acknowledged revocation/fencing.
