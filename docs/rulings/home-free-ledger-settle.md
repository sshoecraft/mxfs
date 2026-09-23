<!-- sess429 RULE-5 ruling: D-0351 0.38.3 regression (P55C-FREE-HOME leaves pub ledger open -> P237 evict shutdown) — settle by equivalence with predicate… -->
# sess429 — RULE-5 ruling: home-free FREE obligation settles the publication ledger by equivalence

## Measured (s432, 0.38.3, tests/evidence/sess429_s432_test1_dmesg.txt lines ~83970-84010)
test1 only, fio_perf prologue: `dd` creates ino 133, `rm` frees it (P128-INACT-DEFER pin=1 in_ail=1),
xfsaild flush hits the NEW 0.38.3 branch `P55C-FREE-HOME ino=133 gen=636730301 disk_gen=0` (chunk-init
image, mode 0) and discharges; flush_out's abandoned-publication chokepoint then marks `i_mxfs_pub_fenced=1`
(P383-HOME-VS-OWED pend=14 dur=0). The only consumer of pub_fenced is the deferred-RELEASE worker (BAST side);
an unlinked inode gets no BAST and goes straight to reclaim → `P237-EVICT-OBLIGATION pend=14 dur=0 nlink=0
imode=00` → force shutdown → P-SESSION-POISON. fio_perf's barrier then stalls all 32 nodes (0 MiB/s),
every later criterion pre-asserts. In 0.38.1 the same inode took FOREIGN, whose dead_incarn_gen poison
EXEMPTED P237 (masked, never satisfied) — that is why 0.38.1 passed fio_perf 32/32.

## GPT verdict (gpt-5.6-sol)
1. Settle-by-equivalence is SOUND iff: in-core mode 0 + nlink 0 + live committed FREE obligation
   (freeob==2, PUBOB); home dinode mode 0 (gen irrelevant); the ifree transaction is log-complete
   (inode item UNPINNED — xfs_iflush_cluster never flushes a pinned inode; worker checks explicitly);
   pending seq snapshot final (a freed inode takes no further change).
2. Generic in_ail is not proof; the unpinned-exact-item invariant is.
3. Recovery worker: same predicates, SETTLE-ONLY (no write/adopt/unlink-convert) — a peer may have
   allocated+freed the number in the lock gap; mode 0 now still proves the free image requirement.
4. P237's last-chance publish must NEVER write an ISTALE_CAW shell (could overwrite a peer/new incarnation).

## Landed (0.38.4 → built as 0.39.0 together with tauth view-record step 1)
- `mxfs_pubob_settle_home_free(mp, ip, site)` (xfs_mxfs_dlm.c, next to mxfs_pubob_discharge): predicates
  above, stamps fepoch/wmb/durable/flush exactly like the adopt discharge, clears pub_fenced;
  P55C-FREE-HOME-SETTLED / P55C-FREE-HOME-UNSETTLED (fail-closed: ledger left open).
- Called BEFORE the discharge at both home-free sites (xfs_inode.c P55C iflush; recovery worker).
- P237 last-chance publish gated on !XFS_ISTALE_CAW.
- Verification: tests/sess429_chain.sh s433 (MARK-bounded sweeps; verdict counts settled/unsettled/P237).
