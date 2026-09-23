<!-- sess426 tauth: D-0345 UNOWNED routing, D-0346 poisoned-dcache ESTALE, D-0347 CAW conditional commit, D-0348 collision redesign, D-0349/50 filed. -->
## sess426 — tauth/authority-ledger campaign (continuation of the sess422-425 arc in ``docs/history/docs/history/compiled-tauth-step3-step4-campaign.md``)

Six defects worked in one session against the TCP/CAW authority ledger (tauth): D-0345
(UNOWNED page routing), D-0347 (page-write race), D-0346 (dcache ESTALE on dir recreate),
D-0348 (hash-slot collisions), D-0349 (commit pace), D-0350 (incarnation stamping on
departure). Tree moved 0.35.3 → 0.35.4 → 0.36.0 → 0.36.1(queued) → 0.37.0 across the
session; mxfs.ko on disk stayed at 0.36.0 through the relay boundary.

### D-0345 — UNOWNED page parked forever
Root (proven via `tests/tauth/unowned_page_test` + rig s427): `dlm_page_acquire`'s UNOWNED
branch at a non-bootstrap view-master has nobody to ask (`auth_node=0`) and parks forever.
GPT ruling: route `FREEZE_REQ(page, target=self)` to the bootstrap node via a new
`bootstrap_node_cb`; the bootstrap's existing bootstrap-for-request path claims UNOWNED then
PREPAREs to the sender. Validation must additionally require `target_node==sender` (existing
checks — `config_id==view`, `owner==sender` — are not sufficient alone), sender+inc live in
that view, and a durable re-read under the page lock confirming still-UNOWNED immediately
before claiming. Landed 0.35.4. Known unresolved safety hazard (pre-existing, not
introduced): bootstrap tenure is not exclusive/fenced — write+exact-readback is NOT an
atomic CAS, so two nodes each believing themselves bootstrap (lowest-slot flip) could both
claim; needs a PR fence before another may claim, or an on-disk lease/epoch. Never let the
mapped (non-bootstrap) master claim UNOWNED directly — bootstrap-only is load-bearing while
storage has no compare-and-write primitive at that layer. The 10-retry/~1s caller budget is
too tight for 3 page writes + 2 messages on a slow LUN; prefer parking/coalescing waiters
woken on FROZEN (with a durable-IO-derived timeout) over burning REMASTER retries, and never
block synchronously in the receive path — it would block the FROZEN that resolves it. s429
confirmed the fix: retry_exhausted=0, 1293 ACTIVATE/1278 PAGE-MINE first-touch claims, zero
STALE-BASE/TICKET-*/VERIFY-FAIL/CONFLICT/POISON — D-0345 is GONE.
(``docs/rulings/unowned-page-route.md``,
``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``,
``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``)

### D-0347 — tauth page write is not a conditional commit
Root, proven by `tests/tauth/bootstrap_race_test`: two nodes both claiming one UNOWNED page
race, and the late writer — building on a stale read — becomes highest-seq and silently
erases the other's activation + committed grant, because `mxfs_tauth_page_write` ties
nothing to the image the caller patched (readback only proves "my copy validates now").
GPT-ruled design (P1: ticket-on-the-spare-copy via SCSI CAW; rejected: retiring the
committed copy — mutates truth, still needs a lock, worse recovery):
1. Read both copies, pick the unique highest valid, return a base token
   `{fs_gen,page_id,seq,write_nonce,copy_index}` plus the exact spare-copy sector.
2. Revalidate against the WHOLE base token immediately before commit, else `-ESTALE`.
3. CAW-acquire the spare: compare = recorded spare sector, write = a self-invalidating
   ticket sector `{page_id,fs_gen,proposed_seq,base_seq,base_nonce,writer_node,writer_inc,
   ticket_nonce,IN_PROGRESS,ticket_crc}`; durable (CAW+FUA/flush) before any body write.
   Miscompare = `-ESTALE`.
4. Write body sectors 1..7 FUA, durable before publication.
5. Publish: CAW compare = exact ticket sector, write = final valid-CRC header; miscompare
   here is a fatal fencing error only if ownership was stolen without fencing.
6. Adopt/cache MINE only once the outcome is resolved as committed.

ABA closed by: seq never wraps within `fs_gen`; `write_nonce` unique per publication/ticket;
reformat bumps `fs_gen`; nothing writes headers outside the protocol. A third writer arriving
during a live ticket gets `-EBUSY` — never replace a live ticket just because CAW would
compare clean. Crash recovery: a recovery writer may CAW over an abandoned ticket only after
the ticket owner's exact incarnation is durably fenced from LUN I/O (membership purge alone
is insufficient unless it guarantees no further storage commands); if fencing can't be
proved, reads stay OK but writes return `-EBUSY`. An ambiguous outcome after a timed-out
final CAW/flush is resolved by re-read, never by resending from the stale base: own final
nonce present = committed; own ticket still present = resumable; base still highest and own
ticket absent = not committed; a later valid seq exists = resolve via nonce/base chain or
idempotency. A readback mismatch after later commits land is NOT proof of failure — CAW
completion IS the publication event. Landed in tree 0.36.0
(`tauth_store.c`, `mxfs_tauth.h` ticket struct, `dlm_store_fenced_cb` wired at attach,
`pal/linux/user.c` CAW emulation for regular files); `bootstrap_race_test` FAIL→PASS, all 7
usermode suites pass. (``docs/rulings/tauth-conditional-commit-ticket-caw.md``)

### D-0346 — mkdir ESTALE on a recreated shared directory (P34H poisoned shell)
Evidence from a 32/caw board archive: lookup of a freshly recreated dir hits a POISONED
SHELL of the previous incarnation (`i_count=2`, up to 11 nodes, `I_DONTCACHE|I_REFERENCED`).
The existing `P34H-POISON-EVICT` retry loop (`d_mark_dontcache`+`d_prune_aliases`+`irele`+
`retry_iget`, `xfs/xfs_inode.c` ~1540-1590) never retires it → `P34H-POISON-UNRETIRED
tries=5` → lookup `-ESTALE`. A correlated `P-DIRCRC-RETRY-FAIL err=-117` storm (durable CRC
failure surviving the transient-torn retry loop, `pal/linux/xfs_buf.c:1473`) appears in the
same window. Hypothesis H1 (unproven at session end): `d_prune_aliases` drops only UNUSED
aliases; a peer's cached CHILD dentries of the old directory pin the old parent dentry via
`d_parent` refs, so `i_count` never reaches the last `iput` and `retry_iget` cache-hits the
same shell. Candidate fix if proven: per-alias `d_invalidate`
(`shrink_dcache_parent`+`d_drop`) instead of `d_prune_aliases`. Instrumentation added
(`P34H-POISON-ALIAS ino= dentry= d_count= children= d_flags=` per alias) plus reproducer
`tests/dir_recreate_estale.sh <label> [A B C D] [laps] [gap_ms]`; not run before the session
ended (rig busy) — verification is deferred to s430, with the read-first rule: `children=1`
and `d_count>0` on the alias line proves H1.
(``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``)

### D-0348 — 44 P-TAUTH-COLLISION events / new slot-hash design
Measured on s429: 8000 live inode locks → 44 collisions (two inodes hashing to one of 65536
slots) → `-EEXIST` → `MXFS_ERR_LEDGER` turned into `-EIO` at the file op (`dlm.c` ~3452).
GPT-ruled fix: page-local open addressing + a substantially larger mkfs-sized region.
Rejected: cross-page probing/multi-master, waiting behind an unrelated tenure, a bigger
direct-mapped table alone, simple cuckoo hashing (two masters can create duplicate entries),
and deferring resolution. Rule: a resource hashes to exactly one `home_page =
hash(hash_version,seed,resource) % page_count`, mastered by `active_nodes[home_page % N]`;
that page's master exclusively finds/creates/updates/deletes the record among the page's 31
entries by the FULL key `{type,ino,ag}`; allocates the lowest-index EMPTY/FREE entry;
commits the page via CAW. No reusable entry → retryable `LEDGER_CAPACITY_WAIT` (capped
backoff, waiter registration, loud health event) — never `-EIO`. Two occupied entries for one
resource is corruption requiring quarantine; never relocate an occupied entry. Identity
splits into `home_page` (routing) / `entry_index` (0..30) / locator
`{ledger_generation, home_page, entry_index}`; grant/release handles must carry
`resource_id + locator + lineage + grant_seq` (+ node/inc/epochs); `RELEASE_PR` must validate
page+entry+full resource id+occupied+lineage/grant_seq+holder node+inc+holder bit —
validating only `{lineage, hash_slot, node, inc}` lets a stale locator hit a reused entry.
Capacity: current geometry (2115 pages × 31 = 65,565 records, ~16.5 MiB dual) is
categorically undersized even around ~40k tenures given realistic occupancy skew; size from
PEAK simultaneous occupancy (not table size), with telemetry on occupied total, per-page
occupancy max/histogram, page-full events/waiters, longest capacity wait. Callers must not
sleep on capacity while holding tenures that can form a lock-order cycle — unwind and retry
instead. Format/migration: on-disk+wire version bump (hash algorithm, seed, page_count,
entries_per_page, region geometry, locator fields); mixed-version nodes refused; migration
needs offline or full ledger quiescence (rehash all records into new home pages, build
shadow regions, atomically publish geometry/version) — never reinterpret or move active
old-format records live; geometry is a generous mkfs-time parameter since changing
`page_count` rehashes everything.
(``docs/rulings/tauth-slot-collision-page-open-addressing.md``)

### D-0349 — commit pace regression (filed, unmeasured root cause)
s429: all 4 workload nodes hit `rc=124` at 30s on the token stage. Each ledger commit now
costs 2 CAW ops + body write + 3 flushes, plus a first-touch handoff cost per page — the
D-0347 conditional-commit protocol's overhead was not budgeted against the derived-budget rule. Fix queued
for s430: `P-TAUTH-STORE-STATS` per-phase timers every 200 commits, to identify which phase
dominates before optimizing.

### D-0350 — incarnation not stamped on departure
Filed in the END-state pass: NODE_LEAVE/GOODBYE messages must carry incarnation so a
takeover can distinguish a stale goodbye from a live one (`TAKEOVER-NOINC` sweep tag must be
0 once fixed). Folded into tree 0.37.0, unverified as of relay boundary.

### Harness / infra lessons
- The rig kernel build compiles against `/usr/src/linux-headers-6.8.0-101-generic` field
  names (e.g. `d_u.d_alias`) — NOT `/src/linux` 7.1-rc7. Check field names there when adding
  dentry/inode instrumentation for this rig, not against upstream HEAD.
- `tcp_token_plumbing_verify`'s "report did NOT advance" check compares against a stale
  pre-remount sample count and wraps (`18182→4940 mod 8192`), producing false FAILs; its
  `.wl` files also capture no per-file errno. Both need fixing before trusting a token-stage
  FAIL from this harness alone.
- Ledger discipline: D-0347/D-0348/D-0349/D-0350 all filed critical same-session; D-0345 and
  D-0341..0344 held open pending a clean s430 sweep rather than closed on a single good run;
  D-0287 (departure-arm invariant) needs its DEATH arm exercised, not just the PASS arm, before
  closure.

### Checkpoints (state snapshots, for relay continuity — not new defects)
11:44Z s429 verdicts landed D-0345=GONE, surfaced D-0348+D-0349.
(``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``)
11:58Z checkpoint: d0287 stage PASS (new master did not serve a write during H's 100s pause,
md5 equal), board running, s430 queued as tree 0.36.1 folding in D-0345/0346/0347/0348/0349
plus two unrelated pending items (`D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO` items 1-2:
`hb_rebase_epoch`/`P-HB-INC-ZERO`; `D-DUP-RELEASE` invariant 4: `rel_instance`/
`P283-REL-FINISH-SKIP`). Ledger 155/68 open.
(``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``)
~12:07Z END state at the relay boundary: tree bumped to 0.37.0 (adds D-0350); the 0.37.0
kernel build as a WHOLE is unproven — only individual objects (`disklock.o`, `v5_mount.o`,
`xfs_mxfs_dlm.o`, `xfs_inode.o`, `dlm.o`, `tauth_ledger.o`) had compiled standalone; disk
`mxfs.ko` still 0.36.0. s430 queued via `tests/rig_after.sh` (survives relay): build → tauth
→ prep caw → `dir_recreate_estale` (D-0346) → `incarnation_mismatch_probe` (expect zero) →
prep tcp → token (+ token-wl/token-errs phase capture) → prep tcp → d0287 → prep caw → board.
Read-first checklist for the session picking this up: STAGE build rc; STAGE dre +
`P34H-POISON-ALIAS` lines (`children=1` + `d_count>0` proves D-0346 H1, fix = per-alias
`d_invalidate` in `xfs_inode.c` ~1564); STAGE incprobe; token stage requires collisions=0,
zero EIO in token-errs, per-phase `STORE-STATS` ms (D-0349), `retry_exhausted=0`; sweep tags
`TAKEOVER-NOINC=0` (D-0350), `P283-REL-FINISH-SKIP`, `P-TAUTH-PAGE-FULL=0`; d0287; board.
(``docs/history/docs/history/docs/history/compiled-sess426-tauth-ledger-campaign.md``)
