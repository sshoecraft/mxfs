<!-- sess429-430: D-0351 FREE-HOME settle, FREE-FOREIGN chain fix, deferred-release audit gap, dialloc containment; ends on free-image-never-lands cluster… -->
## D-0351 (FREE-PUBLISH / ifree-never-published) — sess429-430 continuation

Picks up after `docs/history/docs/history/compiled-sess428-tauth-view-table.md` (0.38.1-0.38.3 landed). This
article covers 0.39.0 through 0.39.4: home-free ledger settlement, the
same-node free/recycle/free "chain" hazard, a deferred-release audit gap,
dialloc-time platter-live containment, and the still-open root cause found at
sess430 END (free image writes that never land on the platter).

### 0.39.0 — FREE-HOME leaves the publication ledger open → P237 evict shutdown
s432 board (0.38.3) collapsed at fio_perf: only test1 shut down. Sequence:
`dd` creates ino 133 → `rm` frees it (pin=1, in_ail=1) → xfsaild flush hits the
0.38.3 `P55C-FREE-HOME` branch (chunk-init image, mode 0) and discharges →
flush_out's abandoned-publication chokepoint stamps `i_mxfs_pub_fenced=1` →
nothing consumes `pub_fenced` for an unlinked inode (no BAST, straight to
reclaim) → `P237-EVICT-OBLIGATION` → forced shutdown → P-SESSION-POISON, which
stalls fio_perf's barrier across all 32 nodes. In 0.38.1 the same inode took
FOREIGN instead, whose dead_incarn_gen poison accidentally exempted P237 — why
0.38.1 had passed the same test.

GPT ruling (`docs/rulings/home-free-ledger-settle.md`):
settle-by-equivalence is sound iff in-core mode 0 + nlink 0 + a live committed
FREE obligation (freeob==2, PUBOB) + home dinode mode 0 (gen irrelevant) + the
ifree transaction is log-complete (inode item UNPINNED, checked explicitly —
`xfs_iflush_cluster` never flushes a pinned inode) + the pending seq snapshot
is final. Generic `in_ail` is NOT proof; unpinned-exact-item is. Recovery
worker gets the same predicates, SETTLE-ONLY (no write/adopt/unlink-convert —
a peer may have allocated+freed the number in the lock gap; mode 0 still
proves the free-image requirement). P237's last-chance publish must never
write an ISTALE_CAW shell (could overwrite a peer/new incarnation).

Landed as 0.38.4/0.39.0: `mxfs_pubob_settle_home_free(mp, ip, site)` in
xfs_mxfs_dlm.c, called before discharge at both home-free sites (xfs_inode.c
P55C iflush; recovery worker); stamps fepoch/wmb/durable/flush like the adopt
discharge and clears pub_fenced; P55C-FREE-HOME-SETTLED/-UNSETTLED
(fail-closed — UNSETTLED leaves the ledger open); P237 last-chance publish
gated on `!XFS_ISTALE_CAW`. Bundled into the same 0.39.0 build: tauth
view-record step 1 (mkfs writes the ROOT ctrl page, chk `check_tauth_ctrl`,
`mxfs_sha256_compress` rename to dodge chk's local sha256_block symbol clash)
— note this step alone does not change authority behavior, legacy per-page
authority still runs on v3 regions (TCP only).
(`docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

Disposition rule for D-0351 as of 0.39.0: clean dre×2 + clean board (zero
P237/P-SESSION-POISON/UNSETTLED) + a second lap, but containment (dialloc
pre-dirty platter validation) stays open regardless.

### 0.39.1 — same-node free→recycle→free "chain" reclassified as FOREIGN
s433 board on 0.39.0 was clean (0 FAIL, 0 shutdowns) but produced 164
`P55C-FREE-FOREIGN` events across 63 inos (0 with disk_gen==gen-1, single-node
per ino, FOREIGN → P-RECYCLE-DEADSTAMP-CLEAR repeating up to 5 laps), plus 634
audit `P-FREEOB-FOREIGN` and 1 `P32D-DEADINCARN-SKIP` poisoning a live file.

Root: `XFS_IRECLAIM_RESET_FLAGS` clears `MXFS_IF_PUBOB` on recycle but the
store entry stays kind=FREE; a chained free then finds its own OLDER live
image at a mismatched gen → misclassified FOREIGN → never written → inobt
freed while the platter still holds a LIVE image (latent DISK-LIVE for the
first peer allocator to pick the number). (`docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

GPT ruling (`docs/rulings/free-foreign-chain.md`): tenure
continuity (pubwrite_begin(ob.epoch) / retiring token) alone is necessary but
not sufficient — same-node chains need explicit chain provenance recorded at
the recycle transition under the same epoch, with AG EX excluding stale peer
inode writers, foreign replay never writing concurrently with a granted EX,
and the chain anchor never bootstrapped from a foreign image. The recycle-time
gap is an independent hazard: a live inode must never be representable by an
actionable FREE entry. Rejected "keep FREE + chained flag"; required a real
state machine: FREE → CHAIN_LIVE(epoch, chain) → FREE(new gen, same epoch,
chain+1). Rejected sync-publish-at-recycle (I/O per hot reuse, allocator hot
spots) in favor of the chain state machine.

Landed 0.39.1: `mxfs_pubob.chain` + `MXFS_PUBOB_CHAIN_LIVE`;
`mxfs_pubob_recycle()` hooked from `xfs_iget_recycle`
(create||deadshell_create): same-epoch FREE/FREE_PENDING → CHAIN_LIVE
chain+1 (P-FREEOB-CHAIN-LIVE), other-epoch → CHAIN-BROKEN, other-kind →
RECYCLE-ANOMALY; strikes/freeob reset. P55C write branch extended to
`dgen==gen-1 || chain` (P55C-FREE-CHAIN). Audit skips CHAIN_LIVE and never
poisons a live shell on FOREIGN. Verified via
`tests/free_foreign_realloc_repro.sh`: chain=199, FOREIGN=0, DISK-LIVE=0;
board 23 PASS/5 FLAKY/0 FAIL.

### 0.39.2 — deferred AG release path skipped the publish audit entirely
Full journald sweep of the 0.39.1 board still showed 32 P55C-FREE-FOREIGN, 6
worker FOREIGN, 2 CHAIN-BROKEN, 12 RECYCLE-ANOMALY. Root:
`mxfs_dlm_ag_release_work_fn` (the deferred-release path, taken when AG meta
writeback is pending at COMMIT) never called
`mxfs_p86_agi_unlinked_publish_audit` — only the inline `bast_work_fn` path
did. FREE obligations crossing a deferred release went un-audited, breaking
tenure and reproducing the FOREIGN/CHAIN-BROKEN symptom.
(`docs/history/docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

Fix: factored `mxfs_ag_release_publish_gate(pag, path)`, called on both the
inline and deferred paths; added `mxfs_pubob_unlock_census` →
`P-FREEOB-XRELEASE` instrumentation at all 4 unlock sites; deadshell over
CHAIN_LIVE now yields `P-FREEOB-CHAIN-SUPERSEDED`. Verified clean (0
FOREIGN/CHAIN-BROKEN/XRELEASE) — see next entry for the residual it exposed.

### 0.39.3 — audit early-return skipped FREE-obligation enforcement
s436 (0.39.2) board was clean end-to-end but the sweep still found 42
P55C-FREE-FOREIGN, 3 CHAIN-BROKEN, and 8 XRELEASE (all path=bast-inline,
free=1): DENIED at ag_epoch=0 → XRELEASE 6ms later with zero audit lines →
CHAIN-BROKEN 0.26s later. Root:
`mxfs_p86_agi_unlinked_publish_audit`'s early `return 0` (knob off / AGI not
incore / XBF_TRYLOCK failure / bad magic) skipped the entire obligation
section, not just the audit proper. Fix: `goto obligations` +
`P86-HEADWALK-SKIPPED`; obligations now always run regardless of the
early-return reason. (`docs/history/docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

Also landed alongside: `mxfs.dialloc_validate` module knob (default 1; 0 =
pre-containment allocator, for A/B) and harness env
`MXFS_DIALLOC_VALIDATE=0`, ahead of the containment work below.

### Dialloc containment — GPT ruling: two-phase required, not a plain read
Question was whether a plain lock-free LUN read inside
`mxfs_dialloc_pick_in_rec` (next to the existing DLM try-reserve) suffices.
Ruling (`docs/rulings/d0351-dialloc-containment-two-phase.md`):
REFUSED — synchronous I/O under AGI/btree cursor nesting is not grandfathered
by the DLM probe already there (sess427 item-6 ruling). Required design
(Option B): collect candidates without modifying the trees; drop
cursors/AGI/any I/O-dependent ialloc locks; consult the local pubob store;
authoritative plain reads; quarantine bad candidates; restart and REVALIDATE
the selected free bit immediately before `xfs_dialloc_ag_update_inobt`
(transaction stays clean across validation); release reservations on
rejected/unused candidates; bounded restart count + per-attempt visited set.
Quarantine is a per-AG agino set with NO expiry (not the old 8-entry timed
cooldown), sized for every observed DISK-LIVE, cleared only after coordinated
repair + authoritative re-verification (platter mode 0 AND metadata
agreement). Error policy: one rate-controlled P-line per DISK-LIVE candidate,
quarantine + release + continue — never fail an otherwise satisfiable
create; all-candidates-quarantined is a distinct clean failure (EIO/EUCLEAN),
never ENOSPC, no dirty cancel, no shutdown. Pubob same-node chain exception
only on an exact ino+gen/tenure match with expected unpublished state, never
flushed inline. Release audit queues {agino, gen/tenure, platter evidence,
owner identity} to the async path — never infers ownership from a possibly
stale dinode, never clears quarantine on request alone.

Landed in tree as 0.39.3 (unbuilt at ruling time, built by s437):
`mxfs_dialloc_two_phase` / `mxfs_dialloc_validate_candidate` in
xfs/libxfs/xfs_ialloc.c, `pick_only` param on `xfs_dialloc_ag`,
`rs->validated/quarantined/disklive/restarts`, `-EUCLEAN` tail;
`pag_disklive_q` xarray + `pag_disklive_n` in xfs_ag.{c,h}. New test tooling:
`tests/dinode_inject.py` (plant a live/free image with a resealed v5 CRC),
`tests/dialloc_disklive_inject.sh` (plants a LIVE image under a
verified-free number, allocates 16 files, fails on P-CR62/shutdown/create
error/that number being handed out), `tests/sess430_containment_chain.sh`.
(`docs/history/docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

Containment measured: the pre-fix arm (0.39.2, cache-hit create) silently
clobbered the planted LIVE image with no shutdown — a data-loss arm, not a
crash — so the injector was changed to drop caches after planting
(cache-miss arm). Post-fix 0.39.3: `P-DIALLOC-DISKLIVE ino=X`, X never
handed out, creates succeed, no shutdown → PASS.
(`docs/history/docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

### sess430 END — containment holds, but the free image is not reaching the platter
0.39.4 (knob `mxfs.dialloc_validate` + CHAIN-SUPERSEDED reclassification)
verified A/B: knob off → P-CR62 shutdown as expected; knob on → PASS.

s437 board (0.39.3): 23 PASS/5 FLAKY/0 FAIL, 0 shutdowns. XRELEASE=0 and
CHAIN-BROKEN=0 (the 0.39.3 audit fix holds; `P86-HEADWALK-SKIPPED`=561
fleet-wide confirms the skip path was common). But P55C-FREE-FOREIGN=39 and
**P-DIALLOC-DISKLIVE=123** — containment is now firing on genuinely
disk-live numbers (67 reg 0644, 29 reg 0600, 27 dirs). This reframes D-0351:
containment is masking symptoms of a real write bug, not a false positive.

Decisive per-inode timelines
(tests/evidence/sess430_s437_inos/, via grind agent) proved it: e.g. test11
ino 134217887 logs `P55C-FREE-FLUSH gen=1788827488 disk_gen=1788827487
040755` ("writing the committed free image") at t=5658.16, then 35s later
the SAME node hits `P-DIALLOC-DISKLIVE disk_mode=040755
disk_gen=1788827487` — the PRE-FREE image is still on the platter. Two more
inos (test12, test14) reproduced the identical pattern. Conclusion: the P55C
copy-in *reports* the free image written, but the image never lands; FOREIGN
on the next life is a downstream symptom of the platter still holding the
older live image, not an independent bug.

Prime unread suspect for next session: `pal/linux/xfs_buf.c` cluster-write
passenger mask — `is_free`/`is_nl` computed at :3526-3548 (`if (is_free ||
is_nl)` skip) and applied ~:4234/4600. Hypothesis: a slot whose image is
mode 0 (the just-copied-in FREE image) gets classified `is_free` and is
MASKED OUT of the cluster write even though it was logged this round, yet
`xfs_iflush_finish` still marks it flushed → PUBOB_FLUSHED → discharge →
the FREE-PUBLISH crossing happens silently with no durable write. Plan:
read the `is_free` skip condition (does it check logged/`bli_dirty`?), then
instrument a `P218-FREE-SLOT-MASKED ino= logged=` print, and/or add an
FUA-verify after the P55C write (the audit's P-FREEOB-PUBLISHED path
already FUA-verifies; the P55C tenure path does not). Related existing
probes: `P218-CLUSTER-PASSENGER skipped=`, `P170-CLWR` (capped 800/module
load), `mxfs_cluster_passenger_skip=3` (bit0 PR-held, bit1 nocore). Consult
GPT again once the `is_free` mask read is done, before touching it — the
mask exists to stop stale free images clobbering peers' live inodes, so the
fix must distinguish a LOGGED free image from a genuine passenger.
(`docs/history/docs/history/docs/history/compiled-sess429-430-d0351-free-publish-chain-containment.md`)

### Cross-cutting operational notes from this arc
- Bash tool hard timeout cap is 600s regardless of the `timeout` param
  passed — any foreground wait must stay ≤570s or it blocks.
- `tests/sess430_containment_chain.sh` and `tests/sess430_chain.sh` are read
  incrementally by a running bash process; never edit one while its chain is
  in flight — wait for the DONE line, then edit and relaunch under a new lap
  id.
- `sess430_chain.sh`'s verdict line cosmetic bug: `chain_live` reports 0
  because the counter moved to the HIGHVOL overflow line, not because chains
  stopped.
