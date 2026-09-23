<!-- sess472-473: D-0529..D-0535 dirshard/authority defects filed+fixed 0.64.14-0.64.23, transaction-refusal-ordering rule, 2 recurring rig traps. -->
# sess472-473 dirshard authority campaign (D-0529..D-0535)

Continuation of `docs/history/docs/history/compiled-sess466-470-dirshard-authority-campaign.md`. Both sessions ran
2026-09-02, same rig queue, same tree lineage 0.64.14 → 0.64.23. Ledger moved 76→81 open,
190→195 total across the two sessions.

## sess472

**MID1** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) —
sess471 was killed by the server-side safeguard classifier mid-summary, having edited two
fixes into the tree as 0.64.14 but never building or ledgering them. sess472 filed both:
- **D-0529** (critical): `mxfs_inact_cert_evict_check_locked` compares `auth_incarn`
  (install-time i_generation) to current i_generation, but `xfs_ifree` bumps generation by 1
  — every deferred-free evict misclassifies as cls=2 → false `xfs_force_shutdown`. Fix:
  accept `DEFERRED && FREE_COMMITTED && gen==(u32)(incarn+1)` as cls 0; `auth_incarn` stays
  immutable.
- **D-0530** (critical): dirshard `free_container`/`free_holder` unlocked an ILOCK a second
  time after commit/cancel (already joined) → rwsem underflow WARNING at
  `mxfs_ilk_note_unlock`. Fix: drop the explicit unlocks.

Also found: the D-488 test harness had the wrong shape — MXFS pins both inode allocation and
shared-dir block growth to the *creating* node's own AG, so node Y creating in X's dir never
touches X's AG; only Y *freeing* X's inodes does. Harness changed to have Y `rm` X's files.

**MID2** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) —
0.64.14 verified D-0529/D-0530 fixed (WARN gone, cls2 gone, chk clean, cc 3/3 PASS). Two new
criticals surfaced:
- **D-0531**: rmdir of a sharded dir → `free_holder` dirties the transaction (binval/bunmapi/
  iunlink) → `xfs_attr_removename(locator)` takes the DEFERRED attr path → a 0.64.12 guard
  refuses `-EFSCORRUPTED` *after* the transaction is already dirty → `xfs_trans_cancel` on a
  dirty transaction → shutdown → node loses its PR key → `P277-FENCED-SELF-WITHDRAW`. Initial
  (wrong) hypothesis: parent's attr fork not shortform-capable.
- **D-0532** (high): create reuses an inode whose previous life was `P128-INACT-DEFER`-freed
  → `xfs_iget_recycle` → `xfs_iunlock` at `xfs_icache.c:888` → `P71-UNDERFLOW`. Matching
  `xfs_ilock` site not yet found.

Built 0.64.15 with guard/probes for both plus the D-0527 fix (bracket the untrusted `xfs_imap`
read with `mxfs_ag_dlm_lock`/unlock in `xfs_iget_cache_miss`).

**MID3** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`)
— D-0532 root PROVEN by code + adjacency: `xfs_iget_cache_hit` takes the IRECLAIMABLE
corpse's ILOCK via `xfs_ilock_nowait(EXCL)`, which never runs the DLM-begin path (only IOLOCK
gets `ilock_try`); `xfs_iget_recycle` then releases with a plain `xfs_iunlock`, which *always*
runs `mxfs_dlm_ilock_end` — decrementing a counter whose matching increment never happened.
Fix: new exported `xfs_iunlock_nodlm()` (rwsem-only release) used at the recycle release site.
Built 0.64.16 sv `D8320EFC13DFECB949C859C` (prod+LAB).

Chain108 s472b (D-FOREIGN-SLICE-INTENTS-ABANDONED fix-A arms): all 7 arms showed
`installed=1 got=0` — **not a kernel defect**. Root: the harness's mkrm workload never
published the file cross-node (sess44 local-only EX, no slot), so every certificate install
hit `MXFS_AUTH_TRY_UNPUB` (try=7), the ruling's approved classless case. Harness fixed to walk
+ cat every file from a peer node before the rm, to force publication via BAST.

**MID4** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — GPT spotted
the real D-0531 root: freeing the holder's real extent *always* queues a deferred EFI, so
**any** refusal issued after that free — regardless of cause — cancels an already-dirty
transaction. The "attr fork not shortform" check was real but harmless; it just happened to
fire first. Rule learned: **any refusal that can cancel a transaction must run before that
transaction's first dirty; after the first dirty only commit or shutdown are honest.** Fix
0.64.17: count `t_dfops` around `xfs_attr_removename`, alert+commit instead of refusing
post-dirty. 0.64.18 adds the same discipline to `mxfs_dirshard_locator_set`'s post-add checks,
plus a proactive guard: `pal/linux/xfs_xattr.c xfs_attr_change` now refuses *any* xattr
set/remove (including ACLs, security.*) on a sharded parent with `-EOPNOTSUPP`
(`P-DIRSHARD-XATTR-REFUSED`), so the attr fork stays shortform by construction and the whole
failure class is prevented rather than caught.

**MID5** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — measurement on
0.64.16 disproved the attr-fork-LOCAL hypothesis directly (attr fork was fine; the deferred
EFI-misattribution above was confirmed instead). Built 0.64.18 sv `8F2B9ADEBCBDFB2349E7CF5`
(prod+LAB, everything since 0.64.14). **Trap** (recurs through the campaign): killing a
chain's driving bash process does not necessarily kill the orphaned `timeout N ./run.sh`
child — it can keep running, writing to the same log and polluting a relaunch's caches/state.
Always check the log's STAGE lines after a kill and run `tools/mxfs_pgrep.sh run.sh` before
relaunching (the unkillable-wedge rule-safe pgrep, not raw `pgrep -f`).

**END** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — Chain113 stage-1 on 0.64.18: D-0529,
D-0530, D-0531, D-0532 all verified clean on **one** lap (the zero-defect bar multi-lap verification still
owed before disposition). **NEW D-0533** (critical): peer readdir of an N=64 sharded dir →
EUCLEAN. `mxfs_dirshard_iget_probe` igets members with `lock_flags=0` → cache-hits the peer's
stale shell of a reused inode number (old parent gen vs new container gen mismatch) →
`P-DIRSHARD-STRANGER` ×8 → `-EFSCORRUPTED`. Proposed fix shape: iget with `ILOCK_SHARED`
(DLM begin + stale reload) or an explicit reload before the identity compare.

## sess473

**MID1** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — D-0533 fix
landed: `mxfs_dirshard_probe_revalidate` — on gen mismatch, FUA-read the platter; if platter
gen != manifest gen, force one peer flush and re-read; if platter gen == manifest gen, mark
the shell stale and `mxfs_dlm_reload_inode(expect_ftype)` retrying 200×10ms until
`igen==gen` → `P-DIRSHARD-SHELL-ADOPTED`, else `-EBUSY` (`P-DIRSHARD-SHELL-UNCONVERGED`).
Built 0.64.19 sv `9576BB1BCC9082B1023D312`. Separately, chain110 (D-0527) harvest showed
3/3 PASS but the probe counts were **unbounded by the uptime mark** — a rerun's counts could
include a stale prior run's lines; harness fixed to stamp an uptime mark and sweep only after
it.

**GPT review** (`docs/history/gpt-review-d0533-probe-revalidate.md`) — the design-consult rule review
of the D-0533 fix: **STOP-SHIP**, 12 findings. Actioned in 0.64.20:
- Convergence test was buggy: it could report success on `igen==gen` even with `i_dlm_stale`
  still set. Fixed to require `!stale && igen==gen && ftype==expect`.
- The reload-wait loop needed a hard round bound (20 rounds) whenever it can run under a
  transaction or under parent ILOCK_EXCL during teardown — 2s under a held parent lock is
  operationally unsafe; `-EBUSY` leaves the set for the next pass instead of blocking.
- `-EBUSY` must not leak out of getdents: `mxfs_dirshard_iget` maps it to `-ESTALE`.
- A genuinely different, live, nonzero disk gen (`P-DIRSHARD-STRANGER-LIVE`) must fail closed
  as `-EFSCORRUPTED` on deletion, not silently proceed.

Documented-but-not-actioned hazards (real, deferred): in-place reload of a *referenced* shell
is unsafe in principle — open fds/dentries silently jump incarnations; wants a reuse
quarantine or {ino,gen}-keyed objects eventually. Reload state isn't serialized against
concurrent reloaders (relies on the existing trylock+bail contract). Parent→member lock
ordering is only safe if no peer ever waits on the parent while holding the member EX. The FUA
read is authoritative only under the drain-before-unlock invariant, and — flagged as a live
follow-up — `mxfs_inode_disk_di_size` currently returns `dmode=0` for both "platter free" and
"read failed", so an I/O error on the revalidate path can misread as "gone" and clear a bit
over a live container; needs a `(u64)-1` error sentinel before it's trusted for teardown.

**MID2** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — D-0533
mechanism **PROVEN** on the rig via `P-DIRSHARD-SHELL` trace lines (31 adoptions across reuse
laps, 0 unconverged/stranger). But those same laps showed `P-DIRSHARD-CORRUPT=100` →
**NEW D-0534** (critical): the peer's cached manifest **block** buffer goes stale when a
holder block's disk address is reused (`blk_owner` mismatch at the same daddr). Fix 0.64.21:
`manifest_load_slow` stales any clean cached buffer at the holder daddr before `blk_read`
(`P-DIRSHARD-BLK-REFRESH` / `-BLK-KEEP` when it carries uncheckpointed local mods). Latent
lost-update arm (same block set, an older mgen served to a new EX holder) recorded as item 3
of the record, not yet fixed. **Trap repeated from [[ccloop-c7ee71c6-sess472-MID5-d0531-root-efi-misattribution-06418]]/sess468**: killing a chain waiter whose gate had *already opened*
orphans a live harness run that keeps executing concurrently with the relaunch, corrupting the
relaunch's shared state (buffer cache, log). Always check the chain's LOG for a START line
before killing a "waiter."

**MID3** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) —
Chain108 s472u re-harvest: 3 arms (edeadlk/advance/escalate) genuinely VERIFIED; the other 4
"FAILs" were all harness defects, not kernel defects — a deferred-retirement vs knob-window
timing mismatch, a `pr_warn` 96-lines-per-module-load cap exhausted by unrelated filler output,
and a ring-delta computed across the whole dmesg ring instead of only the post-mark region.
Harness fixed on all three counts. D-0534 fix widened in 0.64.22 to also cover
`inactive_parent`'s direct bmap read (audited: `manifest_load_slow` and `inactive_parent` are
the *only* two read call sites touching the holder's bmap).

**MID4** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — Chain115
harvest on 0.64.22: selftest PASS, reuse laps 1-2 PASS on both arms (arm B — peer rmdir of a
reused set — passed for the first time ever). Lap 3: **creator-side** shutdown,
`xfs_attr_shortform_verify` corruption on the attr fork. **NEW D-0535** (critical):
`mxfs_dlm_reset_inode_for_create` used `xfs_idestroy_fork(&ip->i_af)`, which frees `if_data`
but *keeps* `if_bytes`/`if_format`. A shell whose prior incarnation had a 32-byte attr-fork
locator, freed by a **peer** (so this node's own `xfs_ifree`, which zaps the fork, never ran),
inherits a stale `if_bytes=32`. The next locator add grows from that stale size (a
`shortform_create` ASSERT that would have caught it was compiled out) → header totsize 32 vs
actual fork size 64 → verifier trip. **Not dirshard-specific** — any xattr-carrying inode
reused after a peer-side free is exposed. Fix 0.64.23: `xfs_ifork_zap_attr` at four sites —
`reset_inode_for_create`, the reload path's pre-`from_disk` destroy, recycle-adopt, and
dead-shell reset. New generic reproducer `tests/d0535_xattr_reuse.sh` (victim←peer, both node
pairs) added to the chain115 stage list.

**END** (`docs/history/docs/history/docs/history/compiled-sess472-473-dirshard-campaign.md`) — 0.64.23 sv
`2A4E0D0E70720DEA30A608F` frozen, containing all of D-0529 through D-0535. Ledger at 81
open/195. Status at relay: D-0533 PROVEN+fixed, D-0534/D-0535 found+fixed, 20-lap verdicts
still owed on 0.64.23 (chain115 s473c) for all three. D-0527 handle-open class MET (chain110
s473b 3/3 PASS, mark-bounded harness now trustworthy per MID1's fix). D-FOREIGN-SLICE-
INTENTS-ABANDONED fix A: edeadlk/advance/escalate VERIFIED; refuse/foreign/gone/defer FAILs
attributed to harness (per MID3), harness fixed, rerun in flight with a new diagnostic line
already showing the walk/rm/ring-delta/unlink-trail data needed to resolve the one remaining
open mystery (the `refuse` arm's unexplained 46s silence). Traps recap: (1) the
already-gate-passed-waiter-kill orphan trap, hit twice this pair of sessions — check the LOG's
START line before any kill; (2) a source edit landing after the build agent's rsync snapshot
is silently **not** in the resulting `.ko` — verify by `strings` for the newest marker string,
not by diffing source.

## Cross-cutting lessons

- **Transaction-refusal ordering is a hard rule now**: D-0531's true root (and the general
  principle GPT extracted from it) is that *any* refusal capable of cancelling a transaction
  must be evaluated before that transaction's first dirty operation. 0.64.17/0.64.18 fixed
  three separate call sites (`free_holder`, `locator_set`, xattr-on-sharded-parent) against
  this same class.
- **`xfs_ilock_nowait` / `xfs_iunlock` pairing must match on the DLM path**: D-0532's
  `xfs_iunlock_nodlm()` is now the required release for any acquire that used
  `ilock_nowait` and therefore skipped the DLM-begin — a second such pairing bug is plausible
  elsewhere and was flagged but not yet swept.
- **Inode reuse across a peer-driven free is the recurring hazard shape** for both D-0533 (stale
  cached identity) and D-0535 (stale attr-fork residue) — this node's own teardown code that
  normally zaps/reconciles state never runs when the *peer* did the free.
- **Chain-relaunch orphans** are now a known, repeated (3×) operational trap in this queue
  style: never trust that killing the driver bash also kills its `timeout`-wrapped child.
