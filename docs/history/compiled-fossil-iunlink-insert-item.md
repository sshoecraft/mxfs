<!-- Compiled sess395-398: platter-fossil di_next_unlinked at insert, F1/F2 to INSERT-mode iunlink item redesign, plus the dead-incarnation relog/typeflip… -->
# Platter-fossil di_next_unlinked at insert, and the dead-incarnation relog it exposed (sess395-398)

One continuous chain on the AGI-unlinked-list machinery: a platter fossil in
`di_next_unlinked` corrupts the bucket chain at insert (sess395) → the first
containment fix breaks the non-empty-bucket case, forcing a redesign to an
explicit INSERT-mode iunlink item (sess396) → that redesign verifies clean and
in the process a second, unrelated root surfaces on the release-drain path: a
dead incarnation gets re-logged without tenure, producing typeflip ESTALE
(sess398). Builds 0.23.1 → 0.23.8.

## sess395 — root proof: bucket head repointed at a freed-then-reused inode

`docs/history/docs/history/docs/history/compiled-fossil-iunlink-insert-item.md`: two
independent lap-3 AGI-unlinked kills (0.23.1 test10 AG10 bucket10; 0.23.2
test27 AG16 bucket16, with new ingress probes) proved the same mechanism.
Upstream's **empty-bucket insert never logs the dinode** and assumes
`i_next_unlinked==NULLAGINO`; `xfs_inode_from_disk` (the only writer) instead
imports whatever the platter slot carries. The platter carries a dead chain
value because a prior removal's NULL never landed home — `xfs_iflush` never
rewrites `nu` for an un-logged passenger slot, and cluster writes skip it. On
a fresh fs, `P-CREATE-NUFIX` fired 29-111×/node in lap 2 — platter fossils are
the norm after one lap, not rare. The earlier sess388 `P-IUNL-FOSSIL-RESET`
only covered `fossil==head`; `head==NULL` (empty bucket) was the hole. Fix
0.23.3: F1 — `mxfs_dinode_nu_clear()` resets a non-NULL in-core
`i_next_unlinked` to NULL on insert entry regardless of head, logging
`P-IUNL-FOSSIL-ENTRY`/cert field; F2 — the empty-bucket branch additionally
clears a non-NULL **buffer** `nu` (`P-IUNL-NUFIX`) before the AGI head update,
using the same NUFIX idiom as the create path.

`docs/rulings/iunlink-insert-fossil-reset-f1-f4.md`
(RULE-5): F1 accepted as correct containment but flagged for weakening the
"already an interior member" detector — keep a per-caller proof requirement
(fresh nlink→0 under lock; tmpfile/EEXIST orphan; orphan-scan only after the
64-bucket membership check) and log old value+gen+head+caller. F2 accepted in
principle (needed, or the next reload re-imports the fossil) but flagged for
lock order: AGI→cluster-buffer must match iunlink precommit, buffer must be
acquired+validated *before* modifying the AGI head, and a gen/incarnation
check is required so a passenger-slot buffer isn't mistaken for this inode's.
F3 (fix ingress instead: never import a fossil for a LINKED image) deferred —
correct as an invariant but needs a decision on effective-linkedness after
LIVESKEW/iunl-store overlays. F4 (online repair of an own-bucket LINKED
not-cached head) ruled detection-only — provenance isn't provable online;
repair belongs to an offline scrub. Seven-mode fault-injection matrix
specified for verification (empty/non-empty, core-only/core+platter fossil,
reload of a linked inode with non-NULL next, stale-image inversion, crash
points around dinode-repair/AGI-update/commit+replay).

**Deploy trap**: `module_swap_deploy.sh` on an aged fs failed its last join —
a dirty shutdown from a prior fossil kill left a slot in TERMINAL REFUSAL
quarantine, `P300-CLAIM-EXHAUSTED` admitting only 31 of 32
(D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376). Harvest evidence before
re-prep clears it.

## sess396 — F1+F2 breaks the non-empty case; redesign to an INSERT-mode item

`docs/history/docs/history/docs/history/compiled-fossil-iunlink-insert-item.md`: A/B
on 0.23.4 (25 AGs, 32/caw). CONTROL (fix off, 20 inj/node) reproduces the
sess395 cascade deterministically on lap 1. TREATMENT (fix on) ran clean for
2 laps (40 injections/node absorbed, zero LIVE/P53/INSFAIL/LOGSAME/shutdown)
before lap 3 died on an unrelated defect (#18, below) — but a residual
`P86-AGI-UNLINKED-BADHEAD` (disk_nlink=1, next=NULL) kept surfacing on
peer-owned buckets, meaning F1/F2 contains but does not close #3.

`docs/rulings/insert-mode-iunlink-item.md`: 0.23.5 lap 5
found F1 alone made the **non-empty**-bucket case worse. Sequence: entry fires
`P-IUNL-FOSSIL-ENTRY` with a non-empty head and resets core `next` — but the
buffer dinode still carries the old fossil value, so precommit's
old_agino==buffer equality check now mismatches
(`P53-IUNLINK-MISMATCH`) → `-EFSCORRUPTED` → shutdown. (Before F1, old_agino
== buffer == fossil, so the apply silently overwrote a live pointer instead —
also wrong, just not caught.) Ruling: replace the inferred-from-NULL apply
with a **dedicated INSERT opcode** on the iunlink item. Every insert —
including the empty-bucket NULL→NULL case — creates an INSERT item. At sorted
precommit, INSERT requires `old_agino==NULLAGINO` but does **not** require
`buffer==old`; if the buffer is non-NULL, log
`P-IUNL-PRECOMMIT-INSERT-FOSSIL` and overwrite it there, at the point where
lock ordering is already sorted. F2's early buffer lock is **removed** — it
was a real ABBA: a buffer locked before the sorted precommit is an unordered
prefix, and a second transaction whose sorted iunlink precommit holds that
same buffer dirty while waiting on the first's inode-item precommit can
deadlock against it. The sess48-era `P-CREATE-NUFIX` (create path) carries
the identical hazard and needs the same conversion — "weeks without a
detected hang" is not proof it's safe. INSERT mode is authorized only where
non-membership is proven (fresh droplink nlink→0, O_TMPFILE/EEXIST-loser,
orphan scan strictly after its membership walk); AG EX alone does not prove
it.

**New facet, not fossil**: same note documents #18
D-NOINO-RELFENCE-AIL-FREEZE-474 (test31) — an AIL-min INODE item sat in
`FLUSHING` (liflags IN_AIL|FLUSHING) for 23s because xfsaild's
`iop_push` skips FLUSHING items before checking them, so existing probes were
blind to it. Instrumentation added (0.23.5:
`b_mxfs_dwskip_n/why/ms`, `b_mxfs_dwsub_ms`, `mxfs_buf_diag_dump()`,
`P-AILMIN`/`P-AILMIN-IBUF`, `P129-FLUSHING-SKIP/-BUF`) with three open
hypotheses (skipped on every submit_nowait pass; left off the delwri list
without completion; FUA re-read disturbing delwri state) — unresolved at
session end, carried into sess398.

## sess398 — INSERT item verifies clean; a second, unrelated root surfaces

`docs/history/docs/history/docs/history/compiled-fossil-iunlink-insert-item.md`:
0.23.6 INSERT-item A/B — CONTROL (fix off) reproduces the kill class at the
3rd injection; TREATMENT (fix on) PASS 32/32 across 3 laps
(`fe==ij, pif==ib, p53=insf=sd=dc=ds=0`); natural laps 4-5 also clean. The
INSERT-mode redesign from sess396 is FIXED AND VERIFIED for the fossil-insert
family. `P86-AGI-UNLINKED-BADHEAD` residual (1-3 occurrences, 7 nodes)
persists — #3 stays open as a separate, still-unattributed signal.
Rig note: TREATMENT re-prep tripped the kmsg-guard FLOOD halt twice — root
cause and fix in `docs/history/docs/history/docs/history/compiled-fossil-iunlink-insert-item.md`
(SCST `mgmt_dbg` burst at every 32-node re-prep; rig trace default changed).

Lap 6 then failed on a **new, unrelated** family: dead-incarnation re-log
without tenure, ledger
`D-RELEASE-DRAIN-RELOGS-DEAD-INCARNATION-WITHOUT-TENURE-TYPEFLIP-398`. Traced
inode: test18 mkdir'd a directory (gen A); a peer removed+freed it; test27
`icreate`'d a *file* in the same slot (gen B) 2s later. On test18's release
drain: `P15-REL-ABORT held_mode=0` (tenure verify had already refused, orph=1)
→ `P-ICD-TENURE-REFUSE` sets `i_dlm_stale + i_dlm_icd_refused` → but the
**P146V "unlanded" re-log arm still fires anyway**
(`P146V-UNLANDED incore[dir gen=A] disk[file gen=B] — re-logging core`),
writing the dead directory incarnation back over the live file's platter
image (`P56-DIRWRITE logged=1 relflush=1`) → xfsaild
`P56-CORESIDENT-DIR-SKIP` → both nodes hit `P201-TYPEFLIP-UNRESOLVED-FAIL`,
ESTALE. Existing guards all missed it for structural reasons: `P146D` needs
`i_mxfs_dead_incarn_gen`, set only by a dirent-validated reload (never set
here); `P189` needs gen *equality* (genuinely different gens here, so no
alarm); `P218`'s passenger filter only drops *un-logged* slots (this write is
logged). GPT ruling: never synthesize a re-log at `held==0`; gen
(in)equality is never grounds for an exception — this is a straight ABA;
directories require EX, not PR, for this decision; `i_dlm_icd_refused` must
veto re-log outright; on a genuine foreign gen, poison+mark stale instead of
relogging; on the same gen, treat as not-durable and merge at the next
acquire rather than force a write now; a durable write-side backstop
(tenure/epoch provenance token carried on logged slots) is flagged as
follow-up work, not required for this fix. Fix 0.23.8:
`mxfs_dlm_relog_authorized(ip, site, disk_gen)` gates both the P146V arm
(before `mxfs_dlm_bast_process`) and the P182 pre-merge path; new probe
`P146V-NOAUTH-REFUSE` on refusal.

Also landed in 0.23.7/0.23.8, closing the sess396 ABBA warning: the
create-path `P-CREATE-NUFIX` converted to the same sorted-precommit INSERT
item as the iunlink insert (site 2), with O_TMPFILE's two-items-per-txn case
handled (cert retired only by its owning item) and an `inj%5` injector
matrix (`tests/tmpfile_churn.sh`) added for regression coverage.

## Recurring lessons across sess395-398

- A platter-slot fossil (`di_next_unlinked` or `nu`) surviving because an
  un-logged passenger slot was never rewritten is a **class** of bug on this
  codepath, not a single fix — it hit insert (F1/F2/INSERT-item) and,
  structurally, the same un-logged-passenger gap underlies why the sess398
  re-log guards were all individually blind.
- A containment fix (F1 reset) that's locally correct can still break an
  adjacent case (non-empty bucket) that wasn't in the original evidence —
  always run the full fault-injection matrix, not just the reproducing case,
  before calling a fix verified.
- Locking a buffer early, ahead of a transaction's *sorted* precommit phase,
  is a standing ABBA hazard on this codepath (hit twice: F2's empty-bucket
  buffer lock, and `P-CREATE-NUFIX`'s equivalent in the create transaction) —
  route any such write through the sorted-precommit item mechanism instead of
  an ad hoc early lock.
- `module_swap_deploy.sh` can fail its last join on an aged fs if a prior
  dirty shutdown left a slot in terminal-refusal quarantine
  (`P300-CLAIM-EXHAUSTED`, D-376) — harvest evidence before re-prep clears it.
- `make modules` mid-lap-series triggers an unwanted re-prep (srcversion
  mismatch check in run.sh); compile-check a single object instead:
  `make -C /usr/src/linux-headers-6.8.0-101-generic M=/src/mxfs xfs/libxfs/<file>.o`.
- Keep raw fleet dmesg payloads inside subagents and request tight filters —
  two prior sessions (393/394) died on the Fable safeguard flag from dumping
  raw dmesg into the parent.
