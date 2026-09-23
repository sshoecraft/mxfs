# Authority certificates and the token producer

The foreign-slice replayer applies a dead node's buffer image only when the
image's **authority token** names a tenure the fence-time recovery manifest
confirms the victim held at death (`docs/recovery-manifest.md`).  This file
covers the *producer* side: how a buffer log item earns its token, and the
per-inode **certificate** most tokens are derived from.

## The certificate (`xfs/xfs_mxfs_dlm.c`)

Per in-core inode: `i_mxfs_auth_state` ∈ {NONE, UNPUBLISHED_EX, DURABLE_EX,
RELEASING} with `{kind, resource, epoch, lineage, incarn}` and a monotonic
`i_mxfs_auth_gen`.  Only DURABLE_EX with a nonzero epoch proves anything.

- **Install** — `mxfs_inode_authority_install_durable_ex_locked()`, only from
  a *completed* grant result (`struct mxfs_grant_result`) and only when the
  caller's gen snapshot (taken under `i_dlm_lock` before the blocking acquire)
  still equals `i_mxfs_auth_gen`.  Refusals, each counted and recorded as the
  inode's last install attempt (`i_mxfs_auth_try`, P241): non-proving grant
  status, gen moved (STALEGEN), RELEASING, unpublished, routing mismatch
  (cluster vs per-inode backing), reclaim/shutdown, and a grant epoch this
  node's journal already certified clean-released (P-RELMARK-REINSTALL-REFUSED).
- **Begin release** — moves DURABLE_EX → RELEASING and bumps the gen at
  release-BEGIN, before the slot is peer-visible; **revoke** → NONE with an
  unconditional gen bump.  Every relinquishment moves the counter, which is
  what makes the snapshot/recheck pair sound against a late completion.
- Consumers of DURABLE_EX are the token producer, the publication tripwire
  (`mxfs_inode_authority_check_published`), phantom-loss detection and the
  same-tenure advance.  Nothing else reads it: it is a replay certificate,
  never a fast-path enable.

## The producer (`pal/linux/xfs_buf_item.c`)

`mxfs_bli_auth_capture()` runs from `xfs_trans_dirty_buf` — the first
protected dirty of a buffer in a transaction window — and resolves the ladder
ONCE (`mxfs_auth_classify(tp, bip, mp, out)`); format only serialises it:

1. superblock → CLASS_SB, UNPROVEN;
2. AG-authorised family (AGF/AGI/AGFL, AG btrees by `b_ops` **and** BLFT) with
   a nonzero durable AG grant epoch → CLASS_AG, VALID;
3. **iunlink image of an inode cluster** (sess468, fix shape B) → CLASS_AG,
   VALID: `mxfs_buf_iunlink_ag_authorized()` — `xfs_inode_buf_ops` + BLFT
   DINO, logged in the `xfs_trans_inode_buf` form (`XFS_BLI_INODE_BUF`, not
   ALLOC/STALE), dinode 0 verified (magic, v3, meta uuid, plausible ino), the
   ino maps to this AG and this buffer, and the transaction holds that AG's
   AGI.  Recovery of that form applies only `di_next_unlinked`
   (`xlog_recover_do_inode_buffer`), so the AG grant never vouches for an
   inode core; the replayer refuses a class-AG DINODE token without
   `XFS_BLF_INODE_BUF` as MALFORMED (`P-IUNLINK-AGCLASS-SHAPE`);
4. otherwise the INODE arm: derive the owner from the block's own v5 header
   (`mxfs_buf_derive_owner`), look the inode up RCU-only, and take the
   certificate → CLASS_INODE VALID, or the specific non-proving status
   (OWNER_UNKNOWN / INCOMPLETE / AUTH_NOT_CACHED / AUTH_NOT_HELD / …).

Every non-durable INODE-arm outcome is named on the producer
(`P239-OWNAUTH-NONDUR blkno len blft outcome ino mode unpub gen try comm`,
bounded per outcome), because the wire token flattens them all to
MISLABELLED and the replayer cannot otherwise say *why* an image is classless.

## Inactivation (sess468, fix shape A)

`xfs_inactive` takes its cluster-wide EX through the **raw** acquire
(`mxfs_v5_dlm_inode_lock` / `mxfs_iclus_lock` with a grant result), never
`mxfs_dlm_ilock_begin`, because an `I_FREEING` inode must not be reloaded.
Until 0.64.7 that path installed no certificate, so every truncate/ifree image
of a dying node's `rm` was captured NONE/RELEASING at a writing mode and the
whole transaction was policy-refused at replay (chain 93: 39 classless bmbt
images per burst, FSWIDE quarantine).

Now (`mxfs_dlm_authority_gen_snapshot` / `mxfs_dlm_inactive_authority_install`
/ `mxfs_dlm_inactive_authority_revoke`):

- the gen is snapshotted before each blocking acquire (again after the
  `-EDEADLK` demote-and-retry, which moves it);
- the certificate is installed from the completed grant result through the
  one install routine — all refusals above apply, so a recycled or rerouted
  inode aborts the install (fail closed, images stay classless) — *before*
  the first truncate/ifree dirty; `P-INACT-CERT ino installed try …` names
  the outcome;
- at INACT-EXREL, after the ifree-end drain and before the raw DLM release,
  the certificate is revoked by the **exact** identity that was installed.

### 0.64.8/0.64.9 — the design-consult review rework (sess469)

The first implementation (0.64.7) was reviewed STOP-SHIP twice; the shipped
shape is:

- **A refusal aborts the free.**  `P-INACT-CERT-REFUSED` → the zombie is
  handed to the deferred reap (`mxfs_defer_reap_cert_refused`, which counts
  refusals on the reap entry) and `xfs_inactive` exits through `out:` with a
  plain grant release, before any truncate/ifree dirty.  The only approved
  classless case is UNPUB (inode still on the unpublished list, ruling Q3).
  After `MXFS_INACT_CERT_REFUSE_MAX` (8) refusals of one zombie the refusal is
  permanent (routing/relmark class) and the node fails closed
  (`P-INACT-CERT-REFUSED-ESCALATE` + shutdown) — never by permitting the free.
- **Exact identity.**  The install wrapper reads `{kind, resource, epoch,
  lineage}` back under `i_dlm_lock` (`struct mxfs_inact_cert_id`), so a
  same-tenure ADVANCE past the grant result's epoch is matched.  The revoke
  returns REVOKED, GONE (no proving certificate left) or FOREIGN (a different
  proving certificate).  **GONE and FOREIGN both fail closed** (`P-INACT-CERT-
  GONE` / `P-INACT-CERT-FOREIGN` + shutdown): a certificate moved while the
  inactivation was dirtying under it may have left classless images, and a
  foreign one would outlive the release.
- **Loss detection.**  `i_mxfs_auth_inact` tracks the certificate's lifecycle
  (ACTIVE → LOST / DEFERRED → NONE).  Any `revoke`/`begin_release` by a
  release-side actor while ACTIVE prints `P-INACT-CERT-LOST by=… L…` (the
  actor's line) — that is the forensic answer for a later GONE.
- **Publication.**  The tuple is written under `i_dlm_lock` but the token
  producer reads it under `i_flags_lock` from an RCU lookup; a
  `seqcount_spinlock_t i_mxfs_auth_seq` (associated with `i_dlm_lock`) brackets
  every writer and the producer's read, so a token can never carry one
  tenure's epoch with another's lineage.
- **Per-attempt grant result.**  `memset` before the first acquire and every
  `-EDEADLK` retry; the routing decision is computed once and used for the
  acquire, the install, the census and the unlock (a sticky-flag disagreement
  is a ROUTING refusal → abort).
- **DEFER.**  P128-INACT-DEFER marks the certificate DEFERRED with the cached
  grant; `mxfs_dlm_evict` asserts it just before its begin-release
  (`P-INACT-CERT-EVICT cls=…`): an epoch-0/other-incarnation certificate or one
  an inactivation left ACTIVE is authority-state corruption → shutdown.
  **0.64.14 (D-0529, sess471-472).**  The first fleet run of that assertion
  (chain 109, 0.64.12) shut test1/test2 down on *every* deferred-free evict:
  the check compared `auth_incarn` (the install-time `i_generation`) with the
  current `i_generation`, and `xfs_ifree` bumps the generation by exactly one
  at the free — so a legitimate deferred tenure could never match
  (128 lines, all `gen == incarn+1`, `was=DEFERRED free_committed=1`).  The
  design-consult ruling rejected shifting `auth_incarn` after the free (it is the
  immutable install-time identity carried in tokens, revoke acks and the log)
  and accepted the narrow recogniser: cls 0 also when the certificate is
  DEFERRED, `MXFS_IF_FREE_COMMITTED` is set and
  `i_generation == (u32)(auth_incarn + 1)`.  A reused inode number
  re-randomises the generation at create, so it never lands in that window;
  every other mismatch is still cls 2 → shutdown.
  The window is a proof, not a probability, because of two invariants it
  rests on (design consult, sess582): the old certificate and the
  `FREE_COMMITTED` flag never survive into a reissued incarnation — the check
  itself retires the certificate to NONE, `mxfs_dlm_inode_init` resets the
  whole authority block on a fresh `xfs_inode`, and `MXFS_IF_FREE_COMMITTED`
  is in `XFS_IRECLAIM_RESET_FLAGS` so a recycled shell starts without it — so a
  new incarnation whose random generation happened to equal the old plus one
  would meet no certificate to match; and `FREE_COMMITTED` is set only after
  `xfs_trans_commit` returned success, so the `+1` never describes a free
  that did not commit.  What cls 0 does NOT prove is that the grant may be
  released: after a log shutdown the session is POISONED and every release
  through `mxfs_dlm_evict`'s begin-release is refused by the poison gate
  (`docs/tcp-authority-ledger.md`), so a deferred tenure whose free committed
  but never destaged stays held for the survivor's manifest.
- Census: `P-INACT-CERT-TOTAL revoked gone foreign lost evict_ok evict_gone
  evict_foreign evict_active` beside every `P228-TOKCLASS`.

Verification knobs (`mxfs.inact_cert_inject`, TEST ONLY): 1 refuse every
certificate (free must defer, then escalate after 8), 2 corrupt the saved
identity (FOREIGN → shutdown before the release), 3 force the `-EDEADLK` retry
with a poisoned result, 4 advance the installed epoch past the grant result
(exact revoke must still hit), 5 a release-side actor moves the certificate
before INACT-EXREL (LOST + GONE → shutdown), 6 (0.64.24) a DEFERRED
certificate is made to look like another incarnation's at evict (cls 2 →
shutdown), 7 (0.64.24) the inactivation leaves the certificate ACTIVE (evict
cls 3 → shutdown).  `mxfs.ifree_drain_ms=0` forces the DEFER arm — though
with `mxfs.ifree_eager_durable=0` (the default) every free on the rig already
DEFERs (chain 108 s473c, sess474), so the deferred retirement through
`mxfs_dlm_evict` is the COMMON path and the sync INACT-EXREL revoke (knobs 2
and 5) is only reached with `ifree_eager_durable=1`, which the foreign and
gone arms now set for their rm.  Mandatory arms (ruling): the 32-node kill/replay primary arm,
refusal injection, permanent-refusal escalation, `-EDEADLK` with poisoned
result, ADVANCE + exact revoke, FOREIGN injection, forced GONE, and DEFER →
evict through DURABLE_EX → RELEASING → NONE with no token after NL.

A certificate on an `I_FREEING` inode attests a real DLM EX tenure, not VFS
reachability; it clears no `I_FREEING`, takes no reference, and enables no
fast path.

## Still classless by design

Images of an inode still on the unpublished list (UNPUBLISHED_EX) — a locally
created, never-published inode's bmbt blocks — have no durable slot of their
own and stay classless until a real delegation protocol exists (ruling Q3:
inferring from the co-present ICREATE/AG images is a false-APPLY hazard and is
not done).

## Evidence
- `P228-TOKCLASS n ag iunlink_ag sb mislabel noepoch unknown incomplete` and
  `P239-OWNAUTH …` (producer, every 1023 captures);
- `P227-TOKENSUM … classless … dino_none dino_agsib` (replayer, per txn);
- census lap `tests/intents_classless_attribute.sh`; verification arms
  `tests/d_intents_undischarged_verify.sh burst|clean`
  (chains 103 and 105, sess468).

## CANCEL records carry the proof too (0.64.34, sess476)

Chain 105 (the intents burst: a node dies inside an EFD hold with fragmented
rm transactions in its slice) kept ATOMIC-SKIPPING the victim's rm
transactions after the inactivation certificate and the iunlink AG class had
landed: `buf_items=6 tokened=5 untagged=1`, one untagged buffer item per
transaction.  The 0.64.32 probe (`P227-UNTAGGED blft= flags= cancel=`) named
it: **208 of 208 untagged items were `XFS_BLF_CANCEL` records** (chain 105
s475b).  By construction: `xfs_buf_item_format_segment` appended the trailer
only `if (!(bli_flags & XFS_BLI_STALE) && wants_authority)`, and
`xfs_trans_binval` set STALE/CANCEL, cleared the BLFT and the data map and set
`XFS_LI_DIRTY` directly — no `xfs_trans_dirty_buf`, so no capture either.  Every
transaction that frees a metadata block (bmbt collapse, dir/attr block, AG
btree block, inode cluster) was therefore unreplayable by a survivor.

Design-consult ruling (`docs/rulings/cancel-item-untagged-fixa-tokenize-binval-pass1-verdict-aware.md`):
**fix A** — a CANCEL is not inert (its pass-1 table entry suppresses every
earlier image of the block, an effect that needs authority over *that* block;
the sibling AGF/bnobt images prove other resources), so tokenize it; the
"allowlist CANCEL as a no-image item" shape was rejected.

**Producer.**  `xfs_trans_binval` calls `mxfs_bli_auth_capture` *before* the
stale conversion, while the BLFT, `XFS_BLI_INODE_BUF` and the block's own
header (the owner derivation reads it) are intact; first-capture semantics are
the capture's own.  `xfs_buf_item_size` (stale branch) and
`xfs_buf_item_format_segment` (the STALE exclusion is gone) both carry the
trailer — the two predicates are identical, an underestimate overruns the CIL
shadow buffer.  The format-time "BLFT changed since capture" void tolerates
exactly the stale transition (STALE && CANCEL && blft_now == 0) and nothing
else.  A bmbt CANCEL therefore rides class INODE with the owner's grant epoch
and lineage; an AG btree CANCEL rides class AG.

**Replayer, part 4 — the pass-1 cancel table is built from ADMITTED
transactions only.**  Upstream pass 1 adds every CANCEL to
`l_buf_cancel_table` before any verdict exists; a transaction pass 2 then
REFUSES (no puts) leaves its entries in place and they suppress an *earlier,
admitted* transaction's image of the block — a torn admitted transaction
before any quarantine publishes.  GPT's inline pass-1 classifier is unsafe
here for a reason it did not know: clean-release markers are inserted by pass 1
*as it reaches them* (`xlog_recover_relmark_commit_pass1`), so an early
transaction classified inline misses a later marker and refuses what pass 2
admits as REDUNDANT_CLEAN — common (a per-AG release lands after almost every
AG image), and a skipped add would let a stale earlier image land on a block
the victim had reused.  So a CANCEL-bearing untrusted transaction is **parked**
through pass 1 (`mxfs_cdefer_stash`: `r_mxfs_deferred`, items kept on
`log->l_mxfs_cdefer`, its cancel entries added as before) and decided once the
walk is complete (`mxfs_cdefer_resolve`, called between the passes in
`xlog_do_log_recovery`): the same classifier run *pure* (`publish=false`:
counters into a scratch copy of the evaluator, no telemetry line, only
`rman_abort` copied back), and a transaction whose verdict means "pass 2 runs
none of its items" (SKIP / SBCLEAN / PREINC) gets one
`xlog_put_buffer_cancelled` per CANCEL item — exactly undoing its adds.  The
verdict is remembered by (tid, lsn) and pass 2 must reach the same one
(`mxfs_cdefer_verify`: `P-FR-PASS-VERDICT-MISMATCH` aborts the attempt with
-EIO, retryable, nothing published).  A REDUNDANT CANCEL is no longer skipped
by the per-item REDUNDANT skip (its put must run); a CANCEL whose put misses
never falls through to a buffer write (`P-FR-CANCEL-PUT-MISS`, then the
cancelled path).  Report-only apply-all mode parks nothing.

Probes: `P-FR-CANCEL-PASS1 txns= refused= cancel_kept= cancel_suppressed=
put_miss=` (once per attempt), `P-FR-IMAGE-CANCELLED-SKIP blkno= len= lsn=`
(an image the table suppressed, untrusted replay only), `P227-TOKENSUM
untag_cancel=` (must be 0 on a 0.64.34+ producer).

**Negative arms** (`dbg_cancel_token_forge`: 1 = skew the captured grant epoch,
2 = mis-target the resource; `P-DBG-CANCEL-FORGE` on the producer):
`tests/d_intents_undischarged_verify.sh` with `FORGE=1|2` requires reason=1
(POLICY-REFUSED), >= 1 ATOMIC-SKIP, `P-FR-CANCEL-PASS1 refused>=1
cancel_suppressed>=1`, and **zero** `P-FR-IMAGE-CANCELLED-SKIP` — a refused
CANCEL suppresses no image.  `STRICT_TOKENS=1` is the positive set: reason=8
only, zero ATOMIC-SKIP, zero classless, zero untagged CANCEL, `refused=0`,
zero `P-AUTHCAP-VOID` on the victim, zero put-miss / mismatch.
