# TCP authority ledger — VIEW RECORD + membership barrier (design v3, sess428)

Status: BUILD STEP 1 LANDED (sess429, 0.39.0): format v3 constants, the
view/root structs and the header-only digest/crc/validation/HRW helpers
(`include/mxfs/mxfs_tauth.h`), portable SHA-256
(`include/mxfs/mxfs_sha256.h`), PAL-backed root/view I/O
(`dlm/tauth_view.{c,h}`), mkfs writes the mkfs ROOT (view slots A/B zero),
`chk_mxfs` validates the control pages (`TCP authority view ...... OK`), and
`tests/tauth/view_format_test` (34 checks against the committed vectors
`tests/tauth/vectors/{view_v1,root_v1}.bin`) is part of the usermode gate.
v1/v2 regions are refused (`MXFS_TAUTH_VERSION` 3).  Steps 2+ (proposals,
ballots, the barrier) are NOT built.  Design history: v3 after two design-consult
passes; pass 5 gave the GO for step 1.  Pass 2 (ccmemory
`…-sess428-GPT-review2-view-record-spec-v2-nogo-step1`, findings R1-R7) was a
NO-GO for build step 1 until the manifest lifetime (R1), the root nonce /
ambiguous-CAW rule (R5) and the byte-level format (R6) were frozen — §11-§13
below freeze them; R2, R3, R4, R7 are folded into §3.1, §5 and §7.  Target of
D-TCP-LEDGER-SMALLFILE-WORKLOAD-PACE-the budget rule-0349.  Rulings: `docs/rulings/d0349-view-table-barrier-design.md` (shape),
`…-sess428-GPT-review-view-record-barrier-spec-20-findings` (this revision
answers every finding; F<n> below cites them), `…-sess428-GPT-ruling-d0349-
eager-page-activation` (refused shapes).  Supersedes build-order step 4's
per-page ordered handoff as the AUTHORITY model; the page store, grant
records and blocker import are unchanged.

## 1. Problem being solved

Format v2 sizes the ledger from the device: 67,651 pages on the rig.  Today
authority is durable PER PAGE (`mxfs_tauth_page_hdr.auth_state/auth_node/
authority_epoch`); establishing or moving it costs 1-3 serialized page writes
per page, and a page is acquired only on its first request (the requester is
parked and retries at 100 ms).  Measured: 1092 `P-TAUTH-REMASTER-PARKED` on
1083 distinct pages in one 30 s workload; an eager per-page pass was refuted
(bootstrap serialization, formation_test 9 fails).  Any per-page scheme is
O(pages) per membership change.

## 2. Invariants that must survive

I1  A page is decided on by exactly one durable authority at a time.
I2  Every in-flight commit under the old assignment is durable or
    conclusively failed before the new assignment can decide (drain).
I3  A node the view calls dead cannot commit after the survivors proceed
    (false-death exclusion: storage fence + incarnation, never a timeout).
I4  Grant records are page-scoped durable blockers regardless of which
    generation created them; a new owner imports them before deciding.
I5  Fail closed: with no valid committed view, nothing is granted.
I6  Incarnations are never reused; a restart is a new incarnation that is a
    non-member until a later committed view includes it (F17).

## 3. Key observation

The owner map is a FUNCTION of the committed member list: `owner(page) =
member[bucket(page)]` where bucket() is a stable mapping (§3.1).  The durable
"view table" is ONE record — the committed member list — not a per-page
map.  Moved pages between generations are computed on every node from the
two lists.  Owner identity is the TUPLE `{node, inc}`: a page is MOVED when
the tuple differs, so a node that restarted at the same list position moves
every page it owned (old inc purged before the new inc decides) (F4).

### 3.1 Placement (F16)

`page % count` moves nearly every page on any membership change.  Use
rendezvous (HRW) hashing over a STABLE placement identity (R7): the member's
heartbeat slot, never its incarnation (a same-position restart must not
remap unrelated pages):

    x              = ((u64)page << 16) | (u64)m.slot          /* page < 2^20, slot < 64: no overlap; u64 wraparound arithmetic throughout */
    z = x + 0x9E3779B97F4A7C15; z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB;  score = z ^ (z >> 31)   /* SplitMix64 finalizer; mix64(0) = e220a8397b1dcdaf, mix64((5<<16)|3) = 4f9e38f1a4abce77 */
    owner(page)    = the member with the highest score; tie → lowest slot
    authority      = {owner.node, owner.inc}               /* the tuple that decides */

Every member is eligible.  Adding/removing one member moves ~1/count of the
pages.  The member list is still the only durable input.  Build step 3
measures the worst-case moved set, drain time and post-commit import burst
against the 6 s target.

## 4. On-disk format (region v3, PROTO_GEN 9 → 10, mkfs required)

Region: `hdr[2] | control[3] | pages copy0[npages] | copy1[npages]`
(`MXFS_TAUTH_CTRL_PAGES = 3`; `mxfs_tauth_page_off` adds it).  A v2 region
is refused (version 3 required): mkfs reformats, so NO legacy grants
survive the cutover (F15).

Two records (byte-level layout frozen in §13, which is authoritative):

- `mxfs_tauth_view` — control slots A/B: generation, predecessor
  {gen, digest}, coordinator ballot, membership {epoch, digest}, the sorted
  member list `{node, slot, inc}[64]`, the embedded fence-and-recovery
  certificates of the members removed since the predecessor (§11), a
  128-bit nonce, SHA-256 digest, crc32c.
- `mxfs_tauth_root` — control page +2, one device logical block: the
  committed {slot, gen, digest}, the coordinator ballot, fs identity, a
  128-bit nonce, crc32c.

Root writes are SCSI COMPARE-AND-WRITE of the ENTIRE logical block
(compare = the last image read, every byte, nonce included; a fresh
non-repeating nonce on every write, ballot and no-op writes included)
(F12, F19).  4Kn devices: the root is one aligned 4 KiB block.

Proposal identity = `{prev_gen, prev_digest, gen, digest, ballot}` (F7); a
generation number alone never identifies a promise, a freeze or a wakeup.

Per-page fields: `mxfs_tauth_page_hdr.config_epoch` / `mxfs_tauth_entry.
config_epoch` carry the view generation the transition was authorized under
— PROVENANCE only, older than the current view on untouched pages (F9).
`auth_state/auth_node/authority_epoch/target_*` become diagnostics; no code
path consults them after the cutover (F15).

Write ordering (F11): slot write = FUA write, then a durability barrier,
then a full readback validation (structure, identity, digest, crc, gen,
predecessor); the root CAW only after that; the root-selected slot is never
overwritten (proposals always target the OTHER slot); `chk_mxfs` rejects a
root whose slot fails validation.

## 5. Coordinator = single storage writer (F2, F3, F13)

Before any slot write the would-be coordinator (the bootstrap node: lowest
live heartbeat slot under a settled membership) must:

1. hold an exclusive coordinator token enforced by storage — a dedicated
   SCSI PR reservation key/role for "ledger coordinator" (the existing PR
   fencing machinery), taken only after the previous coordinator
   incarnation has reached the disklock recovery stage FENCED: PREEMPT AND
   ABORT proven on every path (multipath included), reservation verified,
   its outstanding I/O drained (R4; docs/recovery-manifest.md stage
   machine).  The fence is a precondition, not a consequence (F13): an
   unresponsive coordinator that cannot be fenced leaves the cluster
   fail-closed;
2. install its BALLOT in the root by full-block CAW: `ballot = root.ballot
   + 1` with `{coord_node, coord_inc}`, gen/slot/digest unchanged, nonce
   fresh.  Ballots are therefore monotonic across ALL coordinators and
   incarnations — the root is the allocator and the full-block CAW makes
   two installs of the same ballot impossible; a node accepts a
   PREPARE/ABORT only if its `{coord_node, coord_inc, ballot}` EQUALS the
   currently validated root's (R3; a lower or a higher-than-root ballot is
   both refused — the root is re-read on mismatch).  `ballot` is u64; the
   allocator REFUSES to install when the validated `root.ballot >=
   UINT64_MAX - 1` (it never CAWs a root with ballot `UINT64_MAX`), and an
   on-media `root.ballot == UINT64_MAX` is a validation failure (fail
   closed, operator repair);
3. only then write the inactive slot and run the barrier.

A coordinator may CAW-commit only while it still holds the token and the
root still carries its ballot; every node accepts PREPARE/ABORT only from
the ballot the root names and only while the proposal's prev_gen/
prev_digest match the root (F3, F14).

## 6. In-memory state per node

    committed {gen, digest, members[], ballot}      what the root names
    proposal  {identity, members[], moved set}      a PREPARE we ACKed
    frozen[page]                                    moved pages under the proposal
    imported_gen[page]                              in-memory (F9): the view gen the
                                                    page's blockers were validated under
    view_state ∈ {NONE, STEADY, PREPARED}

Routing: `master(res) = owner(page(res))` under COMMITTED members (never
the local active-node list).  Decision gate:

    may_decide(p) = view_state != NONE && owner(p) == {me, my_inc}
                    && !frozen[p] && imported_gen[p] == committed.gen

`imported_gen[p]` is advanced by the ordinary lazy blocker import of the
page's durable records (unchanged code) — no page write.  Only pages newly
owned under this generation (or invalidated by a purge) import.

A remote LOCK_REQ carries the requester's committed gen + digest.  Mismatch
→ `MXFS_ERR_REMASTER` (requester re-reads the root, re-routes).  Frozen page
→ `MXFS_ERR_VIEW_PREPARED` returned promptly; the requester waits LOCALLY on
a proposal-identity-aware, cancellable wakeup that honours the operation's
deadline and holds no lock/RPC/admission state; it re-routes after root
validation; the wait does not consume the caller's RETRY budget (F20/Q4).

## 7. The barrier

Trigger: the membership service reports a settled active set (20 s settle
window, as today) with a certified `memb_epoch`/digest (F10) that differs
from the committed members.  Validation of a member list (every node, every
PREPARE): unique node ids, unique heartbeat slots, nonzero incarnations,
sorted, 1 ≤ count ≤ 64; otherwise the proposal is refused (F10).

0. FENCE + MANIFEST.  For every member being REMOVED `{node, inc}`: storage
   fence complete (PR preempt, outstanding writes resolved) and recovery
   purge complete.  The coordinator writes an immutable RECOVERY MANIFEST
   record `{old view gen/digest, removed [{node, inc, fence result/epoch,
   purge scope/completion}], manifest_gen, SHA-256}` (the existing
   recovery-manifest region, sess404, gains this record type) and binds
   `{manifest_gen, digest}` into V' and later into the root (F5, F18).
   Manifests are retained for late validation/repair.
1. PROPOSE.  Coordinator (holding token + ballot, §5) builds V' = {gen =
   committed.gen+1, prev = committed, members = certified set with their
   incarnations, memb_epoch/digest, manifest binding}, writes it to the
   inactive slot with the ordering contract of §4.
2. PREPARE(identity, memb_epoch/digest, manifest binding) to every node in
   `survivors(committed) ∪ V'`.  Each recipient:
   a. verifies root ballot == PREPARE ballot and root gen/digest == prev
      (else NACK(root state); coordinator re-reads and restarts);
   b. validates the member list and memb_epoch against the membership
      service;
   c. computes the moved set (owner tuple differs);
   d. DRAIN as OLD owner of moved pages — the linearization rule (F8):
      under each page's lock: close admission, stamp the page with the
      proposal identity, reject/redirect every later decision op
      (`VIEW_PREPARED`); then wait for every previously admitted mutation,
      publish, release and durable callback on those pages to finish;
      every delivered grant is discoverable in durable state; async
      completions are generation-gated so none can mutate under the old
      ownership after the ACK; releases remain idempotently processable by
      the new owner after its import (never dropped for a stale request
      generation);
   e. as any node: stop originating requests to OLD owners of moved
      pages; local waiters on those pages move to the wakeup (§6);
   f. ACK(identity, node, inc, drained).  No per-node persisted promise
      (F17/Q1): I6 makes it unnecessary; the heartbeat descriptor may carry
      it as diagnostics only.
3. COMMIT.  ACK condition (F1): every SURVIVING old member, every admitted
   NEW member, and every reachable voluntarily-departing old member has
   ACKed the exact identity; for each unreachable removed incarnation the
   manifest record of step 0 (its durable fence-and-recovery certificate)
   SUBSTITUTES for its ACK.  A missing ACK from a survivor is never timed
   out: the node ACKs, or the membership service removes it → fenced +
   purged + manifest → the barrier restarts with a new proposal (new
   identity, same or new ballot).  Then the coordinator, still holding
   token + ballot, CAWs the root (full block) to {slot', gen', digest',
   ballot, manifest binding, fresh nonce}.
4. RESUME.  COMMITTED(identity) is broadcast; every node — and any node
   that missed the message, on any of: COMMITTED, ABORT, coordinator
   change, conflicting PREPARE, REMASTER — reads and validates the root
   (F14).  Root at the proposed gen → install committed = V', clear the
   freezes of THAT identity, wake waiters, NEW owners open admission (lazy
   import on first decision, I4), old owners drop master-role entries for
   moved pages (own held grants survive as mirrors).  Root still at prev →
   only the root ballot's ABORT(identity) or a superseding PREPARE clears
   the freeze; a same-gen ABORT with a different identity is ignored (F7).
   Never roll back an installed committed generation.

Formation: root {gen 0, slot none}: every node parks all requests (I5)
until the first COMMITTED (gen 1) — replaces the per-page UNOWNED bootstrap
chain.  Cost: fence/token + ballot CAW + one slot write + one root CAW.

## 8. Failure cases

- Coordinator dies before the root CAW: the next bootstrap node fences the
  old coordinator incarnation (F13), takes the token, reads the root (still
  prev, old ballot), installs its ballot; nodes holding a freeze for the old
  identity keep it until this ballot's PREPARE/ABORT arrives (F14).  The old
  coordinator can never CAW again: fenced, and the root block changed.
- Coordinator dies after the root CAW: successor reads root = gen' →
  COMMITTED(identity); never rolls back.
- Member dies mid-barrier: fence + purge + manifest, restart with V''.
- Node crashes after ACK: new incarnation, non-member until included (I6).
- Two coordinators: impossible by construction (§5: token + ballot CAW);
  a stale one's slot write cannot be the root-selected slot (§4) and its
  CAW fails on the nonce.
- Root unreadable / slot fails validation / ambiguous: fail closed
  cluster-wide, loud; `chk_mxfs` repair from the redundant validated state.
- Stale requester gen → REMASTER → re-read root.

## 9. What stays as it is

Page store (two copies, seq/nonce, CAW ticket+publish), grant records and
their durable-before-deliver commit, release ACK/re-send, blocker import on
first decision (`dlm_ledger_import_page`), recovery purge of a dead
incarnation's records, seal/manifest path, `P-TAUTH-*` stats.

## 10. Cutover (F15) and build order

Cutover is atomic by format: v3 regions exist only via mkfs, which writes
root {gen 0}; a v3 mount NEVER runs the legacy per-page authority code
(`dlm_page_ensure_mine` / `dlm_page_acquire` / FREEZE_REQ chain removed in
step 4; until then the v3 path refuses to mount).  No dual-authority window.

1. Format v3 + `mxfs_tauth_view` / `mxfs_tauth_root` / manifest record +
   SHA-256 in the PAL (kernel crypto / usermode impl) + mkfs/chk.  Usermode:
   root full-block CAW semantics, nonce rule, slot/digest/crc/predecessor
   validation, torn-slot tolerance, chk rejection matrix.
2. Committed-view state + HRW routing by committed members + REMASTER on gen
   mismatch + fail-closed with no view + `imported_gen`.  Usermode: requests
   park until a view exists; a non-member gets no grants.
3. Coordinator token + ballot + barrier messages (PREPARE/ACK/NACK/COMMITTED/
   ABORT) + moved-set drain (F8) + wakeup (§6) + manifest binding.  Usermode
   12-node ramp: one barrier per settled change, zero parked round trips,
   coordinator kill before/after the root CAW, member kill mid-barrier,
   same-position restart (F4), duplicate-slot proposal refused (F10),
   worst-case moved-set measurement (F16).
4. Retire per-page authority; v3 mounts enabled.
5. Rig: 32/tcp formation wall, `tests/tcp_token_plumbing_verify.sh` workload
   < 6 s, d0287 remaster measure, crash-matrix rows touching mastership.

## 11. Manifest binding and lifetime (R1, F5, F18)

The per-victim sealed recovery manifest (docs/recovery-manifest.md: header
{victim slot, incarnation, recovery_gen, fence_term, seq, count, crc32c,
seal}) is the fence-and-recovery certificate.  It lives in a per-heartbeat-
slot rman slot that a later occupant of that slot overwrites, so the view
must not depend on it staying readable.  Therefore the VIEW RECORD EMBEDS
the certificate essentials for every member removed since `prev_gen`:

    struct mxfs_tauth_removed {          /* 48 B, one per removed member, sorted by slot */
        u32 node; u16 slot; u16 stage;   /* stage: the disklock recovery stage reached
                                          * (>= FENCED required; PURGED for pages) */
        u64 inc;                         /* the removed incarnation */
        u64 recovery_gen; u64 fence_term;
        u64 manifest_seq; u32 manifest_crc; u32 manifest_count;
    };

The coordinator reads and validates the sealed manifest (header crc, seal
marker, victim inc match) BEFORE writing the proposal; the view's SHA-256
covers the embedded certificates; a late reader trusts the root-selected
view (only a token-holding coordinator that validated the manifests could
have written it) and never needs the rman slot.  Capacity: up to 32 removed
members per view record (1536 B); a change removing more than 32 members is
committed as successive views.  `chk_mxfs` validates each embedded
certificate against the rman slot when that slot still holds the same
{inc, seq} and reports it as "superseded" (not an error) otherwise.
Manifests keep their existing lifetime (retained until the slot is zeroed).

## 12. Root nonce and the ambiguous-CAW rule (R5, F12)

`nonce` is 128 bits: `{writer_inc (64), seq (64)}` where `writer_inc` is the
writer's mount incarnation (never reused, I6) and `seq` a per-incarnation
counter starting at 1 — non-repeating without any persisted state beyond the
incarnation.  Every root write (ballot install, commit, repair) uses a fresh
nonce.  A CAW whose outcome is not a clean success or a clean miscompare
(transport error, timeout, path failover) is AMBIGUOUS: the writer re-reads
and validates the root; if it equals the image it intended → success; if it
equals the expected old image → retry — the COMPARE image is necessarily that
unchanged old root, but the PROPOSED image is regenerated with a FRESH
nonce (a failed proposed image or nonce is never reused); anything else →
another writer landed: the proposal is abandoned and the coordinator
re-derives from the root.

## 13. Frozen byte-level format (R6)

All multi-byte fields little-endian; all reserved/pad bytes are zero on
write and MUST read zero (a nonzero byte fails validation).  Bytes inside
the digest/crc ranges are integrity-covered by those; bytes outside them —
root `pad_end [504,512)` and the 4Kn root tail `[512,4096)` — are protected
only by that explicit zero validation.  Every structure is exactly one
4096-byte page unless stated.  Digest coverage = bytes `[0, 4024)` of the
canonical view image; `crc32c` covers the half-open range `[0, 4088)` for
the view and `[0, 500)` for the root — the stored crc field lies outside its
own range.
Domain separation: the SHA-256 input is prefixed with the 16-byte ASCII tag
`"MXFS-TAUTH-VIEW1"` (view record) / `"MXFS-TAUTH-ROOT1"` (root, digest of
the committed view as stored, no recomputation).  Test vectors: build step 1
ships `tests/tauth/view_format_test.c` with a fixed all-fields-known record
and its expected SHA-256/crc32c, checked identically by the kernel PAL
(`crypto/sha2.h` `sha256()`) and the usermode implementation.

    mxfs_tauth_view (control slot A = page hdr_copies+0, B = +1)
      off  size  field
        0     4  magic            = 0x56484154 ('TAHV')
        4     2  version          = 1
        6     2  count            1..64
        8     8  gen              >= 1
       16     8  prev_gen         0 for gen 1
       24    32  prev_digest      all-zero for gen 1
       56     4  coord_node
       60     4  pad0             = 0
       64     8  coord_inc
       72     8  coord_ballot
       80     8  memb_epoch       membership service sequence (view_seq)
       88    32  memb_digest      membership service digest (my_view_hash widened; §7 validation)
      120     4  fs_gen
      124     4  pad1             = 0
      128    16  fs_uuid
      144     8  stamp_ms
      152    16  nonce            {writer_inc, seq}
      168     2  nremoved         0..32
      170     6  pad2             = 0
      176  1024  member[64]       16 B each: u32 node, u16 slot, u16 pad(=0), u64 inc;
                                  sorted by node ascending; entries >= count all-zero
     1200  1536  removed[32]      48 B each (§11), sorted by slot; entries >= nremoved zero
     2736  1288  reserved         = 0
     4024    32  digest           SHA-256("MXFS-TAUTH-VIEW1" || bytes[0,4024))
     4056    32  reserved2        = 0
     4088     4  crc32c           over bytes[0,4088) with this field zero
     4092     4  pad_end          = 0

    mxfs_tauth_root (control page +2; the CAW unit is the device logical block
    holding bytes [0, lbs); the page's remaining bytes are zero and never written
    with CAW — on 512 B devices the record is 512 B, on 4Kn it is the full page)
      off  size  field
        0     4  magic            = 0x54524854 ('THRT')
        4     2  version          = 1
        6     2  slot             0 = A, 1 = B, 0xffff = none (gen 0)
        8     8  gen              committed view gen; 0 = none
       16    32  digest           committed view digest; zero for gen 0
       48     4  coord_node       ballot owner (0 = none)
       52     4  pad0             = 0
       56     8  coord_inc
       64     8  coord_ballot     0 at mkfs; monotonic thereafter
       72     4  fs_gen
       76     4  pad1             = 0
       80    16  fs_uuid
       96     8  stamp_ms
      104    16  nonce            {writer_inc, seq}; mkfs writes {0, 1}
      120   380  reserved         = 0
      500     4  crc32c           over bytes[0,500)
      504     8  pad_end          = 0
     (512..4095 zero on 4Kn; the 4Kn CAW compares/writes bytes [0,4096))

Validation rules: magic/version/fs identity; root gen 0 ⇔ slot 0xffff ⇔
digest zero; root gen ≥ 1 ⇒ the named slot holds a view with `gen ==
root.gen` and `digest == root.digest`; a view's `prev_gen == gen-1`; a view
with gen 1 has prev_gen 0 and prev_digest zero; the other slot is either
zero, a valid older view (`gen < root.gen`), or a proposal (`gen ==
root.gen+1`, `prev_digest == root.digest`) — anything else is reported by
`chk_mxfs` and the region is fail-closed until repaired.

### 13.1 Frozen details (pass 3)

- Magic values are on-media byte sequences, not C multi-character
  constants: view = `54 41 48 56` ("TAHV"), root = `54 48 52 54` ("THRT").
- SHA-256 domain tags are exactly the 16 ASCII bytes `MXFS-TAUTH-VIEW1`
  (`4D 58 46 53 2D 54 41 55 54 48 2D 56 49 45 57 31`), no NUL.
- CRC32C = Castagnoli, reflected polynomial `0x82F63B78`, initial
  `0xFFFFFFFF`, final XOR `0xFFFFFFFF` (the `~crc32c(~0, …)` convention
  `tools/mkfs_mxfs.c` already uses); check value `crc32c("123456789") =
  e3069283`.
- `removed[i]` (48 B): `node u32@0, slot u16@4, stage u16@6, inc u64@8,
  recovery_gen u64@16, fence_term u64@24, manifest_seq u64@32,
  manifest_crc32c u32@40, manifest_count u16@44, pad u16@46 (=0)`.
  `stage` = the disklock recovery-descriptor stage enum value reached
  (docs/recovery-manifest.md); valid range = `FENCED .. CONSUMABLE`
  inclusive; anything else fails validation.  Entries `i >= nremoved` are
  all-zero.
- Root canonical payload is exactly 512 bytes: `pad_end u64@504 = 0`; bytes
  `508..511` are inside `pad_end`.  On 4Kn the CAW unit is the whole page;
  bytes `512..4095` are zero on write and validated zero on read.
- Kernel SHA-256 via `crypto/sha2.h` `sha256()`; usermode via
  `dlm/sha256.c` (both builds, same test vector).

### 13.2 Canonical test vectors (`tests/tauth/vectors/view_v1.bin`,
`root_v1.bin`, generated 2026-08-28 from the layout above)

View: gen 7, prev_gen 6, prev_digest = bytes A0..BF, count 3, coord_node
1001, coord_inc 0x5005, ballot 42, memb_epoch 9, memb_digest = bytes 10..2F,
fs_gen 0x12345678, fs_uuid = bytes 50..5F, stamp_ms 1787923200000, nonce
{0x5005, 1}, members {1001,slot 1,0x5005} {1008,2,0x5008} {1015,4,0x5015},
nremoved 1, removed[0] = {1022, slot 3, stage 6, inc 0x5022, recovery_gen
17, fence_term 2, manifest_seq 5, manifest_crc 0xDEADBEEF, count 129}.

    view digest@4024  = cb9907805abea7e5d1114318b25653d10ad9ea488a3af718fe5b2c1b437c7a78
    view crc32c@4088  = ce752c32
    sha256(view_v1.bin, all 4096 B) = 07b9082709417a90f685c50a0407932679a280a9c534fc698cc0285e0283036a

Root: slot 0, gen 7, digest = the view digest above, coord {1001, 0x5005,
42}, fs identity as above, stamp_ms 1787923200001, nonce {0x5005, 2}.

    root crc32c@500   = aa7c022f
    sha256(root_v1.bin, 512 B) = d7db7bcc7fd17f335713b81bac6b3881c9f6f4c386f5b7b954ace7a977ac7387

`tests/tauth/view_format_test.c` (build step 1) must (a) rebuild both
records from the field values and match the files byte-for-byte, (b)
recompute digest/crc and match, (c) flip each single byte of the view in
turn and prove validation fails, (d) build the 4096-byte root CAW image
(`root_v1.bin` + zero tail) and prove that a nonzero byte anywhere in
`[512, 4096)` — and in `pad_end [504, 512)` — fails validation, (e) verify
the SplitMix64 check values, (f) prove the allocator refuses a ballot
install at `root.ballot = UINT64_MAX - 1` and validation rejects an
on-media `UINT64_MAX`.
