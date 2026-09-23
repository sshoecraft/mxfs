# TCP durable authority backend — design and build plan

Status: DESIGN (sess418, 2026-08-28), design-consult ruled (`docs/rulings/tcp-replay-authority-shape-a-plus.md` and
`docs/rulings/tcp-durable-authority-ledger.md`).
Ledger: D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-0288 (critical),
D-TCP-MEMBERSHIP-CHANGE-PURGES-HELD-GRANTS-NO-RECONSTRUCTION-0287 (critical);
closure dependency of D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286.

## The problem, measured

0.29.0, 32 nodes, TCP DLM over the multipath LUN
(`tests/evidence/20260828T043116Z_d0286tcp`): three injected dirty deaths, three
slices refused (`P227-FR-ATOMIC-SKIP` on every transaction → `P227-FR-TORN-
UNPUBLISHED` → -117 → `P240-QUAR-IMPORT`), every peer read of a victim-domain
inode failed EIO after the 60-retry acquire budget (185 s).  The identical
injected deaths on CAW replay and the peer read returns the victim's data in
70 s.  Two roots:

1. The foreign-replay image-authority gate (docs/recovery-manifest.md) certifies
   an image from the victim's **fence-time manifest** of held EX/PW grants, which
   the prover scans out of the **CAW slot table**.  TCP has no slot table: the
   prover writes a `NO_CAW_TABLE` manifest, every lookup answers -ENODEV, no
   image is ever admissible.
2. The TCP lock arm (`mxfs_v5_dlm_inode_lock` → `mxfs_dlm_lock`) never fills
   `mxfs_grant_result`, so every TCP-committed image carries `grant_epoch=0 /
   lineage=0` ("noepoch") and could not be matched against any manifest anyway.

And the structural sibling (D-0287): mastership is `hash(resource) %
active_nodes`, lock records live only in the masters' memory, and
`mxfs_dlm_update_active_nodes` purges **every** node's whole table on any
membership change with `v5_membership_cb_tcp` a no-op — a new master starts
empty and reads "no record" as FREE; a dead master's table is simply gone.

## Why the obvious fix is not enough

"Masters seal the victim's grants into per-victim manifest shards after the
fence, dead master ⇒ UNKNOWN ⇒ refuse" is sound but recovers almost nothing:
~1/N of a victim's own resources were mastered by the victim itself, that
shard dies with it, and the whole-slice rule (one refused transaction ⇒ the
slice is TORN-UNPUBLISHED ⇒ quarantine) means at N=32 nearly every slice still
fails.  The authority record must **survive its master**.

## The design: the CAW authority table with a single-writer WRITE backend

Keep the CAW authority *schema* (per-resource slot selected by resource hash;
holders, grant epoch, lineage; `manifest_collect` + the replay verdict code
unchanged) and replace the CAW *physical protocol* (compare-and-write by any
node) with **one authorised writer per slot — the resource's current master —
using plain, crash-safe writes**.  Plain writes are reliable on the hardware
where CAW is not; PR fencing already excludes a dead writer.

### Records
- `grant_id = {authority_epoch, grant_seq64}` — never wraps (exhaustion ⇒
  epoch change or refusal).  `u32 grant_gen` is retired as the token.
- ACTIVE entry: fs uuid, resource type + full id, owner node + **incarnation**,
  mode, authority (master) node + incarnation, config (membership) epoch,
  authority epoch, grant_seq64, dir_epoch, transition_seq64.
- FREE/tombstone entry: resource + authority identity, config/authority
  epoch, last_grant_seq64, transition_seq64.  Absence is FREE only when the
  authority range has complete, valid coverage.
- Every TCP image's lineage tag carries `grant_id` (the TCP arm fills
  `mxfs_grant_result` from the grant it received).
- `open_holders` (entry byte 104, version 4): one bit per heartbeat slot, the
  TCP open-unlink registry described next.

### Open-holder marks — cross-node open-unlink on the ledger (0.89.0)
POSIX open-unlink across nodes needs the unlinker to know that a peer still
has the file open.  On CAW that is a bit in the slot the release CAS writes.
On TCP the same mark lives in the resource's ledger record and moves only in
release transitions, so every property the grant history has, the mark has:

- **Publication is inseparable from release.**  A node releasing its inode
  grant publishes its ABSOLUTE protected state (open descriptors or live
  mappings ⇒ set, else clear) as `open_op` on the `LOCK_RELEASE`; the master
  applies it in the transition that retires the grant, and the ACK follows
  the commit.  A release the ledger refuses applies no mark and the releaser
  keeps re-sending; a stale release (naming an older grant than the record's)
  applies nothing.  Absolute rather than delta so a mark the shell does not
  remember (a lost clear, a mark inherited from a retired tenancy of the same
  slot) is repaired by the next release instead of deferring a reap for ever.
- **The exclusive grant carries the snapshot.**  `LOCK_GRANT` returns the
  record's mask at the decision; the grantee's destructive-inactivation guard
  reads it from its mirror entry (no round trip).  Sound because every peer
  that had the file open published inside the release that preceded this EX,
  and no peer can publish a new mark while the EX is held (open-at-NL first
  acquires PR, which the EX blocks).  A later clear only makes the snapshot
  conservative.  Hence the guard's deferral RELEASES the EX (never keeps it
  cached): the reaper's retry must take a fresh grant whose snapshot can
  have seen the peer's last close.
- **Every path that constructs a grant carries the snapshot, and a
  re-affirm can only add to it.**  The master stamps the record's mask on its
  chain entry at the commit and at a takeover import, and a re-affirm of a
  grant still held (the same durable grant id, no commit behind it) sends
  that stamp.  The grantee replaces its snapshot only for a grant naming a
  NEW grant id (a fresh commit); a re-affirm's mask is OR-ed into the
  snapshot it has.  No peer can publish a mark while the EX is held, so a bit
  the mirror has and a re-affirm lacks is a lost bit, never a cleared one —
  and losing it is the free.  The stamp can only be stale toward "more bits
  set" (a fence purge while the EX is held), which is one more deferred reap
  under a fresh grant.
- **A mark is cleared only by a release.**  Last close at NL (the mark was
  set by a release under BAST, the shell holds nothing) takes a PR grant
  through the ordinary acquire and queues its demote; that release publishes
  the clear.  Ordering against a concurrent reopen is the grant's own: the
  older grant's release is stale at the master, the newer grant's release
  publishes what is then true.  There is no standalone clear on the wire.
- **The genuine free zeroes the mask** (`open_op = -2` on the free path's
  release): the guard that ran under that EX proved no occupied slot holds
  the incarnation open, so what it erases is residue of retired slots.
- **Records that carry marks are live lifetime records.**  A FREE tombstone
  with a non-zero mask is never reclaimed for another resource and pins one
  of its home page's 31 entries until the last opener clears.  This is the
  registry's capacity bound: a page whose entries are all pinned refuses
  further grants of the resources that hash to it until a close or a fence
  purge frees one (`P-TAUTH-PAGE-FULL open_pinned=`), the same bound the
  page already imposes on simultaneously held tenures.  Clearing, releasing
  and purging a resident record never allocate.
- **Marks are stripped only by the owner's fence purge**, which runs at its
  recovery completion — never on suspicion.  The guard masks the snapshot by
  slot OCCUPANCY (the disklock table): a mark in a slot with no tenant is
  residue (its owner departed cleanly or its tenancy was retired after the
  purge); a mark in an occupied slot is honoured whoever the occupant is.
  When the purge cannot name the departed slot (a live successor already
  occupies it) the marks are left alone: a slot-keyed bit cannot be told
  from the successor's own, keeping it is the integrity-safe side, and the
  successor's next release of that inode publishes its own state over it.
- **An exposed shell's incarnation is immutable.**  If a coherency reload
  finds the platter naming another incarnation (freed, or reused under a new
  generation) while the shell has descriptors or mappings, the shell is
  poisoned — every file operation refuses `-ESTALE`, faults `SIGBUS`, the
  revocation worker discards its page cache — instead of adopting the
  successor's forks.  The same on a freed-incarnation ring entry for an open
  shell, and every data path re-checks the poison AFTER its I/O lock ride,
  which is where the reload runs.  That is containment, not open-unlink: it
  is what a lost mark degrades to, and it never serves another file's bytes.

### Storage — crash-atomic by construction
In-place 4 KiB RMW + crc is rejected: a torn page would make the resource
UNKNOWN and routine master crashes would quarantine slices again.  Each 4 KiB
page has **two shadow copies** {page id, authority/config epoch, seq, crc}: write
the inactive copy, flush, highest valid committed seq wins, never overwrite the
only valid copy.  Headers dual-copy too.  Capacity: the rman region's 2 MiB +
64 KiB per node cannot hold two copies of 65536×32 B plus headers plus the
victim manifest ⇒ a **new envelope region** (`MXFS_FORMAT_F_TAUTH`, `tauth_offset/
size`, `PROTO_GEN` bump, mkfs/chk).  Ledger-full ⇒ refuse the grant, never omit
a record.  Corruption / duplicate key / bad seq / broken probe chain ⇒ UNKNOWN.

### Ordering invariants (all fifteen from the ruling; the load-bearing ones)
1. Durable-before-deliver: no LOCK_GRANT before its record is durable (group
   commit across concurrent grants is allowed: one flush per batch).
2. Durable-before-release-complete / -promote: a release is externally complete
   and a successor promoted only after the superseding transition is durable
   (coalesce release + successor grant into one transition; lazy tombstone GC).
   Never ACK a release and keep the old ACTIVE record as "continuity".
3. Single authority writer per resource + authority epoch.
4. No empty reconstruction: a replacement master imports a complete, valid
   predecessor state or answers UNKNOWN — never FREE from an empty table.
5. Ordered handoff: old authority frozen/fenced before new authority activates;
   "neither can grant" is allowed, "both" never.
6. Stable seal cut; replay/reuse exclusion (no incompatible successor grant on
   R until V's replay verdict for R is fixed and published).

### Mastership handoff (this is the D-0287 fix)
Dead master M: FENCE(M) → read M's latest valid durable pages → DURABLE_IMPORT
at M2 (INACTIVE) → config/activation barrier → first grant on M2.
Live handoff: freeze R at source → drain → TRANSFER_PREPARED → dest imports
INACTIVE → commit config → source MOVED → dest ACTIVE → grants.
`mxfs_dlm_update_active_nodes`'s unconditional purge becomes post-barrier GC
only; `v5_membership_cb_tcp` drives freeze / import / activate / GC.

### Fence-time seal (feeds the unchanged replay gate)
SEAL(V, victim inc, fence id, config epoch) barrier to every surviving
authority; each serialises it against grant/release/transfer, drains
transitions ordered before it, records a watermark, writes a fence-specific
shard (COMPLETE or UNKNOWN, with victim/fence/config/authority identity, range
coverage, watermark, count, seq, crc), flushes, acks.  The coordinator builds a
dead master's shard from its durable pages after proving it fenced.  The victim
manifest (existing rman format + shard directory) is valid only when every
authority range is a valid shard or explicit UNKNOWN, and is published before
any verdict uses it.  Post-seal: no incompatible grant on a sealed resource
until replay/publication completes.

## Build order (each step lands, builds, and is rig-verified before the next)
1. Token plumbing (no format change): TCP lock arms fill `mxfs_grant_result`
   (`grant_epoch := grant_seq`, `lineage := {master, seq}`); images become
   tokenized.  Verify: `P-RMAN-EVAL` shows lookups with non-zero tokens on TCP.
   **LANDED sess420 (0.30.0):** `dlm/v5_mount.c v5_tcp_grant_result_fill()`,
   called after every successful `mxfs_dlm_lock*` on the seven TCP arms
   (`inode_lock`, `inode_lock_retries`, `iclus_lock`, `inode_lock_try`,
   `inode_reserve_try`, `ag_lock`, `ag_lock_try`; there is no TCP convert
   path).  Token = the master-minted `grant_gen` (`dlm.c dlm_next_gen`,
   delivered in `resp.grant_gen`): `grant_epoch = gen`,
   `resource_lineage = (master << 32) | gen`, status classified exactly as
   `caw_grant_result_fill` (WRITE_EPOCH / WRITE_ZERO_EPOCH / NONWRITE_MODE).
   `reaffirm` stays 0 on TCP: the master's re-affirm arm bumps the gen and
   re-sends the grant, so every fill is minted by the response this acquire
   received (the xfs install takes MAX epoch within a tenure).  Verify
   harness: `tests/tcp_token_plumbing_verify.sh` — per-node deltas of the
   capture-point histograms (`P228-TOKCLASS` noepoch, `P239-OWNAUTH`
   durnoep/durable) across a private-dir small-file workload on 32/tcp.
   Known limit carried into step 3: `gen` is u32 and restarts at 1 when a
   master (re)starts, so `{master, gen}` is unique only within one master
   incarnation — `{authority_epoch, grant_seq64}` replaces it.
2. Envelope region + on-disk page format + shadow-page writer/reader in
   `dlm/` (usermode-buildable), mkfs/chk support, PROTO_GEN bump; unit test
   under `tools/` for torn-write recovery (write copy A, kill, verify B wins).
   **LANDED sess421 (0.33.0, PROTO_GEN 7→8):**
   - `include/mxfs/mxfs_tauth.h` — the layout, kernel/user neutral, pure
     helpers only: 128-byte `mxfs_tauth_entry` (state EMPTY/ACTIVE/FREE/
     UNKNOWN, res_type + res_id[2], owner node+inc, mode, authority node+inc,
     config/authority epoch, grant_seq64, last_grant_seq64, dir_epoch,
     transition_seq64), 4 KiB pages = 128-byte header + 31 entries, 65536
     slots → 2115 pages, TWO copies per page plus a dual-copy region header
     → `MXFS_TAUTH_REGION_BYTES` = 16.5 MiB.  Page crc32c covers the whole
     page (seed ~0, crc field zero); validity = magic/version/page_id/fs_gen/
     seq≠0/crc.  `mxfs_tauth_fs_gen()` is the disklock fold of the uuid.
   - Envelope: `MXFS_FORMAT_F_TAUTH`, `tauth_offset/size` in the super,
     layout `[super][journal][disklock][rman][tauth][XFS data]`.  mkfs
     formats every page as a committed EMPTY page (seq 1) in copy A so the
     region has complete valid coverage from the first mount ("absence ==
     FREE" is only sound with complete coverage); chk validates geometry,
     overlap, both header copies and sweeps all pages (`two/one/none`
     counts; any `none` page is an error — every resource on it is UNKNOWN);
     `chk -U` refuses a volume without the region; mount refuses a malformed
     region and plumbs the offsets into `mxfs_v5_dlm_opts` → ctx (consumer
     lands in step 3).
   - `dlm/tauth_store.{c,h}` — PAL-only shadow-page store: `open` (validates
     either header copy for THIS fs), `page_read` (both copies, highest
     valid seq wins, none ⇒ `-EUCLEAN` = UNKNOWN, fail closed), `page_write`
     (seq = highest valid + 1, written to the copy NOT holding it, FUA +
     flush, then read back and required to validate before it counts as
     durable; a page with no valid copy may be repaired with the CALLER's
     content — the store never invents FREE), `verify`.  Test fault knob
     `torn_after_bytes` writes a sector-aligned partial image without flush.
   - `tests/tauth/` (`make -C tests/tauth && ./tauth_test`) — the SAME
     `dlm/tauth_store.c` linked against `pal/linux/user.c` on a temp file:
     format/verify, alternate-copy RMW, torn write (previous commit wins,
     torn copy invalid, next write repairs it), bit-flip fallback, both
     copies destroyed ⇒ UNKNOWN then caller-content repair, foreign-fs page
     ignored, 200-write monotonic seq, missing region header.  21/21 PASS
     sess421.  Not in the module build; run it after any store change.
   **FORMAT v2 — mkfs-sized geometry, sess427 (0.38.0, PROTO_GEN 8→9;
   D-TAUTH-SLOT-HASH-COLLISION-REFUSES-GRANT-EIO-0348 step 2, ruling
   `docs/rulings/tauth-slot-collision-page-open-addressing.md`):**
   - The fixed 65,536-slot schema was categorically undersized (44 collision
     refusals at 8,000 live inode locks, s429).  The page count is now an
     MKFS-TIME PARAMETER: `mxfs_tauth_region_hdr` v2 carries `npages`,
     `hash_version` (1 = seeded fnv1a-32) and a per-format random
     `hash_seed`; `mxfs_tauth_region_valid` accepts `npages` in
     `[MXFS_TAUTH_NPAGES_MIN=2115, MXFS_TAUTH_NPAGES_MAX=2^20]` and REFUSES
     v1 headers.  `MXFS_TAUTH_REGION_BYTES_FOR(npages)`; the old
     `MXFS_TAUTH_REGION_BYTES` is the minimum (usermode-test) geometry.
   - Routing: `home_page = mxfs_tauth_res_hash(res, seed) % npages`,
     preferred `home_index = (hash / npages) % 31` (`mxfs_tauth_home_page` /
     `mxfs_tauth_home_index`, kernel/user neutral).  The DLM ctx carries the
     geometry (`page_count`, `hash_seed`) from `mxfs_dlm_attach_ledger` or
     `mxfs_dlm_set_ledger_geometry`; `mxfs_dlm_resource_master` and every
     page-routing site use `dlm_res_page(ctx, res)`.  The ledger's own
     `mxfs_tauth_ledger_page/home/hash(l, res)` take the open ledger.  A
     member that routes by a different geometry would master a resource on a
     different page (two writers for one record) — hence the proto-gen bump.
   - mkfs: `-t ENTRIES` or the default `tauth_npages_for_device` = one
     record per 64 KiB of device, clamped (128 GiB → 67,650 pages = 2.1M
     records, 528 MiB dual copy, 0.4 % of the device).  The seed comes from
     /dev/urandom and is never 0.  chk reads the geometry from the header,
     checks the two header copies agree, checks the size covers it, sweeps
     `npages` pages, prints `records=` and `seed=`.  Mount accepts any
     page-aligned region ≥ the minimum; the store validates the header's
     geometry against the envelope size when the ledger opens.
   - Tests format the minimum geometry with `TL_SEED`; `tl_page/tl_home`
     route without an open ledger; `tests/tauth/pageof <type> <ino> <ag>
     [npages] [seed]` joins rig P-lines to pages for a real region.
3. Master-side ledger: durable-before-deliver on grant, coalesced
   release+promote, group commit; ledger-full backpressure.  Verify with the
   crash matrix rows for grant/release/regrant (fault knobs).
   **SPEC FROZEN sess421** (two design-consult rulings, `docs/rulings/tauth-step3-master-ledger-design.md`);
   the entry layout in `mxfs_tauth.h` already reflects it.  Build order
   inside step 3, each piece compiled and unit-tested before the next:
   - 3a **page-aligned mastership** — `mxfs_dlm_resource_master`: slot =
     `resource_hash_raw % 65536`, page = slot / 31, master =
     `active_nodes[page % N]`; every routing/validation/redirect site uses
     it.  Page ownership carries a *generation* (membership epoch + master
     node + master incarnation); every pending ledger operation records it
     and rechecks it before I/O and again before delivery.
   - 3b **wire** — `LOCK_REQ` carries the sender's 64-bit mount incarnation,
     its heartbeat slot and a per-requester request id (idempotent retries
     return the already-durable grant instead of minting another);
     `LOCK_GRANT` / `LOCK_RELEASE` / new `RELEASE_ACK` / upgrade / re-affirm
     carry the full `grant_id = {authority_epoch, grant_seq64}` plus
     `resource_lineage`; requesters reject grants from an obsolete
     master/generation.  PR messages carry `{lineage, slot, node, inc}`.
   - 3c **ledger layer** `dlm/tauth_ledger.{c,h}` on top of the store:
     per-page cached image + per-page mutex (covers select-latest-image,
     patch, `page_write`, cache update), per-page allocators from the page
     header (`grant_seq_next`, `transition_seq_next`; exhaustion fails
     closed), ownership-generation check, and page **poison** on an
     uncertain write outcome (reread both copies and reconcile before any
     further operation; never roll an uncertain ACTIVE back to FREE in
     memory).  Opened from `mxfs_v5_dlm_init` (TCP branch) with
     `ctx->dev` / `ctx->tauth_offset` **before the first grant** — that is
     the activation barrier (a fresh mount holds nothing).  Lazy page load
     is allowed only because no resource on an unread page is ever granted.
   - 3d **grant path** — new table state `MXFS_LSTATE_PENDING_DURABLE`:
     counts as a holder in every compatibility check, is never returned to
     a local caller and never sent.  Sequence: decide + install pending
     under `table_rwlock`; unlock; page mutex; revalidate generation; patch
     the latest cached image; `page_write`; on verified success commit the
     cache, mark GRANTED, recheck generation, then send / return.  A batch
     from `promote_waiters` is one page transition (distinct grant_seq per
     EX grant); nothing in the batch is delivered before the whole page
     verifies.  Proven-not-committed failure ⇒ cancel + `LOCK_DENY`
     (`MXFS_ERR_LEDGER`) / local `-EIO`; uncertain ⇒ poison page.  A durable
     grant whose send failed is a ghost that stays a blocker until superseded
     and is what a retry with the same request id gets back.
   - 3e **release** — validate `{node, inc, grant_id}`; install a pending
     release keeping the old holder effective; select successors as pending;
     ONE page transition (old → FREE with `last_grant_seq64`, successors →
     ACTIVE / holder bits); then deliver successor grants and `RELEASE_ACK`
     (either order, neither before the commit).  The releaser stops using
     the lock at once but keeps pending-release state and cannot report
     release / unmount completion until the ACK; duplicate releases join or
     get an ACK; a stale release (older grant_id) never removes a later
     grant.  PR release clears `holders[slot]` only when lineage matches,
     the CURRENT heartbeat row for the slot equals the `{node, inc}` the
     message carries, the request is in the current lock-service epoch, and
     the bit is set; reaffirm never recreates a clear bit.
   - 3f **blocker import** — an ACTIVE record found on page load that has no
     table entry is honoured as a holder (ledger-backed blocker) in every
     compatibility decision until recovery proves the owner fenced and
     purged; it survives the membership-change table purge (it lives in the
     ledger cache, not the table) and is reported `P-TAUTH-IMPORT-ACTIVE`.
     The matching live owner may release/reaffirm it with
     `{node, inc, grant_id}`.  Never cleared because the epoch is old, the
     owner is absent from membership, or the table was purged.
     **An imported record of THIS node's own incarnation is a tenure without
     a generation** (0.85.5, D-0966): the grant's response or release was lost
     against a departing master and this node took the page over.  The
     gen-aware release names tenures by generation and reads 0 as "nothing
     held", so such an entry is invisible to every ordinary release while it
     stays a live holder in whichever master's queue the page reaches.  Two
     rules close that: a local request that meets it adopts it (fresh
     generation, `imported` cleared, `P-TAUTH-ADOPT-LOCAL`) exactly as the
     remote re-affirm does, so its later release names a real generation; and
     a BAST that finds the mirror holding a generation-less grant of ours with
     nothing in-core adopts and releases it through the ordinary gen-aware
     unlock (`mxfs_dlm_unlock_genless`, `P-REL-NOTHING-MIRROR-HELD`), so the
     peer's request is served rather than parked for ever.  A record under our
     node id but ANOTHER incarnation is never adopted
     (`P-TAUTH-ADOPT-INC-MISMATCH`, the request retries): that incarnation's
     departure purge retires it.  Measured before the rules existed (2/tcp
     s616d): the survivor's own record on a reused inode number, handed to the
     rejoined peer at the view change, parked the peer's first listing of the
     survivor's directory for 300 s+ while the survivor answered every BAST
     with "no held tenure; unlock skipped".
   - 3g **fail closed** on: grant_seq exhaustion, slot/resource-identity
     collision, no valid copy, inconsistent duplicates, unreconcilable
     uncertain write, unsupported version, unread page.  Readback verify
     stays per commit; throughput only via batching.
   - Verification: the usermode ledger test (grant/release/regrant crash
     rows via the store's torn knob), then `tests/d0287_remaster_measure.sh`
     with the membership purge still present (blockers must hold W off H's
     resource across the change), then 32/tcp board rows.
   **LANDED sess422 (0.34.0, unbuilt as a module at write time — the
   queued `tests/sess422_chain.sh` builds it):**
   - 3a `mxfs_dlm_resource_master` = `active_nodes[page % N]`, page =
     (hash % 65536) / 31 (`dlm_page_master_locked`); the dg_grant_ex
     stale-master probe uses the same map.
   - 3b wire: `LOCK_REQ` +{owner_inc, owner_slot, req_id}; `LOCK_RESP`
     +{authority_epoch, grant_seq64, lineage, req_id}; `LOCK_RELEASE`
     +{rel_id, authority_epoch, grant_seq64, owner_inc, lineage, owner_slot,
     mode}; new `MXFS_MSG_LOCK_RELEASE_ACK` (`mxfs_dlm_release_ack`);
     `MXFS_ERR_LEDGER` (requester -EIO) and `MXFS_ERR_REMASTER` (requester
     retries against the master the current membership names).  The
     handlers take the wire structs (`mxfs_dlm_process_remote_{request,
     grant,release}`, `mxfs_dlm_process_release_ack`).
   - 3c `dlm/tauth_ledger.{c,h}`: per-page cached committed image + mutex,
     `ensure` (load under the ownership generation / reconcile a poisoned
     page from BOTH copies), `lookup`, `scan_active`, `commit` (one page
     transition of GRANT_EX/GRANT_PR/RELEASE_EX/RELEASE_PR ops; refuses
     -EEXIST collision, -EBUSY conflicting live holder = double grant,
     -ENOSPC exhaustion, -EUCLEAN UNKNOWN, -ESTALE generation; write
     failure ⇒ poison + immediate reconcile ⇒ 0 / -EIO proven-uncommitted
     / -ENOTRECOVERABLE), `purge_owner` (recovery only).  Entry gained
     `auth_node`/`auth_slot`/`volume` in the reserved bytes;
     `authority_epoch` = the minting master's mount incarnation.  A shared
     grant JOINS the record's lineage; an exclusive grant starts one.
   - 3d/3e in `dlm/dlm.c`: states `PENDING_DURABLE` / `PENDING_RELEASE`
     (`lk_is_holder`), `struct dlm_txn` (heap), `dlm_txn_commit` (3 bounded
     retries through reconcile; -EIO/-ENOTRECOVERABLE after them latches
     `ledger_failed` = fail stop), `dlm_txn_finalize` (re-find by
     {resource, owner, gen}; GRANTED or removed/restored; remaster check
     `ctx->ledger_gen != txn->gen` ⇒ not delivered, record stays = ghost),
     `dlm_promote_txn` (release + successors in ONE transition, further
     rounds for waiters that queued behind the PENDING_RELEASE holder),
     `dlm_grant_txn` (immediate grants/upgrades, old mode restored on
     refusal).  Every promote_waiters site (unlock_gen, remote release,
     convert, purge_stale, purge_node) runs through it.  Holder side:
     `rel_pending` list, `mxfs_dlm_release_retry_tick` (v5 TCP death
     worker, 500 ms; 10 sends then `P-TAUTH-RELEASE-UNACKED`),
     `mxfs_dlm_wait_release_acks` in `mxfs_dlm_release_all` (3 s).
   - 3f: `dlm_ledger_prepare` before every decision = `ensure` + import of
     ACTIVE records as GRANTED `imported` entries (`P-TAUTH-IMPORT-ACTIVE`;
     shared bits resolved by `slot_node_cb` = the disklock row, unresolved
     ⇒ owner `MXFS_DLM_NODE_UNKNOWN`, never BASTed); the membership purge
     keeps this node's own GRANTED/CONVERTING/PENDING entries (their
     records carry the grant id: D-0287) and drops the rest for re-import;
     `ledger_gen` = f(view hash, incarnation, MONOTONIC view_seq) — the
     harness proved a view flap A→B→A must not reuse a generation.
     Retirement only by `mxfs_dlm_ledger_purge_owner` (v5: after
     `v5_refresh_active_nodes` in recovered_cb / recovery_complete2 /
     clean_depart / GOODBYE / slotless death, then `mxfs_dlm_purge_node`).
   - 3g: `ledger_required` (TCP mount on a volume with the region) refuses
     every grant until `mxfs_dlm_attach_ledger` (v5 init, right after the
     slot claim; open failure = mount refused, `P-TAUTH-MOUNT-REFUSE`).
   - Token plumbing: `v5_tcp_grant_result_fill` records
     `grant_epoch = grant_seq64`, `resource_lineage` = the record's.
   - `tests/tauth/`: `ledger_test` (15 groups, 52 checks) and
     `dlm_ledger_test` (the ENGINE: 2–3 in-process nodes, one shared
     temp-file ledger, message mesh; 11 groups: durable-before-deliver,
     release+ACK, contention, local master, blocker import after master
     loss, D-0287 membership-change retention, recovery purge, torn
     write / injected collision fail-closed, lost GRANT idempotent retry,
     activation barrier, clean unmount) — both PASS sess422; `make -C
     tests/tauth test` runs all three.  `dlm/dlm_user_compat.h` is the
     usermode shim for the engine's kernel-idiom probe lines.
   - Known step-3 limits (step 4/5 obligations): no storage fence of a
     departed master before the new page owner loads (the takeover relies
     on the existing PR fence at death); fail-stop after 3 failed commits
     is a log + refuse, not a withdraw; PR imports of an unresolved slot
     block until the recovery purge.
4. Handoff protocol + membership_cb driver; delete the global purge (D-0287).
   Verify: `tests/d0287_remaster_measure.sh` (W must NOT be served during H's
   pause across a membership change) + master-loss import matrix.
   **design-consult ruling sess423** (`docs/rulings/tauth-step4-ordered-handoff.md`): a
   volatile FROZEN is insufficient — two nodes with divergent views can both
   write page P at seq s+1 and both read back a valid image; authority moves
   only through DURABLE page transitions, every timeout fails closed, and
   the dead-owner successor must be unique and ordered.
   **LANDED sess423-424 (0.35.0, built by `tests/sess424_chain.sh`):**
   - Page header (`mxfs_tauth.h`): `auth_state` UNOWNED/ACTIVE/PREPARED,
     `auth_node` + `authority_epoch` (= the authority's mount incarnation),
     `target_node/target_inc` (PREPARED), `write_nonce` (xorshift64 per
     write; two valid copies with the same seq but different content are
     CONFLICTED = `-EUCLEAN`, never "pick one").
   - `tauth_ledger.{c,h}`: `commit`/`purge_owner` require the cached page
     ACTIVE(self) — `-EPERM` otherwise, nothing written;
     `prepare(page, gen, target, victim, retarget)` writes PREPARED from a
     FRESH two-copy read with the entries unchanged (idempotent for the
     same target; retarget only with the caller's proof the old target's
     incarnation is recovery-purged; UNOWNED is never prepared);
     `activate(page, gen, expect_seq, bootstrap)` consumes the EXACT
     PREPARED record (target == self, seq == expect_seq) or, with
     `bootstrap`, claims an UNOWNED page; `page_auth(fresh)` reads both
     copies with no cache side effect; `config_id` is a rendezvous cookie
     only.  Counters `prepares/activates/authority_refusals`.
   - `dlm.c` engine: per-page `page_state` UNKNOWN/MINE/FROZEN/WANTED;
     `dlm_page_ensure_mine` before every ledger decision (not mine ⇒
     `-EAGAIN` ⇒ requester gets REMASTER / retries, fail closed);
     `dlm_page_acquire` = adopt ACTIVE(self) / consume PREPARED→self /
     bootstrap UNOWNED (only `bootstrap_cb` = lowest live heartbeat slot) /
     FREEZE_REQ to the current authority (or the target it is prepared to)
     every 500 ms; **UNOWNED at a non-bootstrap master (sess426, D-0345,
     0.35.4)**: FREEZE_REQ to the bootstrap node named by
     `bootstrap_node_cb` (id + incarnation), whose handler claims the page
     as bootstrap and PREPAREs it to the sender (`bootstrap-for-request`)
     — before 0.35.4 this branch parked forever (no auth_node to route
     to), so every request on a never-decided page exhausted its budget
     (REMASTER ×60 on the rig, `why[remaster=N]` / `why[prepare=N]`);
     usermode proof `tests/tauth/unowned_page_test`.  The handler also
     requires `target_node == sender`; `MXFS_MSG_PAGE_HANDOFF` kinds FREEZE_REQ (owner:
     freeze + drain in-flight txns (bounded, else stays frozen and NOT
     prepared) + PREPARE + FROZEN{page, prepared_seq, target, cfg}),
     FROZEN (target: activate; a target whose view no longer names it
     owner activates as a NON-serving relay and hands onward on the next
     tick), DEFER, NOT_OWNER; `mxfs_dlm_handoff_tick` (eager PREPARE of
     pages that moved away at the last view change, retarget of PREPAREDs
     aimed at a recovery-purged target); `mxfs_dlm_handoff_takeover(node,
     inc)` = the certified successor (bootstrap node) PREPAREs every page
     still ACTIVE({node,inc}) to its owner under the current view (self ⇒
     activate at once; else FROZEN to the owner); `mxfs_dlm_handoff_depart`
     = clean departure PREPAREs every served page to its successor before
     GOODBYE.  The membership change no longer purges blindly: it only
     re-keys `ledger_gen`/`config_id`, marks pages that moved away FROZEN
     and arms the tick.
   - **Conditional commit (sess426, D-0347, 0.36.0)** — `tauth_store.c`
     `mxfs_tauth_page_write` no longer trusts "write the spare copy at
     max+1 and read it back": two nodes that both believed they were the
     bootstrap node (a falsely-dead lowest slot + its successor) both
     claimed one UNOWNED page and the later, stale-based write erased the
     other's activation and grant (`tests/tauth/bootstrap_race_test`).
     Now: (1) the caller's image carries its BASE TOKEN — `hdr.seq` +
     `hdr.write_nonce` of the committed image it was derived from (0/0 =
     repair of a page with no valid copy) — and the write refuses
     `-ESTALE` (`P-TAUTH-STALE-BASE`) unless the platter's unique highest
     valid image matches it exactly; (2) the spare copy's sector 0, as
     read, is the compare value of a SCSI COMPARE AND WRITE that installs
     a 512 B **ticket** (`struct mxfs_tauth_ticket`, magic `ATTK`:
     page, fs_gen, proposed/base seq, base nonce, writer node+inc, nonce,
     crc) which makes that copy an invalid image — one winner per spare,
     miscompare = `-ESTALE`; a live foreign ticket = `-EBUSY` unless the
     store's `fenced_cb` (`dlm_owner_purged`: recovery-purged after the
     PR fence) says that incarnation is fenced (`P-TAUTH-TICKET-TAKEOVER`)
     or it is our own abandoned ticket (resume); (3) ticket flushed before
     any body byte, body sectors 1..7 FUA + flush; (4) publish =
     CAW(ticket → final sector 0) + flush, miscompare =
     `P-TAUTH-TICKET-STOLEN` `-EIO` (poison + reconcile); (5) readback:
     exact match, or a later valid seq / a ticket citing our seq as base
     on our copy = superseded = committed.  The ledger treats `-ESTALE` /
     `-EBUSY` as "nothing written": reload the cache, no poison
     (`stale_writes`).  Usermode: `mxfs_pal_bdev_compare_and_write`
     emulates the sector CAW on a regular file under a process mutex.
     Ruling: `docs/rulings/tauth-conditional-commit-ticket-caw.md`.
   - `v5_mount.c` (sess424): `bootstrap_cb` = `mxfs_disklock_lowest_live_slot
     == local_slot`; `bootstrap_node_cb` (sess426) = that slot's node/inc
     via `v5_slot_node_cb`; `node_inc_cb` = node → the incarnation the disklock
     table shows in its slot; PAGE_HANDOFF dispatch; tick in the TCP death
     worker (500 ms); `v5_handoff_takeover(node, inc, why)` after the ledger
     purge at recovery completion (`recovery_complete` ladder with the
     victim epoch, `v5_recovered_cb` with the slot's last epoch), on
     clean-release observation (epoch from the monitor) and on GOODBYE
     (incarnation read from the slot before the lease unregister);
     `mxfs_dlm_handoff_depart` after `release_all`, before GOODBYE.  A
     slotless identity never attached a ledger, so the two slotless
     purge arms need no takeover.
   - Where the departure trio runs (0.75.2): the ledger purge, the table
     purge and the takeover for a departed peer are each a pass over the
     whole ledger, so the clean-release, recovered and GOODBYE callbacks
     hand them to a departure worker (`v5_depart_queue`, one departure at
     a time in that order, a second request for the same departed
     incarnation coalesced, `P-DEPART-WORK` phases) and keep only the
     immediate membership work: lease unregister, remaster, beacon, notify.
     The elected replayer's recovery-complete ladder runs the two PURGES
     synchronously because its held-failure gate must see the ledger purge's
     result before the slot is republished — a partial purge means recovery
     is NOT published.  **The takeover is not in that barrier.**  What the
     barrier owes the cluster is that the dead incarnation can no longer
     write or grant authority and that every request to a page it owned has a
     safe live path; the fence, the replay and those two purges establish all
     of it.  Transferring the pages is eager cleanup and first-access
     prewarming on top, and holding recovery completion behind it held the
     survivor's single-holder Write Exclusive reservation for the length of
     the pass — measured 4779 pages / 71 s on a 2-node rig, 7984 pages /
     103-107 s on an aged one — during which the rebooted victim could not
     re-register or rejoin.  So the takeover runs on the departure worker,
     with its own request flag: routing it through the ordinary departure
     queue would put it under that queue's `{node, incarnation}` dedupe,
     which the completion's call has never been subject to, and it would then
     be dropped whenever a GOODBYE or clean-release departure of the same
     incarnation had already run — a pace problem converted into pages nobody
     ever takes over.
   - **What being off the barrier costs the pass, and what pays for it.**  A
     pass that outlives the reservation runs while membership moves, so two
     things that were free under the gate have to be bought:
     *Certification is rechecked between pages,* not once at entry: a peer
     that returns on a lower heartbeat slot becomes the node certified to
     write authority transitions, and the running pass stops between pages
     (`P-TAUTH-TAKEOVER-DECERTIFIED`, `-EAGAIN`) and leaves the rest under
     the departed authority.  Nothing is lost by stopping: every mount queues
     an orphan sweep at its own settle, so the node that took certification
     is the node that finishes the work.  This is placement, not fencing —
     the departed incarnation is dead by proof and every write is a
     conditional commit, so a late write could not corrupt; it would just be
     the wrong node writing.
     *Dead is not reclaimable* (D-0981, design consult Astra 2026-09-19).  A
     departed authority that is a recovery VICTIM whose slice replay has not
     reached IMAGES_REPLAYED keeps its pages and its records, whatever else
     says it is dead (off the slot map, settled, purged): those records are
     what the replay's current-safety check judges against the sealed
     fence-time manifest, and a takeover that retires one turns a healthy
     replay into "authority mutated after the seal" and a terminal
     whole-filesystem quarantine.  The guard is judged once, at the choke
     point every takeover path shares (`dlm_takeover_page`, before the
     prepare, the activation and the purge — `P-TAUTH-TAKEOVER-UNDER-
     JUDGEMENT`, `-EAGAIN`), so the orphan sweep, an on-demand takeover for a
     request that needs the page and the named passes all obey it; the sweep
     also pre-filters (`P-TAUTH-ORPHAN-AUTH ... judging=1`,
     `judging_pages=`) so it does not issue a refused takeover per page.  The
     answer (`recovery_judging_cb`) is PLATTER-BACKED (0.89.4, design
     consult Astra 2026-09-19): the retention obligation is durable and
     belongs to the victim, whoever declared the death, whoever wrote the
     intent and whoever holds or abandoned the attempt.  This node's own
     recovery-pending marker is only a hint: when one names {node, inc} its
     slot's descriptor is read, and at IMAGES_REPLAYED or beyond the
     judgement is over and the completion ladder's own purge and takeover
     run as before (a completed descriptor is a valid negative because a
     victim's descriptor lives in its own slot).  With no marker the 64
     records are read: an ACTIVE record naming the incarnation contradicts
     "dead" and protects; a RECOVERY_GUARD whose descriptor names it below
     IMAGES_REPLAYED protects at any owner, lease state or age; a slot that
     cannot be read or a descriptor present but undecodable is UNKNOWN and
     protects, since "no valid descriptor" is evidence only when every slot
     was classified.  A descriptor nobody advances protects the records for
     as long as it stands: that is the fail-closed side, and the
     availability answer is adoption of the stranded attempt, never a
     timeout.  The marker-only form failed under a lone cold return onto a
     departed prover's standing FENCING intent for this node's own previous
     incarnation: the mount's sweep ran before the join gate declared
     anything, retired the victim's records, and the manifest sealed later
     was empty (`P-RMAN-COLLECT-TAUTH entries=0`), so the replay refused every
     committed image and quarantined the domain.  Retention is a different
     question from liveness — a guard record answers "may its authority
     history be destroyed", never "is it a live owner" — so it lives in the
     reclamation predicate, not in the occupancy map.  Still open from the
     same consult: the mount-time sweep should run after the mount's
     recovery census rather than before the join gate's declarations, and
     the ACTIVE → GUARD → released handoff should be stated as an invariant
     with no durable gap.  Refusing the on-demand path is safe for
     liveness because a request on such a victim's resources is already
     parked by the recovery-blocked cutoff until the same stage; an
     unfenceable victim can hold its pages indefinitely, and that is the
     safety side of the trade — elapsed time never turns a pending recovery
     into an orphan.  The verdict path is deliberately NOT weakened for a
     local mutator: an absent record cannot say whether a foreign write
     landed after the seal, so preventing the mutation is the only sound
     fix.  Harness: `tests/d0981_pending_victim_sweep.sh`.
     *The per-page record purge names the incarnation,* not just the node id.
     A page is published as this node's the moment the takeover activates it,
     which is BEFORE the purge on that page, so the ordinary grant path can
     serve a request and write a record in between — and the node id it
     writes is the departed one whenever a live mount carries that id, which
     a resumed term (`boot_resume_node`) and a pinned id both arrange, and
     which is the whole reason a departure of this mount's own id skips the
     id-keyed bulk purges.  An id-only match retired that live tenure and the
     import rebuilt the page without it: a lock lost with no error anywhere.
     Records of the departed id under another incarnation, or under an
     incarnation the caller cannot match, are now spared and counted
     (`P-TAUTH-PURGE-INC-SPARED`, `purge_inc_spared`) — unknown provenance is
     not evidence that removal is safe.  The whole-ledger purge still names a
     node id alone, deliberately: its callers run it where no other
     incarnation can be carrying that id, inside the barrier with the
     departed node fenced, or skip it entirely when the id is this mount's
     own.
   - Both ledger passes build their
     candidate set from one bulk scan of the region (16-page runs, both
     copies): the takeover keeps the per-page fresh read only for pages
     whose platter image names the departed authority, the purge visits
     only pages whose image is this authority's and holds an entry naming
     the departed owner (an unreadable page stays a candidate; a failed
     scan falls back to the full walk).  Nothing membership-critical runs a
     ledger pass on the heartbeat thread.
   - Tests: `tests/tauth/ledger_test.c` bootstraps its pages and proves
     the -EPERM/-ESTALE refusals, the PREPARED→ACTIVE takeover from a dead
     authority (idempotent prepare, wrong victim, wrong seq, retarget
     without proof all refused, entries unchanged across the handoff);
     `dlm_ledger_test.c` runs the successor takeover after every recovery
     purge (the engine parks a dead authority's pages forever otherwise —
     that IS the fail-closed contract) and keeps the page's authority on
     its collision plant.  All three PASS sess424.  Two later cases cover the
     two prices above, both without a rig: `ledger_test` case 17 puts EX for
     `{5,100}` and EX for `{5,101}` on one page and purges naming inc 100 —
     the second survives, and the same call with `inc = 0` retires it, which
     is what makes the case non-vacuous; `dlm_ledger_test` case 12 decertifies
     a running bulk pass at an exact page boundary (the mesh's bootstrap
     predicate answers truthfully for a budgeted number of calls and false
     after) and asserts `-EAGAIN`, one decertification, pages still under the
     dead authority, and that a later certified pass drains them.
   - **GHOST grants (sess424, D-TCP-LEDGER-GHOST-GRANT-STUCK-SHARED-BIT-0340,
     ruling `ccloop-c7ee71c6-sess424-GPT-ruling-ghost-grant-delivery-and-
     unresolved-pr-bits`)**: 0.34.0's finalize refused delivery of a
     SUCCESSFUL commit when `ledger_gen` moved in between, freed the entry
     and answered REMASTER — the durable holder bit stayed with no holder
     to release it; on the 32/tcp rig the root inode's record kept a PR
     bit and every later mount timed out on ino=128 (EIO).  Fixed: a
     successful commit is delivered whatever the view did afterwards
     (`P-TAUTH-LATE-DELIVERY`; the page write + exact readback IS the
     authority proof and every successor imports the record), remaster
     only on the ledger's own `-ESTALE`; an imported shared bit whose slot
     the heartbeat table could not name yet is re-resolved on every import
     (`P-TAUTH-IMPORT-RESOLVED`) and stays an EX blocker until then (never
     retired on a timer — ruling).  Reproducer: `tests/tauth/formation_test`
     (12-node join ramp, PR/EX storm on ino=128; part of `make test`).
     Owed to step 5 by the ruling: durable `{node, inc}` per shared holder
     (a slot-indexed bitmap cannot tell an old holder from the slot's new
     occupant), a serialized cancel protocol, and the audit of every
     uncertain-completion path.
   - **Concurrent-release page wedge (sess425, 0.35.1,
     D-TCP-CONCURRENT-RELEASE-DOUBLE-GRANT-PAGE-WEDGE-0341, ruling
     `docs/rulings/concurrent-release-fix-shape.md`)**:
     0.35.0's successor selection treated every PENDING_RELEASE holder as
     already retired; with two shared holders releasing concurrently the
     second round decided EX over the first holder's still-durable bit, the
     ledger refused the bundled `[release, grant]` (-EBUSY, DOUBLE-GRANT),
     and the refusal stranded the release entry — kept PENDING_RELEASE with
     the releaser's retry ACKed OK as a duplicate.  A stranded PENDING entry
     is exactly what the handoff freeze drains on, so the root inode's page
     could never move (`P-TAUTH-FREEZE-DRAIN-TIMEOUT` ×94, 26/32 mounts
     aborted).  Fixed: the bypass is scoped to the transition's own release
     item(s); every durable retirement re-scans the waiters (the last of
     concurrent releases finds what the others unblocked); a refused bundle
     re-commits its releases alone; a retirement that still fails is
     `P-TAUTH-RELEASE-STUCK` and re-driven by the MASTER's release tick
     (the releaser may be dead) — the invariant is *every PENDING\_\* entry
     has exactly one live master-owned driver*; a conflict-refused grant is
     `MXFS_ERR_LEDGER_BUSY` (requester retries), not -EIO.  Reproducer:
     `tests/tauth/concurrent_release_test` (part of `make test`).
   - **Local orphan grant (sess425, 0.35.1, D-...-0343)** — the same
     invariant from the delivery side: a local requester that exhausted its
     budget while its grant was PENDING_DURABLE has no waiter when the
     commit lands, and finalize ignored that (`pending_signal_resource`
     false), leaving the master a durable holder nobody unlocks.  Fixed:
     `mxfs_lock.unclaimed` + `dlm_release_local_orphan`
     (`P-TAUTH-LOCAL-ORPHAN-RELEASE`) — the local analogue of answering an
     unsolicited GRANT with LOCK_RELEASE.  The timeout unlink deliberately
     never frees a PENDING\_\* entry (the committing thread owns it), so a
     "waiter gone" outcome is always handled at delivery.
   - **Purged-slot poisoning (sess425, 0.35.2, D-...-0344)**: the purged-owner
     memory ("dead ids never return") also matched on heartbeat SLOT, so a
     later occupant of a purged slot had its live records lazily retired
     from the platter on the master's next page import (`P-TAUTH-PURGE
     node=<live>`, proven by `dlm_ledger_test` 7b) and its EX re-granted —
     concurrent EX.  Identity is the per-incarnation node id only now; an
     unnamed shared bit on a purged slot stays an UNKNOWN blocker.
   - **Requester attach (sess425, 0.35.2)**: a requester whose own grant is
     mid-commit attaches to the transition (pending registered under the
     table lock) instead of spinning RETRY every 10 ms — the spin burnt the
     10-retry budget under a slow page write and produced the D-0343 orphan
     shape from the requester side.  `dlm_retry(ctx, why)` tags every RETRY
     site and the exhaustion line prints the per-request tally (D-0345).
   - **Partial recovery purge (sess425, D-...-0342, 0.35.2)**:
     every `mxfs_dlm_ledger_purge_owner` caller ignored a partial purge and
     dropped the victim's imported blockers (recovery-complete also
     republished the slot EMPTY) over retained bits.  Ruling
     `docs/rulings/partial-ledger-purge-held-failure.md`:
     held failure at recovery-complete; blockers stay until a COMPLETE
     purge pass over the pages mastered NOW returns 0 (master-owned
     purge-pending list on the release tick); -ESTALE is not success — the
     successor inherits the purge via the purged-owner tombstone on import.
   - Known limits carried to step 5 (the first is closed by 0.75.1/0.75.2:
     bulk candidate scans and the departure worker, see the step-4 note
     above): takeover read every page fresh (2 reads × every page) on the
     heartbeat / replayer thread; a departed
     incarnation nobody can name (`P-TAUTH-TAKEOVER-NOINC`) leaves its
     pages parked until a survivor names it; no rig verification yet —
     the s422 run of step 3 (0.34.0) had 4/32 tcp mounts refused and a
     hung workload/unmount that `tests/sess424_chain.sh` captures raw.
5. Seal barrier + shard directory + prover TCP branch + dead-master shard
   reconstruction; replay gate reads TCP manifests (live-check no-op on TCP).
   Verify: `tests/d0286_tcp_wedge.sh` RECOVERY lines complete with the holder's
   md5 (~70 s, the CAW shape); 32/tcp node_death_replay on the multipath rig.
   **LANDED 0.71.0 — the single-survivor shape (every survivor reads the same
   platter, so it is also each survivor's local half of the N-survivor
   barrier):**
   - The ledger IS the authority table, so there is no separate shard
     directory: the prover (`dlm/v5_mount.c v5_rman_snapshot`, TCP branch)
     seals the victim in the DLM and then collects every ACTIVE record whose
     exclusive holder is the victim's `{node, slot, incarnation}` straight
     from the platter — `mxfs_tauth_ledger_collect_ex_holder` over
     `mxfs_tauth_store_scan` (both copies of every page, 64 KiB runs of each
     copy array, the store's selection rule per page: highest valid seq,
     same-seq divergent images = UNKNOWN).  A page with no committed image
     fails the snapshot closed (it may hide a grant); the manifest is written
     in the CAW collector's entry format with `slot_idx` = the record's
     ledger index and the header flagged `MXFS_RECOV_MPTR_F_TAUTH_LEDGER`,
     `scan_slots` = pages scanned, which the consumer
     (`mxfs_v5_dlm_victim_manifest_load`) checks against its own region.
   - The seal cut (`mxfs_dlm_seal_owner`): the victim's node id is entered
     in `sealed_owners`; `mxfs_dlm_process_remote_release` refuses (no ACK)
     a release from a sealed owner, and the seal returns only once no
     PENDING_RELEASE of that owner remains (3 s bound, else the snapshot is
     retried).  The CAW transport needs none of this because a fenced victim
     can no longer CAS its own slots; on TCP the master commits on the
     victim's behalf, so a release queued before the death and delivered
     after the fence would otherwise mutate the sealed authority.  The
     recovery purge (`mxfs_dlm_purge_node`) clears the seal.
   - The seal is the SECOND line of defence against the victim's own releases,
     not the first.  A withdrawal is explicit, so the survivor fences without
     waiting for a lease to lapse, and the seal lands about 2.4 s after the
     victim's log shutdown on the 2-node rig; anything the victim releases
     inside that window is accepted by the master and is simply absent from
     the manifest — measured with the victim-side gate disabled: the manifest
     sealed with 3 entries instead of 4, and the survivor would answer
     `notheld` to any VALID token the slice carried for that resource.  The
     first line is therefore on the victim: once its session is POISONED no
     wire release of its own leaves it, from any emitter.  There are exactly
     two ways a LOCK_RELEASE is built — `dlm_send_release_msg` (reached from
     `mxfs_dlm_unlock_gen`, the pending-release re-send tick and the
     unsolicited-grant reject) and `mxfs_dlm_send_unconditional_release` —
     and every path into them is refused while POISONED: the front-end
     wrappers in `v5_mount.c` through `v5_tcp_release_gate`, the re-send tick
     and the grant reject through `dlm_refuse_release_while_poisoned`.  A
     release the master had not acknowledged at the poison stays in its table
     as a held grant, which is exactly what the manifest must say about it;
     the recovery purge retires it.  The two primitives also carry a
     choke-point probe (`P945-RELEASE-WHILE-POISONED`, log only) so a path
     that reaches one of them while poisoned names its caller — a survivor
     purging a dead peer's records is the opposite operation and is not
     gated, so the disposition is per site.
   - The gate's current-safety check (`mxfs_v5_dlm_victim_live_read`) reads
     the resource's record fresh (`mxfs_tauth_ledger_read_fresh`) and
     answers in the CAW live read's terms — holds iff ACTIVE with the
     victim's heartbeat slot as exclusive holder, `-ENOENT` otherwise — so
     `P-RMAN-POSTSEAL-MUTATION` / `P-RMAN-LIVECHECK-ERR` keep their
     meaning; the pre-purge verification runs on TCP for the same reason.
   - What the N-survivor case still owes: the ruling's SEAL message to every
     surviving authority with an acked watermark.  With one survivor the
     local seal is the whole barrier; with several, a release the victim
     sent to ANOTHER master just before dying can still commit at that
     master after this prover's scan (the record then reads FREE at replay
     time and the gate aborts the attempt fail-closed — never applies over
     a mutated authority — so the exposure is availability, not integrity).
   - Cost: the collect reads the whole region (0.4 % of the device) at
     fence time on the heartbeat thread, in 64 KiB transfers; measured
     walls are printed by `P-RMAN-COLLECT-TAUTH ... ms=`.
   - Usermode proof: `tests/tauth/ledger_test.c` group 16; rig oracle:
     `tests/tcp_death_replay.sh` (fsync-acknowledged writes on the victim,
     virsh destroy, survivor replays from the ledger manifest, every
     acknowledged file verified from the survivor), driven by
     `tests/tcp_2node_death_chain.sh`.
6. The full ~35-row crash/ordering matrix from the ruling as `tests/tauth_matrix.sh`.
7. **VIEW TABLE + membership barrier (D-0349 target design, sess428, PROTO_GEN
   10 — NOT YET BUILT).**  Ruling: `docs/rulings/d0349-view-table-barrier-design.md`.
   - Why: format v2 sized the rig ledger at **67,651 pages** (chk-geometry,
     s431).  Per-PAGE durable authority (UNOWNED/PREPARED/ACTIVE header,
     1-3 writes per transition) makes every ownership move O(pages): ~2,114
     pages per node per view change, and the lazy first-touch park (REMASTER
     deny / RETRY + 100 ms requester retry, `dlm_page_ensure_mine`) costs the
     small-file workload one round trip per page it touches (s430: 1092
     `P-TAUTH-REMASTER-PARKED` on 1083 distinct pages, 30 s budget missed).
     An EAGER per-page activation pass in the handoff tick was built and
     **refuted** in the 12-node usermode ramp (bootstrap-node serialization:
     ~1 page per 500 ms pass, then 12 lock failures / 9× -110 on the
     post-ramp EX check); it is removed.
   - Shape: a durable VIEW TABLE (page range → owner incarnation for a table
     generation) in double-buffered slots with a CAW-switched ROOT pointer;
     2-phase barrier on membership change — PREPARE(Gnew, Gold, digest,
     moved ranges, membership digest, coordinator term) → every admitted
     node freezes new requests on moved ranges, finishes/cancels old-routed
     queued requests, blocks new old-generation commits, waits for admitted
     old-generation commits to be durable or conclusively failed, persists
     the promise, ACKs the exact digest → coordinator CAW-commits the root →
     nodes validate the committed root, new owners open admission, frozen
     requesters reroute.  A missing ACK is never converted by timeout: the
     node returns, or it is removed + storage-fenced + its ranges recovered.
     Grant commits carry the table generation + deciding owner incarnation
     (provenance, not expiry); old page grant records stay valid blockers;
     the new owner's first decision on a page is the ordinary lazy page
     import — no ownership transition, no park.  Coordinator death: the
     replacement reads the root (Gold → abort/unfreeze or retry the exact
     proposal after excluding the old coordinator; Gnew → finish, never roll
     back; ambiguous → stop).  Late joiners hold no authority until a later
     committed generation maps ranges to them.  The per-page owner header
     loses authority semantics at one explicit barrier.
   - Interim allowed by the ruling: real page-GROUP authority (one durable
     generation per group, whole-group admission close + drain, grants stay
     page-scoped).  Landed meanwhile (0.38.2, ruling option (c)): the
     bootstrap node prepares an UNOWNED page straight to its view-owner in
     ONE transition (`mxfs_tauth_ledger_prepare_unowned`, FREEZE_REQ
     handler) instead of ACTIVE(self) then PREPARED; `handoff_parked` is in
     `P-TAUTH-DLM-STATS`.
   - Verify: `tests/tcp_token_plumbing_verify.sh` workload < 6 s (2× native)
     on 32/tcp; formation wall; zero `P-TAUTH-REMASTER-PARKED` in steady state.
