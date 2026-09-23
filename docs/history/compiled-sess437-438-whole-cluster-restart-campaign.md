<!-- sess437-438: D-437 whole-cluster-restart — incarnation-owner-liveness tuple fix, 64-bit PR key+ledger (item 2) landed 0.43.0, items 3/4 shortcut reje… -->
## Topic

D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437: recovering an MXFS
cluster after ALL 32 nodes crash/reboot together, with no live peer to
preempt a dead node's SCSI PR key. sess437-438 (fleet 0.41.10 -> 0.43.0)
found two liveness holes, got binding GPT (RULE-5) design rulings for both,
landed one build item, and had a proposed shortcut for the remaining items
rejected. Chronological.

## Discovery (sess437 chain7)

`docs/history/docs/history/docs/history/compiled-sess437-438-whole-cluster-restart-campaign.md`:
two failures exposed the holes.
- **radv takeover arm, fails=4**: harness rewrote the recovery descriptor to
  owner=(R.node_id, R.epoch+1) mid-ladder. R's retry re-enters
  `mxfs_v5_dlm_recovery_acquire`: `replay_authorized("reacquire")` ->
  `-EBUSY` (recov_auth_holds fails) -> auth mask cleared -> fresh claim
  `-EBUSY` -> `v5_mount.c:5160` branch treats "owner_node alive" (true — R
  itself is alive, just under a new epoch) as "wait", so R and every survivor
  wait on P238-RECOV-OWNED every 30s forever. `v5_complete_classify`
  (TAKEOVER) is never reached. Root: liveness was being decided on
  `node_id` alone, not on the specific (node_id, epoch) that claims
  ownership.
- **nosurv arm, fails=1**: all 32 VMs destroyed; test1's remount refused
  with `P305-PR-PREDECESSOR-KEY-PRESENT` (`SCSI PR register failed (-17)
  refusing to join unfenced`). The node's own previous-boot PR key survives
  PTPL; with no peer alive, nothing can PREEMPT it; the only remedy was
  manual `single_node_exclusive=1`. This is the whole-cluster-restart gap
  itself — filed as D-437.

Same session, a separate defect closed cleanly: **chain9 zeroinc, fails=1**
— root was `hb_still_dead_stamp` treating an epoch-0 same-node record as a
SUCCESSOR (P163-RECOVERED fired with no replay 2s after death, grants
purged, -ENODATA thereafter) plus no fence re-drive after restore. Fixed in
0.41.11 with an epoch-0 guard in `hb_still_dead_stamp` (same node + invalid
epoch = still dead, no spurious RECOVERED) and P238-FENCE-REDRIVE added to
`recovery_acquire` (claim -ENOENT + slot UNFENCED + dead_epoch != 0 ->
re-prove fence -> claim again).

## GPT ruling — Hole 1 (owner liveness) and Hole 2 (unattended restart)

`docs/rulings/incarnation-owner-liveness-and-whole-cluster-restart.md`:
- **Hole 1**: owner liveness must be keyed by the exact **(owner_node,
  owner_epoch) tuple**, never `node_id` alone. Classification table: exact
  tuple == my incarnation -> continue; exact tuple, another live incarnation
  -> WAIT; same node_id, different LIVE epoch -> owner REVOKED, eligible for
  takeover; no exact tuple heartbeating past expiry -> eligible; two live
  epochs for one node_id -> invariant violation, fail-stop. Every
  "owner_node alive => WAIT" branch (including the reacquire path) must be
  removed — "SUPERSEDED" means "my cached ownership is invalid, reclassify",
  not "takeover prohibited". Same-node adoption is an ordinary CAW takeover:
  owner=(R, epoch_new), owner_term=T+1; R never inherits epoch_old
  authority. Epochs compare by equality only (random draw), never
  numerically. Unfenced-incarnation takeover is sound only if the whole
  ladder is incarnation-fenced (every stage CAW carries the owner tuple +
  term; no unguarded non-idempotent step; stale async completions revalidate
  via CAW) — otherwise fall back to fencing the whole node_id's PR key.
  13 required tests enumerated (concurrent same-node adoptions, delayed
  completions under old term, forged future epoch, two slots same node_id,
  etc).
- **Hole 2**: reject a 32-bit-node_id/32-bit-boot-hash PR key. Require a
  full **64-bit unpredictable PR key, one per host boot per LUN**, plus a
  CAW-protected on-disk **registrant ledger** (`pr_key -> {cluster_uuid,
  stable_host_uuid, initiator_identity, full_boot_uuid, key_generation,
  state}`), reserved atomically before use, regenerated on collision, gated
  by an incompat feature bit — no mixed 32/64 semantics (this also folds in
  D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377). Self-replacement of a node's
  own predecessor key is allowed only under strict conditions: same stable
  host identity, a *different* authentic boot uuid, and topology proof of
  non-concurrency (refuse on any duplicate-IQN/host-uuid/VM-clone/session-
  reinstatement evidence). "Heartbeat-dead + holder absent" is explicitly
  NOT a fence — a paused host can resume; HB expiry only authorizes fencing
  a *foreign* host, backed by successful PREEMPT-AND-ABORT + verification.
  4-phase bootstrap sequence (establish boot identity/PR key before any slot
  claim or FS write; claim slot preserving the prior occupant's dirty
  recovery generation; scan+observe+fence dead foreign boots with persisted
  certificates; recover own previous slice only after own key is cleared,
  foreign slices only with certificates). 19 required tests. **Build order**:
  (1) tuple classifier everywhere; (2) harden the ladder (CAW auth, idempotent
  restart) before enabling unfenced takeover; (3) same-node/new-epoch
  ordinary takeover; (4) 64-bit keys + identity ledger + feature bit;
  (5) predecessor-boot self-replacement + duplicate-IQN refusal; (6)
  serialized bootstrap path; (7) fence-before-replay per old boot with
  certificates; (8) full matrix before enabling unattended startup by
  default.

## Build sequence 0.41.11 -> 0.42.0 -> 0.43.0

`docs/history/docs/history/docs/history/compiled-sess437-438-whole-cluster-restart-campaign.md`: 0.42.0
adds `v5_incarnation_state` (LIVE/REVOKED/UNKNOWN) driving the -EBUSY
takeover gate and the FENCING/SNAPSHOTTING takeover gate (build-order item 1
executed), plus `dlm/hostid.{c,h}` printing `P-HOSTID host=<id> boot=<id>`
once per module load (Hole-2 item 1, identity visibility with no protocol
change yet).

`docs/history/docs/history/docs/history/compiled-sess437-438-whole-cluster-restart-campaign.md`:
0.42.0 built+deployed (chain 12). Layout finding blocking Hole-2 item 2:
`struct mxfs_disklock_heartbeat` is **exactly 512 B** (hdr 40 + union 384 +
prov 32 + mepoch 44 + feat 12) — no spare bytes for an identity block, and
the disklock region (64 HB records + 65536 CAW slot records) has no spare
records either. Decision: add a new per-node identity region
(`MXFS_FORMAT_F_HOSTID`, 64x512B) written at claim time, OR carry `pr_key`
in the existing recovery descriptor's `fence_victim_key`. Fencers must stop
deriving the victim key as `(uint64_t)node_id` — 147 grep hits found, with
the actual derivation points at `dlm/scsipr.c:31,545`, `v5_mount.c:2001,
2610`, `dlm/mount.c:857,1068,1137`.

`docs/history/docs/history/docs/history/compiled-sess437-438-whole-cluster-restart-campaign.md`: chain
12 harvest confirmed both fixes work on the rig: takeover arm did exactly
the ruled thing (`P236-REPLAY-REFUSED` -> `P238-RECOV-TAKEOVER why='our OWN
earlier incarnation'` -> term 1->2 -> `P238-RECOV-TAKEN` ->
`P163-RECOVERY-COMPLETE`); zeroinc arm recovered all 31 nodes through
`P-HB-INC-ZERO` correctly, with one survivor correctly doing
`P238-FENCE-REDRIVE` -> intent -> `PREEMPT_ABORT_DONE` -> replay. Two
harness bugs found+fixed during verification, not FS bugs: `RNODE` unbound
under `set -u` in `d_recov_advance_bounded_verify.sh`; the zeroinc PASS grep
needed two spaces (`'slot 4  .* complete'`). Item 2 (64-bit PR key + HB
identity block + registrant ledger) then landed in 0.43.0 across
`mxfs_super.h` (PROTO_GEN 12, `MXFS_FORMAT_F_PRKEY64`), `dlm/disklock.{h,c}`
(evict ring cut 23->19, `mxfs_hb_identity` @360), new `dlm/prledger.{c,h}`,
`dlm/scsipr.{c,h}`, `dlm/v5_mount.{c,h}`, mkfs/chk region support, and docs.
A layout trap surfaced during this: the new identity entry struct came out
504 B — a **sub-sector I/O length**, which the fleet's PAL bdev path hangs
(not fails) on rather than erroring, the same failure class as
`trap-pal-bdev-write-must-be-sector-aligned-subsector-bio-hangs-dm` — fixed
by padding to `reserved[412]` with a static assert on the size.

`docs/rulings/prkey64-item2-ledger-not-deferrable.md`:
GPT reviewed the item-2 design as proposed and ruled it NOT SAFE, with 9
required fixes, the two structural ones being: (5) **the registrant ledger
cannot be deferred to a later item** — a crash after REGISTER but before
slot claim leaves a durable PTPL registration with no durable owner, so a
minimal CAW-protected ledger (write a PREPARED entry before REGISTER,
transition after verified registration/claim) had to land in item 2 itself,
not item 5 as originally planned; and (1) the victim-key latch used by
fencing must live **inside the frozen incarnation/death snapshot**
`{slot,node,epoch,pr_key,key_gen}`, copied before successor adoption — never
looked up live via current slot state in the fence callback, since a
different key for the same (node,epoch) is a protocol violation, not an
update. Other fixes: WITHDRAWN records may supply the key (never a GUARD
identity block, which names the guard writer, not the victim); "once per
module load" isn't "once per host boot per LUN" — key selection must be
serialized per-LUN and persisted across mount attempts; collision check
exactly once under a per-LUN lock, verified after via READ FULL STATUS;
GUARD descriptor CRC must bind `fence_victim_key` to the victim tuple;
identity CRC must bind slot + fs_uuid + flags + key_gen (CRC is transplant
detection, not authenticity); key_gen increments only on key change, and a
key change for an already-observed (node,epoch) is fatal; keep an explicit
incompat bit rather than relying on proto_gen equality.

## Items 3+4 shortcut — rejected

`docs/rulings/items3-4-shortcut-unsafe-full-bootstrap-required.md`:
proposed shortcut was self-replacement at REGISTER `-EEXIST` (same host,
different boot, key present in READ KEYS) plus a 2-read HB liveness scan
(>=4s) treated as proof of "no live peer/no clone", gating an *ungated*
identity-keyed pass-1 replay of the node's own dead ACTIVE/WITHDRAWN
record. GPT rejected it as UNSAFE: HB silence is not exclusion (a paused
host can resume after any finite scan — only bounded self-fencing leases +
PREEMPT-AND-ABORT prove it); a survivor may already own recovery while the
rebooter is scanning; publishing a new ACTIVE identity makes survivors
retire the pending recovery and purge the dead tuple's grants before the
rebooter's own replay finishes (a torn window); cross-slice LSNs are
incomparable, so an ungated own-slice replay followed by token-gated
foreign-slice replays has no proven redo-ordering invariant; READ KEYS
listing a key doesn't prove per-nexus registration (need READ FULL STATUS
transport IDs). Required real shape instead: a durable CAS
bootstrap/recovery-owner token; fence-and-verify removal of every old/
unknown registrant against ledger+HB before marking anything FENCED;
freeze/reconstruct all dead grants; replay **all 32 slices — including the
node's own predecessor slice — through the same sealed-manifest +
recovery-ownership + token-gated foreign-replay engine** (claim into a
GUARD/RECOVERING state, never publish a plain ACTIVE successor first);
publish ACTIVE / allow old-grant purge only after a durable
RECOVERY_COMPLETE record. Consequence: D-OWN-CRASH-RECLAIM closes via the
common bootstrap engine treating the own slice as a dead incarnation, not
via a special-cased identity pass-1. Open design question carried to the
next session: the bootstrap owner itself needs a slot before the survivor
engine can run at all — needs a dedicated bootstrap record and a
transitional GUARD/RECOVERING claim on the node's own old slot, flagged as
requiring its own RULE-5 consult.

## State at sess438 end

`docs/history/docs/history/docs/history/compiled-sess437-438-whole-cluster-restart-campaign.md`:
tree at 0.43.0 (item 2 complete, compile-checked per object, not yet linked
into a deployed `.ko` pending chain 17). Build-order items 3-6 (bootstrap
serialization, fence-before-replay per boot, full matrix before default-on
unattended startup) remain open, blocked on the bootstrap-slot design
question above. Ledger touched this arc: D-WHOLE-CLUSTER-CRASH-RESTART-
REQUIRES-OPERATOR-437 (open, driving item), D-RECOV-ADVANCE-UNBOUNDED-RETRY,
D-RECOV-ZERO-EPOCH (root found + fixed 0.41.11), D-PR-KEY-32BIT-NODE-ID-
COLLISION-RISK-377 (folded into item 2's 64-bit key design), D-OWN-CRASH-
RECLAIM (updated, see items-3-4 ruling above).

Secondary threads riding the same two-session arc, same checkpoints, not
part of the core liveness/PR-key design: D-0133 inobt/ifree mismatch
occurrence recorded (chain8 ubsweep); D-0346 ESTALE x2 fixed (chain10);
D-380 dlm_scaling still no repro (chain10, 5/5 PASS); D-RSYNC-OVERWRITE's
EBADE assertion found VACUOUS — EIO was 0, so the check never fired
(chain11, needs a non-vacuous rerun); D-CROSSNODE-OPEN-UNLINK's
unlinker_death FAIL root-caused as `foreign_replay_token_enforce` being
off by default (blanket refusal), harness updated to arm enforcement fleet-
wide for chain 18; D-32NODE-SHARED-DIR-CREATE-PACE got an increment-0
measurement baseline (P138 release anatomy: p50 10.4ms dominated by 5ms
wire-unlock; 83% of `find_slot` calls are hint-miss probe walks, not CAS
contention) with `tests/handoff_anatomy.sh` written to capture it, but the
increment-1 per-node dir-shard prototype is not started.
