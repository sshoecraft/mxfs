<!-- TCP 2-node ledger-takeover/handoff campaign sess506-513 (0.73.3-0.75.14): D-0904-D-0908 chain, root causes, fixes, rig traps. -->
# TCP 2-node ledger takeover/handoff campaign (D-0904–D-0908), sess506–513, 2026-09-04/05

Run 140e6b67 (and predecessor fe306e35), rig: QNAP iSCSI LUN, test1+test2, TCP
transport. Criteria answer stayed NO throughout ("is 2-node TCP production
ready?"). Version arc 0.73.3 → 0.75.14. One continuous root-cause chain: fixing
each ledger-takeover/handoff bug exposed the next, all under the same defect
family (per-page ledger ownership handoff across mount/unmount/rejoin on TCP).

## 0.73.3–0.74.x: death-checker D-state, foreign-replay ordering, transport split

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
`v5_tcp_death_worker_fn` idled in plain `msleep(500)` → permanent D-state
worker, false-positive readiness failures. Fixed 0.73.3 with
`mxfs_pal_sleep_ms_interruptible`. 0.74.0 designed (unbuilt): bounded fence-retry
series → `MXFS_RECOV_F_FENCE_BLOCKED` fail-fast instead of unbounded retry.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
D-state closed F&V. 0.74.0 built; first plain death lap FAILED: foreign replay
of a 2-txn slice OVERRIDE-APPLIED an older partial dir-block image, but the
per-LSN drain (`xlog_recover_process_ophdr`) wrote it to platter before the
newer txn overlaid it → `__xfs_dir3_data_check` failure → force-shutdown of the
*survivor*. Three defects filed (foreign-replay override-vs-per-LSN-drain
ordering; write-verifier failure shuts down survivor; joiner not
transport-conformed — a default-CAW mount joined a live TCP cluster, causing a
split DLM). Fixed 0.74.1: defer the per-LSN drain until the replay is trusted.
0.74.2 (verifier routes through `b_mxfs_foreign_recovery`, no shutdown) and
0.75.0 (transport census before transport select: `MXFS_HB_FEAT_TCP`,
join-time ADOPT/CONFORMED/MISMATCH-REFUSED, PROTO_GEN 19) designed in tree.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`: drain-order
defect closed F&V on 6/6 dirty-death laps (forward + reversed order). 0.75.0
build launched.

## 0.75.0–0.75.4: takeover bulk scan, HB-thread stall, TCP same-boot gap

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.1 (takeover candidate bitmap via bulk ledger scan) built. Rig recovery
needed after a killed prior session left test2 powered off and test1 stuck in
injected FENCE_BLOCKED with a hung umount → filed umount-hangs-while-blocked
defect (mechanism unproven at this point). Root-caused a verify-arm "vacuity":
the harness's own cross-node visibility check drained the victim's dirty
metadata before replay could exercise the verifier — not a defect, harness
artifact. Added `TDR_VERIFY_INJECT` arm to force it.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
measured takeover bulk scan at ~4 s/pass over 26426 pages, THREE scan passes
for two departures. Found the scan itself running on the HB thread caused
`P278-HB-STALL`/`P-HB-MONSLOW` (18.6 s monitor stall). Found test2's second
clean unmount went dirty (`P-SB-SEAL-DIRTY-DEPARTURE`): SB-summary lock
retries (60 × 100 ms = 6 s budget) exhausted while parked on a page prepared
for its own earlier incarnation. Root: the TCP init branch never ran the CAW
branch's same-boot sequence (departure lock, quarantine reap, self_succeed,
settle-before-claim) — retire machinery was wired only after the claim, so
every remount after that hung. Fixed 0.75.2 (bulk candidate scan off the HB
thread + async departure worker) and drafted 0.75.3 (TCP same-boot port).

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.2 verified: zero HB stalls, clean departing-peer unmounts, ~8 s/departure
worker cost. 0.75.3 verified functionally (conformance arms A-D PASS in 58 s)
— but this run used CAW, not TCP, unknowingly (see trap below). Found
sameboot arm 1c: last leaver's remount waits 64 s on the peer's
RETIRE_PENDING record in `mxfs_bootstrap_survivor_scan` (RETIRE_PENDING
treated as "occupied"). Fixed in 0.75.4.

## 0.75.5: D-0904 born — successor imports predecessor's shared ledger bit

[[trap-sameboot-remount-harness-reloaded-module-without-force-transport-measured-caw-not-tcp]]:
`tests/sameboot_remount.sh`'s `join` reloaded `mxfs.ko` without
`force_transport=1`; every remount formed a new cluster and picked CAW by
default, so the "0.75.3 TCP same-boot" claim was actually a CAW measurement —
the CAW path already had this settle logic since sess451. Fixed: MODARGS
default now carries `force_transport=1`, every join asserts the `transport=`
line. General rule: any harness that reloads the module must pass the
transport explicitly and assert it per mount — a prep's `force_transport=1`
does not survive the harness's own reload.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
with the harness fixed, 0.75.4's arm-A rejoin hung in D-state in
`xfs_iget(root)`. Rooted: shared ledger holder bits are keyed per HB slot with
no incarnation tag. A rejoin's view change hands pages to the successor
*before* the old master's (now-deferred, per 0.75.2) departure worker purges
the departed incarnation; the purge skips handed-off pages ("notmine"); the
successor imports the predecessor's PR bit as its OWN grant; its own EX
request then self-deadlocks (`-EDEADLK`) against that phantom grant, self-demote
finds the inode not yet in the radix tree, and the demote-wait has no waker.
This is **D-0904**, and it recurs in different shapes through the rest of the
campaign. Fixed 0.75.5: on ledger-page import, a shared bit that resolves
locally with no local table entry and no pending request is residue — unlock
it (`P-TAUTH-IMPORT-RESIDUE`); an EX resolving to a different node id is
purged by that node id. New harness `tests/rejoin_residue.sh`. The
EDEADLK/no-waker self-demote path itself was filed as a separate open xfs-layer
defect, not fixed here.

## 0.75.6–0.75.7: D-0905 — whole-cluster restart never takes over the last leaver's pages

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
after a whole-cluster clean stop on TCP, the last leaver still owns (ACTIVE,
under a dead incarnation) every ledger page its era touched. The next era's
bootstrap mount settles that incarnation's heartbeat record but never runs
page takeover — `mxfs_dlm_handoff_takeover` was driven only by GOODBYE,
clean-release monitor observation, and fence recovery-complete, none of which
fire for a lone bootstrap remount (a single node bypasses the DLM entirely).
Result: the first join after a full restart parks on every hot page
(`why[prepare=60]`), the survivor's fail-fast arm shuts down the *healthy*
node, the joiner fences it, cluster dead. Wrote `tools/tauth_page_auth.py
<dev> <base>` (platter ledger census) to confirm: after the wreck, 12 pages
were still ACTIVE under the predecessor's incarnation. Probe (0.75.6) proved
the hypothesis directly (`P-TAUTH-PAGE-PARKED ... auth=<predecessor>`). Fixed
0.75.7: `v5_settled_incarnation()` queues the departure trio (own-predecessor
settle, empty retire-worker, empty admission-barrier) for every incarnation a
mount settles, deferred until DLM init completes, with dedup
(`P-DEPART-DONE-ALREADY`).

## 0.75.8: D-0906 — takeover import installs a dead node's grant as a live blocker

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.7's takeover worked (verified: purge + takeover ran, zero shutdown/fence).
But the *other* node then activated a handed-off page and imported the last
leaver's EX as a live blocker (`P-TAUTH-IMPORT-ACTIVE owner=<departed>`) —
`purged_owners` tracking is per-node-that-observed-the-departure, and the
receiving node never saw it directly; the 0.75.5 own-slot residue branch didn't
apply because the blocked slot wasn't its own. Its mount queued behind a
holder that no longer existed and sat silently for 5+ minutes. This is
**D-0906**. Fixed 0.75.8: `dlm_page_departed_authority()` — on takeover (a
PREPARED page whose writer != authority, either via the platter path or the
`MXFS_HANDOFF_FROZEN` message path), mark the authority purged by node id
*before* activation. Also: `mxfs_dlm_ledger_purge_owner` now purges by node id
alone when a slot names a different live occupant, clearing that node's shared
bits across every page the purging node masters.

## 0.75.9–0.75.14: D-0907, election residual, D-0904 continuation, D-0908

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.8's D-0906 assertions passed both laps, but a new failure appeared: a
settled predecessor's page stayed PARKED for the ~8 s bulk-takeover window,
during which the SB-summary lock retry budget (6 s) was exhausted at
`put_super`, producing a dirty unmount and a refused same-boot remount. This
is **D-0907**. A non-bootstrap joiner also parked with nobody to ask. Fixed
0.75.9: per-page on-demand takeover (`dlm_takeover_page()` factored out of the
bulk path; a parked page on a bootstrap node with a purged authority takes
over immediately; a non-bootstrap node sends `FREEZE_REQ` at 500 ms cadence).

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.9 confirmed D-0907's root (sameboot all arms PASS). New joiner residual:
~2 s of spurious parks because lowest-live-slot election named the joiner
itself before its monitor had read one HB interval's beat (not, as first
hypothesized, a node_inc_cb DECLINED race — no DECLINED lines were ever seen).
Fixed 0.75.10: when the elected node is self or unknown, broadcast `FREEZE_REQ`
to the whole view instead of waiting. Also surfaced a D-0904 recurrence in a
new shape: test1 imported the predecessor's slot-1 PR bit attributed to the
*new* test2 (not the departed id), producing 65 rounds of `P109-EDEADLK-NL`
retry with no release message ever sent (the arm's local unlock is a no-op
when nothing is locally held) — racy, timing-dependent on when the import
happens relative to the slot map update.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
0.75.11 added an inc-number hint to takeover so a stale FREEZE_REQ target can
be declined precisely. 0.75.12 fixed the D-0904 EDEADLK-NL livelock: the P109
arm now also sends `mxfs_v5_dlm_inode_orphan_nak` (gen-0 unconditional
release, gated on no local entry, TCP only) — verified once healing in 1 lap.
0.75.13 redefined PARKED as a stall condition (unanswered ≥500 ms) rather than
logging on every retry pass. **D-0908 filed** (major, unresolved): the root
mechanism behind both D-0904's shapes — a master attributes a predecessor's
slot PR bit to whatever currently occupies that slot, healing in 1 lap if the
new occupant is live (shape A) or BASTing a dead holder until purge if not
(shape B). No fix chosen: options (per-slot incarnation tagging = on-disk
format change; admission-time slot purge = racy) both need more measurement.
Estimated to hit ~50% of rejoins.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
two clean closure laps on 0.75.13. Census tool extended with `--entries` to
inspect specific pages. Delayed-join and held-rejoin harness arms added to
directly test whether D-0906's fix left a hole for pages a node takes over
*for itself* (no import path exercised, so no purge-before-activation check
runs) that are later handed on to a third node.

`docs/history/docs/history/docs/history/compiled-tcp-ledger-takeover-campaign-sess506-513.md`:
that hole was REAL — census showed a predecessor's AG0 EX surviving a
self-takeover and landing on a later joiner. Fixed 0.75.14: retire+import the
departed authority's records immediately after a self-takeover activation, not
only on cross-node import. Verified via census (clean after the fix). D-0904
heal further verified: planted held-lap heals in 1 lap, plus 3 natural
shape-A heals — residual noted (one `P142-BWORK-STALE` self-BAST survives each
heal, not yet fixed). Three closure-lap chains (s513m/n/o) were still running
at the session's relay boundary — a background job risk, not a result.

## Open at end of campaign (sess513 END)
- D-0905, D-0906, D-0907: need 3 clean full-chain laps on 0.75.14 to close F&V
  (2 had landed on 0.75.13 pre-hole-fix; must be re-run on .14).
- D-0904: needs the post-heal `P142-BWORK-STALE` self-BAST fixed and reverified.
- D-0908: unresolved design question; needs a 10-lap plain-rejoin cost
  measurement of shape B before choosing a fix.
- Deferred since sess510: `tests/sess507_chain_0750.sh` (fio yardsticks,
  domain_admission_matrix R8, full 2/tcp board) — parked behind the D-090x
  chain for the entire campaign, never resumed.

## Rig/harness traps hit during this campaign

[[trap-proto-gen-bump-needs-make-tools-or-every-mount-is-refused-eproto]]:
bumping `MXFS_PROTO_GEN` and running only `make modules` leaves `mkfs_mxfs`
(built by `make tools`, not `make modules`) stamping the old gen — every prep
mount then fails EPROTO ("Protocol not supported") at the C7 gate on the
*first* mount after mkfs. Always `make tools` after a proto-gen or on-disk
header bump.

[[trap-bare-run-sh-prep-on-the-qnap-2node-rig-needs-mxfs-dev-and-node-list-exported]]:
`./run.sh 2 tcp prep_cluster` run directly, without the chain driver's
`MXFS_NODE_LIST`/`MXFS_DEV` exports, silently falls back to the fleet default
`/dev/sda`, which is claimed by device-mapper on this rig — fails in 13-20 s
after already unmounting the nodes. Never call `run.sh prep` by hand on this
rig; always go through `tests/sess511_chain_0756.sh <label> <steps>`, or
export both variables first.

[[trap-reused-node-id-override-is-a-retired-identity-p164-dead-reject-peer-never-admitted]]:
a harness that rejoins a node with a `node_id_override` value that already
departed once in the current run hits `P164-DEAD-NOTE`/`P164-DEAD-REJECT` —
the peer manager permanently ignores announces from a retired identity, so the
rejoining mount parks forever and gets fenced. Not a filesystem defect (real
node ids collide with a retired one at ~k/2^32 odds) — a harness rule: never
reuse a departed id within one run; pick a fresh id per rejoin.

[[trap-qnap-mkfs-zero-region-verify-fail-transient-right-after-fleet-unmount]]:
one occurrence of `mkfs.mxfs: zero_region verify FAIL @67119616 byte 2560 =
0x4b`, ~1 s after a clean fleet unmount, at an offset just past a 64 MiB
tauth-ledger zero_region boundary. PR state was clean (not the known
stale-PR-blocks-mkfs shape). Rerun succeeded. Not root-caused — a single
occurrence. If it recurs: capture mkfs timing against the last node's teardown
and dump the 4 KiB page before the rerun overwrites it; a second occurrence
would make this a ledger-worthy data-integrity defect on the shared LUN
itself, not a test artifact.

## Recurring operational notes
- Every mid-session handoff in this campaign carries "no GPT consults" (user
  directive, stated twice) and "never edit/rebuild while a chain or prep is
  using the tree" (a mid-board `make` desyncs the cluster marker's srcversion
  check; editing a harness script while a chain executes it changes behavior
  mid-run).
- Multiple sessions in this campaign (sess508's predecessor, sess510-bis,
  sess511's predecessor, sess512's predecessor) were killed by a safeguard
  flag mid-task; recovery was always via a miner-subagent digest, never by
  reading the killed session's transcript directly.
- Keep backgrounded rig jobs under ~25 minutes or delegate to a
  rig-runner-style agent — a long background job risks being killed by the
  session's own monitor before it reports (observed at the sess513 relay
  boundary).
