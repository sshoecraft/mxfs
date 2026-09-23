<!-- QNAP LUN qualification, TCP direction, and D-0904 sole-survivor fencing campaign sess500-505 (2026-09-04): CAW fix, EXCLUSIVE_WRITE_GATE, stale-view… -->
# QNAP target qualification, TCP push, and D-0904 sole-survivor fencing (sess500-505, 2026-09-04)

One continuous campaign on the QNAP TS-453 Pro iSCSI LUN (192.168.1.4, target
iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772) from test1/test2: target
qualification -> CAW fix -> TCP direction decision -> a critical fencing defect
found and fixed twice -> a mount-path UAF found and fixed -> a strategic
ship-envelope audit that used the same findings.

## 1. Target qualification: CAW is real, FUA READ is not `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Raw-CDB probe (`tests/scsi_caw_probe.sh`, new this session) on the QNAP LUN:
COMPARE AND WRITE works correctly (correct-expect lands, stale-expect
miscompares 0E/1D/00). READ(16) FUA=1 is refused: Illegal Request / Invalid
field in CDB (05/24/00). `sg_opcodes` and `caw_verify` both fail to qualify
this target — `caw_verify`'s pre-read is exactly the FUA read that fails, and
`sg_opcodes` itself is rejected (05/24/00). Correction to a standing note: the
prior "pve1/pve2 on this QNAP has no SCSI CAW — TCP DLM only" belief was wrong;
what read as "CAW unreliable" in June was the FUA read failing, not CAW. PR
capabilities present (CRH/SIP_C/ATP_C/PTPL_C/PTPL_A) but the target purges all
registrations on iSCSI session events without bumping PRgeneration — flagged
as mandatory follow-up (D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381).
Qualify every target with `scsi_caw_probe.sh`, never with `sg_opcodes` or
`caw_verify`.

## 2. CAW fix, verified green `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

the instrument-first loop loop: hypothesis "0.70.18 can't cluster on the QNAP, no CAW" disproved
by the probe above. Mount attempt failed instead at ledger publish (`rc=-5`)
after a READ FUA fallback. Proven cause: `kern.c` hard-codes FUA bit
(`cdb[1]=0x08`) at four CDB sites (READ(16), WRITE(16), caw_manual_bio,
`mxfs_pal_bdev_compare_and_write`); `sg_raw` confirmed CAW+FUA -> Illegal
Request, CAW without FUA -> Good. Fix 0.70.19: `mxfs_pal_cdb_fua()` returns
0x00 under `fua_disable=1`. Verified: 2/caw prep 50s, 9 rows PASS (184s wall
vs 185s budget). Strategic reframe: LIO-based home/SMB NAS targets
(Synology/TrueNAS, `emulate_caw` on by default) are a CAW-capable class whose
only missing primitive is FUA read; `fua_disable=1` (write-through target,
power-loss out of scope) is the correct declaration for it, not a fallback to
TCP.

## 3. TCP direction decision and lab-build measurement `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

User decision (repeated 3x, emphatic): 1.0 ships as a 2-node TCP cluster on
NAS iSCSI, then 4-node TCP — "99% of the people who are gonna use it" are that
class; do not steer back to CAW. Measured on production build: first refusal
was the durability gate (TCP branch of `prep_node.sh` lacked
`target_cache_protected=1`, fixed — the declaration describes the target, not
the transport). Second refusal: `mxfs_transport_domain_admit` (0.55.0,
sess448 ruling) blocks TCP because the TCP authority ledger isn't qualified
(D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-0288). Lab build
(`KCFLAGS=-DMXFS_TCP_TRANSPORT_READY=1`, full rebuild, minutes) lifts the gate
for measurement only: 2/tcp green, 9 rows, but running ~2x the CAW walls on
this LUN — derive TCP timeout budgets from TCP walls, not CAW walls (a 185s
CAW-derived wrapper overshot by 43s). Queue set: TCP authority ledger step 5
closes D-0288 and allows a reviewed gate lift; then D-PRLESS-DEVICE-ADMITTED-
UNFENCED-BOTH-TRANSPORTS-0904 and D-PR-RESERVATION-HEALTH-UNMONITORED-
AFTER-MOUNT-381 (the QNAP-purges-registrations problem from step 1).

## 4. First TCP dirty death: survivor frozen forever `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Filed as D-SESSION-PURGED-VICTIM-KEY-FENCE-NEVER-CERTIFIES-SURVIVOR-FROZEN-0904
(critical). On `virsh destroy` of the victim, the QNAP removes its PR
registration with the dropped iSCSI session (no PROUT, PR generation
unchanged) — confirming the reservation-health gap flagged in step 1. MXFS's
fence logic only proves exclusion via PREEMPT_ABORT_DONE (key present),
SINGLE_NODE_EXCLUSIVE, or SELF_SUCCESSION_DONE (sess432 ruling: absence alone
never proves exclusion); with the key already gone it lands on
KEY_ABSENT_UNPROVEN and retries the PRECOMMAND forever. Survivor's held locks
freeze every path op for 900s; the frozen node had to be power-cycled
manually — SCST/LIO rigs never exposed this because they keep a dead
initiator's key. Candidate fix identified: sess93 ruling option 2, temporary
single-holder WRITE EXCLUSIVE via PREEMPT AND ABORT sark=0, needs no victim
key.

## 5. SCSI-layer measurements confirm the gate shape `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Two probes (`pr_session_drop_probe.sh`, `pr_preempt_sark0_probe.sh`) both
PASS. Victim's registration purges +34s after kill (PR generation unchanged —
purge is target-internal); a rebooted, unregistered victim's writes get
RESERVATION CONFLICT under the surviving WE-AR. PROUT PREEMPT AND ABORT
rk=own sark=0 type=1 removes every other registration and installs a
single-holder Write Exclusive (matches SPC-4 5.9.10.4.4 / LIO
`core_scsi3_pro_preempt`); a re-registered victim still gets CONFLICT under
type 1; self-preempt rk=own sark=own type=7 restores WE-AR atomically (no
unreserved gap). This closes both D-0904(SESSION-PURGED) and the
re-registration hazard, at N=2 only — sark=0 evicts every OTHER registrant,
so N>2 survivors need a freeze/drain protocol or a WE-RO holder-preempt
design (not built). Multipath hazard noted: sark=0 also strips the survivor's
own sibling-nexus registrations.

## 6. Fix landed: EXCLUSIVE_WRITE_GATE (0.72.0) `docs/pr-fencing-departure.md`

Decided from the step-5 measurements directly, no GPT consult. New on-disk
fence kind 20 (`MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE`): sole survivor takes
PROUT rk=own sark=0 type=WR_EX (0x01, new PAL define), verifies exclusion,
restores WE-AR at recovery publish. Guarded: complete READ KEYS with own key
on exactly one nexus (else -ENOTUNIQ), victim key still absent (else no-op),
WE-AR held (else refused), idempotent if already held. Wired into
`v5_mount.c`: tried only when kind is still KEY_ABSENT_UNPROVEN, `nlive==1`,
and no lower live slot exists. Failure to restore at recovery-complete is
retried every 250ms by the PR worker. Hazards ledgered, not closed: multipath
refuses (fails closed), joiners refused while the gate is held
(P303-FENCECAP-WRONGTYPE), and mount-time recovery (as opposed to
in-mount) has no gate arm yet.

## 7. Second defect under the same fix: sole-survivor stale view `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Filed as D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-DEATH-0904
(critical). After the first fully successful TCP dirty death (gate certified,
foreign replay complete), the survivor's verdict-time verify showed 0/91
files — a stale root dir healed itself only via readdir's ungated P95D
reload loop. Root: three single-node bypasses
(`mxfs_dlm_dir_consumer_refresh`, the ILOCK "Single-node bypass" in
`xfs_dir_lookup`, `mxfs_drevalidate`) return before consuming staleness
signals, and `v5_membership_cb_tcp`'s "XFS cache layer self-recovers via
BASTs" no-op is false once no peer remains. Fix 0.72.2:
`mxfs_v5_dlm_sole_survivor(ctx)` = single-node-now && ever-multi; gates the
three bypasses to reload/refresh instead of short-circuiting. Wrong
prediction recorded and worth keeping: a demote to NL already sets
`i_dlm_stale` (bast release path), so rewritten pre-cached files were already
covered — only iget-only inodes with no flag were structurally uncovered.
~220 `is_single_node` call sites exist; the coherency-relevant subset was
audited this session but not all flipped (xfs_da_btree.c dir-block read
hooks still gated, no failing measurement yet).

## 8. Closure with a widened oracle `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

D-SURVIVOR-SINGLE-NODE-BYPASS closed FIXED AND VERIFIED on 0.72.2 after 6
laps (both node-role orders) of `tcp_death_replay.sh`, widened with five new
stale-view vectors: differently-sized rewrite of a pre-cached file, negative
dentry for a victim-created name, 40-entry block-format dir readdir+stat,
`drop_caches=2` full re-verify, and a checkpoint-then-relog case
(`dino_clobber_check` armed, asserts 0). Unresolved oddity, not yet a defect:
in some laps a second TCP-death-path fence attempt fires ~3s after the gate
already certified (NO_VICTIM_KEY, kind 18) but doesn't overwrite the sealed
EXCLUSIVE_WRITE_GATE certificate — traced to `dlm/scsipr.c`'s
`P-PR-FENCE-NOKEY` caller, not yet root-caused. Also noted: only 2
transactions are ADMITted per replay (P227-FR-ENFORCE-ADMIT) although ~80
fsync'd transactions preceded the kill, yet everything verifies — needs
understanding before the 32/tcp D-0288 leg.

## 9. sess504 end: TCP gate lift landed, unbuilt `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Handoff state: D-0904(SESSION-PURGED... stale view) closed per items 7-8.
Split off D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904 (new,
critical) and a mount-time gate gap note on D-WHOLE-CLUSTER-CRASH-RESTART-
REQUIRES-OPERATOR-437. 0.73.0 (TCP domain-gate lift for D-0288) landed in
tree but unbuilt: `mxfs_transport_domain_admit` now admits CAW+TCP,
lab-only markers removed. Reiterated house rules: no GPT consults on Fable
(user said so twice); never edit a harness script while a chain is executing
it; never `make` while a lap's prep may be copying `mxfs.ko`.

## 10. sess505 mid: fence-capability gate exposes a UAF `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

Production 0.73.0 built plain, death lap PASS (9th gate lap toward the
D-0904 closure count). Pre-patch measurement on B516: CAW already refuses a
PR-less device (P303-FENCECAP-UNREGISTERED); TCP does not call the same
check at all and reaches the disklock claim — a PR-less iSCSI target with
CAW would mount read-write unfenced
(D-PRLESS-DEVICE-ADMITTED-UNFENCED-BOTH-TRANSPORTS-0904, flagged since item
3). Fix 0.73.1: shared `v5_fence_capability_admit()` gate on both branches.
Building it exposed a second, more severe defect: every pre-existing TCP
refusal arm after `tcp_death_thread` creation tears down peer+dlm and frees
`ctx` WITHOUT joining the death worker thread — the worker then ticks on
freed memory ~500ms later. First observed as an unexplained test32 reboot at
teardown.

## 11. sess505 close: both fixed and verified `docs/history/docs/history/docs/history/compiled-qnap-tcp-caw-d0904.md`

D-PRLESS-DEVICE-ADMITTED-UNFENCED-BOTH-TRANSPORTS-0904: FIXED 0.73.1,
VERIFIED 0.73.2 via `tests/fence_capability_admission.sh`. D-TCP-MOUNT-
REFUSAL-ARMS-FREE-CTX-UNDER-RUNNING-DEATH-WORKER-0904: proven twice on
test32's serial console (the only record — VM journald had already stopped,
VMs have no pstore): `claim_slot failed (-28)` at T, panic in
`v5_tcp_death_worker_fn` ~500ms later, at two different builds. Fix:
`v5_tcp_transport_unwind(ctx)` (join the death thread, then peer
shutdown/dlm destroy) replaces every inline teardown across all seven
refusal arms. Verified: test32 stayed up, module cleanly unloaded, death lap
43/43 PASS. Lesson generalized: a harness that greps only for named refusal
lines will report "refused but no reason" for any other cause — always read
the full log before concluding.

## 12. Strategic conclusion drawn from this campaign `docs/cost-audit.md`

Separate user-requested audit, same day, explicitly using the CAW-is-real
finding (item 1) to refute the premise that home/SMB NAS requires TCP.
Ledger census: 87 open defects, 52 fire at any N>=2, only 20 are genuinely
TCP/dirshard/host scoped and deferrable. Recommendation: ship 1.0 at 4 nodes,
CAW only, sharding off — not 2, because 2-node topology cannot reach
successor-dies-mid-takeover, double-victim-with-survivors, or 2-2 partition
cases that 4 nodes exposes. "Guarantee" requires the envelope enforced in
code (refusal before writable activation), not merely documented. Every rule
not enforced in code is relabeling, not a guarantee.

## 13. Harness gap found running the 4-node board for that audit [[trap-node-death-replay-row-unrunnable-below-32-nodes-slotmap-empty-and-32-node-geometry]]

`node_death_replay` (via `tmpfile_churn_kill.sh`) FAILs in 3s at 4/caw
without killing anyone, for two independent reasons: (1) the slot map is
scraped from a `disklock: claimed heartbeat slot N` kernel-log line that this
mount never emitted (drowned by P291-EXWIN probe lines) — must read the slot
from sysfs/the disklock table instead; (2) victim classes are hard-wired to
32-node geometry (`slot 7..24 = single`, `ag = slot % 25`), meaningless at 4
nodes. Consequence directly relevant to item 12's 4-node ship gate: a 4-node
board currently has ZERO death/replay coverage even when every other row is
green, and a FAIL here is a harness verdict, not a filesystem verdict — must
not be filed as a replay defect until both causes are fixed.
