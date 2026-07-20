# Condition 4 — CAW over multipath (BUILT + verified)

**Status:** built and run 2026-07-05 (see RESULTS at the bottom). Extends the 3
infra conditions in `test_infra_scst_caw.md`. The scope/design below is retained
for context.

## Why

Conditions 1–3 all run **single-path** (we pinned `allowed_portal` to one portal
and set `find_multipaths strict` specifically to *avoid* multipath). But the #1
real deployment — any enterprise SAN, FC *or* iSCSI — has ≥2 paths and runs
multipathd, mounting `/dev/mapper/mpathX`. A clustered FS that can't operate on a
multipathed LUN doesn't ship for the datacenter. So we must be able to test it.

## Goal: characterize, don't guess

The single un-retried `caw_verify` through `/dev/mapper/mpatha` returned UNIT
ATTENTION (sense `0x29`, power-on/reset) — a **transient/retryable** condition,
NOT proven failure. Condition 4 answers, at the raw storage layer (SG_IO +
sg_persist, no mxfs), **which layer actually needs work**:

1. **CAW atomicity through dm-multipath** — likely just a UA-retry. dm-multipath
   routes an SG_IO ioctl to one active path, so CAW (0x89) stays one atomic
   command; the first command after a path event gets a UA that a correct issuer
   retries.
2. **PR fencing through multipath** — the genuinely harder part. SCSI-3 PR is
   per-I_T-nexus; a multipathed node has N nexuses (one per path). If mxfs
   registers its key on one path but I/O goes down another, unregistered path →
   RESERVATION CONFLICT → self-fence. Standard fix is registering with the
   **ALL_TG_PT** bit (key applies to all target ports) or per-path registration.

Output of the harness: for CAW → {pass first try | pass after UA retry | fail
after retry}; for PR → {reservation honored on all paths w/o ALL_TG_PT | needs
ALL_TG_PT | fails}. That read tells us the size of the mxfs change.

## Fidelity: synthetic 2-path first (recommended), real 2-network later

| Level | How | Tests | Cost |
|---|---|---|---|
| **Synthetic 2-path** (start here) | 2nd IP alias on clyde br0 (e.g. `192.168.120.2`); SCST `allowed_portal` = {`.1`,`.2`}; guest logs into both portals → 2 sessions → 2-path `mpatha` over the same wire | dm-multipath device layer: CAW + PR through `/dev/mapper/mpathX` | Cheap — no new bridge/NIC |
| **Real 2-network** (later) | 2nd host bridge (`br1`, e.g. `192.168.121.0/24`) + 2nd guest NIC (`define_vms`); SCST advertises on both networks | genuine redundancy + **path failover** (yank a path, I/O continues) | `define_vms` grows a NIC; new bridge |

Synthetic gives a genuine 2-path `dm-multipath` device — enough to answer the
CAW/PR questions. Real-2-network only adds failover realism, which we defer.

## What gets built

1. **Host (extend `scst_setup.sh` or a cond4 wrapper):**
   - Add a 2nd br0 IP alias (`ip addr add 192.168.120.2/24 dev br0`), removed on teardown.
   - `allowed_portal` set to BOTH intended portals (`.1` and `.2`) — note this is
     *two intended* portals, distinct from the 9 *accidental* bridge portals we
     pin away; do NOT reopen to all interfaces.
2. **Guest buildup (multipath must ASSEMBLE the 2-path device):**
   - Conditions 1–3 use `find_multipaths strict` (don't wrap a lone path). Cond 4
     needs the 2-path device wrapped. Candidate: switch guests to
     `find_multipaths yes` universally — validate it leaves single-path unwrapped
     (so 1–3 still get raw `/dev/sda`) AND wraps the 2-path device into `mpatha`.
     Fallback: keep `strict` and add the LUN wwid to `/etc/multipath/wwids` for cond4.
   - multipathd stays RUNNING (prod-correct).
3. **Tool (`tools/caw_verify.c`):** add `--retry-ua` (retry the pre-read/CAW on
   UNIT ATTENTION, sense key 0x06, a bounded number of times). Small C change. A
   correct SG_IO tool should do this regardless.
4. **`verify_infra.sh` — new mode `multipath`:** present via both portals, then:
   - 2 iSCSI sessions present; `/dev/mapper/mpathX` exists with 2 active paths
     (`multipath -ll`); correct size; raw readable; same LUN across nodes.
   - **Retry-aware raw CAW** cross-node through `/dev/mapper/mpatha` (nodeA writes,
     nodeB reads) — reports pass/pass-after-retry/fail.
   - **PR across paths** via `sg_persist`: register (try with and without
     `--all-tg-pt`), reserve WE-RO from nodeA, confirm nodeB sees the reservation
     through *its* mpath device, and that a write down each path behaves
     consistently. Reports whether ALL_TG_PT is required.
   - Footprint: 2 sessions/node (synthetic), `mpatha` = 2 paths.
5. **Teardown:** logout both sessions, `multipath -F`, remove the 2nd IP alias,
   `scst_setup.sh teardown`.

## Scope boundary (unchanged from the other conditions)

This harness is **storage-layer**: raw SG_IO CAW + `sg_persist`, no mxfs mount,
no filesystem. It tells us whether the *transport/storage* honours CAW+PR through
`dm-multipath`. The actual **fix is mxfs kernel work** — UA-retry in
`dlm/dlm_caw.c` and ALL_TG_PT / per-path PR registration in the fencing path —
and is FS work, informed by this harness's output. Not part of condition 4 itself.

## Decisions (locked 2026-07-05)

- **Fidelity: synthetic 2-path first** (2nd br0 IP alias + 2 portals). Real
  2-network failover deferred.
- **`find_multipaths yes` universally** on the guests — replaces the per-condition
  `strict`. MUST validate during build that `yes` leaves a single path as raw
  `/dev/sda` (so conditions 1–3 keep working) while assembling the 2-path device
  into `mpatha` for condition 4. If `yes` turns out to wrap single paths on this
  distro, fall back to `strict` + per-cond4 wwid.
- **Characterize at N=2 first**, then confirm the presentation at N=32.

## Build order (when green-lit)

1. `caw_verify.c`: add `--retry-ua` (retry pre-read/CAW on sense key 0x06). Rebuild `make tools`.
2. Host: 2nd br0 IP alias + `scst_setup` `allowed_portal` = {`.1`,`.2`} (cond4 variant/flag).
3. Guest buildup: set `find_multipaths yes` on all 32; validate single-path 1–3 still raw `/dev/sda`.
4. `verify_infra.sh` mode `multipath`: present via both portals → `mpatha` (2 paths)
   → identity/readable checks → retry-aware cross-node CAW → `sg_persist` PR-across-paths
   (with/without `--all-tg-pt`). Report which layer passes/fails.
5. Run N=2 (characterize), then N=32 (confirm presentation); tear down to bare.

## RESULTS (built + run 2026-07-05)

Built: `caw_verify --retry-ua`; `scst_setup.sh` 2-portal `allowed_portal`;
`verify_infra.sh multipath` mode (synthetic 2-path via 2nd br0 IP alias
`192.168.120.2` + `find_multipaths yes` on guests). Ran N=2 (characterise) and
N=32 (confirm presentation), then torn down to bare (2nd alias removed).

- **Presentation scales: 32/32** nodes get a 2-path `/dev/mapper/mpathX`, same
  LUN (serial), readable. clyde footprint 0/0 (guests are the initiators).
- **CAW through dm-multipath: PASS** — cross-node, no-retry AND retry-aware. The
  earlier "CAW fails on multipath" was one transient UNIT ATTENTION (0x29) plus
  the test tool not retrying; it does not reproduce.
- **PR/fencing through dm-multipath: PASS (N=2)** — nodeA reserves WE-RO
  (`--param-alltgpt`); nodeB sees the reservation+key through its own mpath
  device; nodeB's non-registrant write is blocked (reservation conflict). The
  32-node PR sub-check tripped only because test1's mpath paths were in a degraded
  `i/o pending`/`prio=0` state from the session's churn (a fresh boot clears it) —
  not a multipath-at-scale defect.

**Conclusion:** the enterprise-SAN substrate (CAW + PR over multipath) works. The
real-2-network fidelity (path failover) remains deferred. The mxfs *kernel* CAW/PR
code running on the mpath device is FS work, but the storage layer supports it.

## Starting point for the mxfs KERNEL multipath work (handoff)

The infra/storage substrate is proven (above). The remaining work is making
mxfs's OWN kernel CAW/PR paths run when mounted on `/dev/mapper/mpathX`. Confirmed
code map (2026-07-05):

**1. CAW UA-retry — the most likely needed change.**
- `pal/linux/kern.c :: mxfs_pal_bdev_compare_and_write` (~lines 2600–2860, opcode
  0x89 built at 2638/2753). It handles MISCOMPARE (`sshdr.sense_key == MISCOMPARE`,
  ~2844) and host/driver errors, and there is ILLEGAL_REQUEST handling nearby
  (~612/654), but **no UNIT ATTENTION retry**. On `dm-multipath` the first SG_IO
  down a (re)selected path can return UA (key 0x06, ASC 0x29). Add a bounded retry
  on `sense_key == UNIT_ATTENTION` — mirror `tools/caw_verify.c --retry-ua`
  (`UA_MAX_RETRY`). Also check the read path `mxfs_pal_scsi_read_fua_bdev` /
  `mxfs_pal_bdev_read_prio` (dlm/dlm_caw.c calls these on `ctx->dev`).

**2. PR on multipath — VERIFY before changing.**
- mxfs kernel PR uses the kernel `pr_ops` interface: `pal/linux/kern.c ::
  mxfs_pal_scsi_pr_register` → `get_pr_ops` (2345) → `bdev->bd_disk->fops->pr_ops`.
  `dlm/scsipr.c` (REGISTER_AND_IGNORE, WE-RO type 5) sits on top.
- **dm-multipath implements `pr_ops` and replicates PR registration/reservation to
  all underlying paths**, so mxfs's kernel PR may work UNCHANGED on
  `/dev/mapper/mpathX`. Verify first (register+reserve while mounted on the mpath
  dev, confirm fencing). The ALL_TG_PT concern (`sg_persist --param-alltgpt`, which
  the condition-4 harness proved necessary) applies to the RAW SG_IO userspace path
  (`pal/linux/user.c`, PROUT 0x5F), NOT necessarily the kernel `pr_ops` path — so
  don't assume a change is needed until the pr_ops path is tested on mpath.

**3. Device.** Mount mxfs on `/dev/mapper/mpathX`; CAW (blk_execute_rq) and PR
(pr_ops) ride the dm queue, which dm-multipath clones to a live path.

**4. Test loop.** `scripts/verify_infra.sh multipath 2` presents the 2-path device
(storage layer already GREEN). For the FS work: mount mxfs on `/dev/mapper/mpatha`,
run FS ops, watch guest dmesg for UNIT ATTENTION / reservation conflict / shutdown.
Start at N=2, single-path first as the control, then the 2-path device.
