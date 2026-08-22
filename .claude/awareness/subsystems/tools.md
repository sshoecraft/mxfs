# tools (User-space utilities)

**Owner files**: `tools/` (13 files, ~6.7K LOC)
**Last updated**: 2026-06-12; 2026-07-16 (mkfs Step 3b: transport self-test scratch sector reservation); 2026-08-01 (chk_mxfs C7 `-U` upgrade + orphan inode audit); 2026-08-12 (caw_slotdump documented + `revoke` field); 2026-08-19 (caw_slotdump `--slot`/`yield`/always-`ag`; new caw_slot_hash.py)

## Purpose

Standalone user-space binaries that build against the user-PAL variant. Used for filesystem creation/check, low-level coherency probes, and debug helpers. They DON'T link the kernel module; they re-implement enough of dlm + xfs structures via libxfs userland to read/write the on-disk layout.

## Binaries

| Tool | Source | Purpose |
|---|---|---|
| `mkfs_mxfs` | `mkfs_mxfs.c` (~1500 LOC) | Format a device with the MXFS envelope (super @ off=0, journal, disklock, then native XFS data region). Bumps version per format change. |
| `chk_mxfs` | `chk_mxfs.c` | Read MXFS super + structural checks. |
| `resize_mxfs` | `resize_mxfs.c` | Grow XFS data region (envelope's data tail). |
| `fua_verify` | `fua_verify.c` (sess22) | Validate FUA-read passthrough — write a known pattern, read back via FUA, ensure no stale-cache on peer. |
| `caw_verify` | `caw_verify.c` (sess24; `--retry-ua` 2026-07-05) | Validate cross-init CAW coherence — raw SCSI CAW(0x89)+READ(16)FUA via SG_IO on a block dev, no mxfs. Also used as the storage-layer CAW probe for the SCST/multipath infra conditions. |
| `caw_slotdump` | `caw_slotdump.c` (sess241) | **Offline forensic dump of the live disklock region**: heartbeat slot table + every CAW lock slot (holders/waiters bitmaps, modes, epochs, lineage, `revoke`). The primary post-mortem instrument for DLM defects — reads the platter directly via SG_IO, so it works when every node's FS is shut down. |
| `caw_slot_hash.py` | `caw_slot_hash.py` (sess375) | **Computes a resource's CAW home slot in userspace.** Reproduces `resource_hash_raw` (seedless FNV-1a over the raw `struct mxfs_resource_id` bytes) and the `% 65536` binding, so slot placement can be predicted and audited offline. `verify` self-checks the replication against a live `caw_slotdump --all` capture (must report ZERO mismatches before trusting anything else); `collide`/`pick` find inode pairs that share a home slot across an AG boundary. Turns "wait for a 1-in-65536 slot collision" into a lookup, which is what makes the closure purge's tombstone/slot-reuse hazard testable with real files instead of a forged slot image. |
| `mxfs_sshpass.sh` | shell wrapper for ssh+sshpass | Bench harness uses this to talk to test1/test2. |

## Public API

These are CLI binaries; no library API.

```bash
mkfs_mxfs [-f] [-n COUNT] [-v] [-V] /dev/sda   # -n = per-node XFS log slices (1-64, default 4); -V prints version
chk_mxfs [-v] [-a|-p|-y|-n] /dev/sda           # check (+repair with -a/-y); exit 0 clean, 1 corrected, 4 errors
chk_mxfs -U /dev/sda                           # --upgrade-protogate: offline C7 format upgrade (O_EXCL + HB-liveness proof)
resize_mxfs /dev/sda
fua_verify {write|read} /dev/sda LBA HEX_PATTERN
caw_verify [--retry-ua] {write|read} <dev> LBA HEX_PATTERN   # dev may be /dev/sda OR /dev/mapper/mpathX
caw_slotdump <dev> [--type {ag|inode|...}] [--held-only]     # run ON A NODE; dev = /dev/mapper/mpatha
caw_slotdump <dev> --slot N                                 # ONE slot, one line, READ(16)+FUA
caw_slot_hash.py verify  <slotdump-capture>                 # replicate the kernel slot hash
caw_slot_hash.py collide <dump> <inolist> <inoshift>        # cross-AG home-slot collisions
caw_slot_hash.py pick    <dump> <inolist> <inoshift>        # one usable colliding pair
```

**`caw_verify --retry-ua`** (added 2026-07-05): retry a command that returns
UNIT ATTENTION (sense key 0x06, e.g. ASC 0x29 power-on/reset), bounded by
`UA_MAX_RETRY`. Needed on `dm-multipath` — the first SG_IO command down a path
after (re)selection gets a UA, which a correct issuer retries; without it a lone
UA looks like a hard CAW failure (this is what produced the false "CAW fails on
multipath" scare — it does NOT; CAW+PR both work through `/dev/mapper/mpathX`).
Off by default, so single-path behaviour is unchanged. The flag is stripped from
argv up front, so it may appear before the mode.

## Internal Architecture

**On-disk layout** (set by mkfs_mxfs, post-2026-03-06 layout):
```
[MXFS super @ offset 0]    — magic, journal_offset, disklock_offset, xfs_data_offset, max_nodes, uuid
[MXFS journal region]      — per-node log slices (max_nodes × slice_bytes)
[MXFS disklock region]     — 64×512B heartbeat slots + lock-region (slot table)
[XFS data region]          — native XFS format; XFS sees this as offset 0 via mxfs_pal_bdev_clone_with_offset
```

mkfs_mxfs writes super, zeros journal+disklock regions, then runs `format_xfs_native` (essentially the upstream mkfs.xfs core) inside the XFS data region with appropriate base_offset.

**Transport self-test scratch sector (2026-07-16, mkfs Step 3b)**: the last sector of the 4K-alignment gap between journal end and `disklock_offset` (i.e. LBA `disklock_offset/512 - 1`; the gap always exists — journal_size ≡ 4608 mod 4096 → 3584 bytes) is formally reserved for raw SG_IO transport verification (`tests/caw/dlm_lock_correctness.sh` fua_verify/caw_verify). mkfs explicitly zeroes it; no reader (kernel, chk_mxfs, mkfs) ever touches it. Raw capability probes must use THIS sector, never an LBA inside journal/disklock/XFS regions — the old test hardcoded LBA 83886080 (inside live XFS data) and unmounted node1 to "make it safe", which caused the 2026-07-15 "idle-trigger dir_reuse" disaster (see tests.md).

## Cross-Subsystem Dependencies

| Depends On | How | Notes |
|---|---|---|
| pal | `mxfs_pal_*` user-space variants | Built as `pal_linux_user.c` |
| dlm | `mxfs_dlm_caw_create` (caw_verify, fua_verify only) | Direct CAW ops without the kernel FS |
| xfs | libxfs headers (struct definitions only) | No mxfs hooks needed |

## Invariants

1. **`mkfs_mxfs` MUST write superblock at offset 0 atomically** — if super write succeeds but journal-zero fails, a subsequent mount sees a valid super but garbage journal. mkfs writes super last, after journal+disklock zeroing succeeds.
2. **The MXFS envelope offsets are immutable post-format.** `journal_offset`, `disklock_offset`, `xfs_data_offset` cannot move; doing so would orphan all in-flight DLM grants and journal entries.
3. **Tools build against user-PAL only.** No kernel headers in `tools/`.

## Known Pitfalls

- **mkfs's pwrite-O_SYNC zero is not durable on the LIO target stack.** CAW slot stale-disk garbage is a real concern; v0.3.83 added popcount-based detection in `dlm/dlm_caw.c::slot_appears_corrupt`. Workaround: `dd if=/dev/zero of=/dev/sda bs=1M count=256 oflag=direct` BEFORE mkfs (sess33 cluster_reset.sh prepends this on test1).
- **caw_verify must run with FS unmounted on both nodes.** Otherwise it competes with the kernel's CAW poll and corrupts state.
- **caw_verify is NOT built by `make tools`.** That target builds mkfs/chk/resize/fua only. Compile it directly: `cd tools && cc -Wall -Wextra -O2 -o caw_verify caw_verify.c` (no mxfs/PAL headers needed — pure `scsi/sg.h`).
- **On `dm-multipath`, always use `--retry-ua`** (or expect a spurious first-command UNIT ATTENTION). CAW and PR work through `/dev/mapper/mpathX`; verified at the storage layer 2026-07-05 (see `docs/condition4_multipath_scope.md`). PR-across-paths uses `sg_persist --param-alltgpt` (NOT `--all-tg-pt`, which sg_persist rejects).
- **mkfs version bumps:** the MXFS super has a layout version. Bump on every layout change so older tools refuse to read newer layouts.

## 2026-07-25 refresh (post-7/16 changes)

- **Secrets chokepoint (2026-07-21)**: `tools/mxfs_secrets.sh {get <key> [field]|passfile [path]}`
  resolves test credentials from `~/.config/mxfslab/secrets` (mode 600, NOT in repo) and
  materializes the sshpass passfile. `tools/mxfs_sshpass.sh HOST PASSFILE CMD` is the single
  SSH chokepoint every script uses; it FLATTENS the remote command args (keep remote snippets
  one single-quoted block; no nested single quotes). Node root password stays synced with
  osimager's `images/linux` secret.
- **chk_mxfs "slot N" output = JOURNAL slot table** (region 2, 1MB/slot headers), NOT the
  disklock heartbeat slots. Disklock HB records live at `disklock_offset` (67117056 on the
  standard VM LUN) + slot×512: magic "MXLK" 0x4D584C4B, flags@4 (bit0 ACTIVE), node_id@8,
  fs_gen@12 (folded volume id — forged/ghost records MUST match live fs_gen to be counted),
  ts_ms@16. chk also decodes the MEPOCH record inside each HB slot.
- **fio `--filename` colon-splitting trap** (2026-07-25, scripts/raw_fio_ceiling.sh): fio
  splits `--filename` on `:` (multi-file syntax). Passing an iSCSI by-path device name
  unescaped makes fio CREATE regular files (one in guest devtmpfs = RAM) and benchmarks
  memory. Escape colons (`\:`) or use the plain `/dev/sdX` node.

## 2026-08-01: chk_mxfs C7 upgrade mode + orphan inode audit

- **`-U` / `--upgrade-protogate`**: offline C7 version-gate format upgrade (envelope
  `MXFS_FORMAT_F_PROTOGATE` + `cluster_proto_gen`, then XFS sb incompat bit 30 with the
  primary sb written LAST). Requires O_EXCL open (local offline proof) + a disklock HB
  liveness scan (remote offline proof: 2 samples across a lease window; any live record
  aborts). Idempotent; crash-ordered so a torn upgrade re-runs cleanly.
- **Orphan inode audit** (`check_orphan_inodes`, step 7b of the normal check flow, exit
  code integrated): per AG, cross-references inobt-allocated inodes having `di_mode!=0 &&
  di_nlink==0` (candidates; full-chunk 64-inode reads, holemask/free-mask aware) against
  membership of ALL 64 AGI unlinked-bucket chains (walk via `di_next_unlinked` @0x60,
  bounded 1M steps, magic-checked).
  - candidate ON a bucket   → "bucketed zombie": legal crash residue, informational only.
  - candidate on NO bucket  → **orphan (D-DESTAGE-TEAR-BUCKETLESS-ORPHAN residue)**: error;
    repair (`-a`/`-y`) pushes it onto bucket `agino%64` — inode's `di_next_unlinked`
    written FIRST (dangling pointer is harmless), AGI head second (single-sector commit),
    so a torn repair just re-repairs. Kernel does the authoritative free at next recovery
    (GPT-ruled: no offline free — blast radius).
  - `check_one_inode`'s old unconditional `nlink==0` error is now limited to metadata
    inodes (rootdir/rbmino/rsumino); sampled inodes defer to the audit's bucket-aware
    classification.
  - Verified by `tests/orphan_audit_arm.sh`: NEG (clean device → OK) + POS against REAL
    torn state (A holds open, B rm+dies mid-destage, A killed pre-sweep → detect exit 4,
    repair exit 1, recheck exit 0).
  - **Convergence caveat**: a chk-repaired zombie lands on a bucket that may belong to an
    UNCLAIMED slot — nothing reaps it until the kernel's unclaimed-bucket pass (0.11.353+)
    runs; see xfs.md D-DESTAGE-TEAR notes.
- Dinode offsets used by chk (verified against `xfs/libxfs/xfs_format.h`): magic 0x00,
  mode 0x02, nlink 0x10, gen 0x5C, **next_unlinked 0x60**, crc 0x64 (v3), ino 0x98.
  AGI: root 0x14, level 0x18, **unlinked[64] @ 0x28**, uuid 0x128, crc 0x138. AGI sector
  = ag_base + 1024.

## 2026-08-12: caw_slotdump — the DLM post-mortem instrument

Built sess241 to settle the D-AGLOCK-...-LIVELOCK-488 argument with on-disk
evidence instead of dmesg inference; it has been the deciding instrument in
every AG-lock session since, and sess249 used it to capture the mass
no-inode-wedge state (`tests/forensics/sess249_noino_mass_wedge_slotdump.txt`,
12,730 live slots).

**What it prints**: the disklock/slot-table offsets resolved from the MXFS
super; the 64 heartbeat records (`magic 0x4D584C4B`, flags, node_id); then every
non-empty lock slot — `slot=`, LIVE/TOMB, `gen=`, resource (type/vol/ag|ino),
`gmode=`/`wmode=`, **`revoke=`**, the holder bitmaps decoded to node-slot lists
(`ex=0x8[3]`), waiter/waiter_ex bitmaps, `last_ex_slot`, `ex_epoch`,
`resource_lineage`, `lmod`; and a nonempty/live/tomb summary line.

**Why it exists**: it reads the platter over SG_IO with no mxfs involvement, so
it is valid precisely when the cluster is broken — the on-disk slot is the
single source of truth for CAW, and in-core state is exactly what is in doubt
during a wedge. Reading a slot table any other way requires a healthy mount.

### CRITICAL invariant — the slot struct is DUPLICATED

`caw_slotdump.c` re-declares the on-disk slot layout locally (its own
`struct` near the top of the file), because tools do not include kernel dlm
headers. **Any change to `struct mxfs_caw_lock_slot` in `dlm/dlm_caw.h` MUST be
mirrored there in the same commit**, or the tool silently misparses every field
after the divergence point and reports confident garbage. There is no compile-time
link between the two — nothing catches this.

sess249 exercised exactly this path: the `-488` sticky-revoke fix converted the
slot's `uint16_t pad` into `uint8_t revoke + uint8_t pad0`, so the tool's copy
was updated in lockstep and it now prints `revoke=N`. Same-size edit, so nothing
downstream shifted — but a size-changing edit would have shifted everything and
still compiled cleanly.

### Pitfalls

- **NOT in the Makefile.** Build by hand: `cd tools && gcc -O2 -I../include -o
  caw_slotdump caw_slotdump.c`. `make clean` wipes the binary, so a session that
  rebuilds the module loses it — rebuild before reaching for it.
- **Run it on a NODE, not on clyde.** Clyde is the SCST *target*; it has no
  `/dev/mapper/mpatha` (only `control` and its own LVM volumes). Invoke via
  `tools/mxfs_sshpass.sh test<N> "/src/mxfs/tools/caw_slotdump /dev/mapper/mpatha"`.
  The nodes NFS-mount `/src`, so the binary built on clyde is already there.
- **The FS being shut down does not stop it** — that is the point. A wedged
  fleet still has an intact block path.
- Full output is large (~12.7k lines on an exercised 32-node fs). Redirect to
  `tests/forensics/` rather than paging it; grep by `type=AG` / `type=INODE`.
- Capture BEFORE any re-prep. `./run.sh <N> <dlm> prep_cluster` re-mkfs's and
  destroys the evidence.

## Historical Bugs

- **2026-03-06 layout refactor**: super moved from end-of-device to offset 0 to prevent `mount -t xfs /dev/sda` accidentally mounting the raw device (which would corrupt the MXFS envelope). XFS data region grows toward end. mkfs_mxfs version bumped to 0.7.1.
- **sess24 caw_verify built**: a cross-init CAW probe — write a hex on test1, read on test2, ensure CAS coherence. Falsified sess23's hypothesis #1 (LIO target NOT failing CAW cross-init).
- **sess15 (2026-06-10, v0.4.11) chunked BLKZEROOUT in `mkfs_mxfs.c::zero_region`**: a single
  BLKZEROOUT over the 33MB envelope became ONE strictly-serialized WRITE SAME(16) at the SCST
  target (device blocked + all outstanding cmds drained around it). Under concurrent CAW load
  it starves past the initiator's 60s timeout → ABORT_TASK → LUN_RESET → nexus loss → leaked
  D-state `iscsi_conn_cleanup` threads wedge the target until HOST reboot (sess14/15).
  Fix: issue BLKZEROOUT in 4MB chunks (each completes well under the timeout; same total cost);
  pwrite fallback unchanged. PITFALL: never issue a multi-MB single WRITE SAME/CAW-class
  serialized command against the SCST stack while any node's mxfs heartbeat may be live —
  test harnesses must barrier on umount+rmmod of ALL nodes before mkfs (see
  `scripts/sess88_workload_a_modeN_baseline.sh` mount_cluster).

## 2026-08-19 (sess375): the slot hash is reproducible in userspace

`tools/caw_slot_hash.py` computes the CAW **home slot** of a resource outside
the kernel. `find_slot` binds at `resource_hash_raw(res) % 65536` and linear
probes past tombstones (`dlm/dlm_caw.c:3126, 3187-3279`), and
`resource_hash_raw` (`dlm/dlm_shared.c:34`) is **seedless FNV-1a over the raw
bytes of `struct mxfs_resource_id`** — no boot seed, fixed layout — so it
reproduces exactly. Verified against a live platter: **788 live slots at their
computed home, 10 at probe+1, ZERO mismatches**.

Why it matters: it turns "wait for a 1-in-65536 slot collision" into a lookup.
`collide` found 2478 cross-AG colliding inode pairs among 18669 real inodes,
which is what makes the closure purge's tombstone/slot-reuse hazard testable
with ordinary files instead of a forged slot image.

### Three traps this tool exists around

1. **`resource.ag_number` is only meaningful for `type=AG`.** For
   INODE/ICLUSTER it is 0, and both `caw_slotdump` and the kernel's own strip
   log print that 0. The closure classifier uses
   `XFS_INO_TO_AGNO(ino) = ino >> (agblklog + inopblog)`
   (`xfs/xfs_mount.h:799`; the two logs come from xfs_dsb bytes 124 and 123).
   An audit that trusts the printed `ag=` concludes every inode lock lives in
   AG 0. `tests/closure_foot_parse.py` derives it correctly.
2. **A plain `dd iflag=direct` of a slot sector can return a STALE image** —
   this target stack drops the SCSI FUA bit, which is the whole reason
   `caw_slotdump` uses READ(16)+FUA. Use `--slot N` for single-slot polling.
3. **`last_modified_ms` is the WRITING NODE's monotonic clock.** It is not
   comparable across nodes; ordering arguments built on it are invalid.

`caw_slotdump` also now prints `yield=` (the `yield_to` bitmap) and `ag=` for
every resource type, and its default filter no longer hides slots whose only
state is `waiters_ex`, `yield_to`, or `open_holders` — those are exactly the
frozen-grant shapes D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 strands nodes on.

## `recov_forge` (sess383)

Reads, decodes, forges and restores the RECOVERY GUARD state of a disklock
heartbeat sector: `dump` / `save` / `restore` / `copy` / `mkguard`.

It exists because the D-513 containment machinery could not be tested — the
kernel only ever writes well-formed outcome records, so nothing in the tree
could produce the malformed or misplaced inputs the RULE-5 review required
proof against. `recov_forge` produces them **on the real LUN with the real
CRC binding** (crc32c over the record's own bytes folded with the sector's
`{fs_gen, node_id, epoch}`), so the checks exercise the real kernel path.

- Layout copies of `mxfs_recov_desc` / `mxfs_recov_outcome` /
  `mxfs_disklock_heartbeat` are carried locally with `_Static_assert`s, the
  same convention `caw_slotdump` and `chk_mxfs` use (the kernel headers drag
  in `pal.h`).
- All I/O is SG_IO READ(16)/WRITE(16) with FUA. A plain O_DIRECT access on
  this target stack can be served a stale image.
- Not in `tools/Makefile`; build with
  `gcc -Wall -Wextra -O2 -I../include -o recov_forge recov_forge.c`.
- It WRITES to the shared device. `save` first, `restore` after —
  `tests/d513_forged_record_checks.sh` is the worked example.

**Cross-subsystem contract — this tool is coupled to `dlm/` layout and will
lie silently if that coupling breaks.** It duplicates four things from
`dlm/disklock.h`, none of which the compiler can check across the boundary:

1. the 512-byte `mxfs_disklock_heartbeat` layout (union at 40, outcome at
   160, prov at 424) — guarded here by `_Static_assert`, and on the kernel
   side by `MXFS_BUILD_CHECK_HB()`. **If `dlm/` ever re-carves the union**
   (as sess346 did, evict ring 384->prov carve), update the mirror structs
   or every forge lands in the wrong bytes and reads as "no record".
2. `recov_desc_crc` / `recov_outcome_crc` — crc32c over the record's bytes
   up to its own `crc32c` field, then over a packed
   `{fs_gen, node_id, epoch}`. The seed is `~0U` with **no final inversion**
   (kernel `crc32c()` semantics), which `mxfs_pal_crc32c` matches byte for
   byte. Get this wrong and every shape degrades into `badcrc`, so the
   validating shapes silently stop testing validation.
3. the magic/version constants (`MXLK`, `MRCV` v2, `RVCO` v1) and
   `MXFS_RECOV_F_QUARANTINED`.
4. `sb->disklock_offset` from `include/mxfs/mxfs_super.h` — slot N lives at
   `disklock_offset + N*512`.

The cheap integrity check is `recov_forge <dev> dump`: it prints, for each
slot, `crc=OK/BAD` for both records and **what `read_outcome()` would
return**. If a live rig's own records read as `crc=BAD`, the mirror is
stale — fix the tool before trusting any shape result.

### `mkguard` shapes and what each one is for

Every shape below is an input the kernel cannot produce, aimed at one
consumer of the terminal recovery-outcome record. `--oc SHAPE` sets the
outcome region; the flags beside it shape the descriptor and the sector.

| shape / flag | what it forges | what it probes |
|---|---|---|
| `--oc none` | QUARANTINED descriptor, all-zero outcome | the legacy intent-path backfill |
| `--oc valid` | TERMINAL_REFUSED / POLICY / AG_MASK | the accept path; AG-scoped admission |
| `--oc fswide` | TERMINAL_REFUSED / POLICY / FSWIDE | the whole-filesystem refusal |
| `--oc badkind` | crc-VALID, `outcome=99` | semantic validation of the outcome kind |
| `--oc badreason` | crc-VALID, `reason=99` | validation of the refusal reason |
| `--oc agmask0` | crc-VALID AG_MASK, empty mask | an AG domain that quarantines nothing |
| `--oc fswidemask` | crc-VALID FSWIDE carrying a nonzero mask | noncanonical domain: FSWIDE defines no AG set, and two consumers can disagree about what such a record means |
| `--oc slotmismatch` | crc-VALID, `oc.victim_slot` names another slot | the outcome's identity binding |
| `--oc badcrc` | well-formed fields, wrong crc | the structural fail-closed arm |
| `--break-desc-crc` | descriptor bytes present, crc wrong | `-EPROTO` fail-closed |
| `--victim-slot S` | descriptor names a DIFFERENT slot | the descriptor's identity binding — the only slot binding there is, since the crc binds the sector header, which travels with a byte-copied record |
| `--fsgen G` | a foreign mkfs generation | pre-mkfs ghost handling (`-ESTALE`) |
| `--stage 5` | descriptor at `GRANTS_RELEASED` | slots the requires-recovery sweep SKIPS — the only way to reach the registration-time scan without the admission barrier seeing the slot first |
| `--live` | descriptor without `F_QUARANTINED` | the "live descriptor, no verdict" arm |
| `--oc-agmask M` | the AG mask value | out-of-range AG bits (`0x8000...` against a 25-AG filesystem) |

`--fsgen` and `--stage` are the two that unlock coverage nothing else
reaches, and both are counter-intuitive: a forge with the WRONG generation
is invisible to every sweep (which is the point — it proves the ghost is
ignored), and a forge at a COMPLETE stage is invisible to the barrier
(which is how the registration path gets tested in isolation).

## mkfs_mxfs geometry (sess389, 0.20.0)

- `agcount` is `ceil(dblocks / 262144)` capped at `dblocks / log_ag_need`
  (the whole `-n`-slice log must fit ONE AG: 32 × 64 MB slices ≈ 2 GiB → a
  50 GiB LUN formats to 25 AGs, 128 GiB to 64).  The kernel's home AG is
  `node_slot % agcount`, so `agcount < nodes` makes slots ≥ agcount share a
  home AG pairwise (pace collapse, and — at 25 AGs/32 nodes — the #474
  relfence wedge on the shared slots).
- mkfs now WARNS when `agcount < -n count` with the collision count and the
  minimum device size for `agcount >= nodes` and 2× (verified: 50 GiB `-n 32`
  → "agcount 25 < node count 32 … needs ≥ 65219 MB").  The kernel warns at
  join (`P-AGCOUNT-COLLISION`, `pal/linux/xfs_super.c`) naming the partner
  slot; exactly slots 25-31 fired at 25 AGs.
- `-d SIZE` (K/M/G/T) caps the XFS data area (like `mkfs.xfs -d size=`) to
  reproduce a smaller device's agcount on a larger LUN.  `-n` is hard-capped
  at 32 and cannot be used to force agcount.
- mkfs has only `pr_err`/`pr_info` (no `pr_warn`) and REQUIRES a block
  device — test it on a node with `truncate` + `losetup`, not on a file.
