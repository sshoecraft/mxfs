# tools (User-space utilities)

**Owner files**: `tools/` (12 files, ~6.4K LOC)
**Last updated**: 2026-06-12; 2026-07-16 (mkfs Step 3b: transport self-test scratch sector reservation); 2026-08-01 (chk_mxfs C7 `-U` upgrade + orphan inode audit)

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
