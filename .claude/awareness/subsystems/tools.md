# tools (User-space utilities)

**Owner files**: `tools/` (16 files, ~7.0K LOC)
**Last updated**: 2026-06-12; 2026-07-16 (mkfs Step 3b: transport self-test scratch sector reservation); 2026-08-01 (chk_mxfs C7 `-U` upgrade + orphan inode audit); 2026-08-12 (caw_slotdump documented + `revoke` field); 2026-08-19 (caw_slotdump `--slot`/`yield`/always-`ag`; new caw_slot_hash.py); 2026-08-24 (RULE 8 ledger schema tools: `ledger_validate.py`, `ledger_backfill_dates.py`, `hook_ledger_guard.sh`); 2026-08-29 (sess439: bootstrap record region in mkfs/chk, `check_bootstrap` — see final section); 2026-08-29 (sess439: bootstrap record region in mkfs/chk, `check_bootstrap` — see final section); 2026-08-29 (sess450: chk_mxfs decodes MXFS_DISKLOCK_FLAG_RETIRE_PENDING (4) in check_disklock/--show-quarantine/repair-table — BLOCKED, never consumable; pitfall: chk_mxfs re-declares the flag constants locally and compares some against bare literals); 2026-09-02 (sess462: chk_mxfs `--show-quarantine` decodes the obligation record + reads/validates the obligation list — see the final section); 2026-09-05 (sess517: chk_mxfs -v prints agblocks/agblklog/inopblog — see the final section); 2026-09-08 (sess559: `disklock_hb_dump.py` — plain-pread heartbeat slot table for targets that refuse READ(16) FUA; see final section); 2026-09-09 (sess560: `disklock_hb_dump.py` decodes the recovery descriptor of every RECOVERY_GUARD record — stage/victim/owner/prover/fence kind; see final section); 2026-09-10 (sess575: `defects.py`, `criteria.py`, `defects_import.py`, `criteria_import.py` — the defect queue and the criteria board become writable tools over `data/`, and the 95 OPEN ledger records are imported; see final section); 2026-09-10 (sess576: the old ledger chain is ARCHIVED to `/src/archive/mxfs/` and unwired — `defects.sh`, `showstat.sh`, `tests/suite/open_defects.sh`, all eight `ledger_*` tools, `hook_ledger_guard.sh` and BOTH one-shot importers are gone from this tree, and the `open_defects` board criterion is retired. What remains in `tools/` is `defects.py` and `criteria.py`; see final section)

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
| `mxfs_mmapio` | `mxfs_mmapio.c` (sess416) | **One mmap'd access with fault-disposition reporting**, for the D-512 fault race leg (`tests/d512_race_verify.sh`): `mxfs_mmapio r\|w <file> <offset> [byte]` maps MAP_SHARED and performs the access under SIGBUS/SIGSEGV handlers. Exit 0 = completed (prints `read=0xNN` / `wrote=0xNN msync=RC`), 42 = SIGBUS (the mmap-path shape of -ESTALE from a poisoned incarnation), 43 = SIGSEGV, 2 = setup error. NOT in the tools Makefile — build ad hoc like recov_forge: `gcc -Wall -Wextra -O2 -o tools/mxfs_mmapio tools/mxfs_mmapio.c`; nodes run it via the NFS path `/src/mxfs/tools/mxfs_mmapio`. |
| ~~`ledger_validate.py`~~ | **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/` | Schema gate for the old date-and-status ledger. The schema it enforced no longer exists: the queue has no `status` field and no date fields. |
| ~~`ledger_backfill_dates.py`~~ | **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/` | One-shot date repair for a file that is no longer in this tree. |
| ~~`hook_ledger_guard.sh`~~ | **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/` | Was a PostToolUse hook in `.claude/settings.json`. **The hook entry was removed with it** — `settings.json` now has no `hooks` block at all. |
| ~~`ledger_set.py`, `ledger_owed_work.py`, `ledger_session_dates.py`, `ledger_repair_backtick_damage.py`~~ | **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/` | One-off editors and readers for `OPEN_DEFECTS.json`. `defects.py add/update/remove` is the writer now, which is why none of these are needed. |
| `defects.py` | `defects.py` (sess575) | **The defect work queue** over `data/defects.json` — sole reader and sole writer. Takes `2 tcp` positionally like `showstat.sh`. No `status` field: an entry is in the queue or it is `remove`d with mandatory `--why`, and the fix becomes a `CHANGELOG.md` entry. Carries `nodes`/`dlm` saying which configuration the defect was observed on, so `--at 2/tcp` answers what actually blocks a release. Both fields default fail-closed (`1`/`any` = blocks everything). |
| `criteria.py` | `criteria.py` (sess575) | **The criteria board** over `data/criteria.json` — sole reader and sole writer. Takes `2 tcp` positionally like `showstat.sh`, filters rows to what `applies()` in that configuration, and reproduces showstat's FLAKY rule (FAIL-only, 11-run window, rig-noise excluded). Every criterion is proved once per `<nodes>/<transport>` configuration and is `UNKNOWN` for every column absent from its map. A cell over its `budget_s` records `FAIL` whatever status the caller passed; a cell read back against a different `--build` reads `STALE`. |
| ~~`criteria_import.py`~~, ~~`defects_import.py`~~ | **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/` | One-shot migrations. They ran on 2026-09-10, moving the 95 OPEN records and 4 categories / 44 tests / 601 cells into `data/`. Their source files went to the archive with them, so keeping them in the tree meant shipping a script whose only input path does not exist in a clone. |
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

# ledger_validate.py / ledger_backfill_dates.py / hook_ledger_guard.sh / ledger_set.py /
# ledger_owed_work.py / ledger_session_dates.py / ledger_repair_backtick_damage.py
#   ARCHIVED 2026-09-10 -> /src/archive/mxfs/tools/.  Not in this tree.  Their data file
#   (tests/criteria/OPEN_DEFECTS.json) went with them.

defects.py [2 tcp | 2/tcp | 2] [-d] [-s SEV] [--json]   # bare config == --at, like showstat.sh
defects.py [-d] [-s SEV] [--at 2/tcp] [--json]  # the queue; --at = what blocks that configuration
defects.py show <id>                            # id or unique substring
defects.py add    -s SEV -m "..." [-N 2] [-D tcp] [-n next] [-w evidence] [--id ID]
defects.py update <id> [-s|-m|-n|-w|-N|-D]      # -N smallest cluster seen on, -D transport
defects.py remove <id> --why "what was measured"   # prints the CHANGELOG line to paste
defects.py rename <id> D-SHORT-NEW-ID-0962         # new id only (sess596); keep the number,
                                                   # evidence dirs and memories cite it
# defects_import.py / criteria_import.py — ARCHIVED 2026-09-10, the migrations are done.

criteria.py [2 tcp | 2/tcp] [-v] [--build SRCVER] [--gaps]   # bare config == --at
criteria.py [-v] [--at 2/tcp] [--build SRCVER] [--gaps]
criteria.py show <id> [--build SRCVER]
criteria.py add    -i ID -r "req" -d "detector" [-b BUDGET_S] [-p PHASE] [--why] [--source]
criteria.py update <id> --at 2/tcp -s PASS -m "..." [-e ELAPSED_S] [--build SRCVER]
criteria.py update <id> [-r|-d|-b|--why]        # no --at: edits the criterion, not a cell
criteria.py remove <id> --why "no longer required"
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

**sess434 — the mirror WAS stale, silently, for 29 sessions (D-0358).**
`RECOV_DESC_VERSION` stayed at 2 after the kernel/chk moved to
`MXFS_RECOV_DESC_VERSION 3` in sess405 (same 120-byte layout).  `dump`'s
`crc=OK` did not catch it because the crc is layout-bound, not
version-bound: every forge since sess405 read as a version mismatch (kernel
`-EPROTO`, chk_mxfs "will not interpret it") so every shape exercised only
the version gate.  Found by `tests/chk_guard_inprogress_verify.sh`, whose
`--live --stage 1` forge chk_mxfs classified as a corrupt terminal quarantine.
Fixed to 3 (0.41.1).  **Add the version to the integrity check:** a `dump`
whose `desc: ver=` differs from `MXFS_RECOV_DESC_VERSION` in
`dlm/disklock.h` means every subsequent shape result is void.

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

## 2026-08-22 (sess399-401): `mxfs_agi_dump.py` — platter AGI/btree-root forensics

`tools/mxfs_agi_dump.py [--img PATH] [--xfs-off N] [--scan] AGNO...` decodes,
read-only and straight from the LUN image (default `/home/steve/disk.img`),
each AG's on-platter AGI header — `agi_count` / `agi_freecount` / `newino` /
`agi_lsn` (cycle:block — identifies WHICH NODE'S LOG slice wrote the AGI last)
/ non-empty unlinked buckets — plus the inobt and finobt root block headers
(magic, level, numrecs, lsn, owner).  `--scan` walks every inobt-allocated
inode of the AG and reports dead dinodes (the leak signature).  `--xfs-off`
is the envelope's XFS-region byte offset; without it the tool shells out to
`tools/chk_mxfs -v` and reads `xfs_data_offset=N`.

Built for the sess399 forensics of D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-
AGI-RMW-399 (AGI `freecount` +1 vs inobt/finobt, the 0.23.9 "every create
-> -117" regression): the dump showed AG 0 / AG 5 with `agi_freecount=1`,
every chunk full and every allocated dinode live, i.e. the AGI side was
wrong.  Pair it with `tests/agifc_churn_experiment.sh` (O_TMPFILE churn repro
+ `P-AGIFC-*` audit sweep) and `tests/tmpfile_churn_ftrace.sh` (function_graph
per-callee timing of one node's churn iteration, for the RULE 0 perf defect
D-TMPFILE-CHURN-RULE0-PERF-400).

Oracle trap (sess400): `chk_mxfs` on a LIVE LUN is not a valid AGI-vs-btree
oracle for an AG some node currently HOLDS — the AGI and the btree leaves
destage at different instants (measured: finobt landed 15 s after inobt).
Quiesce (`AGIFC_UMOUNT=1`, 32-way unmount ~1 s) before trusting the numbers.

## 2026-08-23 (sess404-405, 0.25.0-0.26.0): the recovery-manifest (rman) region

`mkfs_mxfs` lays out `[super][journal 32×slices][disklock 64 HB + 65536 CAW]
[rman 64 × (2 MiB + 64 KiB) = 132 MiB][XFS]`, sets `MXFS_FORMAT_F_RMAN`, writes
`rman_offset`/`rman_size` into the envelope super (fields at 112/120), zeroes
the region, and prints a `Manifests:` line; proto gen is 7.  `chk_mxfs -v`
reports `rman_offset=... size=...` and validates the region (size =
`MXFS_RMAN_REGION_BYTES`, must end at/before `xfs_data_offset`, no overlap);
`chk_mxfs --upgrade-protogate` REFUSES a volume without the flag ("re-mkfs")
because the region cannot be carved in place.  `MXFS_RECOV_DESC_VERSION_C` is
3 (sess405 descriptor: SNAPSHOTTING stage + manifest pointer record at body
offset 216).  Measured: fresh 32-node prep with the region = 75 s (was 58-86).
Design + build order: `docs/recovery-manifest.md`.

## sess408 — chk_mxfs: a bucket member with a FREE core is an ERROR (tools/chk_mxfs.c)
- `tools/chk_mxfs.c` orphan audit (AGI unlinked-bucket chain walk, ~line 2580):
  a chain member whose dinode has `di_mode == 0` now raises
  `err("AG %u unlinked bucket %d: member agino %u (ino %llu) has a FREE core
  (mode 0, nlink %u, gen %u) — bucket chain points at a freed/never-written
  inode")` instead of only being listed under `-v`.  XFS links an inode into a
  bucket in the transaction that writes its allocated core and unlinks it in
  the transaction that zeroes di_mode, so a mode-0 chain member cannot exist on
  a consistent medium.  Ledger: `D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408`
  (8 of 29 clean-unmount checks on 2026-08-23 had one and were read as PASS).
- Allocated members with mode != 0 and nlink 0 (pending-reap zombies of a dead
  slot) stay informational — that is the open
  `D-FOREIGN-SLICE-INTENTS-ABANDONED` shape, not corruption.
- PITFALL: this tightens the board oracle — kill-lap arms that used to PASS
  with "chk clean (SB lazy aside)" now FAIL on this error until the defect is
  fixed.  That is RULE 6 working, not a regression of the tool.  `make tools`
  after editing (the rig's prep/chk use `tools/chk_mxfs` from the tree; never
  rebuild mid-run).

## 2026-08-23 (sess411, 0.27.0): `mxfs_logslice.py` — per-slice xlog forensic decoder

`tools/mxfs_logslice.py IMAGE --slice N [--records|--all|--ino I|--agbno A:B|--lsn HEX|--cluster DADDR|--raw-out FILE]`

sess412: `--raw-out FILE` also writes the slice's raw 64MB bytes to FILE at
the ENVELOPE-CORRECT image offset — use this (never a hand-computed `dd
skip=`) to archive a failed slice: the in-FS daddr from the kernel's replay
banner is short of the true image offset by `bt_sector_offset` (~467k
sectors), and a sess412 dd with the banner offset archived the wrong region.
`tests/fence_live_node.sh` now calls it automatically (FLN_BACKING, default
/home/steve/disk.img) whenever a replay-failure line is seen, because the
NEXT arm's prep re-formats the LUN and destroys the evidence (slot-27
type-0 evidence was lost exactly so).

Read-only, envelope-aware, O_DIRECT (dd iflag=direct — page-cache-proof)
decoder of ONE per-node XFS log slice straight off the SCST backing image
(`/home/steve/disk.img`).  Parses the 4KB mxfs_ondisk_super at byte 0, the
XFS sb at xfs_data_offset, computes `slice_daddr = FSB_TO_DADDR(sb_logstart)
+ slice * log_slice_bblks` (identical to mxfs_xlog_recover_foreign_slice),
then decodes every xlog_rec_header (cycle-stamp unpacking, v2 extended
headers) and reassembles transactions EXACTLY like upstream
xlog_recover_add_to_trans/add_to_cont_trans.  Prints per-txn item lists:
INODE (ino/blkno/boff + core magic/mode/nlink/gen/changecount), BUF
(blkno/blft/flags), ICREATE, RELMARK.  `--cluster DADDR` dumps dinode
magics of an inode cluster.

This is THE instrument that root-caused D-527 (sess411): the kernel's
foreign replay saw a bad `ldip->di_magic` for an item the platter holds
valid — comparing kernel item positions (pass-2 batch ≤100) against the
tool's platter ordinals (#~117) proved the kernel's byte view was missing
whole regions.  Pitfall: `--ino` prints EVERY txn containing that ino —
grep the output for `ino=` to see which txns/versions matched; item counts
in the TXN header are items (th_num_items in the trans header counts
regions, ~3× for inode items).

## 2026-08-24 (sess417): the ledger schema tools — RULE 8 enforcement

> **ARCHIVED 2026-09-10.** Every file this section describes now lives in
> `/src/archive/mxfs/`, along with the ledger it operated on. Nothing in this
> tree calls any of them and the `settings.json` hook entry is gone. The
> section is kept because the *reasoning* still applies to the replacement —
> particularly the fail-closed principle and the repo-relative path
> resolution, both of which `defects.py` inherits. Read it as history, not as
> a description of the current tree.

Three files land the CLAUDE.md RULE 8 date schema on
`tests/criteria/OPEN_DEFECTS.json`. They are the first tools in this
subsystem that operate on project *bookkeeping* rather than on a device, so
they share none of the SG_IO/PAL machinery above.

**Why they exist.** The 2026-08-24 cost audit ran a date-range query over the
ledger's `found` field, got near-zero, and reported "Era E discovered 0 new
defects" — while the ledger had in fact grown by 45 records that week.
`found` was ISO-dated on 16 of 142 records; the query was measuring the
schema, not the project. Without dates the closed:found ratio — the only
number that says whether MXFS is converging on shippable
(`docs/cost-audit.md` §11.6) — cannot be computed for any era, permanently.

### `ledger_validate.py` — the gate

Checks per record: `opened` always, `closed` iff status is a disposition and
**forbidden when OPEN**, `updated` always; all three bare ISO `YYYY-MM-DD`.
`status` exactly one of `OPEN` / `FIXED AND VERIFIED` / `DISPROVED` (13
non-canonical spellings existed; each is reported with the canonical form
named, never silently folded). `severity` in
`critical|high|major|minor`. Ordering: `opened <= updated`, `opened <=
closed`, nothing in the future. Duplicate ids fail. A bare date appearing in
a prose field (`found`, `history`, `notes`) fails — that is the exact shape
of the bug it exists to prevent.

### `ledger_backfill_dates.py` — one-shot repair, never a guesser

Applied 2026-08-24: **280 violations -> 45**. Derivation order for `opened`:
exact value, then the ISO prefix of `opened` (prose split off into `found`),
then the ISO prefix of `found`, then the earliest ISO date anywhere in the
record's prose. `closed` falls back to `updated` for a disposed record.
Every non-exact value is recorded in `date_provenance`, and the two weak
sources say so in the provenance text ("DERIVED, verify" / "PROXY, not the
measured disposition date").

**It writes the literal `UNKNOWN` rather than inventing a date**, which the
validator then rejects — so the hole stays visible instead of silently
corrupting the ratio. 28 records / 36 fields are still `UNKNOWN` and need
hand-filling; the board stays red on schema until they are.

### `hook_ledger_guard.sh` — block at authoring time

PostToolUse hook, matcher `Edit|Write|MultiEdit|NotebookEdit`. Payload is
JSON **on stdin** (not env vars — an inline `$CLAUDE_TOOL_INPUT` version was
simply wrong). Non-ledger paths and unparseable payloads exit 0 immediately,
so it can never block an unrelated write.

## Invariants (added sess417)

4. **Nothing in the ledger enforcement path hardcodes `/src/mxfs`.** All
   three resolve the repo from their own location (`readlink -f "$0"` ->
   dirname -> `..`); the hook validates the ledger path **from the payload**,
   so editing a ledger in a second checkout checks that checkout's file;
   `settings.json` uses `"$CLAUDE_PROJECT_DIR/tools/hook_ledger_guard.sh"`;
   `tests/suite/open_defects.sh` honours `$MXFS_LEDGER` and derives
   `MXFS_ROOT` from `$0`, keeping `/src/mxfs` only as a last-resort fallback
   (correct on the rig, where nodes NFS-mount `/src` and run that very file).
   Verified against a real clone at a different path.
5. **All three fail CLOSED.** A missing validator, a missing `python3`, or an
   unreadable ledger blocks the write and fails the board — the same standing
   `open_defects.sh` already gave an unreadable ledger. A guard that no-ops in
   a clone is worse than no guard: ledger and board both look healthy while
   the dates rot.

## Known Pitfalls (added sess417)

- **`OPEN_DEFECTS.json` is a dict, and `_comment` is a list.** Top level is
  `{"_comment": [...20 strings...], "defects": [...]}`. A "first list found"
  or `list(d.values())` heuristic grabs `_comment` and reports 20 records.
  Always index `d["defects"]`.
- **Never read the whole ledger** (~1.25 MB after the backfill, and growing —
  see RULE 6). Use `./defects.sh`, or `json.load` + project the fields you
  need.
- **`found` is prose, not a date.** Nothing may parse it as one. Session
  numbers, incident names and build ids belong there; dates belong in
  `opened`/`closed`/`updated`.
- The backfill reformatted all 142 records to `indent=2`, so the first
  hand-edit diff after 2026-08-24 looks much larger than it is.

## Cross-Subsystem Dependencies (added sess417)

| Depends On | How | Notes |
|---|---|---|
| ~~tests~~ | ~~`tests/suite/open_defects.sh` invokes `ledger_validate.py`~~ | **Both archived 2026-09-10.** The criterion is out of `criteria.json`, `data/criteria.json` and `tests/suite/manifest`; the release question is `tools/defects.py <nodes> <dlm> --release`. |
| ~~—~~ | ~~`.claude/settings.json` PostToolUse hook~~ | **Removed 2026-09-10.** `settings.json` has no `hooks` block now. |

## sess419
- `chk_mxfs` decodes refusal reason 7 as `DBG_INJECTED` (test-published quarantine from
  `mxfs.dbg_purge_refreeze`; never a real replay verdict).

## sess421 — chk_mxfs refusal-reason names (0.32.0, chk_mxfs.c ~787/~898)
- `tools/chk_mxfs.c chk_refusal_reason_name()` now names wire reasons 6
  (`ASSEMBLY_DISCONTINUITY`, sess412 — printed as UNKNOWN before) and 8
  (`INTENTS_UNDISCHARGED`, sess421: the victim's slice holds intent obligations
  with no done record; refused before purge, needs repair).  The `_C` mirror
  constants live beside the others (`MXFS_RECOV_REFUSAL_*_C`); keep them in
  step with `dlm/disklock.h` whenever a reason is added — chk is the only
  operator-facing decoder of a quarantined guard sector.
- **0.33.0 (sess421)**: `mkfs_mxfs` lays out and formats the TCP authority ledger
  region (`format_tauth_region`: region header copy A + every page as a committed
  EMPTY page in copy A; copy B zero) and sets `MXFS_FORMAT_F_TAUTH` + `tauth_offset/
  size`; layout print gains an "Authority:" line.  `chk_mxfs` validates the region
  geometry/overlap (`regions[6]`), sweeps every page (`check_tauth`: hdr_copies,
  two/one/none, maxseq; a `none` page is an error), and `-U` refuses a volume that
  lacks the region (gen 8 requires it; only mkfs can create it).  Both tools use
  `include/mxfs/mxfs_tauth.h` with their local table `crc32c` as the crc callback.

## sess429 (0.39.0) — tauth region v3 control pages
- `MXFS_TAUTH_VERSION` 3: region layout = 2 header copies + 3 CONTROL pages (view slot A, view slot B, ROOT) + 2 page-copy arrays (`mxfs_tauth_ctrl_off()`, `mxfs_tauth_page_off()` in include/mxfs/mxfs_tauth.h). v1/v2 regions are refused.
- `mkfs_mxfs` `format_tauth_region()` writes the mkfs ROOT (`mxfs_tauth_root_init_empty`: no committed view, ballot 0, nonce {0,1}) into the first 512 B of the root page; view slots stay all-zero (= empty).
- `chk_mxfs` `check_tauth_ctrl()` (called from `check_tauth`) validates root + both view slots with `mxfs_tauth_root_validate` / `mxfs_tauth_ctrl_validate` and prints `TCP authority view ...... OK (gen= slot= members= removed= ballot= coord= other=)`; any failure is an `err()` naming the first failed rule (`tview_errname`).
- chk_mxfs.c still carries its own local SHA-256 (`struct sha256_ctx`, quarantine archive); the header's is `mxfs_sha256_*` with the compress step named `mxfs_sha256_compress` to avoid the symbol clash in that single TU.
- Spec: `docs/tauth-view-table.md` §13; usermode test `tests/tauth/view_format_test.c` (target `view_format_test`, in `make -C tests/tauth test`).

## sess433 (0.40.1) — chk_mxfs: recovery guard IN PROGRESS is not a quarantine
- `chk_print_guard()` returns **3** for a readable RECOVERY GUARD whose
  descriptor lacks `MXFS_RECOV_F_QUARANTINED_C` (recovery in progress or
  stuck); the -Q summary counts it as `recoveries in progress`, not
  `quarantined verdicts`, does not subtract it from `usable RW slices`, and
  prints its own advice: the admission barrier refuses EVERY mount while the
  guard stands; stage 1 + fence kind 0/6 = stuck (victim key gone) — remedy
  is a peer PREEMPT AND ABORT (0.40.0 retains keys on dirty departures) or
  `single_node_exclusive=1`.  Exit code **5** for in-progress guards (4 stays
  terminal quarantine).  D-379 item 5.
- Pitfall: return codes of `chk_print_guard` are now 0 unreadable / 1 terminal
  readable / 2 bucket-sweep guard / 3 in-progress — callers must not treat
  `!= 2` as "terminal".
- Cross-subsystem: the advice text mirrors dlm/disklock.c `P300-CLAIM-WITHDRAWN`
  (same sess433 rewrite) — keep the two remedies in sync.

## 2026-08-29 (sess438): PR registrant ledger region + HB identity block
- `mkfs_mxfs`: new envelope region after tauth — `prkey_offset/prkey_size` (256 × 512 B, zero-filled = FREE), flag `MXFS_FORMAT_F_PRKEY64`; printed as "Registrants:" in the layout summary. Layout is now [super][journal][disklock][rman][tauth][prkey][XFS data].
- `chk_mxfs`: validates the region (size/entry alignment, overlap, gen-12 requires it; `-U` upgrade refuses a volume without it — re-mkfs), `check_prledger()` prints every PREPARED/REGISTERED entry (all with `-v`) and validates crc(entry, idx); `decode_hb_identity()` prints/validates each ACTIVE/WITHDRAWN heartbeat record's identity block (offset 360; crc mirrors `dlm/disklock.c hb_ident_crc`).
- `tests/hb_epoch_inject.py`: decodes the identity block (`ident{key gen src crc_ok}`) and reseals its crc on `set` (the crc binds the epoch). `tools/recov_forge.c`'s `pad[168]` still spans the identity bytes (360..424) — it CAS-modifies existing images, so nothing is lost, but a forge that zero-fills its pad would clear the guard writer's identity.

## 2026-08-29 (sess439, 0.44.0) — bootstrap record region

- **mkfs_mxfs**: lays out a new 4 KiB region `[prkey][bootstrap][XFS data]`
  (`MXFS_FORMAT_F_BOOTSTRAP`, super `bootstrap_offset/size`, proto_gen 13)
  and writes ONE valid IDLE record (`write_bootstrap_record`: local
  `struct mkfs_bootstrap_rec` mirroring `dlm/bootstrap.h` byte for byte,
  magic "MXBS", crc32c(record with crc=0, seed ~0, no final inversion —
  same formula as the kernel and as the prledger entries).  An all-zero
  sector is UNFORMATTED and the kernel fails the mount closed
  (`P-BOOT-UNFORMATTED`), so `zero_region` alone is NOT a valid format for
  this region.
- **chk_mxfs**: geometry/overlap/`-v` info for the region; gen ≥ 13 without
  the flag is an error; `--upgrade-protogate` refuses (re-mkfs).
  `check_bootstrap` validates magic/ver/crc/fs_uuid and prints
  `bootstrap: <state> term seq owner key gen host boot victims complete
  registrants prev kind`; a claimed/sealed/recovering state is flagged
  (ACTIVE admission is refused by the kernel while it stands).  The struct
  layout is duplicated locally (as for prledger) — change all three copies
  (`dlm/bootstrap.h`, mkfs, chk) together; each has a 512-byte
  `_Static_assert`.
- **Pitfall**: `chk_mxfs` has `err()`/`info()` only — no `warn()`.

## 2026-08-29 (sess441-442, 0.47.0-0.48.0) — bootstrap record v3 + `--clear-bootstrap`

- **mkfs_mxfs / chk_mxfs**: record v3 (PROTO_GEN 15) adds the adopted-slice
  escrow at offset 224 (`escrow_pad` at 220); all three struct copies
  (`dlm/bootstrap.h`, mkfs, chk) updated together.  `check_bootstrap` prints
  `bootstrap escrow: <state> K cls victim key gen host boot old_crc claim
  replay_rc` when the escrow is not NONE; a REFUSED record is an error
  naming slot/reason.
- **chk_mxfs `--clear-bootstrap`** (sess442, `do_clear_bootstrap`): hands a
  REFUSED record back to IDLE — term/seq carried forward, `prev_owner_*` =
  the refused owner, `prev_fence_kind = 0` (operator clear), everything else
  zeroed, crc sealed, written + read back.  OFFLINE ONLY: O_EXCL open and no
  ACTIVE heartbeat advancing across 3 s (the `--upgrade-protogate` proof);
  refuses any non-REFUSED state (a claimed term belongs to its owner's
  resume or a peer's takeover) and a TERMINAL_SLICE refusal whose named
  sector still carries a recovery descriptor (`--accept-quarantine-loss`
  first).  Exit 4 on every refusal.
- **Pitfalls**: `chk_mxfs.c` defines `_GNU_SOURCE` itself (a `-D_GNU_SOURCE`
  on the command line warns "redefined"); the heartbeat header used by the
  liveness proofs is a local packed `{magic,flags,node_id,fs_gen,ts,epoch}`
  mirror (magic `MXLK` 0x4D584C4B, flags ACTIVE=1, RECOVERY_GUARD=3) —
  keep it in step with `dlm/disklock.h`.  `--clear-bootstrap` shares no code
  with `-U`'s scan (duplicated on purpose: each proof is self-contained).
- **`chk_mxfs --ino-offset INO`** (sess444, D-0510 negative arm): read-only;
  prints `ino agno agbno agino dinode_off cluster_off cluster_bytes inodesize
  blocksize inoalignmt xfs_off` — ABSOLUTE image byte offsets (envelope
  `xfs_data_offset` added) of the dinode and of the v5 inode cluster buffer
  containing it (cluster = 8192 × inodesize/256 bytes; agbno rounded down to
  blocks-per-cluster).  `tests/bootstrap_full_restart.sh` with
  `MXFS_ICREATE_CORRUPT=<node>` uses it to zero a dinode's magic on the image
  (whole-sector O_DIRECT RMW, all initiators destroyed) and prove the
  SYNCINIT ICREATE replay refuses instead of re-initialising.

## sess450: chk_mxfs decodes RETIRE_PENDING (0.59.0)

`tools/chk_mxfs.c` gained `MXFS_DISKLOCK_FLAG_RETIRE_PENDING_C` (4) — a THIRD
local re-declaration of the kernel's flag constants. **Pitfall (found by the
sess450 flag-consumer sweep):** chk_mxfs does NOT include `dlm/disklock.h`; it
carries its own `#define`s at `chk_mxfs.c:84` and `:1594-1596`, and several
sites still compare `h->flags` against bare literals (`== 1`, `== 3`, `case 0`
in `do_clear_bootstrap`, `do_upgrade_protogate`, `do_show_quarantine`). Any
numeric change to the kernel-side flags silently desyncs the fsck tool. When
adding a flag, grep for both the `_C` macros and the bare literals.

Three switches now handle flag 4, all treating it as NOT consumable:
- `check_disklock` — counts it with `withdrawn`, prints "RETIRE_PENDING …
  clean release awaiting proof its PR key is retired", decodes the identity
  block (the record keeps a valid, flags-bound ident crc, unlike EMPTY).
- `do_show_quarantine` — "transient; a live peer settles it".
- `chk_repair_table_clear` — **BLOCKED**: the tool must not consume a slot
  whose PR key may still be registered; a live peer settles it via READ KEYS
  (→ EMPTY) or fence (→ WITHDRAWN).

Cross-subsystem: the flag is written by `dlm/disklock.c::mxfs_disklock_release_slot`
and cleared by `hb_retire_settle` / `mxfs_disklock_retire_complete_self` — see
`dlm/disklock.md` and the dlm awareness doc. `mkfs_mxfs` is unaffected: it never
stamps a disklock flag (slots start implicitly zeroed = EMPTY).

Note: `chk_mxfs --pr-keys` is what `tests/pr_unregister_fail_restamp.sh` uses to
prove a key present/absent around a departure.

## sess462 (2026-09-02, 0.63.0) — chk_mxfs: obligation record + list (item 5 increment 2)

`tools/chk_mxfs.c --show-quarantine` now decodes the OBLIGATION RECORD at
recovery-body byte 280 (sector byte 320; `struct chk_recov_obl`, 40 B, magic
`RVOB`) of every readable RECOVERY_GUARD (`chk_print_obl_record`, called from
`chk_print_guard` and the walker) and, when the record names a published list
(`count > 0`), reads the OBLIGATION LIST from the victim's recovery-manifest
slot zone `[4 KiB, 64 KiB)` — header block (`struct chk_rman_obl_hdr`, 4096 B,
magic `MXOB`) at `rman_offset + slot*MXFS_RMAN_SLOT_BYTES + 4096`, entries
(`{fsbno u64, agno u32, len u32}`) at +8192 — and validates it the way the
kernel does (`chk_print_obl_list`): header crc (bytes 0..107 + zero pad),
stable recovery-case identity (victim node/epoch/fs_gen/slot + recovery_gen
from the sector/descriptor), header-vs-record binding (seq/count/entries
crc/census digest/mask/TERMINAL+FSWIDE flags), entry geometry, entries crc,
canonical form (sorted (agno, agbno), in bounds, no overlap) and the
recomputed mask/fswide.  Output lines: `obligations count=N
TERMINAL-EVIDENCE|OPEN [FSWIDE] ag_mask= seq= list_crc= census=` and
`obligation list VALID: ...` or an `INVALID` `err()` per failed check.

Pitfalls: the mirror structs must stay byte-identical to `dlm/recov_obl.h`
(guarded by `_Static_assert`s next to the outcome ones); the record crc uses
the same identity-bound recipe as the descriptor/outcome
(`chk_recov_body_crc`); the header crc is over bytes 0..107 PLUS the zero pad
(NOT the whole block minus the crc field); every failed check is reported as
INVALID — never as "no obligations" (the kernel treats an unreadable record
as QUARANTINE).  O_DIRECT reads need 4 KiB-aligned buffers (`posix_memalign`).

## sess466 — directory sharding (0.64.0)

- `mkfs_mxfs`: sb incompat now `0x03 | bit30 | MXFS_DIRSHARD_SB_INCOMPAT`
  (bit 29); envelope flags gain `MXFS_FORMAT_F_DIRSHARD`; gen 18 ⇒ every
  prep re-mkfs's.
- `chk_mxfs`: (a) envelope: gen ≥ 18 requires the DIRSHARD flag and vice
  versa; (b) `check_xfs_superblock` cross-checks sb bit 29 vs the envelope
  flag (`dirshard_gates_ok`); (c) new phase `Directory sharding ......`
  (`check_dirshard`): inobt walk collecting PARENT/CONTAINER dinodes
  (di_flags2 @0x78), per PARENT: shortform ROOT xattr locator → holder
  dinode (gen, S_IFREG, CONTAINER, nlink 1, one real extent at offset 0) →
  manifest block (crc32c via `xfs_verify_crc` @12, uuid, blkno,
  `mxfs_dirshard_blk_check`) → lifecycle vs nlink → each live container
  (gen, S_IFDIR, CONTAINER, nlink 2 when PUBLISHED); containers referenced
  by no manifest and not unlinked = ERROR.  Non-shortform locators are
  reported as skipped (not yet decoded).  (d) `--dirshard-hash KEYHEX
  NAME|hex:HEX`: SipHash-2-4 mirror, verified against the published vector
  0xa129ca6149be45e5.

## sess475 (2026-09-02) — `tools/scratch_build.sh <label> [marker]`

- Builds `mxfs.ko` + the userspace tools from an rsync scratch copy (objects/kbuild lists/evidence excluded per ccmemory trap-scratch-compile-rsync-copies-mxfs-mod-links-tree-objects), freezes to `tests/evidence/<label>_frozen_<ver>/{mxfs.ko,tools/}`, verifies the marker string with `strings -a` and that `mxfs.mod` names no tree objects.  Measured 39-42 s at -j$(nproc).  Never touches `/src/mxfs/mxfs.ko`.  Env `SCRATCH_ROOT` / `CLAUDE_SCRATCHPAD`, `JOBS`.

## 2026-09-03 (sess481): `tools/p132_attribute.py` — where a create's milliseconds go

    tools/p132_attribute.py <evidence-dir-or-kernlog>...

Parses `mxfs: P132-CREATE` lines out of node kernel logs (plain or `.gz`; give it
a `tests/evidence/run_*` directory and it finds the `kernlog_*` files itself) and
prints per-bucket `n / sum / mean / p50 / p90 / max / share of total`, split into
ALL / file creates / directory creates, plus a **per-AG `total_ms` table** — which
is how allocation-group contention shows itself when node-to-AG placement collides.

Needs `mxfs.create_cost_ms` armed on the nodes (default 0 = off; see the sess481
section of `subsystems/xfs.md` for the probe and its three exclusive sub-phases
`res_ms`/`dlk_ms`/`dia_ms`, and for the `is_dir` gate that kept this probe off the
file-create path from sess132 to sess481).

It **refuses to report when no input carried the probe** rather than printing a
table of zeros: an unarmed run produces a clean-looking result that is not a
measurement of a fast filesystem but the absence of a measurement. It also reports
`other_ms`, the part of `pre_ms` the three sub-phases do not explain, instead of
folding it away — a decomposition with a large remainder has not found the cost
yet, and saying so is the point.

### `tools/caw_unlock_audit.py` — where a contended CAW unlock's wall time goes

    tools/caw_unlock_audit.py <evidence-dir-or-kernlog>...
    tools/caw_unlock_audit.py --compare <dir-A> -- <dir-B>

Harvests `mxfs: P381-UNLK-CONTEND` (`dlm/dlm_caw.c`, sess380) and accounts for the
wall time of a contended unlock: counted backoff sleep, `find_ms`, `backoff_ms`,
and the explicit **unaccounted** residue. `--compare` puts two runs side by side,
which is the shape the fastpoll A/B needs. Costs no rig time — the probe has been
shipping for a hundred sessions.

Baseline (0.64.37, one 32-node crash_consistency row): **17,558 contended unlocks,
616.5 s of node-time = 21.4% of the run's 2880 node-seconds.** Causes: `contended`
49.9%, `multigen` 47.3%, `holders` 2.6%; `fast`/`ident`/`selfbits`/`removed`/
`yieldto`/`control` **zero across every sample**.

**THE METHOD LESSON THIS TOOL ENCODES — the reason it prints "UNACCOUNTED" in
capitals.** The probe originally reported only `retries`/`miscmp`/`sleep_ms`/
`wall_ms`. Mean wall 35.1 ms minus mean sleep 9.3 ms leaves 25.8 ms, which over
2.7 attempts is 9.42 ms — and sess481 called that "slot I/O service time", divided
it out as a per-round-trip cost, and wrote it into a defect record as the root
cause. **It was wrong.** The same run's *direct* service-time probes say a slot
round trip costs **0.22 ms** (`P297-TKT`: `read_ms`/`reads`) to **0.37 ms**
(`P138-AGWAIT`: `caw_svc_ms`/`reads`). So ~96% of the non-sleep time was in
neither the counted sleep nor the device.

> **A subtracted residue is not a measurement of whatever you suspect is in it.**
> Name it "unaccounted" and go find a direct probe. The two that refuted this were
> already in the build and cost nothing to harvest.

The same signature is on the acquire side and is still open: `P297-TKT` `el_ms`
mean 280.5 ms against `slept_ms` 37.2 and `read_ms` 0.77 — ~242 ms per acquire
wait unaccounted. Host CPU starvation is excluded (clyde has 56 CPUs; the row
recorded `hostload=20.26`, ~36%).

0.65.0 closes the unlock half: `P381-UNLK-CONTEND` gained `find_ms=` and
`backoff_ms=`, bracketing the two unmeasured call sites in the retry loop —
`caw_inode_backoff` (sleeps *without* being added to `sleep_ms`) and `find_slot`,
which re-walks the hash chain in 16-slot span reads **on every retry** although the
retry already holds `slot_idx`. The tool prints `NOT INSTRUMENTED` for pre-0.65.0
logs so an old capture can never be read as a new one.

Do not read a dominant `multigen` as "version the slot's fields separately": one
slot is exactly one 512-byte sector (`_Static_assert`, `dlm/dlm_caw.h:321`), which
is the granularity of the SCSI COMPARE-AND-WRITE, so the compare covers every
peer's waiter bit however the struct is versioned.

### `tools/caw_slot_census.py` — read the CAW slot table offline, from the image

    tools/caw_slot_census.py <lun-image> [--base=0x...] [--top N]

**`tools/caw_slotdump` speaks SG_IO, so it only runs from an initiator (a test
node).** This reads the same table from the SCST `vdisk_fileio` backing file on
the target host — `/home/steve/disk.img` on clyde — so a census costs no rig time,
takes no lock, writes nothing, and cannot disturb a running board.

It finds the table exactly rather than guessing: `chk_mxfs -v` reports
`disklock_offset`, and `lock_region_offset = disklock_offset +
MXFS_DISKLOCK_HB_SIZE` (64 × 512) per `dlm/dlm_caw.c:15522` and
`dlm/disklock.h:125-126`. On this LUN that is `67117056 + 32768 = 0x400a000`.
Scanning for the magic is only the fallback — it fails on an empty table, which is
the normal state between runs.

Reports live/tombstone/empty counts, the **load factor including tombstones**
(tombstones are `MXDL`, explicitly *skip-but-continue*, so they lengthen linear
probe chains and only an EMPTY slot terminates a probe), and the **displacement
distribution** of live slots from their computed home — i.e. how many 16-slot span
reads a `find_slot` actually costs.

**First result (idle table, 2026-09-04):** live 99 (66 INODE, 33 AG),
**tombstones 0**, load factor 0.0015, and **99 of 99 live slots at displacement
0** — one span read per lookup. That weakens the sess481 hypothesis that the
unlock's 9.42 ms/attempt residue is the probe walk. Note the limit: it is an
*idle* table. Even a full 3200-slot working set is load factor 0.05, where
expected displacement is ~0.03 slots, so the hypothesis needs tombstone
accumulation of a wholly different order to survive.

Chain 128 takes the census immediately after each row and **before the next leg's
prep re-mkfs's the LUN**, alongside the in-kernel `find_ms=`. Two independent
instruments — one structural and offline, one direct and in-kernel — that cannot
be fooled the same way.

## 2026-09-03 (sess480): evidence-integrity tooling

Two tools that exist because six harnesses were found reporting success for work
that never happened — an unprepped fleet scored as failures, an assertion whose
variable never expanded, an ordering gate that opened early, three fault-injection
matrices that injected nothing, a board chain that rendered the previous DAY's
board after `run.sh` exited 3 on the run lock, and a consecutive-streak harvest
that read `ls -dt … | head -1` and would have scored the previous lap.

### `tools/closure_evidence_audit.py` — screen CLOSED records for vacuous verification

Reads the ledger, follows each record's cited evidence (both `tests/evidence/*.log`
files **and** timestamped evidence directories — following only the former made 79
of 106 closed records appear to cite nothing), and scans for signatures: a run that
reported DONE within seconds of START while printing a PASS; a verdict printed after
a refusal; a zero injection/opportunity witness beside a PASS; a lap harvest reusing
or back-dating an evidence directory. Costs no rig time.

    tools/closure_evidence_audit.py [--verbose] [--status OPEN|"FIXED AND VERIFIED"]

First run: 2 signature hits, **both verified false positives** (superseded re-run
attempts the records themselves label as such). No confirmed contaminated closure.
But only ~33% of closed records cite a followable artifact, so the screen speaks
for a third of the closed ledger and is silent about the rest.

`SCREENED_CLEAN` is a screening result, not proof. **Absence of a signature is not
presence of a measurement.**

### `tools/harness_lint.py` — stop the shapes recurring

Four rules, each derived from one of the six incidents and each carrying its origin
in its own message: HL001 implicit selection of verdict evidence (`ls -t … | head -1`);
HL002 unconditional `showstat.sh` render; HL003 a textual tool used as a numeric
predicate (`grep -qv '^0$'`); HL004 a shell variable inside a single-quoted pattern.

Deliberately a small rule set. A high-false-positive linter gets suppressed
wholesale and then protects nothing — an `rc=$?`-captured-but-untested rule was
considered and rejected because 690 of its ~759 hits are benign `STAGE … rc=$?`
progress logging. HL004 tracks double-quote parity **across lines**, because the
dominant idiom here is a multi-line remote command string where the single quotes
are literal characters for the remote grep; without that it flagged
`tests/criteria/lib.sh:181` and `tests/criteria/crash_consistency.sh:80`, both
correct and both in the board's own criteria scripts.

    tools/harness_lint.py              # report everything, exit 1 on findings
    tools/harness_lint.py --baseline   # accept current findings as legacy
    tools/harness_lint.py --new-only   # fail ONLY on findings not in the baseline

`--new-only` is the mode to gate on: 54 legacy findings are baselined in
`tests/criteria/harness_lint_baseline.json` and burning them down is separate work
from stopping the bleeding. Suppress one line with
`# harness-lint: ok - <reason>`; a bare suppression with no reason is ignored.

NOT yet wired as a board criterion: adding a row changes the board's shape, and
`D-FOREIGN-REPLAY-UNGATED-IMAGES` criterion (2) requires "a board clean apart from
the policy cell" — altering the row count while that evidence is being collected
would change the acceptance criteria mid-verification.

### sess480 tooling — interface, invariants, pitfalls

**`tools/harness_lint.py` — public surface**

| entry point | contract |
|---|---|
| `RULES` list, populated by the `@rule(code, why)` decorator | each rule is `(code, why, fn)`; `why` is printed with the findings, so it must state the incident the rule came from, not just the pattern |
| `hl001..hl004(line)` / `hl004(line, in_dquote)` | a rule takes the line and MAY take the cross-line double-quote state; `scan()` calls with two args and falls back to one on `TypeError`, so both shapes are valid |
| `scan() -> [{code,file,line,text}]` | walks `tests/`, `scripts/`, `tools/` for `*.sh`, skipping any path with an `evidence` component |
| `key(finding)` | `code:file:text` — deliberately NOT line-numbered, so the baseline survives edits that move a line |
| CLI | `--baseline` writes `tests/criteria/harness_lint_baseline.json`; `--new-only` exits 1 only on findings absent from it; bare run exits 1 on any finding |

**Invariants**

- **A rule must earn its place.** The false-positive cost is not symmetric: a
  linter that fires on benign code gets suppressed wholesale and then protects
  nothing. An `rc=$?`-captured-but-untested rule was written and rejected — 690
  of ~759 hits were benign `echo "STAGE … rc=$?"` progress logging.
- **HL002 cannot see a multi-line guard, and that is deliberate.** It allows a
  `showstat.sh` call only when `run_id`/`RUN_ID`/`--run` appears on the SAME
  line. A correctly guarded call — `run_id` pinned before the board and compared
  after, several lines up — still fires, and the author is expected to suppress
  it with the reason. That happened three times in one session
  (`sess479_chain119`, `sess480_chain122`, `sess480_chain123`). Widening the rule
  to accept a guard anywhere in the file would make it accept the unguarded case
  in any file that guards once, which is the whole failure being prevented. The
  same applies to HL001 on a properly pinned `pre`/`post` directory pair.
- **The baseline is keyed on content, not position**, so re-indenting a legacy
  file does not resurrect 54 findings.
- A suppression must carry a reason: `# harness-lint: ok - <why>`, on the
  offending line **or the line above it**. `SUPPRESS_RE` requires a non-space
  character after the dash, so a bare `# harness-lint: ok` is ignored.

**Pitfalls hit while writing it**

- HL004 first checked only for a double quote **on the same line**. The dominant
  idiom in this corpus is a multi-line remote command string (`ssh_node "$H" "` …
  `"`) where single quotes are literal characters for the *remote* grep and the
  variable expands locally. That version flagged `tests/criteria/lib.sh:181` and
  `tests/criteria/crash_consistency.sh:80` — both correct, both in the board's own
  criteria scripts. `scan()` now tracks unescaped `"` parity across lines and
  passes it in; findings fell 19 → 1.

**`tools/closure_evidence_audit.py` — public surface**

| entry point | contract |
|---|---|
| `load_records()` | tolerates both the `{"defects": [...]}` wrapper and a bare list |
| `cited_logs(rec)` / `cited_dirs(rec)` | evidence is cited BOTH as `tests/evidence/*.log` and as timestamped directories; `cited_dirs` returns only those that exist |
| `scan_log(path) -> (signatures, stats)` | signatures are strings, some suffixed `:<token>`; `stats` carries `bytes`, `lines`, `span_s` (None when unparseable), `evidence_dirs` |
| CLI | `--status` selects the bucket (default `FIXED AND VERIFIED`), `--verbose` prints `stats` |

**Invariants**

- **`SCREENED_CLEAN` is a screening result, not proof.** Absence of a signature
  is not presence of a measurement, and the tool prints that on every run.
- A record whose evidence is a directory only goes to `DIR_EVIDENCE_ONLY`, never
  to clean or dirty: directories hold raw captures, not a chain narrative, so the
  log-shaped signatures do not apply and pretending either verdict would be false.

**Pitfalls hit while writing it — both were vacuity bugs in the vacuity detector**

- `INSTANT_DONE_WITH_PASS` took the first and last **compact** `20260829T124123Z`
  stamp anywhere in the file. Chain logs write START/DONE in ISO form
  (`2026-08-29T12:39:54Z`) and use the compact form only inside evidence-directory
  names, so it measured the gap between two directory stamps and called an
  8-minute run instant. It flagged five records; all five were wrong.
- Following only `.log` paths made 79 of 106 closed records look like they cited
  nothing. Much closure evidence is a directory.
- Two heuristics were tightened after hand-verification: a refusal annotated
  `expected`/`by design` within two lines is skipped (before/after chains
  deliberately fail their pre-fix arm), and `got=0 want=N` counts only when the
  line is not already prefixed `FAIL`/`ERROR` — a gate that fired and scored the
  run down is the system working.

**Cross-subsystem**

- Both read `tests/criteria/OPEN_DEFECTS.json`, so they share the RULE-8 schema
  with `tools/ledger_validate.py`; neither writes it.
- `harness_lint.py` lints `tests/` and `scripts/`, so a new harness there is
  gated by it. It is deliberately **not** wired as a board criterion yet: adding
  a row changes the board's shape, and `D-FOREIGN-REPLAY-UNGATED-IMAGES`
  criterion (2) requires "a board clean apart from the policy cell", so altering
  the row count while that evidence is being collected would change the
  acceptance criteria mid-verification.

## 2026-09-04 (sess487): the create-pace evidence parsers

Three read-only parsers over per-node kernel logs (`kernlog_<node>.gz` in an
evidence directory, or explicit files). None touches the rig; all refuse to
print numbers when no input carried the probe.

- `tools/p132_attribute.py` — the `P132-CREATE` decomposition. Fields are parsed
  by name (`KV` regex), so the 0.69.4 sub-phases `rfr_ms`/`icr_ms`/`mrg_ms`/
  `cc_ms` appear automatically; `other_ms` is pre_ms minus every stamped
  sub-phase present (`SUBPHASES`), so on pre-0.69.4 lines it carries the whole
  unattributed span and on 0.69.4 lines only what the new stamps do not cover.
- `tools/p132_phase_summary.py` — the same rows split into IN-TENURE creates
  (`dlk_ms < 5`, the node already held the directory grant) and first-in-tenure
  ones, with per-field mean/p50/p90/max and share. This is the table that says
  what one create costs while the directory EX is held; it imports
  `p132_attribute.collect()` so both tools agree on what a valid line is.
- `tools/dirtenure_summary.py` — `P483-DIRTENURE` tenures: per node/parent K
  (creates per grant tenure), `gap_ms` (wait between tenures), `wall_ms`,
  `endsrc`, and fleet-wide histograms for the shared parent (the ino present in
  every node's log with the largest create volume).

Pitfall found with the third: before 0.69.4 `wall_ms`/`mean_ms` on every
tenure line read 0 because the tenure probe derived its clock from the
create-cost probe's `p132_t0`, which is stamped only when `mxfs.create_cost_ms`
is armed. A zero there is the clock being off, not tenures being free; 0.69.4
stamps the clock on every clustered create.

Fourth, sess487: the tenure and phase tools were first run on evidence already
on disk (the 04:37Z board's crash_consistency kernlogs and chain 128's), which
resolved the "K≈12.5 vs K≈1" discrepancy in `D-32NODE-SHARED-DIR-CREATE-PACE`
at zero rig cost. Check what an existing evidence directory already answers
before queuing a chain.

Fifth, sess488: `tools/scratch_build.sh <label> <marker>` returned 1 on three
clean builds because its `tree_objs=$(grep -c … || echo 0)` produced "0\n0"
(grep -c prints 0 *and* exits 1 on no match, so the fallback fired too) and the
final `[ "$tree_objs" = 0 ]` failed; fixed in the tool (no fallback). The
`FROZEN … marker=ok tree_objs_in_mod=0` line remains the verdict to read. A
reordering-only change has no new string to use as a marker: pass the newest
string the build must contain and confirm the srcversion differs from the
previous freeze instead.

Sixth, sess489: **`tools/ccph_timeline.py <capture-dir>`** — per-node phase
timeline of one crash_consistency run from the `mxfs-CCph rank=R PHASE=<name>`
kmsg markers the test stamps (start, barrier-ready-done, datawrite-done,
md5write-done, barrier-written-done, dropcaches-done, verify-done,
count-done, barrier-done-done). Reads `kernlog_test*.gz|.txt` or the chain
sweeps' `ctx_test*.gz`, keeps each node's LAST `PHASE=start` and the first of
each later marker after it, and prints seconds from that node's start, then
the fleet distribution of `write_phase_s` (start→md5write-done: the 100
O_SYNC shared-directory creates) and `verify_phase_s` (dropcaches-done→
verify-done: 400 cold reads), and where every node's run ended. It is what
turned the two chain-139 in-chain failures into a number (write phase p50
64-82 s of the 90 s budget, verify ~10 s) and it is the check that the row's
budget went where sess481 said. Timestamps are parsed from the bracketed
`Fri Sep  4 06:57:55 2026` prefix (or raw dmesg seconds); both are monotonic
inside one capture. A node with no `PHASE=start` in the capture is listed as
such, not skipped. Read it with the P132 count (`p132_phase_summary.py`): a
phase timeline of a run whose creates were overwrites is a timeline of the
wrong workload (ccmemory trap-rerunning-a-create-workload-on-the-same-mount).

## 2026-09-04 (sess493): `chk_mxfs -v` names the flag binding of a re-flagged identity; `scratch_build.sh` cleans up

- `decode_hb_identity` (`tools/chk_mxfs.c` ~2259) used to print an identity line only when the crc validated against the record's CURRENT flags, and nothing at all for a zeroed block. A recovery GUARD is the victim's record copied byte for byte with only `flags` moved and the identity crc never re-bound (`dlm/disklock.c` recovery_begin / the fence intent), while a RETIRE_PENDING record IS re-bound (`hb_ident_rebind`). So on a guard the victim's own key sat in the record and the checker said nothing — which is exactly how D-0493 (whole-cluster restart refused after a quarantined victim: `P-BOOT-KEY-UNCLASSIFIED ... carry no identity block`) hid on the platter. Now a crc mismatch is re-tried with `flags` = ACTIVE (1) and WITHDRAWN (2) and reported as `identity ... crc binds as ACTIVE (record re-flagged to 3; the victim's own identity, carried byte for byte)`; a zeroed block on a GUARD/RETIRE_PENDING record prints `identity ABSENT (zeroed block)`; a block binding to no flag value is the old `err`. The bootstrap's survivor scan (`dlm/bootstrap.c` ~1145) still validates only against the current flags — the checker now shows what a classifier could rely on, it does not change what the kernel accepts.
- `tests/sess488_ailpin_fleet_umount.sh` runs the TREE `tools/chk_mxfs -v` (falls back to the frozen one) plus `sg_persist --in -k` and `recov_forge dump 0` on test2 before its remount stage and keeps the output as `platter_before_remount.txt`. Rebuild with `make tools` before a leg that needs the new line; the frozen `*_frozen_*/tools/chk_mxfs` copies predate it.
- `tools/scratch_build.sh` removes its scratch copy after the `FROZEN` line (`KEEP_SCRATCH=1` retains it) and copies `build_modules.log`/`build_tools.log` into the frozen dir. The copy is 600-700 MB on clyde's ROOT filesystem — the one carrying the LUN image and the guest images — and eleven forgotten copies (15 G) were the sess492 preflight refusal at 88 %.
- `tools/recov_forge <dev> dump 0` prints a GUARD record's descriptor and outcome (victim tuple, stage, QUARANTINED, domain/ag_mask, crc) but not its identity block; `chk_mxfs -v` is the identity reader. Neither binary is in the frozen tools set — use the tree build (`/src/mxfs/tools/...` on the nodes over NFS).

## 2026-09-04 (sess496): two evidence parsers

- `tools/p13_release_shape.py --files <list of kernlog_*.gz paths> [--workers 8] --out <json>`: one streaming pass per gzip log; for every `P-ICD-TENURE-REFUSE` / `P13-SFPARENT-DURABLE-FAIL` event it records the nearest preceding `P70-BP ENTRY` (mode/state/qsrc/held_ms), whether `P15-ORPH-PROCEED` preceded it, the following `P146-RELDUR` (in_ail/pin/ili_fields/wrote/rerr), `P51-REL`, `P-RELFLUSH-NOTENURE`, any `P228-RELBAR` / `P220-UNLOCK-LEDGER-OPEN` / `P188` / `P146V` / `P9-ICD-FAIL` marker, and the first reload-family line (`P56-RELOAD-MERGE` resurrect=, `P-RELOAD-IDENTICAL`, `P-SFDIR-REVERT` counts). Output JSON `{files_listed, results:[{file, n_lines, events:[...]}], errors}`. It is the tool that disposed D-DIR-INODE-DURABLE-BARRIER-FAILS-ARM-UNCLASSIFIED (680 events, all orphan releases of clean dinodes). Wall ~2.5 min for 1892 files on NFS.
## 2026-09-05 (sess513): the TCP authority-ledger census dumps a page's records

- `tools/tauth_page_auth.py <dev> <base_bytes> [--page P ...] [--entries]`
  (region base = `P-TAUTH-LEDGER-OPEN ... base=`, 239116288 on the QNAP LUN):
  `--page` prints the page's authority tuple as before; `--entries` adds every
  non-EMPTY `struct mxfs_tauth_entry` of the winning copy — state
  (EMPTY/ACTIVE/FREE/UNKNOWN), res_type/ag/ino, `ex=<node>/<inc>` slot/mode,
  and the shared-holder SLOT bitmap (`holders=[1]`, one bit per heartbeat
  slot, no incarnation — a predecessor's bit is indistinguishable from the
  current occupant's, the D-...-0908 mechanism). Layout constants mirror
  `include/mxfs/mxfs_tauth.h`: 128 B page header, 31 × 128 B entries; the
  entry fields decoded are at offsets 0 (state u16, type u8, shared_mode u8,
  ag u32), 8 (ino), 24 (holders), 40 (ex_node u32, ex_slot u16, ex_mode u8),
  48 (ex_inc). The crc is still not checked. Needs root on clyde (`sudo -n`,
  the LUN is visible via `/dev/disk/by-path/*qnap*lun-0`). Purpose: after a
  page is taken over for the bootstrap node itself (`P-TAUTH-PAGE-MINE
  via=takeover`) and handed on by a view change (`P-TAUTH-HANDOFF ...
  why=view-change`), list what the receiver will import — the D-0906
  hand-on hole is real only if the departed incarnation's records are still
  on the page at that moment. Run it BEFORE the next prep (mkfs zeroes the
  region).

- `tools/xfs_dahash_collisions.py --cc <T> <N>` generates the crash_consistency name set (`node{R}_f{i}` and `.md5`, R≤T, i≤N); without `--cc` it reads names from stdin. Implements `xfs_da_hashname` (4-byte rolling hash, `rol32` by 28/21/14/7) and prints the bucket-size histogram plus the share of names in buckets ≥2/5/10/20. A node-format lookup reads one data block per leaf entry sharing the searched hash, so this bounds the reads a hashed lookup can legitimately issue (the cc set: max bucket 2).

## 2026-09-05 (sess517): chk_mxfs -v prints the inode-to-AG geometry

- `tools/chk_mxfs -v` superblock detail line (the `info()` after the
  `XFS superblock ....` verdict, `tools/chk_mxfs.c` ~2606) now reads
  `sectsize=512, inodesize=512, inopblock=8, agblocks=N, agblklog=L, inopblog=I`
  (it parsed all three values already; they were never printed).  A harness
  maps an inode number to its allocation group with `agno = ino >> (agblklog +
  inopblog)` — the only way to do it on an MXFS volume, because the geometry
  ioctl is not wired on the mount (`xfs_io -c statfs` and a raw
  `XFS_IOC_FSGEOMETRY` both answer ENOTTY) and `xfs_db` reads the wrong
  sectors behind the envelope.  First consumer: the death oracle's AG-mask arm
  (`TDR_AGMASK_INJECT=1` in `tests/tcp_death_replay.sh`, D-0910), which
  classifies each probe directory as inside or outside the imported
  quarantine `ag_mask`.  Read-only (`-n`) on a live LUN is fine for this line;
  the nodes run the tree binary over NFS, so `make tools` on clyde is what
  updates them.  `make tools` prints the module version from `VERSION` into
  the tool; the module's srcversion does not change with a VERSION bump.

## sess559 — reading the heartbeat slot table on a target that refuses FUA reads

- `tools/disklock_hb_dump.py <dev> [disklock_offset_bytes] [--all]` — the 64
  heartbeat records (dlm/disklock.h `struct mxfs_disklock_heartbeat`, 512 B
  each, one per slot) decoded with plain pread: slot, magic, flags
  (EMPTY/ACTIVE/WITHDRAWN/RECOVERY_GUARD/RETIRE_PENDING), node, fs_gen,
  timestamp_ms, epoch (the incarnation), lock_count, and the sess438 identity
  block's pr_key / boot_uuid prefix / key_gen.  `tools/recov_forge <dev> dump`
  reads each record through a READ(16) FUA CDB, which the QNAP TS-453 Pro
  refuses (sense 05/24/00), so on that rig this is the only slot-table view;
  run it on a node (the LUN is not visible from clyde).  The default offset
  67117056 is what every mkfs_mxfs of this era produced; `chk_mxfs -v` prints
  `disklock_offset=` and `tauth_offset=` (the latter is the base
  `tools/tauth_page_auth.py` needs).  Read-only.  Pitfall it exposed: the
  chk_mxfs `slot N: clean (owner=0)` lines are the JOURNAL slice headers, not
  the heartbeat table — a LUN whose journal slots all read clean can still
  carry dead ACTIVE heartbeat records that hold every later mount
  (D-0928); this dump is the view that shows them.  Cross-subsystem: the
  layout constants mirror dlm/disklock.h (record 512 B, 64 slots, identity
  block at byte 360 with pr_key at 400); a carve of that struct must be
  mirrored here.
- sess560: every RECOVERY_GUARD record now prints a second, indented `desc`
  line decoding `struct mxfs_recov_desc` (120 B at record byte 40, the
  `recov` arm of the flags-interpreted union): stage name/number, victim
  node/epoch, victim_fs_gen, flags, owner node/epoch (`none` for
  MXFS_RECOV_OWNER_NONE 0xFFFFFFFF), owner_slot/term, stage_seq, slice
  idx/count, fence_kind name/number, resv_type, fence_victim_key, prover
  node/epoch, fence_term, pr_gen.  The crc is not verified (plain census
  view).  This is the line that says WHY a slice is not takeable: a
  descriptor at stage FENCING names the prover incarnation that must be
  REVOKED (dlm/v5_mount.c v5_incarnation_state) before another node may take
  the attempt over — the s561 LUN showed slots 0-5 at FENCING with provers =
  the two incarnations the joiners had just certified fenced (kind 21), and
  slots 6/7 at FENCED, owner none (D-0931/D-0932).  Fence-kind and stage
  names mirror dlm/scsipr.h `enum mxfs_fence_kind` and dlm/disklock.h
  MXFS_RECOV_STAGE_*; a new kind or stage must be added to the two dicts.

## 2026-09-10 (sess574): two instruments for things that were invisible

### `netconsole_listen.sh` — the only channel that can carry a guest panic

Every test node is configured at boot to netconsole its kernel log to clyde
(`remote IPv4 address 192.168.120.1, remote port 6666`), and **nothing listened
on that port until this session**. Every datagram any guest ever sent while
dying was discarded by the host.

That is not a redundant channel — on this rig it is the *only* one:

- a node that panics reboots, and its `dmesg` restarts at the new boot;
- `journalctl --list-boots` on these guests did not retain the crashing boot at
  all (test1's list held two boots from ten weeks earlier plus the post-crash
  boot);
- `/sys/fs/pstore` **and** `/var/lib/systemd/pstore` are both empty on these
  guests, so systemd-pstore drains nothing. An empty `/sys/fs/pstore` is not
  evidence that no crash occurred;
- `/var/log/libvirt/qemu/<node>.log` records only *hypervisor*-initiated
  destroy/start. A guest that resets itself leaves no entry — so an absent
  libvirt event proves the reboot came from inside the guest, and nothing more.

```
tools/netconsole_listen.sh start|stop|status|tail [n]
```

Log: `tests/evidence/netconsole.log`, appended, never truncated. It parses
nothing on purpose — messages arriving mid-panic are the last thing that should
be filtered by anything clever.

**Guest `console_loglevel` is 1.** Consequences, both of which have already
caused a wrong reading:
- a plain `echo x > /dev/kmsg` (level 4) does **not** appear. Testing with one
  and seeing nothing is not a broken listener — use `echo '<0>PROBE'`;
- the log therefore cannot flood with ordinary probe output, and a kernel panic
  (KERN_EMERG) does arrive.

One MXFS line is emitted at emergency level and so shows up here in normal
operation: `MXFS mount recovery: slice slot=N NOT replayed (-1)`. It is
**transient** — printed while the fence certificate is still being sealed, with
the retry succeeding a second later — so its presence is not by itself a
failure.

### `sole_survivor_audit.py` — the static census of single-node fast paths

`mxfs_v5_dlm_is_single_node()` means "alone right now";
`mxfs_v5_dlm_sole_survivor()` means "has had a peer during this mount and is
alone now". Guards that ask the first when they need the second switch
themselves off exactly when a departed peer's residue is on the platter.

```
tools/sole_survivor_audit.py            # guards that skip work, by file+function
tools/sole_survivor_audit.py --inverted # the !is_single_node() sites too
tools/sole_survivor_audit.py --csv      # diffable
```

Measured 2026-09-10: **77 guards skip work when alone**, out of 394
`is_single_node()` references, against **10** `sole_survivor()` references. The
394-vs-10 figure quoted in earlier sessions counts every reference including
instrumentation; 77 is the number that can actually hide a defect, and it is the
one to work against.

**It is also a gate, not only a report.** `--baseline` writes the reviewed
inventory to `tests/criteria/sole_survivor_sites.json`; `--check` exits 1 if a
guard exists that the inventory does not account for, and the board row
`tests/tooling/guard_census.sh` carries that verdict. Keyed by (file, function),
never by line, because a line-keyed baseline fails on unrelated edits and gets
switched off within a week — which is how the two previous closures of this
class ended up unenforced.

**Fail-closed:** a missing inventory, tool or `python3` is a FAILURE. An absent
inventory is not an empty one.

**PITFALL, found by fixing it:** instrumenting a guard puts a probe line between
the test and its `return`, and a next-line-only scan then stops seeing the site.
The count fell 77 -> 70 the instant seven guards were instrumented — a safety
census silently shrinking in the one direction it must never move. The scan now
steps over probe/comment lines and stops at a closing brace or at any real work.
If this number ever drops, suspect the census before believing the tree.

**Re-baselining to clear a red is the same act as widening a timeout to make a
test pass.** Classify the new site first.

#### Full API

```
tools/sole_survivor_audit.py                     # grouped report
tools/sole_survivor_audit.py --inverted          # the !is_single_node() sites
tools/sole_survivor_audit.py --csv               # file,line,function,shape,exit
tools/sole_survivor_audit.py --check             # the gate; exit 1 on a new site
tools/sole_survivor_audit.py --baseline          # re-record, PRESERVING classes
tools/sole_survivor_audit.py \
    --classify 'file::func' <class> 'reason'     # repeatable; writes and exits
tools/sole_survivor_audit.py --inventory PATH    # point at a different inventory
```

`--root` defaults to the repo the script lives in, so a clone anywhere audits
ITS tree.

#### The inventory is a work queue, not a tally

`tests/criteria/sole_survivor_sites.json` holds, per `(file, function)` site:
`guards` (how many bare skips), `class`, and `note` (the reasoning). A count
alone says the class is 77 wide and nothing about which of them anyone has
thought about — which is how it stayed open through two closures.

Classes, from the sess574 RULE-5 ruling. **The axis is not performance vs
correctness**; it is *what fact makes the skipped work unnecessary, and what
stops that fact changing mid-operation*:

| class | meaning |
|---|---|
| `epoch` | transient coordination, elidable ONLY while an exclusion against peer admission is HELD for the whole operation. A bare "am I alone" boolean is a TOCTOU observation and does not qualify. |
| `durable` | leaves state a future or rejoining peer can observe. Maintain regardless of membership, or convert explicitly before admitting a peer. |
| `recovery` | depends on the departed peer's disposition (clean handoff / unfenced / fenced-but-unrecovered / recovered per-AG), not on member count. Often scope-specific. |
| `instrument` | a probe. Costs measurement, not correctness — recorded anyway, because an unreachable probe is exactly how D-0949 stayed invisible. |
| `unclassified` | nobody has decided yet. The honest default. |

#### Two more pitfalls, both found by hitting them

- **Converting a guard removed it from the queue.** Rewriting a site into a
  nested decision, or deleting the membership test outright, drops it from the
  census — and a live-only inventory silently discards the classification *and*
  the reasoning. The two best-understood sites left the census the moment they
  were touched. Converted sites are now retained with `guards: 0`, class and
  note intact, and `--check` reports them as `note ... is gone (converted or
  removed)`.
- **`--classify` checks the TREE, not the census.** The census's definition of a
  guard is narrow (a *bare* single-node skip), but the sites most worth
  classifying include converted ones. So the existence check is "the file exists
  and contains that function name" — which still refuses a typo, because a
  classification recorded against a typo reads as a decision while the real
  guard stays unclassified.

#### Closure criterion for the class

All sites classified **and** the ambiguous predicate removed — not individual
bug fixes. Until then no guard conditioned on `sole_survivor()` covers the
class, only the within-mount case (D-0956: `ever_multi` is per-mount, so even
that is false again after a remount).

The script deliberately ranks nothing. A guard is dangerous when the work it
skips has consequences that outlive the membership change; it is fine when the
work it skips is a lock or a message a rejoining peer would force to be
re-taken. It finds them; a reader decides.

---

## 2026-09-10 (sess575): `defects.py` and `criteria.py` — the queue and the board become writable

Two tools ported from another project of the user's and adapted to this tree. Both replace
read-only readers (`defects.sh`, `showstat.sh`) whose data could only be changed by hand-editing
megabytes of JSON — which is why ~80 one-off `tools/ledger_*.py` files exist, one per defect, each
written to make a single edit the reader could not perform.

**Both are populated, and as of 2026-09-10 (sess576) they are the only queue and the only board
in this tree.** `tools/defects_import.py --apply` moved the 95 OPEN records into
`data/defects.json` and `tools/criteria_import.py --apply` moved 4 categories / 44 tests /
601 cells into `data/criteria.json`. The 182 closed dispositions did not come across — that is the
design, a queue is not an archive — and they are preserved in the archived snapshot.

**The old chain is ARCHIVED to `/src/archive/mxfs/`** (see its `README.md` there): `defects.sh`,
`showstat.sh`, `tests/suite/open_defects.sh`, `tests/criteria/OPEN_DEFECTS.json` (+ `.prev`,
`.backup`), and all six `ledger_*`/`hook_ledger_guard` tools. What was unwired with it:

| was | now |
|---|---|
| `.claude/settings.json` PostToolUse hook -> `hook_ledger_guard.sh` | no `hooks` block at all |
| `.claude/settings.json` allow `Bash(./showstat.sh:*)` | `Bash(tools/defects.py:*)`, `Bash(tools/criteria.py:*)` |
| `open_defects` row in `tests/suite/manifest` | replaced by a comment saying why it was retired |
| `open_defects` test in `criteria.json` AND `data/criteria.json` | removed from both — the board is 29 rows at 2/tcp, was 30 |
| `./showstat.sh` in `run.sh`, `scripts/caw_ladder_fua.sh`, `tests/suite/run_suite.sh`, `README.md` | `tools/criteria.py` |

**CLOSED in 0.77.0 (sess576): the harness no longer writes a board file.** `run.sh`,
`tests/suite/run_one.sh` and `scripts/dlm_scaling_diag.sh` all go through `tools/criteria.py`;
`criteria.json`, its four rig variants, `scripts/gen_criteria.py` and `scripts/matrix_check.py`
are archived. `criteria.py` gained the operations that made this possible:

| operation | why it exists |
|---|---|
| `update --reason TEXT` | WHICH check failed. `flake_count` reads it to separate a real fault from the rig failing to form; the import had dropped it from the live cell. |
| `update --calibrate` | a run establishing a budget that does not exist yet records elapsed without being scored against a number nobody set. |
| `pending <id...> --at C --run-id R` | mark what a run intends to run; pushes the outgoing verdict to history first. |
| `executing <id> --at C --run-id R` | stamp the one test in flight, so a death can tell in-flight from never-reached. |
| `finalize [--run-id R]` | leftover markers -> ABORTED (was executing) / NOT RUN (never reached). No id = heal every stale marker. |
| `rows` | the matrix as TSV: phase, transport, id, coord, min_nodes, max_nodes, budget_s, budget_scale. |

**Two bugs this fixed.** `run.sh`'s `finalize_pending` and `run_one.sh`'s recorder both replaced
the cell wholesale and **dropped `history`**, so a died run or a single-test invocation erased the
evidence that a criterion was intermittent. `write_cell()` pushes history before every write, so
neither can recur.

**The one thing that stayed in the harness** is the SCALED budget comparison — `run.sh` is the
only place that knows the per-node-count scaling. `criteria.py` also enforces the criterion's own
`budget_s`. Every `budget_scale` is currently `flat`, so the two numbers are identical; **if a
non-flat scale is ever introduced, `criteria.py` must be taught the scaled budget** or it will
fail a run the harness passed.

**Not migrated (they read empty, not wrong):** `tests/d3_dirring.sh`,
`tests/degraded_member_cascade.sh`, `tests/net2/gate3_cawsanity.sh` still parse the archived
`categories[].tests[].runs[]` schema. One-off session harnesses, not the board path.

### `tools/defects.py` — what is broken and still needs work

Data: `data/defects.json`. **Sole reader and sole writer**; hand-editing the JSON is how two
sessions end up disagreeing about what is open.

**It is a work queue, never an archive, and it has NO `status` FIELD.** A fixed defect is `remove`d
and the fix becomes a `CHANGELOG.md` entry; `--why` on `remove` is mandatory and prints the entry
to paste. This is the structural difference from `OPEN_DEFECTS.json`, which carries 168 `FIXED AND
VERIFIED` + 14 `DISPROVED` records as history — 2.8 MB that no session can load.

**Configuration reach — the two fields added for this project:**

| field | means | default |
|---|---|---|
| `nodes` | the SMALLEST cluster the defect has been observed on | `1` |
| `dlm` | transport the evidence is on: `any`/`xfs`/`caw`/`cawd`/`cawp`/`tcp` | `any` |

`blocks(entry, nodes, dlm)` is true when `entry.nodes <= nodes` and the transport matches or is
`any`. So a 32/caw defect does not block a 2/tcp release, and the defaults (`1/any`) block
**every** release — an unclassified entry holds everything up rather than quietly sliding out of a
gate. Narrowing these fields is a claim about reach that needs evidence; it disposes of nothing and
the defect stays in the queue.

```
tools/defects.py                          the queue, severity order, one line each
tools/defects.py -d                       the same queue with each one's next step
tools/defects.py --at 2/tcp               only what blocks that release configuration
tools/defects.py -s critical              filter by severity
tools/defects.py show <id>                one entry in full (id, or unique substring)
tools/defects.py add    -s SEV -m "..." [-N 2] [-D tcp] [-n next] [-w evidence] [--id ID]
tools/defects.py update <id> [-s|-m|-n|-w|-N|-D]
tools/defects.py remove <id> --why "what was measured and what it said"
tools/defects.py --json                   the queue as JSON
```

Ids are minted from the first 9 words of the summary (`D-DIALLOC-VALIDATOR-TREATS-...`), collision
-suffixed. `find()` accepts a unique substring, so `defects.py show DIALLOC` works.

### `tools/criteria.py` — what MXFS must achieve

Data: `data/criteria.json`. Sole reader and sole writer.

**The per-configuration axis is the whole adaptation.** The source project proved each criterion
once per character class; MXFS proves each one per `<nodes>/<transport>` — which is what
`criteria.json` already does, keyed `runs["2/tcp"]`, `runs["32/caw"]`. So `per_class`/`CLASSES`
became `per_config`/`CONFIGS` one-to-one, and a criterion is `UNKNOWN` for every configuration
absent from its map. A board that hid the empty columns would read green; that is exactly what
`D-MATRIX-UNMEASURED` is about, and `--gaps` now reports never-run columns as gaps alongside
missing detectors.

**Both tools take the configuration the way `showstat.sh` always has** — `defects.py 2 tcp`,
`criteria.py 2 tcp`, `2/tcp` equivalently, in any argument position. `lift_config()` rewrites it to
`--at` before argparse sees it, skipping flags and their values (so `-s major 2 tcp` is a severity
and a cluster, not a cluster twice) and stopping at a subcommand name, which is why a leading
config can never shadow `show`/`add`/`update`/`remove`. `defects.py 2` alone means every transport
at that size; `criteria.py 2` alone is refused, because a cell is one exact column and picking one
of five silently is how a tcp green gets read as a caw one.

**`criteria.py` reproduces `showstat.sh`'s FLAKY rule exactly** (user directive, sess43, two
rounds), and it must stay that way:

- FLAKY = the test itself detected a fault on a formed cluster inside the last `FLAKE_WINDOW` (11)
  runs, current cell plus its `history`. It is not green and does not count toward the bar.
- **`FAIL` only, never `ABORTED`.** An `ABORTED` cell says the run died mid-test and the result is
  UNKNOWN; counting it makes "we never found out" indistinguishable from "a fault was detected".
  `ag_strand_repair` at 2/tcp is the case that proves it — one `ABORTED` reading "run died while
  this test was executing", and it is a PASS, exactly as `showstat.sh` has it.
- Failures whose `reason` matches `RIG_NOISE` (`pre-assert|NO_TERMINAL_RECORD|run was killed|prep
  fail`) are rig formation, not MXFS faults, and never count.
- `prep_cluster` and `open_defects` never flake at all.

**`applies()` filters the board to what is runnable in a configuration**, from the criterion's
`transport` + `min_nodes`/`max_nodes`. Without it the 2/tcp board printed 44 rows against
`showstat.sh`'s 30, padding it with single-node tooling checks and a CAW-only criterion as
`UNKNOWN` columns nothing will ever fill — which buries the genuinely unmeasured ones. Verified
equal: 30 rows, 4 FLAKY, both tools.

**Four behaviours that exist because of failures this project has already had:**

1. **A time budget is a performance assertion.** `update -e 400` against a `budget_s` of 120
   records `FAIL` — even with zero errors, even when the caller passed `-s PASS`. The board cannot
   be the place where "it finished eventually" becomes green, and widening a budget to make a cell
   pass is the edit this file exists to make visible.
2. **A cell records the `build` it was earned on.** Read back against a different `--build` it is
   `STALE`, not `PASS`. Stale-build false greens are a recurring trap on this rig.
3. **A status with no `--at` is refused.** Recording a measurement against the criterion as a whole
   is how one column's green gets read as the whole matrix.
4. **`FLAKY` paints but never counts as green.** A cell that passes now but whose own test detected
   a fault recently is an unrooted defect, and the queue is where it belongs.

```
tools/criteria.py                         the board, rolled up across every configuration
tools/criteria.py --at 2/tcp [--build S]  one configuration's column
tools/criteria.py -v                      add each criterion's requirement and why
tools/criteria.py --gaps                  no detector / detector file absent / never-run columns
tools/criteria.py show <id> [--build S]   every configuration's cell for one criterion
tools/criteria.py add    -i ID -r "req" -d "detector" [-b BUDGET_S] [-p PHASE] [--why] [--source]
tools/criteria.py update <id> --at 2/tcp -s PASS -m "..." [-e ELAPSED_S] [--build SRCVER]
tools/criteria.py update <id> [-r|-d|-b|--why]        (no --at: edits the criterion, not a cell)
tools/criteria.py remove <id> --why "no longer something we must achieve"
```

`remove` here means "no longer required", **never** "now passes" — a green taken off the board
cannot regress visibly. That is the opposite of `defects.py remove`, and the two must not be
confused.

### `tools/defects_import.py` — the one-shot migration

> **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/`. It ran; the
> migration is done; its source file is in the archive too. Kept below as the
> record of what the field mapping was.

Ran once, 2026-09-10: 277 records in, 95 `OPEN` out, 182 closed dispositions left behind. It
**never writes the source**, refuses to run into a non-empty queue, and is report-only without
`--apply`.

`next` and `next_step` are the same field under two names in the old schema (83 and 29 records
respectively) and are merged into `next`; a tool reading only one of them would find half the
queue's next steps missing. `mechanism`, `containment`, `found` and `related` have no slot in the
queue's schema but carry the evidence a session needs, so they ride along verbatim —
`defects.py show` prints any field it does not recognise rather than hiding it. `status` is
dropped: membership in the queue IS the status.

**Reach is not imported.** The old schema has no field saying which configuration a defect was
observed on. A keyword sweep over the prose is a heuristic and not an adjudication — a record whose
text says CAW may still reproduce over TCP — so every record arrives at `1/any` and is narrowed one
at a time against its own evidence. As of the import, 1 of 95 is narrowed.

### `tools/criteria_import.py` — the board migration

> **ARCHIVED 2026-09-10** → `/src/archive/mxfs/tools/`. It ran; the
> migration is done; its source file is in the archive too. Kept below as the
> record of what the field mapping was.

Ran 2026-09-10: `criteria.json`'s 4 categories / 44 tests / 601 configuration cells into
`data/criteria.json`. `runs{"2/tcp": …}` becomes `per_config`, which is the same shape under a
different name. Source never written; refuses to run into a non-empty board.

**`history` and `reason` come across because the flake signal lives in them.** Importing only each
cell's latest status would turn `fence_during_write` at 2/tcp green and lose the six genuine
failures behind it in eleven runs — the one fact about that cell that matters.

**Requirements are read from the detector, not invented.** The old board records whether a test
passed but never what it requires, so requirement text is lifted from the leading comment block of
`tests/suite/<name>.sh`, where it has actually been written down all along
(`fence_during_write` → "sustained concurrent cross-node writes must NOT trigger spurious fencing
or lose committed data"). 13 of 44 tests have no script: they get no requirement, no detector, and
`--gaps` reports them. Writing a plausible requirement for those would be inventing the
specification from the implementation.

`--gaps` currently reports 23 entries.

### Invariants

- **Criteria and defects are different lists and must stay apart.** A criterion is the
  specification: permanent, and it can regress. A defect is transient and leaves when fixed.
  `open_defects` as a board criterion was the defect queue wearing a criterion's clothes, which is
  why it could never go green. Ask `defects.py --at 2/tcp` what blocks a release; ask
  `criteria.py --at 2/tcp` whether the requirements are met.
- **Both tools are the only writer of their file.** Anything that needs to change data goes
  through the CLI, not through an Edit of the JSON.
- **Unmeasured is never a pass, in either tool.** An unclassified defect blocks every
  configuration; an unmeasured criterion column is `UNKNOWN` and is called out in the verdict.

### Known pitfalls

- **`data/` did not exist and both tools create it on first write.** Created under a root-owned
  session it lands `root:root` and the user cannot then add a defect. `chown steve:steve data`.
- **`defects.py | head` raised `BrokenPipeError`** until `SIGPIPE` was restored to `SIG_DFL` at
  import in both tools. A 95-row queue is always piped, so this was a traceback on nearly every
  real invocation.
- **Top-level options must precede the subcommand** (`criteria.py --at X show ID` fails).
  `--build` is duplicated onto the `show` subparser for that reason; `--at` is not.
- **`criteria.json` is 636 KB across 4 categories / 44 tests / 26 run keys**, and
  `OPEN_DEFECTS.json` is 2.8 MB / 277 records. Never load either whole to answer a question about
  it; project the fields with `json.load` or use the readers.
- **This very doc must be updated with the Edit or Write tool, never `cat >>` or a `python3`
  heredoc.** The awareness tracker is a PostToolUse hook on Edit|Write, so a shell append writes
  the content but registers nothing, and the Stop hook keeps reporting the subsystem stale however
  complete the prose already is. Both sess575 updates were written that way and both were invisible
  to it.

### Cross-subsystem dependencies

| Subsystem | Dependency | Status |
|---|---|---|
| tests | `tests/suite/open_defects.sh` reads `OPEN_DEFECTS.json`, not `data/defects.json` | unchanged; the new queue gates nothing yet, and the two now diverge the moment either is edited |
| tools | `tools/defects_import.py` — one-shot, refuses to merge into a non-empty queue | run once, 2026-09-10; source ledger never written |
| tools | `ledger_validate.py` / `hook_ledger_guard.sh` enforce a `status` + date schema the new design has no field for | both still live; they and the CLAUDE.md text that mandates them are the pending decision |

## The slice lifecycle region (0.88.0, `docs/slice-lifecycle.md`)

The envelope gained a region after the bootstrap record:
`[super][journal][disklock][rman][tauth][prkey][bootstrap][slife 32 KiB][XFS data]`,
flagged `MXFS_FORMAT_F_SLIFE`, offsets `slife_offset`/`slife_size` in the super,
protocol gen 20.  One 512 B `struct mxfs_slife_record` per log slice (the struct comes
straight from `include/mxfs/mxfs_super.h`; the tools do not mirror it).

- **`mkfs_mxfs`**: the region's offset is fixed before the native format (it is sized for
  every heartbeat slot, `MXFS_SLIFE_BYTES`), zeroed in step 3a'''', and the records are
  written in step 4a, AFTER `format_xfs_native`, because that is what settles
  `log_node_count` (auto-size picks a power of two ≤ 32).  Every record is
  `INIT_REQUIRED`, bound to the new uuid, crc32c(~0U, record with crc=0) — the kernel's
  formula.  Records beyond the slice count stay zero (UNFORMATTED) and are never consulted
  because no slot ≥ the slice count is admitted.  The layout print has a `Lifecycle:` line.
- **`chk_mxfs`**: the super check requires the region to hold `xfs_log_node_count` records,
  sector-aligned, inside the device, and gen ≥ 20 without the flag is an error; the region
  is in the overlap table (now 8 entries); `check_slife` runs after `check_bootstrap` and
  prints `Slice lifecycle ......... OK (N slices: a INIT_REQUIRED, b ZEROING, c READY, d
  invalid)`, every record with `-v`, and every ZEROING record always (a claimant's zero
  that never reached READY).  `--upgrade-protogate` refuses a volume without the region:
  only mkfs can lay it out.
- **Pitfall**: `make tools` after any change to `MXFS_PROTO_GEN` or the super layout, or
  the nodes (which run the tree's binaries over NFS) format with the old generation and
  every mount is refused.  The module does not embed `VERSION`; the tools do, as a string.

## chk_mxfs directory-entry walk (0.88.1, `check_dirents`, D-0964)

Step 7d, after the sharding pass.  Before it the checker parsed no directory name, so a
published dirent naming a freed inode (D-0963's durable outcome: listed on every node,
resolved on none, unremovable) reported CLEAN.

- **Oracle**: the allocated set is built from the inobt leaf records (holemask bit per
  four inodes, free_mask bit per inode) into a sorted array; the dinode is a separate
  validity check (magic, version 3, `di_ino`, CRC, mode != 0).  Inobt FREE with a
  convincing dinode is still a dangling entry — freed inode bytes are not erased — and
  `di_nlink` is never an allocation criterion (open-unlinked inodes are allocated at 0).
- **Formats**: shortform in the literal area (the parent counts as `..`; `i8count != 0`
  widens EVERY number including the parent; entries are packed, not 8-aligned; the
  entries must end exactly at `di_size`); extents and btree data forks (bmdr root in the
  fork, `BMA3` blocks with the 72-byte long header, pointer array based at the block's
  CAPACITY not `numrecs`); directory blocks assembled through the sorted extent map (a
  directory block is `blocksize << dirblklog` and may span extents; a partially mapped
  one is reported, never walked); `XDB3` data ends before `tail.count` leaf entries
  (count includes stale slots) and the 8-byte tail, `XDD3` at the block end; records must
  partition the data area exactly (tags point back at the record; an unused span's tag
  too).  Only data space (logical offset below 32 GiB) is walked — the hash index and
  free index are not validated, so the pass is a data/reference pass, not every
  directory invariant.
- **Output**: `Directory entries ....... OK|ERRORS (dirs= entries= blocks= dangling=
  mode0= ftype_mismatch= bad_blocks= dirs_skipped= allocated=)`; `-v` adds one
  `dirents: directory <ino> format= entries= blocks= dangling= bad_blocks=` line per
  directory (a harness asserts the count it created).  Zero directories, or the root
  never walked, is an error; every skipped directory or bad block is an error, so no
  skip can yield CLEAN.  An `ftype` contradicting the dinode's class is an error; ftype
  0 is "unspecified", not a contradiction.  The first 64 entry errors are listed, the
  rest counted.
- **Report only**: `-a` does not touch a directory entry.  Removing a name needs the
  bestfree table, the hash index and (node dirs) the free index maintained, and it
  destroys the evidence; a later repair would start with ordinary non-dot shortform
  entries on an exclusively owned image.
- **Live-mount caveat**: the same one as the counters — a live LUN's dirent, inobt and
  dinode can come from different moments; the board's offline rows are authoritative.
  `tests/d0964_chk_dangling_dirent.sh` is the fixture lap (four formats healthy, then the
  D-0963 control arm's dangling entry named with rc 4).


## 2026-09-20 (0.89.19): `chk_mxfs --bootstrap`

```
chk_mxfs --bootstrap /dev/sda      # print the whole-cluster bootstrap record and exit
```

Read-only, **O_DIRECT**, and deliberately **without `O_EXCL`** — so it answers
on a node that has the volume mounted and on one that does not. That is the
point of it: the moment the record matters is the moment a mount is being
refused because a bootstrap term is claimed, and the ordinary `-v` check cannot
run then, because another node may still hold the device. `do_bootstrap_show()`
sits next to `do_clear_bootstrap()` in `tools/chk_mxfs.c`.

Two lines, both machine-readable so a harness can assert without parsing prose:

```
BOOTSTRAP state=CLAIMED(1) term=3 seq=12 owner=<node>/<epoch> key=0x… key_gen=1
  host=<uuid> boot=<uuid> victims=0x… complete=0x… registrants=0/2 escrow=<n>
  K=<slot> prev=<node>/<epoch> prev_kind=<n> lineage=<n> episode=<term>
  refused_slot=<n> refused_reason=<n> crc=OK
BOOTSTRAP-ESCROW state=<n> K=<slot> cls=<n> victim=<node>/<epoch> key=0x… …
```

Exit 0 when the record validates, 4 otherwise (unformatted, bad magic/version,
crc mismatch, or no bootstrap region in the envelope).

**Why O_DIRECT and not the ordinary fd.** A buffered read of a shared block
device returns whatever this node's page cache captured the first time anything
touched it; on a volume another node is writing that is an image of the past
presented as the present. The envelope superblock is mkfs-time and constant, so
it still comes through the plain fd.

**The pitfall this replaced.** Before it, reading the record meant `chk_mxfs -v`
— a full fsck, bounded at 240-300 s, that takes the device `O_EXCL`. A harness
that has to capture the record at a precise instant (say, between a claim and a
power cut) cannot use that, and a harness that captures it 300 s later is not
capturing the same state.
