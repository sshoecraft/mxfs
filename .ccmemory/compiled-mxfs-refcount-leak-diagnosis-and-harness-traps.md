---
name: compiled-mxfs-refcount-leak-diagnosis-and-harness-traps
description: MXFS refcount/inode-leak diagnosis: unmount leak instrumentation history, igrab probe decoder, dmesg staleness trap, module-refcount-leak-on-abrupt-k…
metadata:
  type: project
tags: [compiled, refcount, unmount-leak, instrumentation, dmesg, harness, module-leak, drc-cap2]
---

# MXFS refcount-leak diagnosis: instrumentation history and harness traps

Covers two related lines of work: (a) attributing the unmount busy-inode leak
via reference-count instrumentation, and (b) two harness traps that produced
false readings or false failures while doing that kind of diagnosis.

## Unmount inode-leak attribution (sess26): global grab/release balance is unsound

Tried: `P205-REFBAL` — a per-inode grab/release balance (`i_mxfs_tgrabs` /
`i_mxfs_tputs`) on the theory that `net == icount` would identify the
unreleased grab.

Round 1 (chokepoint = `mxfs_igrab_tracked`/`mxfs_iput_tracked` only):
`tgrabs=61 tputs=1 net=60` against `icount=1` — MXFS releases via
`xfs_irele()`, not `iput()`, so the release side was barely counted. The probe
still printed a confident wrong verdict ("TRACKED-IGRAB-HOLDS-IT").

Round 2 (added `xfs_irele()` release chokepoint and `xfs_iget()` grab
hand-off, symmetric): `tgrabs=161 tputs=83 net=78` against `icount=1` — still
off by 77. Residue is VFS-side references (`dput`→`iput`, `evict`,
`d_splice_alias`'s error-path `iput`) that never pass either chokepoint and
have no available hook short of patching the VFS.

**Conclusion: unsound in principle, not just uncalibrated.** Linux has no
reverse map from a refcount to its holders, so no filesystem-confined
count-based scheme can attribute one surviving reference. Do not rebuild this
approach. The probe's only durable value is its honest third verdict,
`UNEXPLAINED (VFS igrab/iput outside both chokepoints)`.

General lesson: three separate instruments in that session produced a
confident wrong answer before validation (journalctl-only harvest, the
loser-vs-peers differential on rank1, and this balance). Sanity-check every
new counter against a known invariant before reading a verdict off it — here
the invariant was `net == icount`, and it failed by 77 on the first capture.

What the captures did establish, three catches in five cycles at 16/caw, one
node each — all DIRECTORY, `icount=1`, `dentries=0`, `hashed=1`,
`lru_linked=1`, `sblist_linked=1`, `dlm_mode=3(PR)`, `dlm_state=1(CACHED)`,
`itemp=1`, `in_ail=0`, no bast/dwork/bwork pending, `demoter=0`. Attribution
converges on `xfs_lookup+0x16c` from two independent fields (`iget_caller` and
`P203-LEVEL[1]`); the grab site is the ordinary `xfs_iget_cache_hit` igrab,
which names nothing useful. Key contradiction: `dentries=0` with `icount=1`
and no dentry alias — no VFS dentry holds it, yet a lookup-obtained reference
survives.

Next experiment proposed (targeted, not global): count per-inode how many
times `xfs_lookup` returned 0 (handing out a reference) vs. dentry count at
unmount. `lookup_handoffs > 0 && dentries == 0 && icount == 1` would show a
lookup reference no dentry ever took ownership of — but `d_splice_alias`
legitimately consumes the reference via `iput` on its error paths without
creating a dentry, so that outcome must be counted too or the result stays
ambiguous.

See [[unmount-leak-global-refcount-balance-cannot-work]].

## The `site=fileN:lineM` decoder (reference probe instrumentation)

MXFS wraps `igrab()`/`iput()` per translation unit with a numeric file id via
`MXFS_REFEV_SITE(file, line)` = `(file << 32) | line`; probes print it as
`site=fileN:lineM`.

| id | file |
|---|---|
| 1 | `xfs/xfs_mxfs_dlm.c` |
| 2 | `xfs/xfs_icache.c` |
| 3 | `pal/linux/xfs_iops.c` |
| 4 | `xfs/xfs_filestream.c` |

A reference taken anywhere else (upstream XFS, the VFS) is not wrapped and
shows as a raw `%pS` return address — `kind < 2` in the ring means exactly
that.

Per `struct xfs_inode` (`xfs/xfs_inode.h`):
- `i_mxfs_refev_ip/kind/cnt/head` — 10-entry ring of grab/release events.
  `kind`: 0=rele, 1=grab(ip), 2=grab(file:line), 3=rele(file:line).
- `i_mxfs_grabst[16]` / `i_mxfs_grabst_kind[16]` — outstanding-grab stack,
  scoped to current tenure (reset by `mxfs_inode_tenure_reset` from
  `xfs_fs_drop_inode`, i.e. at the `i_count`→0 transition). At `i_count==1`,
  slot 1 is the outstanding reference.
- `i_mxfs_tgrabs`/`i_mxfs_tputs` — running totals; `i_mxfs_grab_file`/`_line`
  — last grab.

Consumers: `xfs/xfs_icache.c` ~375-407 (unmount leaked-inode probe,
`P203-LEVEL`, `P202-REFEV`); `xfs/xfs_inode.c` (D-0941 poison-retirement
failure dump, `P566-GRABST`, `P566-REFEV`, `P566-GRABST-SUMMARY`, added
sess566). This machinery predates and underlies all the unmount-busy-inode
work above — reach for it whenever a probe reports a count but not a holder.

See [[reference-mxfs-igrab-call-site-file-id-mapping-for-refev-and-grabst-probes]].

## Harness trap (sess42): `dmesg --follow` ring-buffer staleness in `drc_cap2.sh`

`tests/drc_cap2.sh` started per-node capture with `dmesg --follow` without
clearing first. `dmesg --follow` dumps the entire existing ring buffer at
stream start, then follows — so `tests/_cap/<host>.log` contained the tail of
PRIOR runs interleaved before the current run's lines. Kernel timestamps are
monotonic-since-boot, so stale entries look identical to live ones.

Cost: sess41 had already lost 6 rounds to this ("6 failed rounds were STALE
dmesg ring-buffer entries from the PRIOR failing run"). In sess42,
`P108-REACQUIRE` "old format" lines (52×) were all stale (ts before this run's
round 1); the new `held_raw` format fired 0× and was nearly misread as
not-deployed. `P91-RELOAD-PROTECT` at `ino=0x83` (131) fired at ts=28223,
which superficially matched failing rounds 20/23 — but those were actually at
ts=29108/29148 (this run); 28223 was from the prior run, a false-positive
correlation.

Fix (build-independent, harness-only): `drc_cap2.sh` line ~28 now runs
`dmesg -C 2>/dev/null; dmesg --follow` so the capture contains only
post-clear, this-run lines. Prep (rmmod/insmod/mkfs/mount) runs after the
stream starts, so prep+test are captured and nothing prior is.

Rule for all future dmesg-correlation work:
1. Confirm the capture cleared dmesg (`dmesg -C`) or a fresh boot preceded it.
2. Always anchor correlation to this run's round-1 timestamp:
   `grep 'DRCph r=1 .* PHASE=create-start'`. Any P-line with ts before that is
   stale — ignore it.
3. A FAIL's RDMISS round# is authoritative; bracket by that round's
   create-start..verify-done PHASE markers and trust only P-lines inside that
   window.

See [[dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix]].

## Harness trap (sess43): killing `drc_cap2`/`run.sh` mid-flight leaks the module refcount

Killing the `drc_cap2` / `run.sh 2 tcp` background task with TaskStop while
MID-TEST (nodes actively creating files) leaves a leaked in-kernel reference:
`rmmod mxfs` reports "Module mxfs is in use",
`/sys/module/mxfs/refcnt`=1 with EMPTY holders and NO mounts — the DLM/peer
thread or workqueue does not clean up on an abrupt kill. The next `run.sh`
prep then fails at `mkfs_mxfs -f /dev/sda returned 1` (device/module busy) →
"PREP FAIL (mkfs)" → ABORT.

Recovery (clean slate — rebooting the test VMs is allowed; only the HOST
clyde reboot is forbidden):
```
virsh -c qemu:///system destroy test1; virsh -c qemu:///system destroy test2
virsh -c qemu:///system start test1;   virsh -c qemu:///system start test2
# wait for ssh (test1 ~4s, test2 ~12s), then verify: lsmod|grep mxfs == empty,
# /src/mxfs/mxfs.ko visible (NFS auto-remounts)
```
After reboot: `mxfs_loaded=0`, NFS auto-mounted, fresh `mxfs.ko` visible, prep
succeeds.

Prevention: let `drc_cap2` run to completion — it has its own 450s timeout
plus cleanup that kills streamers and node-side followers. If it must be
stopped early, budget a VM reboot for the refcount leak. To adjust module
behavior instead of aborting a run, pass `MXFS_EXTRA_MODARGS` (exported
through `run.sh` → `prep_node.sh`), e.g.
`MXFS_EXTRA_MODARGS="dir_force_block=1" bash tests/drc_cap2.sh`.

See [[trap-killing-a-harness-run-midflight-leaks-the-module-refcount]].
