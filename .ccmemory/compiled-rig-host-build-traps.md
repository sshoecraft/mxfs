---
name: compiled-rig-host-build-traps
description: Rig/host/build traps sess377-468: clyde ext4 corruption+recovery, 32caw board timing, kbuild usermode-obj trap, script self-edit, sshpass hang, scrat…
metadata:
  type: project
tags: [compiled, rig, clyde, host-safety, harness, build, traps]
---

## Topic

Rig/host/build operational traps on clyde, sess377→sess469 — continuation of
`compiled-rig-operational-traps` (which runs through sess433). Same shape as
that chronology: none of these are MXFS defects, all are ways of operating
the rig, the build, or clyde itself that destroy evidence, wedge state,
corrupt a verdict, or fabricate a false MXFS finding. Chronological.

### sess377 (2026-08-19) — clyde HOST kernel memory corruption, not MXFS
[[clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377]]: three oopses in
clyde's own ext4/jbd2 page-cache path in under an hour. The smoking gun:
oops #2's faulting `buffer_head*` decoded to ASCII `"2004-10."` — the middle
of an iSCSI IQN (`iqn.2004-10.com.ubuntu:01:testN-mxfs-node`). A folio's
`private` field held IQN string text — a wild write / UAF, not a bit-flip.
Only the out-of-tree `iscsi_scst`/`scst`/`scst_vdisk` modules write IQN
strings on this host; `mxfs.ko` was unloaded/unmounted/idle throughout.
Because clyde has ONE disk carrying every VM qcow2 AND the shared MXFS LUN
(`/home/steve/disk.img` via `vdisk_fileio`), any host-side corruption can
fabricate an "MXFS corruption" defect — two free-space-btree shutdown
defects filed the same session became suspect and had to be re-derived on a
healthy host. Each oops leaves unkillable D-state qemu/vhost tasks (inode
rwsem held forever mid-write) — `virsh destroy` on the wedged domain hangs
(rc=124) though it works instantly on a healthy one. Recovery WITHOUT
rebooting clyde (RULE 2): give the dead node a new libvirt domain name +
disk file but keep its MAC (DHCP/DNS repoints the hostname automatically,
verified); clone from the node's own disk with `qemu-img convert -T none -t
none` if still readable (13s; a plain `cp` of 6.5GB pushed kswapd hard and
directly tripped oopses #2/#3), otherwise clone a live donor via NBD and
rewrite identity (`/etc/hostname`, `initiatorname.iscsi`, `machine-id`, SSH
host keys — cloud-init is disabled on these images so nothing else
re-derives identity) before handing the clone the dead node's MAC in a fresh
XML. ~3 min/node. Standing rule: corroborate any rig corruption-family
finding against clyde's oops count before it goes on the RULE 6 ledger.

### 2026-08-20 — 32/caw board timing: the harness-overhead constant and two verdict traps
[[board-32caw-chunking-measured-walls-and-harness-overhead]]: `wrapper =
sum(measured test walls) + 12s × n_tests + 15s startup`. The `12s × n_tests`
term is ssh fan-out + MQTT coord-broker sweep + criteria.json record — it's
invisible in `showstat`'s `elapsed` column and is exactly what a naive
"sum the walls" wrapper misses (confirmed both directions: omitting it
overran a 254s wrapper on 193s of tests; including it correctly predicted
88s for a chunk that ran 61s). For a test running near its budget ceiling,
derive the wrapper from the ENFORCED budget, not the measured wall — a
wrapper built from `dir_reuse_coherency`'s 109s measured wall killed it
mid-run twice against its 120s budget. Two traps found chunking this board:
(1) manifest ORDER is load-bearing — phase P6 (`dirent_durability`) stamps
the window that P8's `dirent_publish_integrity`/`dirent_type_integrity`
scope their measurement to; running the P8 pair without P6 first in the same
cluster incarnation reads `window=0` and FAILS on 30/32 nodes, looking like
a mass correctness failure. (2) a killed `run.sh` inside a pipe (`timeout N
./run.sh ... | grep`) prints NOTHING, not even its immediate startup header
— the pipe buffer dies with the timeout — so redirect to a file and grep the
file, never grep a live pipe you might cut. Also: `prep_cluster` against an
already-mounted fleet can itself fail (119s, exhausts its rmmod retry budget
via `D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B`) — unmount the fleet
yourself, in parallel, before prepping.

### sess440 — a top-level `make dlm/foo.o` silently builds a user-mode object
[[trap-toplevel-make-dlm-o-builds-usermode-objects-breaks-make-modules]]:
`make -s dlm/scsipr.o ...` run at the repo root (not through kbuild)
compiles user-mode objects into `dlm/*.o` with no `.o.cmd` — no build error,
just implicit-function warnings for `READ_ONCE`/`WRITE_ONCE`. The next `make
modules` links them and modpost fails with `undefined!` for those symbols,
reported as `ERROR:` (capital), so a launcher grepping lowercase `error:`
sees `BUILD_RC=2` with zero matches. Correct per-object check: `make -C
/lib/modules/$(uname -r)/build M=/src/mxfs dlm/scsipr.o`. Recovery: remove
the specific stale `dlm/*.o` and `dlm/.*.o.cmd` by full name (no glob, RULE
2b) and rebuild through kbuild.

### sess445 — never edit a bash script a live process is executing
[[trap-never-edit-a-bash-script-while-it-is-running-run-sh-offset-shift]]:
bash reads a script incrementally by file offset; parsed function bodies are
safe, but every top-level command after the current read position is
re-read from the saved offset, so inserting/deleting bytes above it makes
the running instance execute mid-line garbage. Rule: never edit `run.sh` (or
any `tests/*.sh`) while a chain has it in flight — queue the edit for after
DONE, or revert byte-identically if one already landed. (The concrete bug
found this way: `run.sh`'s kill-time phase capture used `pkill -f
'$script'`, which also matches the remote shell's own `bash -c` command line
carrying that same script path, killing itself before it could dump
`dmesg | grep mxfs-CCph`. Fix: bracket the pattern's first character so it
can't match its own text.)

### sess452 — a root-owned sshpass passfile hangs the whole fleet silently
[[trap-sudo-mpath-up-leaves-root-owned-passfile]]: any harness step run
under `sudo` (e.g. `mpath_up.sh`) materializes `/tmp/.mxfs_pass` as
`root:600`. The unprivileged caller's `[ -s ]` check on it is true (stat
still works), so `mxfs_sshpass.sh` hands it to sshpass — which for
unreadable passfiles prints a permission-denied line to stderr and then
**hangs** on the password prompt instead of exiting, silently eating the
outer timeout (rc=124, zero output). Discriminator: `ssh -o BatchMode=yes`
answers instantly; only the sshpass path stalls. Fixed in tooling:
`mxfs_sshpass.sh` now tests readability (`! -r || ! -s`) and re-materializes
or refuses with exit 96 instead of handing sshpass an unreadable file;
`mxfs_secrets.sh secrets_passfile` falls back to a `.uid$(id -u)` path when
the canonical one is owned by someone else and inaccessible. Diagnostic:
`ls -l /tmp/.mxfs_pass*` first, whenever fleet ssh "hangs" after any
sudo'd step ran.

### sess465 — a scratch compile silently links the TREE's old objects
[[trap-scratch-compile-rsync-copies-mxfs-mod-links-tree-objects]]: an
`rsync -a /src/mxfs/ $S/` scratch copy (excluding `*.o`/`*.cmd`/`*.ko`)
still copies `mxfs.mod` — kbuild's generated absolute-path object list. On
the first scratch build the command string differs so kbuild regenerates it
correctly; on a LATER incremental rsync, the tree's `mxfs.mod` overwrites
the scratch one while the excluded `.mxfs.mod.cmd` (left from build #1)
still matches, so kbuild does NOT regenerate it, and `ld -r -o mxfs.o
@mxfs.mod` links 122 absolute paths under `/src/mxfs/` — the tree's objects,
not the scratch ones. srcversion looks fine throughout (it hashes sources,
not the linked objects) so it proves nothing; only `strings -a mxfs.ko | grep
<marker-unique-to-the-change>` catches it. Fix: after every rsync into a
scratch copy, delete `mxfs.mod`, `mxfs.mod.c`, `mxfs.mod.o`,
`Module.symvers`, `modules.order` (or exclude them from the rsync) before
`make modules`. Never rsync the other direction.

### sess468 — killing a chain's process group leaves its `timeout` child alive, holding the run lock
[[trap-timeout-child-escapes-pgroup-kill-run-lock-collision]]: `kill -TERM
-- -<pgid>; kill -KILL -- -<pgid>` on a setsid chain kills the chain and its
`lap()` shells, but GNU `timeout` runs the wrapped command in its OWN
process group specifically so it CAN signal that tree without hitting
itself — so `timeout 160 ./run.sh ...` survives a group kill aimed at the
chain that launched it. The orphaned `run.sh` (plus its ssh fan-out) kept
holding `/tmp/mxfs_run.lock`; the next chain's `prep_joiner` failed
`rc=3 another run.sh holds /tmp/mxfs_run.lock` 19s later and proceeded onto
an un-prepped fleet. Rule: after killing a chain, also kill its `run.sh` by
name (`tools/mxfs_pgrep.sh` — never bare `pgrep -f` host-locally, RULE 2c)
or confirm `fuser -v /tmp/mxfs_run.lock` is empty before the next chain's
gate releases; better, gate the next chain's start on the lock being free
rather than on the prior chain's DONE line. Also noted: `mxfs_pgrep.sh
'<pattern>'` can match the CALLING shell's own cmdline — build the pattern
at runtime rather than as a literal that could echo back.

### 2026-09-02 — clyde takes a silent reset with ZERO fault record
[[clyde-0902-silent-reset-no-fault-record-not-scst-instrumentation-gap]]:
distinguishes two prior incidents wrongly merged into "SCST rebooted the box
two days running." 2026-09-01's double crash (07:15, 08:45) was already
DISPROVED as GPU/PCIe-P2P memory corruption surfacing in unrelated
subsystems (`xas_split_alloc`, `kfree_rcu_monitor` list corruption) — both
traces carry `[last unloaded: scst(OE)]`, which is a record of the last
module EVER unloaded, not evidence it was live (in the 08:45 crash, SCST had
been unloaded 88 minutes earlier and appears nowhere in `Modules linked
in`). The 2026-09-02 06:10 event is a NEW, separate failure: pstore empty,
crash-latch saw nothing, no BUG/Oops/panic anywhere, last journal line is a
cron job completing NORMALLY — the kernel never reached its oops path at
all; this was a triple fault or hardware reset. Every known candidate cause
was checked and ruled out (all three fixed SCST defects, the PR-overflow
precursor, GPU P2P — zero `nv_dma_map_peer`/Xid lines in this boot — OOM,
disk headroom, log flood, host-wide stall). The real finding is the
blocker: clyde has NO fault-recording channel that survives a no-oops death
— no BMC/SEL (no IPMI, SMBIOS type 38 absent), no netconsole, no kdump,
`sysstat` installed but `ENABLED="false"` so it collected nothing across
every incident, and `iommu=off intel_iommu=off intremap=off` on a box with
multiple GPUs, several out-of-tree drivers and 32 KVM guests — no DMA fault
report ever names the offending device, which is exactly why this whole
corruption family surfaces in random, unrelated subsystems.
`mxfs-crash-latch` cannot latch this class at all — it keys on a pstore
record, and a silent reset leaves none, so the rig is free to restart into
whatever caused it. Method note: an EMPTY pstore plus a normally-completed
last service IS meaningful signal (rules out "wedge that killed journald in
its final moments"), unlike a merely-quiet journal, which proves nothing on
its own.

## Cross-cutting pattern

Same pattern as `compiled-rig-operational-traps`, one layer down: a step
that is safe in isolation (a top-level `make`, an rsync into scratch, a
process-group kill, a sudo'd sub-step, editing a script, chunking a board)
becomes destructive because of clyde/kbuild/rig state it doesn't account
for — a build system that silently produces the wrong artifact type, a
generated file excluded from a copy but not from its staleness check, a
child that deliberately escapes its parent's process group, a passfile
whose ownership flips under sudo, a script being read by file offset while
it's still running, a board's per-test overhead that doesn't show up in any
per-test timer, and now a host with real memory-corrupting hardware/driver
interactions and literally no instrumentation that survives the crash it
causes. Two entries here (sess377, 2026-09-02) are not harness bugs at all
but the same meta-lesson as sess432/429 in the prior article: when
post-mortem evidence comes back empty, suspect the capture channel before
concluding there is nothing to find — and here, sometimes there IS no
capture channel, which is itself the defect to fix.
