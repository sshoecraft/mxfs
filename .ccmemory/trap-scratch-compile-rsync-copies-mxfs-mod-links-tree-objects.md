---
name: trap-scratch-compile-rsync-copies-mxfs-mod-links-tree-objects
description: TRAP (sess465): a scratch compile made by rsync of /src/mxfs links the TREE's old .o files — mxfs.mod (kbuild's @-file of absolute object paths) is c…
metadata:
  type: feedback
tags: [trap, build, scratch, kbuild, sess465]
---

# TRAP (sess465, 2026-09-02): scratch compile silently links the tree's OLD objects

Symptom: `strings -a $S/mxfs.ko | grep P300-CLAIM-WAIT` = 0 although `$S/dlm/disklock.o`
(freshly compiled, CC [M] line in the log) had the strings.  `$S/.mxfs.o.cmd` = `ld -r -o mxfs.o
@$S/mxfs.mod`, and `$S/mxfs.mod` listed 122 ABSOLUTE paths under **/src/mxfs/** — the LD step
used the tree's objects from chain 89's prod build (mtime 03:36), not the scratch objects.

Mechanism: `rsync -a /src/mxfs/ $S/` (excluding *.o, *.cmd, *.ko) still copies `mxfs.mod`
(kbuild's generated object list).  Kbuild regenerates `mxfs.mod` via if_changed against
`.mxfs.mod.cmd`; on the FIRST scratch build the command string differs ($S paths) so it is
regenerated (compile #1 was fine), but on a later incremental rsync the tree's mxfs.mod overwrites
the scratch one while `.mxfs.mod.cmd` (excluded from rsync, left from compile #1) still matches
-> not regenerated -> link uses /src/mxfs/*.o.  A srcversion that differs from the tree's proves
nothing (srcversion hashes sources, not the linked objects).

Rule: after every rsync into a scratch copy, `rm -f $S/mxfs.mod $S/mxfs.mod.c $S/mxfs.mod.o
$S/Module.symvers $S/modules.order` before `make modules`, or add `--exclude '*.mod'
--exclude '*.mod.c' --exclude modules.order --exclude Module.symvers` to the rsync.  Then VERIFY the
.ko by `strings -a` for a marker string unique to the change (not by srcversion).  Never rsync
the other way.
