---
name: technique-ask-the-built-module-which-probes-exist-before-trusting-any-harness-that-counts-one
description: TECHNIQUE (s137): 17 probes are written in MXFS source but absent from mxfs.ko; 8 of them are counted by 6 harnesses, so those verdicts read a guaran…
metadata:
  type: feedback
tags: [measurement-integrity, probes, build, harness, tooling]
---

# A probe that is not in the built module is a guaranteed zero

Measured s137 on 0.89.58, build `F3199FE2112E215C2FBB787`, kernel
`6.8.0-101-generic`. `tools/probe_audit.sh` (written for this; it reproduces the
whole finding in one call) compares the probe names written as string literals
in the kernel-built sources against `strings -a mxfs.ko`:

```
source (xfs dlm pal mxfs_clayer): 1594 distinct probes
built module:                     1577
in the source and NOT in the module: 17
```

**Eight of the seventeen are counted by six harnesses.** Those harnesses grade
on a line that cannot be printed, and read the zero as a measurement of MXFS
rather than of themselves.

## The four ways a written probe fails to reach the binary

All four were found in this one sweep, and none of them is visible from reading
the call site:

1. **Unreachable after an early `return`.** `mxfs_disklock_recovery_begin`
   (`dlm/disklock.c:6374`) was retired on a design ruling: it logs
   `P238-RECOV-BEGIN-RETIRED` and `return -EPROTO`s at `:6421`. The ~185 lines
   after it — the whole original body — are dead, taking seven probes
   (`P234-RECOV-*`, `P237-RECOV-*`) with them. The retirement line itself IS in
   the module, which is what proves the function compiles and the rest does not.
   Four harnesses still ask the retired function's questions.
2. **A hook wired only into the false arm of a version `#if`.** The authority
   gate's buffered-data arm; see
   `trap-a-hook-wired-only-into-one-arm-of-a-kernel-version-if-is-deleted-by-the-compiler-not-merely-unreached`.
3. **A condition the compiler can prove false.** `if (0 && ...)` in
   `dlm/dlm_caw.c` (deliberate, documented, `P49-INSTR`); a local
   `bool mxfs_suppress_stale_agwrite = false` never assigned anywhere
   (`pal/linux/xfs_buf.c:9686`, superseded by a later preventer that another
   session made log-only); an uncalled `static` function
   (`mxfs_ilk_dump_stuck`, `P73-ILOCK-STUCK`, zero callers in the tree).
4. **A whole file not in the Kbuild object list.** `xfs/xfs_mxfs_dentry.c` is
   not built; 107 of 236 `.c` files under the four source directories are not
   (scrub, quota, realtime, zones — expected for this fork). Its
   `mxfs_drevalidate` is not the live one; a differently-shaped function of the
   same name in `pal/linux/xfs_super.c` is.

## The one that reading could not settle

`P302-FUA-READ-DEADLINE` (`pal/linux/kern.c:1105`) is **present in the
preprocessed source and absent from the object and the assembly**, with the
control `P-FUA-READ-RETRY` from the same loop present in all three:

```
make -C /lib/modules/$(uname -r)/build M=/src/mxfs pal/linux/kern.i   # grep -c -> 1
strings -a pal/linux/kern.o | grep -c P302-FUA-READ-DEADLINE          # -> 0
```

No `if(0)`, no always-false local, no false `#if` covers it; the guard
(`budget_ms < 0`) is data-dependent. When reading has been done and found
nothing, **go to the compiler**: `make M=... <obj>.i` separates the
preprocessor from the compiler, and `make M=... <obj>.s` says what was emitted.
That pair is the instrument for "the source says it and the binary does not".

## The instrument

`tools/probe_audit.sh` — report form lists every missing probe with the
`file:line` of each site; `--gate P290-X P291-Y` exits 1 if a named probe is not
in the module, which is what a harness's build precondition should use. Extract
probes only from the part of a line AFTER its first double quote: a probe name
in a comment is not a probe, and a comment that WRAPS one yields a truncated
token that reports a live probe as missing (85 false positives became 17 real
ones with that one change).
