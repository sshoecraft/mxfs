---
name: ccloop-c7ee71c6-sess29-PROVEN-cluster-write-reverts-a-freed-inode
description: DIVERGENCE PROVEN: a cluster write with no tenure republishes a pre-free inode image 3.9s after a peer freed it — silently, on a fully passing board.
metadata:
  type: project
tags: [mxfs, D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, sess29, proven, corruption]
---

# sess29 — the inode-cluster authority hole DIVERGES, proven

Build **0.11.254** (`D83B7B59A1B473E30720625`).
Harness: `tests/cluster_authority_merge.sh check <n> [skew_ms]`.

## The capture

```
ino=134
  test8  published mode=0        gen..1968 cc..11 at 1785457521506668546   <- FREED
  test1  published mode=100644   gen..5203 cc..5  at 1785457525450481958   <- passenger, NO tenure
  gap = 3.944 s   differs in: incarnation
```

A peer published the inode as **`mode=0`** — the free — and **3.9 seconds later**
this node wrote a **pre-free regular-file image** of the same inode back over it,
out of its cached 16 KB cluster buffer, holding **no write tenure**. Six such
cases (inos 134/135, three episodes), gaps 3.944-4.101 s: **~78x the 50 ms skew
guard**, so cross-node clock error cannot manufacture them.

**2308 passenger writes, 2306 comparable, 0 blind, DIVERGENT=6.**

## Why this is the important number

The run that produced it had **`dir_reuse_coherency` PASS 32/32 and
`dirent_durability` PASS 32/32**. The corruption is SILENT to every criterion on
the board. It is the same shape sess27 captured by hand (test30 republishing a
pre-free DIRECTORY image 2.5 s after test15 published the new REG incarnation),
now reproducible mechanically in a ~3 minute window.

## The method, and the mistake that nearly hid it

Cross-node merge of two always-on streams: `P170-CLWR` (every slot of every
inode-cluster write as `ino:mode:gen-tail:cc-tail` + `realns`) against
`P218-CLUSTER-PASSENGER` (the slots written WITHOUT tenure).

**First version compared mode+gen only and reported DIVERGENT=0 over 2130
passengers.** That was true and useless: mode+gen only distinguish
INCARNATIONS, so it was blind to a revert *within* one incarnation — the common
case. `di_changecount` is monotone per incarnation and was added to BOTH probes
(P170's triples became 4-tuples, buffer 420 -> 800 bytes). The harness now
reports `compared on incarnation ONLY (no cc)` so the blind fraction can never
again be invisible.

Also caught: the harness first reported **2115 false divergences** because
`img_mode` is printed with `%o` by the kernel but was parsed as decimal
(`100644` vs `int('100644',8)=33188`). A verdict of "everything is broken" is as
suspicious as "nothing is" — the impossible mode `304444` in the output was the
tell.

## ⚠ THE DIAGNOSTIC PERTURBS — never run `arm` beside a criterion

`arm` raises `mxfs.instr`, uncapping probe printing. **Measured on one build:
`dir_reuse_coherency` FAIL 0/32 (111 s/120 s) with instr=1, PASS 32/32 (109 s)
with instr=0.** The printk cost alone fails a pace assertion — the same trap
P56's comment records. The always-on 800-line/node cap (32 x 800 writes) is
plenty for the merge and costs nothing, so `arm` is rarely needed.

## Next

The `no_write_tenure` population (2970/board run) is the smallest and cleanest
target. The fix candidates are unchanged (cluster-block exclusive ownership;
validated read/merge/write under a block lock; or CAW over the block with an
expected version). Note P56's own warning: an all-skip degenerate case can strand
a buffer with no logged inode item, so masking non-dir slots needs that guard.
