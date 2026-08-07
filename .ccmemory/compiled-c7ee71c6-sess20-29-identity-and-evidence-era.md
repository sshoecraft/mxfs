---
name: compiled-c7ee71c6-sess20-29-identity-and-evidence-era
description: Compiled: c7ee71c6 sess20-29 (0.11.150-258) — silent-mkdir-loss hunt, typeflip corpse publish, ABBA, demoter-claim family, cluster-write authority, t…
metadata:
  type: project
tags: [c, o, m, p, i, l, e, d, ,,  , s, i, l, e, n, t, -, m, k, d, i, r, -, l, o, s, s, ,,  , t, y, p, e, f, l, i, p, ,,  , a, b, b, a, ,,  , d, e, m, o, t, e, r, -, c, l, a, i, m, ,,  , c, l, u, s, t, e, r, -, a, u, t, h, o, r, i, t, y, ,,  , o, p, e, n, -, d, e, f, e, c, t, s, -, l, e, d, g, e, r, ,,  , m, e, a, s, u, r, e, m, e, n, t, -, t, r, a, p, s]
---

# c7ee71c6 sess20-29 — the identity, authority and evidence era (0.11.150 → 258)

The era that produced the **`open_defects` ledger** (still the readiness gate), proved the
inode-cluster write-authority hole, and closed a five-session silent-dirent-loss hunt by
inventing a method instead of guessing another marker.

## 1. The board was lying — and the ledger exists because of it

**User directive, sess21:** *"showstat was supposed to show whether we are production ready.
If showstat is not showing that then we need to add entries to the criteria… If you're working
on something, something better not be all green."* Every defect found that session was found
**outside** showstat while the board read 20/20 green — including a soft lockup that killed a
node for 522s, an ILOCK assertion failure on 3 of 4 nodes, and a `mkdir(2)` that returned
success with the entry existing nowhere ([[ccloop-c7ee71c6-sess21-criteria-board-must-show-open-defects]]).

Adding behavioural criteria was **not sufficient**: the intermittent ones go green whenever a
run gets lucky, and *"this run did not reproduce it"* is not *"fixed"* — but a green cell
asserts the latter. Hence `tests/criteria/OPEN_DEFECTS.json` + the `open_defects` criterion as
a **deterministic** gate ([[ccloop-c7ee71c6-sess21-open-defects-ledger-is-the-readiness-gate]]).

Three separate classes of board-lie were then found and fixed:

- **One sync-wedged node makes SEVEN criteria read 0/32.** A node deadlocked by the ABBA bug
  passes every liveness check — mounted, `ls` answers, mkdir/write/fsync/unlink fine, no
  BUG/WARNING/shutdown — it simply can never finish `sync`, so it never reaches a barrier.
  Also: 120k retained MQTT messages crawling every barrier
  ([[ccloop-c7ee71c6-sess24-wedged-node-fakes-broken-fs-and-mqtt-backlog]]).
- **Three evidence-integrity bugs** made cells report on the *previous* run: window scoping
  latched on the OLDEST marker in the ring; `dirent_publish_integrity` never sourced `lib.sh`
  and scanned 0 lines ([[ccloop-c7ee71c6-sess27-three-vacuous-evidence-bugs-in-the-board]]).
- **The harness over-reported**: `sf_mkdir_storm` counted lag as loss
  ([[ccloop-c7ee71c6-sess20-atomic-bug-harness-truth-and-tcp-wedge]]).

## 2. The silent mkdir loss — five sessions, and the method that ended it

Chain first proven byte-exact in sess22 (two independent captures, identical shape,
`nlink=33 visible=31 expected=32` on all 32 nodes, zero nonzero `mkdir(2)` returns): the
epoch adopt is DEFERRED by a reload bail, then the dir-epoch fence blocks every flush of the
already-committed dirent and the drain exits with the obligation unmet
([[ccloop-c7ee71c6-sess22-silent-mkdir-loss-full-chain-proven]]).

**P195 looked like the exact predicate** — same signature every run, byte-for-byte matching
the round-29 loss ([[ccloop-c7ee71c6-sess21-p195-exact-predicate-for-silent-mkdir-loss]]) —
and was then **measured to be neither necessary nor sufficient**: a FAILING run with
`durable_loss=3, mkdir_err=0` had `stale_base_mutations=0`, and a PASSING run had P195 firing
([[ccloop-c7ee71c6-sess23-P195-is-not-necessary-for-the-loss]],
[[ccloop-c7ee71c6-sess23-P195-invalidated-and-race-bail-hypothesis]]). P32E was then the only
marker that was 0 on every passing run and present in every captured loss
([[ccloop-c7ee71c6-sess23-P32E-is-the-discriminator]]).

**By sess26 every documented marker read ZERO in a window where dirents were durably lost** —
P32E, P195, P188, P177, P146V, P51, P65, P194, P34J — all confirmed present in the built
module via `strings mxfs.ko`. The producer had **no probe**, and five sessions of nominating
the next marker by intuition had failed.

**The method that worked — a token-frequency differential.** `tests/dd_loss_differential.sh`
loops until FAIL, then reduces every node's window-scoped log to `mxfs: <TOKEN>` frequencies
and reports where the LOSING node departs from the 31-peer distribution. *The data nominates
the probe instead of the engineer.* It named `P6-MIDTENURE-RELOAD-SKIP`: **loser 661 vs peer
median 37**, nothing else comparable ([[ccloop-c7ee71c6-sess26-P6-MIDTENURE-differential-nominates-producer]]).

**Mechanism:** the P6 mid-tenure skip **swallows peer DIR_RELOAD notifications** (stale_src
2 and 8 are both explicit peer notifications) after the flag has already been consumed. A
`P81-P6-SRC` histogram made it readable without having to catch a losing window
([[ccloop-c7ee71c6-sess26-P6-swallows-peer-dir-reload-notification]]).

A GPT correction that mattered: P6 and P65 are **not** contradictory. `grant_epoch=2,
valid_epoch=0` does not prove a peer wrote *during* our tenure — it proves our base was
**already stale when the tenure began**. Both statements are simultaneously true; the fix
belonged at a different layer ([[ccloop-c7ee71c6-sess21-gpt-epoch-freshness-gate-correction]]).

## 3. D-DIRENT-INODE-TYPE-MISMATCH — a corpse published over a live inode

A dirent whose ftype says REGULAR resolves to an inode whose live incarnation is a DIRECTORY,
agreed by all 32 nodes, reproducible back-to-back
([[ccloop-c7ee71c6-sess22-dirent-inode-type-mismatch]]).

**Root:** `RELOAD-TYPEFLIP-STALE-SKIP` kept the in-core inode whenever `disk_gen <= incore_gen`
— but **XFS generations are RANDOM**, so on a genuine cross-node inode-number reuse that
comparison is a coin flip. When it lost, the node kept a **DEAD incarnation** and its release
drain **published that corpse** over the peer's live inode. (A comment two lines above already
said the gen compare was unreliable, but only the dirent-ftype case had been patched.)
([[ccloop-c7ee71c6-sess27-ROOT-typeflip-random-gen-corpse-publish]])

## 4. The inode-cluster write-authority hole — proven, then fixed

GPT's architectural point: **protection must be at least as coarse as the physical write
unit.** MXFS writes the whole 16KB inode CLUSTER (21+ `ino:mode:gen` triples per write), so
inode-level locks do not prevent one slot's update from carrying stale images of its
neighbours ([[ccloop-c7ee71c6-sess27-GPT-verdict-publication-authority-and-lru-tenure]]).

Detector built (0.11.253): in the per-slot masking loop, every class is guarded — FREE and NL
skipped, a DIRECTORY slot never written unless logged — except the branch commented
*"held non-dir inode → write it"*, which writes unconditionally from whatever the cached buffer
holds. **That `continue` is the defect.** First census: 2,970 slots published with no write
tenure, 68,277 with no in-core inode — on a **fully passing board**
([[ccloop-c7ee71c6-sess29-cluster-authority-detector-built-and-first-numbers]]).

**Divergence proven:** a peer published ino=134 as `mode=0` (the free); **3.9 seconds later**
this node wrote a pre-free regular-file image back over it, with no tenure
([[ccloop-c7ee71c6-sess29-PROVEN-cluster-write-reverts-a-freed-inode]]).

Fixed by `mxfs.cluster_passenger_skip` — drop every un-logged slot this node has no write
authority for, mirroring what `P56-CORESIDENT-DIR-SKIP` already did for directories.
Divergence 3/10 → 0 at both 8 and 32 nodes. **Lost-write safety is structural, not lucky**:
`logged` is built by walking `bp->b_li_list`, so a skipped slot provably has no log item.
A GPT review of the fix caught a real bug in it before it shipped
([[ccloop-c7ee71c6-sess29-cluster-authority-FIXED-and-the-bug-GPT-caught-in-my-fix]]).

GPT's unifying verdict for the era: the three criticals are **one** defect — *MXFS lacks a
linearizable cluster-wide ownership, publication and incarnation protocol for metadata
resources* ([[ccloop-c7ee71c6-sess23-gpt-cluster-inode-identity-protocol]]).

## 5. D-BAST-WRITEBACK-ABBA-DEADLOCK — and why three sessions missed it

Both stacks captured live: `bast_process` blocked on a **folio lock** while holding the
inode DLM/ILOCK context, against writeback holding the folio and waiting on ILOCK
([[ccloop-c7ee71c6-sess24-bast-writeback-abba-deadlock-CAPTURED]]).

**The thing three sessions missed: `bast_process` flushes TWICE, and the two sites are not
equivalent.** Site 1 runs while `i_dlm_mode` is still the granted mode, so a colliding
writeback submitter asking for ILOCK_SHARED is satisfied by the nest-admit fast path and never
parks — **it cannot deadlock**. Site 2 (the `S_ISREG` durability flush) runs **after**
`i_dlm_mode = NL` and before the wire unlock; mode==NL fails every nest-admit, so the submitter
parks *still holding its folio* and this flush walks into `folio_lock()` on it. **Site 2 is the
ABBA site** ([[ccloop-c7ee71c6-sess25-ROOT-PROVEN-abba-drain-site2]]).

## 6. The demoter-claim family (four roots, one field)

- **Clobber**: the dwork release drain overwrote and cleared the work drain's `i_dlm_demoter`
  claim → permanent self-wedge, 3 of 32 nodes at once with climbing etime on a *quiesced*
  cluster. Claim made owned + nestable via cmpxchg
  ([[ccloop-c7ee71c6-sess25-demoter-claim-clobber-ROOT-FIXED]]).
- **Outlives its holder**: 300 reload bails on one node, one inode, one demoter PID — and
  **`/proc/<pid>` was gone** while the claim was still set and still being observed
  ([[ccloop-c7ee71c6-sess28-ROOT-demoter-claim-outlives-its-holder]]).
- **The leaking site**, named by adding `demoter_comm/line/age_ms` to the probe: line 34955
  (`mxfs_trans_defer_inode_unlock`) — *the only claim in the tree whose CLEAR is in a different
  function*, 127 lines away. Healthy population: 1 bail, 150ms, kworker. Leaked population:
  224 bails, 180 **seconds**, comm=mkdir ([[ccloop-c7ee71c6-sess28-leaking-demoter-site-is-line-34955-trans-defer-unlock]]).
- **Root**: the P152 trans-free punt **deliberately retains** the claim when the committing
  task still owns ILOCK-EXCL, and nothing ever ended that retention. Fixed, A/B'd, 0 strands
  ([[ccloop-c7ee71c6-sess29-ROOT-FIXED-demoter-strand-is-the-trans-free-punt]]).

## 7. Sleeping in atomic context — twice, two transports

`mxfs_submit_partial_inode_write` holds `pag_ici_lock` and consults the DLM; on CAW the only
authority is the on-disk slot table, so that is a **blocking SCSI read under a spinlock** —
112-126 hits per node on all 16 ([[ccloop-c7ee71c6-sess20-atomic-bug-harness-truth-and-tcp-wedge]]).
The CAW arm was fixed; the **TCP arm** of `mxfs_v5_dlm_inode_held_nb()` — which promises
"never blocks" — still called down to a `struct rw_semaphore`, and `down_read()` schedules.
sess20's "AG-level ping-pong starvation" diagnosis for that wedge was wrong and should not be
re-chased: `readopt=49` over 781s is one re-adoption per 16 seconds
([[ccloop-c7ee71c6-sess21-tcp-wedge-root-sleep-in-atomic]]).

## 8. Other proven roots

- **Torn LOCAL fork**: `mxfs_dlm_reload_inode` ran `xfs_idestroy_fork` ~150 lines before
  `xfs_inode_from_disk`; `xfs_idestroy_fork` NULLs `if_data` but leaves `if_format=LOCAL` and
  `if_bytes` (it is written for teardown). The TOCTOU bail — the only `return` in that window —
  returned with the fork torn. Byte-exact in 514 microseconds
  ([[ccloop-c7ee71c6-sess20-three-roots-and-four-killed-hypotheses]]).
- **ILOCK/extent-map TOCTOU**: `xfs_ilock_data_map_shared` tests `xfs_need_iread_extents`
  *before* `xfs_ilock`, but MXFS's DLM acquire hook reloads the inode *inside* `xfs_ilock` —
  needs an aged cluster to reproduce ([[ccloop-c7ee71c6-sess21-ilock-extent-map-toctou-p192]]).
- **dir_epoch belongs to the inode NUMBER, not an incarnation** — tombstone/claim deliberately
  carry it across an idle gap and the `grant_meta` cache survives free+recreate, so every
  staleness compare was cross-incarnation. Same invalid-comparison class as the typeflip gen
  bug ([[ccloop-c7ee71c6-sess28-ROOT-dir-epoch-is-per-inode-number-not-incarnation]]).
- **readdir's 200× `msleep(1)` retry can never land** — the caller already holds ILOCK_SHARED,
  so the reload can never succeed. 1210ms → 5ms, 242×, same-build A/B. That stability
  (1201-1215ms every sample) was the tell ([[ccloop-c7ee71c6-sess28-ROOT-readdir-200x-msleep-retry-that-can-never-land]]).
  Separately measured: readdir of a peer-created dir costs **1240ms/op** against stat 4ms,
  open 45ms, rmdir 120ms — with no aging needed
  ([[ccloop-c7ee71c6-sess28-readdir-of-peer-created-dir-costs-1.2s]]).

## 9. The unmount-leak instrument graveyard (read before building another)

Four instruments were built and each **measured its own failure** — worth knowing so none is
rebuilt:

- A fixed 10-entry **history ring** cannot hold a leak by construction: a leak is an OLD grab
  with no matching release, and the ring has wrapped by unmount.
- A push/pop **stack** is wrong and must not be reinstated — grabs are tracked but plain VFS
  `iput()` from dentry eviction is not, so pushes outnumber pops and it only grows
  (`depth=12 over=19 under=0` on its first capture).
- **What worked**: record the grab that took `i_count` to N **in slot N**. With `icount=1` at
  unmount, slot 1 *is* the outstanding reference — self-correcting
  ([[ccloop-c7ee71c6-sess25-unmount-leak-attributed-and-linked]]).
- GPT's final-tenure narrowing (an inode joins the LRU only at `i_count==0`, so the survivor
  belongs to a NEW tenure) was built and returned `tenure_grabs=499` — **pairing is a dead
  end** ([[ccloop-c7ee71c6-sess27-unmount-leak-final-tenure-instrument-NEGATIVE]]).
- The leak was also **decoupled** from the demoter clobber — reproduced on a build where both
  fixes were active ([[ccloop-c7ee71c6-sess26-unmount-leak-decoupled-from-demoter]]).

## 10. Self-inflicted wounds worth never repeating

- **A wrapper MUST honour the wrapped function's contract.** `#define iput(vi)` →
  `mxfs_iput_tracked` dereferenced `vi` *before* calling `iput()`. **`iput(NULL)` is legal**
  and MXFS relies on it; `XFS_I(NULL)` is `-offsetof(i_vnode)`, so the ring write landed at
  address 0x33c → kernel panic in `pr_sweep_work_fn` → whole-rig cascade
  ([[ccloop-c7ee71c6-sess23-wrapper-null-contract-panic-and-board-state-model]]).
- **An infinitely self-recursive inline** shipped in a pending build:
  `mxfs_is_demoter() { return mxfs_is_demoter(ip) || …; }` — a guaranteed stack overflow,
  proven by objdump, not theory ([[ccloop-c7ee71c6-sess26-recursion-bug-and-two-refutations]]).
- **A "fully scoped, root proven" handoff that was a no-op.** sess27's creator-baseline stamp
  was implemented in full at four sites (sess27 named three and missed the one that mattered)
  and **measured to change nothing** — the epoch is 0 at every publish site
  ([[ccloop-c7ee71c6-sess28-REFUTED-creator-baseline-stamp-is-a-noop]]).

## 11. Measurement traps — the most transferable output of this era

- **A `grep -c` of 0 on a ring buffer is not absence.** A refutation that took minutes was
  wrong: the P152 line had aged out while the recent bail flood survived. Log retention varies
  ~60× per node. Carry the fact in state (a flag on the object) and print it at the point of
  damage ([[ccloop-c7ee71c6-sess29-measurement-traps-that-nearly-convicted-the-wrong-path]]).
- **`pr_warn_ratelimited` counts are not measurements.** P65 read 0-1 per run; a counted
  `pr_warn` at the same decision point showed the path firing **68×**. Always check which kind
  of probe you are reading before reasoning about its count
  ([[ccloop-c7ee71c6-sess21-measurement-traps-and-degradation-defect]]).
- An unscoped census makes both A/B arms identical; cumulative counters hide per-run deltas;
  storm harnesses that dump dmesg only on FAIL give you nothing from a passing run; serial
  console and ssh disagree about what a node did.
