---
name: sess54_lessons
description: sess54 — REFUTES sess53 shortform-reload reframe; re-confirms inode-REUSE type confusion + NL-cache coherency root; reliable 19s repro; instr HIDES it.
metadata: 
  node_type: memory
  type: project
  originSessionId: 80482414-55b0-41bc-972e-c9ca6b971792
---

# sess54 (2026-06-03) — cache_coherency root re-confirmed: NL-cached inode coherency gap

Build under test: srcversion `C2D30DB0A37A12264B76A35` (sess53 build, all 4 nodes test1-4, CAW, /dev/sda, /mnt/shared).

## sess53's "shortform-dir reload-not-firing" reframe is REFUTED
- With `instr=1` the cross_visibility test PASSES (all nodes see all files). The 100x
  printk slowdown HIDES the race. **Never diagnose this with instr=1** (re-confirms the
  sess39/53 warning, now with direct A/B evidence: instr=1 PASS, instr=0 FAIL).
- My loose minimal repro (background `&` creates + sleep) also PASSED 12/12 — too loose;
  the bug needs the harness's TIGHT barrier-synchronized concurrent creates.

## RELIABLE REPRODUCER (instr OFF, ~19s, deterministic)
Against a live 4-node mount:
```
MXFS_TESTS_DIR=/src/mxfs/tests ./tests/run_tests.sh --nodes 4 --phase cluster \
  --test test_cross_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared
```
Per-node detail: `~/.mxfs/results/<ts>/test_cross_visibility/nodeN.log`.
(My `tests/repro_cv.sh` does NOT reproduce — too loose; use the real harness.)

## THE ACTUAL FAILURE (instr=0) — two faces, both = NL-cache coherency
### Failure A: inode-number REUSE type confusion → "Is a directory"
`cat .../node3.txt` → "Is a directory". dmesg:
`mxfs: INODE-REUSE-EVICT ino=6291584 incore_ftype=2(DIR) dirent_ftype=1(REG) name=node3.txt try=1`
then (NON-FATAL, no shutdown) `xfs_dir3_data_reada_verify` "corruption" on ino 6291584 —
and the 128-byte dump of that "corrupt dir block" literally contains `"hello from node 3\n"`.
=> ONE inode (6291584) was a DIRECTORY in a prior incarnation (churned barrier/test dir,
freed); a node REUSED the number as the NEW reg file node3.txt + wrote its data. A PEER
still holds a LIVE in-core cached inode of the OLD type (S_IFDIR), serves it to the VFS
(EISDIR) and reads the reg-file data block as a dir block (verifier error, non-fatal).

### Failure B: a file invisible even to its OWN creator
node2 cannot see its OWN node2.txt (nor can anyone). => concurrent shortform→block dir
conversion lost-update on the shared parent dir `d` (a node mutates a STALE cached shortform
copy and drops a peer's just-committed entry on conversion).

## ARCHITECTURAL ROOT (Gemini-confirmed, RULE 5)
MXFS caches in-core inodes / dcache / dir-blocks at **NL (no DLM grant)**. Disk-polled CAW
has NO targeted callback, and the bast poll thread only scans slots THIS node HOLDS — so a
peer's free/realloc/dir-modify NEVER BASTs an NL-cached holder. The stale copy is served
forever. The invariant MXFS violates: **the VFS cache (dentry/inode/page/dir-block) must be
a projection of DLM state — never serve cluster-visible metadata without a covering grant.**
This is the GFS2/OCFS2 glock model.

The current sess48/49 fix (xfs_inode.c ~L701-738: ftype-mismatch detect → force_peer_flush
+ i_dlm_stale + d_prune_aliases + irele + retry_iget, gen-gated recycle re-read) is a
CONSUME-side point patch: it fires but the stale dir inode is already exposed to the VFS /
dir-readahead before/around the evict, and falls through if a dentry can't be pruned.

## FIX DIRECTION (Gemini Q1, partially truncated)
Choke point belongs in VFS-facing methods (`->lookup`/`->getattr`/`->d_revalidate`),
strictly AFTER VFS locks, NOT inside `xfs_iget` under ILOCK_EXCL (that deadlocks xfsaild —
the proven constraint). GFS2 acquires the glock in `->d_revalidate`/`->lookup` OUTSIDE the
parent i_rwsem, checks an on-disk generation, invalidates+rereads if stale, THEN instantiates.
Candidate reuse-invalidation mechanism (cheaper than forbidding NL-cache, which blows up
lock counts at 16 nodes): a per-inode-cluster on-disk generation/epoch bumped on alloc+free,
batch-polled for clusters we cache. (Gemini Q2/Q3 detail was truncated server-side; re-ask
with small max_tokens, it caps ~1 paragraph per call.)

## CONSTRAINTS (do not relearn)
- NO ILOCK_EXCL across CAW poll (xfsaild AIL-drain wedge). In-place reload under ILOCK_EXCL
  in path-walk lookup → D-state deadlock (sess45).
- NO per-op FUA in hot path (barrier markers are empty files hit constantly → 120s timeouts).
- instr=1 logging HIDES the race; use always-on detectors (SESS50-STARVE/COHOLD, P88, P51).
- Keep drain-before-unlock invariant (durable on release).

## Other always-on signals seen during the failure
- `P51-INSTR caw ... sense_key=0xe asc=0x1d` = SCSI MISCOMPARE-during-verify (CAW compare
  failures / slot churn under contention) — abundant.
- `P88-INSTR bnobt-WRITE-low-numrecs ... disk_differs=1 in_ail=1` still fires (bnobt
  staleness coexists; NOT the proximate cross_visibility cause this run).
- SESS50-STARVE abundant (PR readers re-granting vs EX waiter) — expected contention, not
  the proximate cause.

## NEXT (concrete)
1. Re-ask Gemini Q2/Q3 in tiny chunks (it truncates ~1 para/call) for the epoch-counter
   mechanics and the d_revalidate deadlock-safe sequence.
2. Implement DLM-grant-on-serve at the VFS choke point (->d_revalidate / xfs_lookup post-iget,
   OUTSIDE i_rwsem): acquire inode DLM PR, gen-check vs on-disk epoch, evict+recycle if stale,
   gated by epoch so it's not per-op-FUA.
3. Failure B: make dir EX-acquire reload dir inode+da/data blocks from authoritative storage
   before insert, gated by staleness epoch.
4. Build local, deploy via INSMOD_OPTS, re-run the 19s repro (instr=0), check nodeN.log +
   always-on detectors. Iterate per RULE 4.
