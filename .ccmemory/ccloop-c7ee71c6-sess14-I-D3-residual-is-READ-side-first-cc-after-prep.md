---
name: ccloop-c7ee71c6-sess14-I-D3-residual-is-READ-side-first-cc-after-prep
description: sess14: D3 residual ISOLATED w/ reproducer (first cc after fresh prep) — evidence REFUTES stale-reader theory: platter itself retains removed dirents…
metadata:
  type: project
tags: [d3, residual, lost-remove, land-before-release, reproducer, open, next-session]
---

# sess14-I: D3 residual — isolated, reproducible, and diagnosed to the platter

## Reproducer (confirmed on first attempt)
`./run.sh 32 caw prep_cluster` then IMMEDIATELY `./run.sh 32 caw cache_coherency`.
The residual clusters on the **first cc after a fresh prep**; later cc runs on the same
prepped cluster pass (10 consecutive at v0.11.131). Cheap (~3 min) and now known to hit.

## Shape (NOT the cv lost-add that P174 fixed)
    test1:FAIL: uv gone node9_file1..4      (31/32 nodes PASS)
`unlink_visibility`: node9 removed its 4 files; test1 still resolves the names.
380 P26-IGET-FAIL cluster-wide: `dp=27263113 name="node9_fileN" inum=... err=-2 ftype=1`
— the dirents resolve to inodes that ARE free.
Evidence: `tests/logs/firstcc_205730/` (all 32 dmesg + criteria row).

## DIAGNOSIS — my first hypothesis (stale reader) is REFUTED by the capture
test1 did NOT serve a stale in-memory fork. It reloaded, and the reload read the platter:
    [32949.369] P174-STALEGEN-ADOPT ino=27263113 dir_gen=138 loaded_gen=131 — forcing disk adopt
    [32949.370] P56-RELOAD-MERGE  ino=27263113  disk=[node9_file1 node9_file2 node9_file3 node9_file4]
                                                ours=[node9_file1 node9_file2 node9_file3 node9_file4]
**The DISK image itself still contains all four removed names.** So:
- P174 and the read path are working correctly (they faithfully adopted the platter).
- The inode frees DID land (iget returns free, err=-2).
- The parent directory's dirent removals did NOT land — a **lost REMOVE**, the exact
  asymmetry GPT named: the release drain can report success without landing (its
  "nothing dirty / EAGAIN" path), so a committed dinode change silently never reaches the
  home location. The dir is shortform, so the removal is a dinode-content change, while the
  inode frees live in a different cluster — which is why one landed and the other didn't.

## Next step (highest value, already specified)
Implement **strict land-before-release** (GPT design, sess14-D/H item 2a):
1. Track a per-inode publication obligation (pending image seq vs durable seq) INDEPENDENT
   of ordinary XFS dirty state.
2. The release drain must not report success while `pending > durable` — its EAGAIN /
   clean-skip path must reconstruct and submit the image, not return success.
3. A drain that cannot land must fail the handoff (retry bounded, then fence/withdraw) —
   never release the grant silently.
Verification: the reproducer above. Confirm on node9's side first — look for
`P146-RELDUR ... flushed=1 wrote=0 rerr=-11` on ino 27263113 in its dmesg (that print is
the signature of the drain declaring success without writing); it is the same rerr=-11
pattern already seen repeatedly this session and previously dismissed as benign.

## Correction to carry forward
`rerr=-11` (iflush_cluster EAGAIN, "nothing dirty") was recorded in sess13 as
"RESOLVED benign". That verdict is WRONG in the presence of a pending publication
obligation — it is exactly the silent non-landing path. Treat it as suspect.
