---
name: trap-a-kernel-message-containing-debug-colon-is-counted-by-every-bug-colon-sweep-and-ls-la-digests-differ-on-the-local-parent
description: TRAP (sess608, D-0932): a probe line saying "DEBUG:" contains "BUG:" and scored 71 splats; `ls -la` digests across nodes differ because '..' is each…
metadata:
  type: feedback
tags: [harness, measurement-integrity, dmesg, D-0932]
---

# Two false FAIL rows from one otherwise clean lap (s608b, tests/d0932_platter_fallback.sh)

1. **"DEBUG:" in a kernel message is a splat to every `grep 'BUG:'` sweep.**
   The new `P238-FENCE-TAKEOVER-DECLINED` line ended "— DEBUG: the holder is
   proved revoked ...". The harness's "zero shutdown / BUG / Oops" row counts
   `grep -ac 'BUG:\|Oops'` over the journal and scored got=71, exactly the
   DECLINED count. `dlm/dlm.c:2245` carries the same substring in a live
   message ("— DEBUG: residue kept as our grant") and will do the same to any
   sweep that meets it. Rule: never put "DEBUG:" in a printk; the tree's
   convention for test-only lines is "TEST ONLY:" (P236-FENCE-INTENT-HOLD).
   MODULE_PARM_DESC strings are fine, they never reach dmesg.

2. **`ls -la <mount> | md5sum` is never equal on two nodes.** `-a` lists `..`,
   which is each node's LOCAL parent directory (/mnt) with its own mtime, so
   the "both nodes see the same root listing" row scored differ on a healthy
   cluster. Compare `ls -A -l --time-style=+%s` (no `.`/`..`, stable time
   format), or compare the shared root's entries by name and size.

Both rows were fixed in the harness (and the kernel line reworded) before the
re-run; neither was an MXFS defect. The lap's actual measurement — the platter
judge answering REVOKED for a published prover's tuple on a fresh two-node
judge — was clean.
