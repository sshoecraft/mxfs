---
name: feedback-never-write-source-in-tmp-scratch-copy-even-during-rig-runs
description: USER (sess428, emphatic): NEVER write source into a /tmp scratch copy of the tree (w038 pattern) — it is lost on reboot. Edit in /src/mxfs; sequence…
metadata:
  type: feedback
---

# User directive (sess428, 2026-08-28): no source in /tmp — ever

Observed: sess427/428 kept a modified copy of the tree in the session scratchpad (`…/scratchpad/w038`) to avoid racing an in-flight rig chain's build, and wrote NEW source files there (dlm/tauth_view.{c,h}, include/mxfs/mxfs_sha256.h, tests/tauth/view_format_test.c, header edits). User: "WHY ARE YOU PUTTING THAT IN /TMP????? WE WILL LOSE IT WHEN THE SERVER REBOOTS!!! … how many other sources have you written to /tmp that will be lost???"

Rule: every source/test/doc edit goes in /src/mxfs directly. The build-race concern is handled by SEQUENCING (do not run `make` in the tree while a chain's build/proof stage runs; editing sources while a chain is at prep/test stages is safe — it insmods the already-built .ko), never by relocating sources. RULE 3 already says this; a scratch COPY of the tree is the same violation.

State at the boundary: everything that ever lived only in w038 has been ported into /src/mxfs (0.38.1→0.38.3 code, view-record build step 1 files). Nothing remains only in /tmp. Remaining step-1 items (do IN TREE): tests/tauth/Makefile target for view_format_test (+ tauth_view.o in the mesh objects if needed), mkfs_mxfs.c writes the root (mxfs_tauth_root_init_empty at mxfs_tauth_ctrl_off(2)) and zeroes the slots, chk_mxfs.c check_tauth validates the ctrl pages via mxfs_tauth_ctrl_validate, then `make modules` + `make tools` + `make -C tests/tauth clean test` AFTER tests/evidence/sess428_s432.log shows DONE. VERSION bump to 0.39.0 for the format change (PROTO_GEN 10).
