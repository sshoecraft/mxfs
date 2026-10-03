---
name: trap-a-board-chain-read-back-shows-the-standing-board-so-a-run-sh-that-never-started-reads-green
description: TRAP (0.90.41): host preflight aborted all 6 release boards (run.sh rc=3); board_4node_chain read back the OLD 31/31 boards and the chain logged rc=0.
metadata:
  type: feedback
tags: [release, harness, trap, preflight]
---

Observed 2026-10-02, tests/evidence/release_verify_0.90.41.log: the "boards nodes=[8 4 2] side by side" step took 14 s and reported six boards at "Total: 31 — 31 PASS / every criterion green". Every run.sh had aborted at clyde_preflight (test-LUN pool filesystem at 88%, limit <88%) with rc=3. tools/criteria.py prints the STANDING board, which still held the previous release's rows, and board() in tests/board_4node_chain.sh graded only that read-back.

Fixed in 0.90.41: board() returns 1 when run.sh's own rc is non-zero.

Lesson: a chain step's wall time is evidence. A board step that took seconds instead of ~27 min ran nothing; read the board log before believing any "every criterion green". The host filesystem carries the pool LUNs, guest images and the user's caches (vllm/huggingface), so it creeps over the 88% gate between runs. The pool tool's `destroy <number>` (not `lunNN`) on a free LUN is the project-owned lever; deleting other sessions' /tmp scratch was refused by the permission layer.
