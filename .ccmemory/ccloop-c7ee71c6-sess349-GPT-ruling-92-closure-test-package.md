---
name: ccloop-c7ee71c6-sess349-GPT-ruling-92-closure-test-package
description: sess349 RULE-5 ruling: #92 closure = 6-part test package — pre-FUA gate knob for races 1+3, hb_forge wrong-stamp table for 4, GUARD loser audit + mix…
metadata:
  type: project
---

# sess349 GPT ruling — #92 minimal closure test package

Board on 0.13.0 went green first (27/28, only open_defects policy cell red;
crash_consistency re-ran PASS 29s/90s — its 15:39Z FAIL was the pre-existing
#37 create-pace flap, ALSO failed 3x today on 0.12.6 (05:46/06:16/09:01Z all
0/32 NO_TERMINAL_RECORD) each followed by PASS; NOT a 0.13.0 regression).

GPT (gpt-5.6-sol) ruling on the remaining #92 micro-race list — do NOT close on
runs (a)-(d) alone. Closure package:

1. **Race 1 (EMPTY between plain read and FUA confirm in check_dead)** — needs
   deterministic test: default-off SLOT-SELECTIVE pre-FUA gate knob in
   check_dead (after plain-read processing, before FUA read), with
   gate-reached visibility + explicit release + fail-safe timeout.
   Choreography: A tracks B; B stops advancing → A blocks at gate; cleanly
   unmount B; verify EMPTY on disk (caw_slotdump); release A →
   require P163-CLEAN-DEPART-CONFIRM, no death/fence/recovery-pending.
2. **Race 2 (dirty ACTIVE still fences)** — DONE (sess348 real-death run).
3. **Race 3 (stale EMPTY then fresh ACTIVE new tenant)** — same knob build,
   second gate point: after monitor classified EMPTY, before EMPTY-arm FUA
   confirm. Unmount B → A blocks; remount B (new ACTIVE+prov on disk);
   release A → A must reject stale EMPTY, reclassify fresh ACTIVE, track new
   stamp. Lineage clean-retire of OLD tenancy OK; any fence/retire of NEW
   tenant = FAIL.
4. **Race 4 (wrong-stamp EMPTY → conservative death)** — crafted-record
   writer tool (no kernel hook): dirty-stop victim B, before death threshold
   write valid clean-looking FLAG_EMPTY into B's slot with exactly ONE
   mismatched identity field; FUA-read back to prove; require conservative
   death+fence+recovery, NO P163. Table of 3: wrong node / wrong epoch /
   wrong fs-gen. Reset victim between cases. Dead dedicated slot only.
5. **Race 5 (EMPTY vs GUARD CAS)** — NO deterministic collision test needed
   (CAW serializes; one winner). Closure = loser-path code audit (every CAS
   miscompare → fresh read → shared classifier; no stale pending/election/
   reap/stamp survives loser path; both winners have complete cleanup) +
   ONE mixed end-to-end run: dirty-kill one node under I/O + concurrent clean
   unmounts of several others → exactly the dirty victim dies/fenced/replayed,
   clean victims get P163, zero recovery residue.
6. **Race 6 (ACTIVE→EMPTY→ACTIVE missed)** — virsh suspend A; umount+remount
   B once (verify epoch advanced, seq=S+1 chain=1 via dump); resume A inside
   <40s (death threshold ~87s) → require P163-CLEAN-DEPART-LINEAGE + rebase,
   no death. No kernel change.
7. **Race 7 (multi-cycle reuse)** — same but TWO umount/remount cycles while
   A frozen (seq=S+2 chain=2, tracked S at lower end of range). Separate run
   from 6 (tests range arithmetic).

Execution order (sess349): 6,7 on current 0.13.0 green fleet → mixed run 5
(dirties LUN) → GUARD audit → build gate knob 0.13.1 + hb_forge tool →
deploy/re-prep → 1,3,4 → #92 disposition.
