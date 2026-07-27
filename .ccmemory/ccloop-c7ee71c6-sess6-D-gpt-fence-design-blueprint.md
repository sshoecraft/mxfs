---
name: ccloop-c7ee71c6-sess6-D-gpt-fence-design-blueprint
description: GPT RULE-5 design for the dir-block torn-write fix: tenure-authorized write fence + per-tenure publish registry + supersession certificates + reader…
metadata:
  type: reference
tags: [gpt-design, fence, tenure, dircrc, torn-write, blueprint]
---

# GPT design blueprint — dir-metadata write authorization (sess6 consult)

Consulted with the full sess6-C evidence (P-DIRWR gmode timeline). Key rulings:

## Core invariant (the north star)
"For every directory metadata bio, there exists ONE exact DLM tenure that
authorizes its exact buffer image, and that tenure remains physically
exclusive until the bio completes durably. A tenure may unlock only after
every committed mutation from it has durable publication or valid durable
supersession proof." Fence enforces half; exhaustive publication the other.
BOTH required — fence alone cannot make a missed committed update durable.

## Verdicts
(1) Submit-side fence: MANDATORY but gmode alone insufficient — needs
per-buffer authorization {resource, grant gen G, release nonce R, buffer
incarnation I, content seq W}; validate at FINAL submission (queued-vs-
submitted race); separate logical-quiesce vs physical-EX-held vs
DRAINING(G,R) vs PUBLISHED vs UNLOCKED states. Drain runs while EX still
PHYSICALLY held (mode pre-clear is logical only) = drain is restricted use
of a held grant, not an exception.
(2) Fence-refusal ≠ write-success. Dispositions: clean obsolete duplicate
(no AIL obligation) → discard immediately; AIL item WITH durable-
supersession certificate → stale/invalidate + retire normally; NO
certificate → quarantine, keep log obligation, fail release / shutdown
(post-release unsuperseded AIL item == release protocol failure).
Certificate = exact-item coverage + causally-later durable successor +
recovery can't replay old over new. "Later write to same daddr observed"
is NOT sufficient (format change / realloc / epoch passage ≠ content
supersession — the t6 danode was NEWEST content at an OLD epoch).
(3) Undestaged tracking must be epoch/tenure-stamped per buffer IMAGE
(incarnation-aware; aliases exist), stamped atomically with dirtying.
(4) Identical-content sub-EX writes still illegal (sector interleave with
concurrent format-change write tears). Content equality ≠ authorization.
(d) Drain exhaustiveness REQUIRED: per-tenure dirty REGISTRY populated
atomically at dirty time; QUIESCE admission → drain registry until empty
AND in-flight==0 (completion, not just submission, precedes unlock);
waits must not hold locks AIL/DLM callbacks need; on no-progress FAIL
CLOSED (withdraw), never unlock unpublished. Short-EX re-RMW of a stale
image is NOT a recovery (format may have changed; leaf can't merge into
node).
(e) Reader side: fence does NOT starve the HOLE TOCTOU — legit EX format
transitions still race readers. Need PR-held-through-decision protocol or
grant-gen/fork-seq recheck-and-restart; format mismatch after detected gen
change → restart/refetch, not fatal HOLE assert.
(f) Extra failure modes: bios crossing unlock (wait for COMPLETION before
unlock); queued-vs-submitted authorization; per-daddr buffer aliases; ABA
gen reuse (wide monotonic gens + nonce); LOG RECOVERY as unfenced producer
(replay must acquire EX + obey tenure order); dead-node EX transfer needs
storage fencing before regrant; durable ≠ bio-complete (FUA/flush);
scrub/grow/shutdown-writeback paths; dirty-before-registration race;
mutation during DRAINING; partial drain I/O error → no unlock; cross-block
transaction consistency (split touches multiple blocks); gmode read
without memory-order vs DLM transitions; clean≠harmless.

## Phased plan
- v1 (sess6, landed): at the P-DIRWR chokepoint — sub-EX && !drain-task:
  clean non-AIL → SKIP+stale, complete as success (provably safe: no log
  obligation; skip never worsens platter; kills producer B = 19/20 tearing
  writers). AIL-attached → ALLOW + P-FENCE-AILLEAK census print (b_epoch/
  cur_mep context) — the tear window narrows but REMAINS (t6-danode class);
  Defect A stays OPEN per RULE 6 until v2.
  Sanction = mxfs_task_in_dir_drain() task registry set across
  bast_process (demoter ctx), same pattern as FIX-26 wptask registry.
- v2 (next): per-tenure dirty registry + authorization stamps + AIL
  certificate/quarantine + completion-before-unlock + recovery-path
  fencing. Then reader seq-recheck (HOLE). Then re-verify CC/dir_reuse/
  full rungs.
