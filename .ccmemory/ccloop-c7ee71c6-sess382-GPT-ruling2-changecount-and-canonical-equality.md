---
name: ccloop-c7ee71c6-sess382-GPT-ruling2-changecount-and-canonical-equality
description: sess382 RULE-5 ruling 2: suppress both changecount bumps under pipe_relog, but land a COMPLETE canonical-equality oracle FIRST; SELFAHEAD needs EX re…
metadata:
  type: project
tags: [mxfs, changecount, obligation, rule5, gpt-ruling]
---

# sess382 RULE-5 ruling 2 — changecount, canonical equality, and SELFAHEAD

Context: the fenced-publication wedge fix (0.18.2) verifies against fault
injection but all 9 NATURAL firings report `closed=0`. Correlation showed the
fence is always **P119-NONEX-FLUSH-SKIP** (we no longer hold EX) with
`P219-LOGGED-NO-AUTHORITY`, the reload **waits** for the demote
(`P198-RELOAD-DEMOTE-WAITED` — so P34J was NOT the bail), and the outcome is
either `P-RELOAD-IDENTICAL` or `P34F-RELOAD-SELFAHEAD-SKIP`.

## Q1 — the second self-inflicted loop is real; suppress BOTH bumps

The drain's own re-log is a CORE-logging transaction, so it bumps `i_version` /
`di_changecount` — MXFS's cross-node freshness stamp, deliberately forced to
"one bump per CORE-logging transaction" by sess6. After a re-log storm our
in-core looks strictly AHEAD of the platter **purely from our own repair
attempts**, which is exactly what `P34F-RELOAD-SELFAHEAD-SKIP` refuses to adopt
over. Same shape as the `pending_seq` runaway, different counter.

**Ruled correct.** Suppress both the upstream clean→dirty bump and the MXFS
forced per-CORE-transaction bump under `i_mxfs_pipe_relog`. A re-log is a new
*publication attempt*, not a new *logical modification*: "a repeated publication
of version 10 should still contain changecount 10; incrementing it to 11 would
falsely claim a modification occurred."

Guard: assert the canonical persisted image (excluding checksum/LSN) is
UNCHANGED across a pipe re-log. If that can fail, the flag is too broad and
suppression would hide a real modification.

Nothing should rely on a changecount EDGE to detect republication — use
changecount for logical version, DLM tenure for cache validity, and the
publication ledger for completion.

## Q2 — my planned fix was NOT sufficient

`P-RELOAD-IDENTICAL` compares gen, mode, format, size, nextents, and
`di_changecount == i_version`. Adding nlink + LOCAL fork bytes (my proposal)
closes the known holes but **is not complete**. Equal `nextents` is not equal
extents, just as equal LOCAL length is not equal LOCAL bytes. Also uncovered:
inline btree roots, attr fork format/contents, ownership/project ids,
timestamps, flags, block counts, device data, fork offset.

**Required:** a canonical field-by-field comparison of every persisted semantic
field and inline fork byte (or canonical serialization + byte compare),
excluding publication-only fields (checksum, LSN, padding). Compare against the
image owed by the obligated sequence, not whatever in-core state exists at
reload time; recheck `pending_seq`/version did not move between building the
expected image, reading home, and closing.

**Equal changecount but unequal canonical image is an INVARIANT VIOLATION** —
do not adopt, do not stamp durable, do not pick a side. It means one of the
protocol's premises is false.

Obligations covering metadata outside the inode sector need their own proof;
inode equality proves only the inode portion.

## Q3 — SELFAHEAD: reacquire authority, don't shut down the mount

There IS a correct middle option. Retain the obligation, asynchronously request
EX (holding no folio/transaction/DLM locks while waiting), and **after** the
grant, reload and reclassify: exact owed image at home → durable; valid newer
descendant → superseded; home older and ours still authoritative → publish under
the new EX and wait for real `iflush_finish`; equal version but divergent
content → invariant failure/fence.

Reacquiring EX is NOT permission to blindly write the stale image — the
post-grant reload decides. The sound rule is not "the original node must always
retake EX" but "**some recovery agent must obtain publication authority and then
either publish the still-authoritative owed state or prove it was superseded**".

Pinning correctness state need not mean whole-mount shutdown: an inode-scoped
blocked state with an EX recovery enqueue is a correct intermediate. What is not
correct is dropping the obligation because reacquisition was inconvenient.

If the DLM refuses EX while this obligation is open, that is a protocol cycle
needing a sanctioned recovery token (an extension of RELFLUSH), not a P119
bypass.

## Q4 — ORDER MATTERS, and it is the reverse of what I planned

**Land Q2 before Q1.** Q1 converts currently self-inflated SELFAHEAD outcomes
into equal-changecount outcomes; if the weak IDENTICAL test may then close the
ledger, Q1 opens a false-durable-close path for exactly the P175 class.

Order: (1) canonical equality oracle, weak equality fails closed; (2) validate
exact-match close AND crafted-mismatch refusal; (3) suppress both bumps under
pipe_relog; (4) EX reacquisition for genuine SELFAHEAD.

**Do not use the ~9-natural-events-per-board rate as the success metric.** Use
one per-episode probe (episode_id, obligated_seq, pipe_relog_count,
logical_image_changed, version before/after, cc before/after,
home_vs_owed_canonical_equal, close_result) and one counter:

```
bad_episode = (pipe_relog && !logical_image_changed &&
               (version_after != version_before || cc_after != cc_before))
           || (close_result == durable-identical && !home_vs_owed_canonical_equal)
```
Require `bad_episode == 0`, a nonzero deterministic eligible-episode count, and
positive controls for BOTH exact-match and deliberate-mismatch.

Injection cases for Q2: differing nlink; differing LOCAL data-fork bytes;
differing LOCAL attr-fork bytes; equal `nextents` but differing inline extent
records; differing inline btree-root bytes; plus an exact match that MUST close
(otherwise the test only proves fail-closed, not reconciliation).
