---
name: trap-a-truncated-subagent-table-is-a-sample-never-generalize-a-field-from-the-shown-rows
description: TRAP (sess491): concluded 'all 53 releases were at PR' from a sweeper table that showed 80 of 647 rows; the full histogram was 36 PR / 17 EX. Ask for…
metadata:
  type: feedback
tags: [trap, subagent, evidence, sess491]
---

# TRAP: a truncated subagent table is a sample

sess491, D-0491: a log-sweeper returned 80 of 647 rows for the directory's lock events on test23 (first 25 + a window + last 20). Every P51-REL row SHOWN had held_mode=3, and the tag histogram said "P51-REL 53". I combined the two into "all 53 releases entered at PR", built a hypothesis on it (EX ends outside the release pipeline), had a scout map every mode-write site, and wrote it into a relay memory. A second sweep with an explicit per-value histogram gave 36 at PR and 17 at EX on that node, and EX-entered releases on all 32 nodes.

The shown rows were selected by position (head / window / tail), and the EX releases sat in the omitted middle (the create wave). Position-selected rows carry no information about the distribution of a field.

## Rule
- When a subagent report truncates a table, every claim of the form "every row has X" or "no row has Y" is UNSUPPORTED unless the report states a full-population count for that field.
- Ask the sweeper for `field -> count` histograms over the whole match set, and only then for rows.
- Before turning a "never / always" observation into a hypothesis, re-derive it with a count over the full population (one grep -c), the same way a disposition-critical negative is re-run in the parent.

Related: RULE 10's cap hazard (selection is a conclusion wearing evidence's clothes) — this is the same hazard on the parent's side of the cap.
