---
name: trap-ledger-next-vs-next-step-two-fields-and-the-reader-showed-only-one
description: TRAP (sess566): the RULE 6 ledger has both `next` and `next_step`; defects.sh -d showed only the first, hiding ~130k chars on 18 open records. ledger…
metadata:
  type: feedback
tags: [trap, ledger, rule6, tooling, sess566]
---

# The defect queue had two "next step" fields and showed you one

sess566. `tests/criteria/OPEN_DEFECTS.json` records carry up to three spellings of the
same field: `next`, `next_step`, `next_steps`. `defects.sh`'s `nextstep()` returned the
**first non-empty** one, so on any record carrying two, one was invisible.

**Scale:** 18 of 86 open records populate both. Roughly 130,000 characters of guidance,
never displayed. On several records the hidden field holds MORE text than the shown one
(`D-32NODE-SHARED-DIR-CREATE-PACE`: 36,065 hidden vs 33,181 shown;
`D-NOINO-RELFENCE-AIL-FREEZE-474`: 12,446 hidden vs 1,473 shown).

**Why it compounds:** `tools/ledger_set.py prepend <ID> next_step ...` writes whichever
field you name. Recent sessions name `next_step`. Older records carry `next`. So a session
could write a full analysis to a record that already had `next`, get `ok: prepend ...`
back, and have deposited it where nothing reads. The **session-start state hook** uses the
same function, so every session opened on a partial view of its own queue.

**Fixed** in 0.75.104: the list view now shows every populated variant, labelled
(`[next_step] ... || [next] ...`), newest spelling first. Nothing merged, nothing moved —
consolidating the fields is a data migration and belongs in a deliberate pass. The
single-record view `./defects.sh <ID>` was NEVER affected: it prints each field
separately from its own `TAIL` list, which is why this survived so long.

## How I found it, and the near-miss on the way

I queried `next_step` alone, got 56 open records "with no next step", and was about to
report a systemic planning gap. Only one record is actually planless
(`D-MATRIX-UNMEASURED`, minor) — the other 55 have `next`. I checked the field list
before acting, and the wrong finding became the right one.

**The habit that saved it:** before believing a count, ask what would make it wrong. Same
habit that caught a `pr_warn_ratelimited` probe reporting exactly 10 (the burst ceiling)
earlier the same session, and a harness regex matching `[PASS]` against output that prints
a bare leading word.

**When writing to the ledger:** check which field a record already uses
(`./defects.sh <ID>` shows all of them) before choosing where to prepend, or your work
lands in the field the summary view is not reading.
