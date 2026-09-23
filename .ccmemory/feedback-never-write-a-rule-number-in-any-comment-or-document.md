---
name: feedback-never-write-a-rule-number-in-any-comment-or-document
description: USER DIRECTIVE 2026-09-10: never write a rule number in any comment, doc, commit message or record. Say the rule itself. Applies to every project.
metadata:
  type: feedback
tags: [user-directive, rules, comments, citations]
---

## The directive

User, 2026-09-10 (profanity removed, meaning unchanged):

> "Yeah, see this is the problem with citing rule numbers instead of rule names
> or the actual rule. I told the other project to stop doing that too. Do not
> use rule numbers in any comments or documents. Stop it completely."

**Applies to every project, not just MXFS.** The user had already given the same
directive to the ccenv project.

## What it means in practice

Never write `RULE 0`, `RULE-4 PROVEN`, `RULE-5 ruling`, `per RULE 6`, or any
numbered form — in source comments, docs, `CHANGELOG.md` entries, commit
messages, defect records, handoff notes, or awareness docs. Say the thing:

| instead of | write |
|---|---|
| `RULE-4 PROVEN` | `PROVEN BY INSTRUMENT` / "established by instrumentation, not by reading code" |
| `RULE-5 ruling <name>` | "design-consult ruling, recorded in ccmemory as `<name>`" |
| `RULE 0` (a budget) | "derived time budget" / "a timeout IS a test failure" |
| `RULE 0` (the ceiling) | "the 2x-native-XFS performance ceiling" |
| `per RULE 3` | "this script lives in the tree deliberately, not as scratch" |
| `RULE 6` | "this is a defect and stays open until disposed of" |

Rule numbers belong ONLY inside the rules file itself, as its own headings.

## Why it bit, concretely

The 2026-09-10 audit retired four project rules. **830 comments in the tree
instantly began citing retired stubs.** A census found **2,133 rule citations
across 605 files** — the debt is real and the user is right that it was avoidable.

## The trap I fell into on the way

Having found the 2,133, I wrote a section into `CLAUDE.md` *documenting the
numbered labels and what they meant* — effectively blessing the convention the
user wanted killed. Corrected the same turn. **When a bad convention turns out to
be widespread, that is an argument for removing it, not for canonising it.**

## Sweep exclusion — do not destroy this

`dlm/disklock.c`, `dlm/disklock.h` and `dlm/disklock.md` use lowercase
**"rule 3" / "rule 6" for the DISKLOCK PROTOCOL's own internal rules**
(recovery-descriptor invariants, broadcast-predicate splitting). Nothing to do
with the rules file. Any sweep must leave them alone.
