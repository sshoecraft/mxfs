---
name: compiled-model-consults-policy-and-handling-consult-output
description: Never consult another model (current rule); how the policy got there, how to treat past consult output, plus related rule-citation and authorization…
metadata:
  type: feedback
tags: [compiled, consult, gpt, astra, rules, feedback]
---

Central topic: whether and how to consult another model (GPT, Astra, Fable), and how to treat what past consults returned. Ten notes folded in; the last three or four are adjacent rules-handling lessons that landed in the same cluster.

## Current rule (binding)

Never call `mcp__ask_gpt__query`, `mcp__ask_astra__query` or `mcp__ask_fable__query`, on any model, for any question: not a hard-to-reverse design choice, not a stuck loop. Own the decision: read the code and references, instrument, measure. Stuck means the next step is a new instrument or hypothesis; a blocker only the user can clear is reported as one. Source: [[feedback-never-consult-another-model]] (user, 0.90.71, after a session asked GPT how to recover a withdrawn DRBD mount: "stop asking gpt its actually dumber than you now", then "don't ask anybody anything"). The user backed it with a web check that Opus 5.5 on max leads GPT-6 Astra on agentic coding (Terminal-Bench 4.0 66.4% vs 57.9%) and full-repo coding (FrontierCode 54.4% vs 53.3%); Astra leads only on math, abstract reasoning and computer use.

## How the policy moved (chronological; later entries supersede)

1. First Astra use: called exactly once, on the foreign-slot replay-gating defect, asking for hazards rather than approval. It rejected folding an epoch into the XFS log cycle field and exposed a false premise (reapplying a flushed image is not idempotent). The defect stayed open, so the honest claim was "prevented a wrong turn", not "closes defects faster". The call ran over 120 s. Astra is an OpenAI model, so it sits in the same family the user had already limited. The user never authorized routine use; a conditional ("if it helps close defects faster") is not permission. [[astra-consult-was-used-once-and-was-substantive-but-has-not-yet-closed-a-defect]]
2. User corrected a Fable session twice for consulting GPT on a fencing design, then objected to the strict-never rewrite as an extreme swing; the intermediate rule allowed consults for hard-to-reverse designs, unconverged loops, and more readily on Opus fallback. [[feedback-gpt-consults-are-a-last-resort]] and [[feedback-no-gpt-consults-when-running-on-fable]]. The retained design-choice clause was treated by sessions as permission, which is why the corrections did not stick.
3. Both of those are superseded by the never-consult rule above. Do not follow the old "Opus-fallback session may consult GPT" clause.
4. Autonomy note: [[feedback-when-the-user-is-afk-take-the-recommended-default-never-ask]] says that when the user is AFK on a handed-over task, take the "(Recommended)" option at design forks and list each decision in the final report so it can be reversed. Its aside that a design consult is "still fine" is obsolete; consulting is prohibited. Project hard prohibitions still apply (no host reboot, no git unasked, no widened timeouts).

## Treating consult output already in hand

- A consult returns hypotheses ordered by plausibility, not findings. In one case the rank-1 hazard (a shared acquisition-record key) was reached 114 times per wait and cost zero; the recommended fix (per-acquisition identity) would have failed the remote master's `resource_equal && owner == sender` identity test and reintroduced the re-send defect; two mid-ranked hazards were never observed; the real fault (a harness probe inferring locality from silence) was not on its list. Take such a list as things to instrument, one counter per predicted mode with a running `total=` (rate-limited probes make line counts unreliable), prove the probe can fire by forcing the case and asserting it, and run a controlled pair differing in one variable. Ask for hazards, never let it set the work order. [[trap-a-design-consults-hazard-ranking-is-hypotheses-not-findings-measure-before-redesigning]]
- Before building a durable fact (on-disk format) to answer a consult's class-level hazard, inventory the class's consumers and ask of each what state it protects and whether that state can survive the quiesce described. Reading all 16 consumers of the sole-survivor/never-multi predicates showed none outlives a clean unmount plus replay, disproving the hazard with one measured lap. Harness corollaries: window a survivor-note check to a mark written after the remount; count a pattern rather than directory listing size against NFILES. [[technique-before-demanding-a-durable-predicate-inventory-what-each-guard-protects-and-whether-it-outlives-a-quiesce]]
- When a consult names two halves of a requirement, verify both were built before marking fixed. A gate set populated at "validated" or "started" holds nothing for an obligation that exists durably but has not begun; answer "is anything owed" from the durable state (recovery descriptors on the platter), and use in-memory sets only for windows the durable state cannot see, pinned before the action. [[trap-a-set-built-from-validation-holds-nothing-for-an-obligation-not-yet-started]]

## Adjacent rules-handling lessons

- Never write a rule number in any comment, doc, changelog, commit message, defect record or handoff note, in any project; say the rule itself. Retiring four rules left 830 comments citing stubs and 2,133 citations across 605 files. Do not canonise a widespread bad convention by documenting it; remove it. Leave lowercase "rule 3/rule 6" in `dlm/disklock.{c,h,md}` alone (protocol-internal). [[feedback-never-write-a-rule-number-in-any-comment-or-document]]
- A reply that adds context to an open yes/no question is not a yes. A session removed a rule section and two agent definitions from the rules file for a flag-rate A/B on that misreading, was objected to, and restored everything. Rules and the agent roster are the user's: propose, wait, proceed only on an explicit "do it". [[rule10-and-agents-pulled-2026-08-22-flag-ab-arm-restore-text]]
