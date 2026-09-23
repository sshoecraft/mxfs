---
name: technique-audit-a-stated-invariant-against-every-site-that-must-honour-it
description: TECHNIQUE (sess482): grep every site that must honour an invariant the code states in a comment, and diff them. Found a dcache ABA in one call — 9 of…
metadata:
  type: project
tags: [technique, audit, invariant, dlm, dcache, rule4, rule6]
---

# Audit a stated invariant against every site that must honour it

## The technique

Many defects here are not subtle logic errors — they are **one site out of N
that forgot a rule the codebase states explicitly, usually in a comment next
to a field declaration.** Those are findable mechanically, without the rig,
without a reproduction, in a single command:

1. Find an invariant the code **states about itself**. Field declarations are
   the richest source: `unsigned long i_dlm_epoch; /* Bumped every time this
   node LOSES the inode's DLM grant (mode -> NL) ... */`.
2. Enumerate **every site that must honour it** — here, every assignment of
   `i_dlm_mode`.
3. **Diff the sites against each other.** Conformance is usually
   byte-identical, so the outlier is unmistakable.

In sess482 this took one command and found a directory-lookup ABA:

```
NL@17331 OK-bump   NL@17348 OK-bump   NL@19084 OK-bump   NL@24139 OK-bump
NL@31611 OK-bump   NL@31696 OK-bump   NL@36528 OK-bump   NL@36832 OK-bump
NL@38701 OK-init   NL@32755 *** NO EPOCH BUMP ***
```

Nine sites carried the identical three statements
(`epoch++; epoch_src = __LINE__; relbar_epoch_check(ip);`). One did not.
That one was `D-PHANTOM-GRANT-BAIL-SKIPS-EPOCH-BUMP-DCACHE-ABA-482`.

## Why it works here

The invariant is load-bearing for a **cache**, and a cache that wrongly says
"fresh" fails **silently** — no error, no EIO, just a lookup answering from a
warrant that was withdrawn. Silent failures do not show up in a board; they
show up as an unexplained wrong result three defects later.

## Prove the enumeration is COMPLETE, or the audit means nothing

This is the step that turns an audit into evidence. For `i_dlm_mode`:

- 18 writes in the **entire tree**, all in one file (every hit in `pal/`,
  `dlm/`, headers is a comment).
- `MXFS_LOCK_NL == 0`, so a `= 0` spelling would have escaped a by-name grep —
  **checked, none exists**. No `WRITE_ONCE` writes either.
- Known false positive: a multi-line `ip->i_dlm_mode == MXFS_LOCK_NL`
  *comparison* matches a naive `=\s*(.+?);` assignment regex. There is one at
  ~24018. Always eyeball the flagged lines.

Only after that could I say "every route to NL now bumps", which is a much
stronger claim than "I fixed the one I found".

## What it does NOT give you

A source audit proves the invariant was **violated**; it does not prove the
branch **executes**. Here the branch's own probe fired **0 times** in a
2.9M-line, 32-node row. Two things follow:

- File it as landed-and-**unverified** and keep it open. A patch is not a fix.
- **A printk count is not a denominator.** Zero warnings bounds nothing unless
  you also know how often the branch's *precondition* was reached — which
  nothing counted. Add the precondition counter before saying "rare".

## Where to point this next

Any field whose comment says "always", "every", "must" — and any place the
codebase already redesigned one consumer of a transition for robustness. **When
one transition feeds two independent consumers, hardening one does not harden
the other**, and the second is forgotten *because* the first was done
carefully. That is exactly what happened here: the ICLUSTER coverage sweep was
deliberately made robust to exotic NL transitions; the dcache epoch counter,
fed by the same transitions, was not.
