---
name: feedback-never-write-lab-password-into-any-file-in-tree
description: User directive: the lab node root password belongs ONLY in ~/.config/mxfslab/secrets — never in prose, docs, comments, or handoff notes. Repo is PUBL…
metadata:
  type: feedback
tags: [secrets, git, public-repo, user-directive]
---

# Never write the lab password into any file in the tree

**User reaction (2026-07-27, verbatim):** "WHY IS A PASSWORD IN ANY FILE
OTHER THAN secrets????"

## What happened

At a "commit and push" the pre-commit scan found the lab node root
password in FOUR pending files. `git show HEAD:CLAUDE.md | grep -c` = 0,
so this would have been a **new** publication to
`github.com/sshoecraft/mxfs`, which is **PUBLIC** (`gh repo view` →
`isPrivate:false`).

Offenders — all documentation prose, zero of them functional code:

| File | Why it was there |
|---|---|
| `CLAUDE.md:224` | "Node root password is `<pw>`, kept in sync with osimager…" |
| `lab/README.md:68,73` | printed the secrets-file line **verbatim as the example** |
| `continue_troubelshooting.md:127-128` | pve1/pve2 handoff note, incl. `echo '<pw>' > /tmp/.proxmox_pass` |
| `.claude/awareness/subsystems/tests.md:27` | the `mxfs_secrets.sh` table row |

The perverse part: three of those four sentences *assert* "the password
is never committed" / "nothing hardcodes a password" — and then hardcode
it. `tools/mxfs_secrets.sh`, the actual credential-handling code, was
clean. **Prose is where the leak lives, not code.**

## The rule

The node root password lives in `~/.config/mxfslab/secrets` (mode 600)
and NOWHERE else. Not in prose, docs, comments, tables, examples,
awareness docs, ccmemory bodies, session handoff notes, or commit
messages. "Documenting it for the next session" is not an exception —
that is exactly how all four of these got written.

To reference it in docs, write: *"password from the lab secrets store"*
or `password=<the lab node root password>`, and point at
`tools/mxfs_secrets.sh passfile [path]`.

## Related, distinct defect

`infra-sshpass-2arg-litters-repo-with-password-files` — a *different*
leak path (calling `mxfs_sshpass.sh` with the passfile arg omitted wrote
the password into command-named files/dirs). Already fixed by the
command-shaped-path guard in `secrets_passfile()`. This memory is about
humans/agents typing it into docs, which no code guard catches.

## Pre-commit check (this repo is public — run it every time)

```bash
cd /src/mxfs
grep -rIn 'P@55' --exclude-dir=.git .            # must be empty
git diff --cached | grep -nE 'P@55|password=[A-Za-z0-9@]'   # must be empty
find . -path ./.git -prune -o -type d -name '*[ ;|&]*' -print  # sshpass litter
```

## Fixed in

Commit `053f3c4` (v0.11.139). All four sites scrubbed before staging;
`CLAUDE.md` note strengthened to "NEVER hardcode a test password in the
tree — that includes prose, docs, comments, and handoff notes, not just
code." `state.md` also untracked + gitignored (rewritten per handoff,
carries node credentials).
