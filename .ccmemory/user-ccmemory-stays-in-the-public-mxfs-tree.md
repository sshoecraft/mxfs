---
name: user-ccmemory-stays-in-the-public-mxfs-tree
description: USER 2026-09-25: .ccmemory stays committed in the public MXFS repo — a clone with the ccmemory MCP gets every memory. Never propose removing it.
metadata:
  type: user
tags: [repo-hygiene, public-repo, ccmemory, user-decision]
---

Decision by the user, 2026-09-25, answering the open "repo hygiene" item (whether agent state stays in the public tree):

**`.ccmemory/` stays in the public github.com/sshoecraft/mxfs tree.** It is a feature, not leakage: anyone who clones the repo and has the ccmemory MCP installed gets all of the project's memories — the traps, techniques and corrections — for free.

How to apply:
- Do not list `.ccmemory` removal, `.gitignore`-ing it, or moving it out of the repo as a hygiene item again. The question is closed.
- This is consistent with the commit rule that `.ccmemory/` travels in every commit.
- Because it is public, a memory must never hold secrets or test passwords (those live in `~/.config/mxfslab/secrets`), and site specifics belong in the lab file, not the tree.
- Still open from the same hygiene item: the root launcher scripts and other root scratch files — that part was not decided.
