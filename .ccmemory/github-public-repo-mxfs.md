---
name: github-public-repo-mxfs
description: MXFS is public at github.com/sshoecraft/mxfs (GPL-2.0-only, "written entirely by AI"); tests/evidence and .ccloop/runs are NOT published since 0.89.7…
metadata:
  type: project
---

Public GitHub repo created 2026-07-07: **https://github.com/sshoecraft/mxfs** (PUBLIC, branch `main`). `/src/mxfs` has a real `.git` + `origin` remote.

**Context (non-obvious):**
- An OLD `sshoecraft/mxfs` existed but was an **unrelated abandoned project** of the same name; it was **deleted first**, then this v5 tree published fresh.
- License = **GPL-2.0-only** — mandatory: MXFS is a GPL-2.0 Linux-XFS derivative, so the combined `mxfs.ko` can't be anything else. Copyright **Stephen P. Shoecraft** (full legal name — NOT "Steve"); `MODULE_AUTHOR` matches it since 0.89.77. Upstream XFS `Author:` lines (Darrick Wong, Allison Henderson) are GPL notices and must stay.
- Version comes from `VERSION` via `mxfs_version` in `packaging/common.sh`.
- **Authorship framing:** README + repo description say **"written entirely by AI (Anthropic's Claude Code)"**, explicitly **"not by a human using an AI tool."**
- **README top block** (0.89.77): the released configuration is **2 nodes on TCP only**; more than 2 nodes and CAW are in development. Keep it that way until the user says otherwise.

**Publish policy (user decisions):**
- 2026-07-07: full tree public, including `.ccmemory/`, `.claude/`, `CLAUDE.md`, internal notes and infra references (lab IPs, hostnames).
- 2026-09-23 (0.89.77 release): **`tests/evidence/` and `.ccloop/runs/` are ignored and untracked** — evidence had reached 22 GB / 107k files (past GitHub's 2 GB push limit) and `.ccloop/runs` is local loop state. They stay on the rig host.
- 2026-09-23: user reviewed a full scan and ruled that **lab IPs, hostnames, hardware IDs (IQNs, WWIDs, MACs) and `/home/steve` paths stay** — private-LAN values give nothing away, and `/home/steve` only appears in lab-only rig scripts, never the build or packages. Do not scrub them. What must never be published: credentials. The rig password lives only in `~/.config/mxfslab/secrets`; verified absent from the tree and from all history at that date.
- History is not rewritten: the user cares about going forward only.

**Releases:** `scripts/release.sh` builds the .deb, Proxmox .deb and .rpm in containers; `--publish` creates the GitHub release. git ops (commit/push/release) happen only when the user directs them in that turn.
