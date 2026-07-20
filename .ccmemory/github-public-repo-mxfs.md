---
name: github-public-repo-mxfs
description: MXFS is public at github.com/sshoecraft/mxfs (created 2026-07-07, main, v0.10.0, GPL-2.0-only, framed "written entirely by AI").
metadata:
  type: project
---

Public GitHub repo created 2026-07-07: **https://github.com/sshoecraft/mxfs** (PUBLIC, branch `main`). Initial commit `47f699e` "MXFS 0.10.0 — initial public release"; head now `6f64177` (README authorship wording fix). `/src/mxfs` has a real `.git` + `origin` remote.

**Context (non-obvious):**
- An OLD `sshoecraft/mxfs` existed but was an **unrelated abandoned project** of the same name (last push 2026-02-12); it was **deleted first**, then this v5 tree published fresh.
- License = **GPL-2.0-only** — mandatory: MXFS is a GPL-2.0 Linux-XFS derivative, so the combined `mxfs.ko` can't be anything else. `LICENSE`=GPLv2 text; README, `packaging/mkrpm.sh` License field, and source SPDX headers are all GPL-2.0. Copyright **Stephen P. Shoecraft** (full legal name — NOT "Steve").
- **Version normalized to 0.10.0** from a messy state: `VERSION` was 0.6.3, `mxfs_common.h` fallback macros were 0.0.0, 4 man-page `.TH` headers were placeholder "1.0.0", stale `mxfs_0.5.7_amd64.deb` at root. Unified to 0.10.0 (above the highest in-tree ref 0.9.28, pre-1.0); deb removed. Build reads version from `VERSION` via `mxfs_version`.
- `CHANGELOG.md` (root) consolidates all 13 subsystem `## History` sections verbatim; per-subsystem sections stay in place.
- **Authorship framing:** README + repo description say **"written entirely by AI (Anthropic's Claude Code)"**, explicitly **"not by a human using an AI tool."** User caught that the earlier "written entirely by Claude Code" wording could be misread as a human using the CLI — reworded 2026-07-07. README also states WIP / tested to 16 nodes, pointing at `./showstat.sh <nodes> <dlm>` instead of hardcoding pass/fail.

**Publish policy (user's deliberate, informed choice — I flagged the leak risk, they chose full-tree):**
- `.gitignore` excludes ONLY: kernel build artifacts (`*.o *.ko *.mod* .*.cmd Module.symvers modules.order`), the 5 tool binaries under `/tools/`, and `tests/**/*.txt` + `tests/**/*.log` (~190MB dmesg/timeline captures). `.ccmemory/index.db` self-ignored by `.ccmemory/.gitignore`.
- **PUBLICLY INCLUDED** (deliberate): `.ccmemory/` memory (1293 files), `.claude/`, `CLAUDE.md`, all internal `*-analysis.md`/`sess*.md`/`journal.md`/`state.md`, `notes/`, `.ccloop/`, and infra references (IPs `192.168.120.182/186`, `192.168.1.4/166`, hostnames `clyde`/`test1`/`test2`). No secrets (`*.pem`/`*.key`/`.env`) — checked.
- Repo ≈28MB, 3523 files. A later scrub of infra refs would need history rewrite + force-push (they're in the initial commit) and may persist in caches/forks.

To push updates: standard `git` from `/src/mxfs` (git ops authorized for this repo per the 2026-07-07 publish directive; still confirm before force-push).
