---
name: trap-settings-deny-rm-rf-slash-star-blocks-every-absolute-path-rm
description: TRAP (sess493): .claude/settings.json deny "Bash(rm -rf /*)" is a WILDCARD — it denies rm -rf on ANY absolute path, even a literal scratchpad dir. Us…
metadata:
  type: feedback
---

# The deny entry is a glob, not a literal

`.claude/settings.json` deny list carries `"Bash(rm -rf /:*)"` and `"Bash(rm -rf /*)"`. The second was written to forbid the literal shell glob `/*`, but Claude Code reads `*` as a pattern wildcard, so it matches `rm -rf /tmp/claude-1000/.../scratchpad/mxfs_0705` too. sess493 was denied twice (11 explicit literal paths, then a single one) — no prompt, just a denial, in an unattended loop.

## What works
Change directory first and remove by relative name, one Bash call:

    cd /tmp/claude-1000/-src-mxfs/<sess>/scratchpad && rm -rf mxfs_0705 mxfs_0706; cd /src/mxfs

That is exactly what the deny intends to allow (a named scratch dir), and it still never touches `/` or a variable/glob path (RULE 2b).

## Why the trees were there
`tools/scratch_build.sh` copies the whole tree (~600-700 MB per version) into the session scratchpad on clyde's ROOT ext4 (`/dev/nvme0n1p2`, the same fs that carries the LUN and VM images) and never removes it after freezing. Eleven of them = 15 G = the 88% preflight refusal at the sess492 boundary. After removal: 87%, 233 G free, preflight PASS. Remove the scratch tree after the FROZEN line lands (the frozen ko/tools live on NFS under tests/evidence).
