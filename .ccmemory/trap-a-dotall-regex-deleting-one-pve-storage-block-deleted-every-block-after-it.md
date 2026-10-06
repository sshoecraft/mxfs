---
name: trap-a-dotall-regex-deleting-one-pve-storage-block-deleted-every-block-after-it
description: TRAP (0.90.55): re.sub(r"(?ms)^mxfs: shared\n(?:[ \t].*\n)*") on /etc/pve/storage.cfg — DOTALL let .* cross lines and deleted nfs: iso too; builds fa…
metadata:
  type: feedback
tags: [pve, regex, config-edit]
---

Removing one section from /etc/pve/storage.cfg (the plugin for its type was gone, so `pvesm remove` could not parse it) with `re.sub(r"(?ms)^mxfs: shared\n(?:[ \t].*\n)*\n?", "", s)` deleted every section after it: with `s` (DOTALL) the `.*` inside the indented-line group ran across newlines to the end of the file. The cluster lost `nfs: iso`; both mkosimage builds failed with "storage 'iso' does not exist". The file had been copied to /root/storage.cfg.backup first, which is how it was put back (`pvesm add nfs iso ...` with the saved options).

**Why:** the `(?s)` flag was copied in by habit; a line-oriented edit must not let `.` match newline.

**How to apply:** for line-structured config, drop DOTALL (`(?m)` only, `[^\n]*`), or parse into sections and drop one; diff the result against the backup BEFORE writing a cluster-wide file; always keep the copy-first step.
