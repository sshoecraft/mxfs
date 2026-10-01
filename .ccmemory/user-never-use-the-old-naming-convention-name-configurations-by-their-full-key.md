---
name: user-never-use-the-old-naming-convention-name-configurations-by-their-full-key
description: USER 2026-10-01 (angry): NEVER use the old naming again ("2-node TCP", "8-node CAW", TCP/CAW, tcp/cawd/cawp codes). Always <nodes>/<class>/<method>/<…
metadata:
  type: user
tags: [user, naming, configuration, readme, documentation]
---

## The directive

The user, 2026-10-01, after a README table and a chat summary used "(TCP)",
"(CAW)" and "2-node TCP": "you are never going to use the Old Naming Convention
ever again, yes? Confirm."

## What that means

- A configuration is named ONLY by its full key `<nodes>/<class>/<method>/<attach>`:
  `2/net/mesh/direct`, `8/disk/caw/direct`, `4/net/mesh/mpath`. This applies
  everywhere: chat, README, docs, CHANGELOG, defect records, commit messages,
  release notes, queue files, harness output written by me.
- A lock manager is named `net/mesh` or `disk/caw`, never "TCP" or "CAW", and
  never "the TCP transport" or "the CAW transport" as a name.
- Never "N-node TCP", "N-node CAW", "TCP or CAW", "on TCP", "on CAW".
- Never the retired condition codes `tcp`, `cawd`, `cawp`, `caw`, `tcpmp`
  (data/configurations.json `retired_keys`; the tools refuse them).
- A family is written as a pattern of the key: `{2,4,8}/net/mesh/direct`,
  `8/*/*/direct`, `*/disk/caw/*`.
- Existing code and parameter identifiers (`force_transport`, `dlm_caw.c`,
  `mxfs_v5_dlm_transport_caw`) are not renamed without being told to.

## Why

0.90.37 replaced the condition codes because each one fused two independent
choices (lock manager and attachment) and hid that every release was verified on
`direct` only (docs/attachment-methods.md, "Why four fields"). Old names in new
text bring that ambiguity back, and the user had just asked for the README to
document the configurations.
