---
name: infra-src-mxfs-is-nfs-root-squash
description: /src/mxfs (whole source FS) is NFS from 192.168.1.4; squash/ownership quirks — files show root-owned, write failures can be silent/deferred; details…
metadata:
  type: project
---

# /src/mxfs lives on NFS — squash/ownership rules (user directive, sess6 ccloop 46efd8b6)

- The ENTIRE source filesystem at `/src/mxfs` is an NFS mount from **192.168.1.4**
  (clyde: NFSv3 on /src; test VMs: NFSv4.1 of the same export). The user's
  standing warning: "it's all going to be owned by root, all of it."
- Observed behaviors to remember:
  - Files/dirs commonly display **root:root** ownership even for content written
    as steve — server-side identity mapping. New files created by this session
    arrive owned root:root.
  - During a 2026-07-10 incident (~12:50Z–14:45Z) ALL client writes were denied
    (root_squash-type state): creates EACCES, and appends to existing files
    **failed silently/deferred** — `>>` reported success but data never landed
    (NFS close-to-open semantics swallow the error). ALWAYS verify a critical
    tree write by re-reading after `sync`.
  - `sudo` on clyde does NOT help (root is squashed); VM-root over ssh is also
    squashed. Fixes are SERVER-side only (192.168.1.4) — surface to the user
    immediately ("I need to fix that ASAP" — user), do not burn cycles on
    client-side workarounds beyond verification probes.
  - mode-600 files owned by "steve" can still be unreadable in squashed states
    (effective uid ≠ display uid): run.sh's mktemp→mv makes criteria.json 600,
    which then breaks `./run.sh` row listing ("jq: Could not open criteria.json").
- Practical rules:
  - After any permission anomaly under /src/mxfs: probe with (1) `touch` new
    file, (2) append+sync+re-read an existing file — the two can differ.
  - Workaround used successfully while read-only: run tests from a scratchpad
    copy (run.sh + tools/mxfs_sshpass.sh + tests/ + `git show :criteria.json`),
    since VMs only need READ access to /src for scripts and mxfs.ko.
  - To modify a root-owned file when direct write is denied but create works:
    write a new file and `mv` over (rename needs only dir write).
  - Heavy scratch I/O belongs in /tmp (local), not the NFS tree.
