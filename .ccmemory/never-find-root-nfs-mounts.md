---
name: never-find-root-nfs-mounts
description: ABSOLUTE: NEVER run `find /` on clyde. Not ever. For any reason. No exceptions. (NFS mounts make it hammer the server, but the rule is unconditional…
metadata:
  type: feedback
---

**NEVER run `find /` on clyde. Not ever. For ANY reason. No exceptions.**

This is an absolute, unconditional prohibition — not a "scope it better" guideline.
There is no situation, no urgency, no "just this once," no clever variant that
makes `find /` acceptable. If you are about to type `find /`, STOP.

**Why it is banned (context, not a loophole):** clyde has NFS mounts — `/src`
and `/data` are QNAP NFS (192.168.1.4; see
[[infra-src-is-qnap-nfs-do-not-touch-exports]]). A root find crawls into them,
which is slow and hammers the NFS server for the whole cluster. But the rule
holds regardless of the reason you think you have.

**What to do instead** (these are NOT exceptions to the ban — they are how you
accomplish the actual goal without ever running `find /`):
- Find an installed binary: `command -v` / `which` / `dpkg -L <pkg>`.
- Look in a specific known LOCAL directory you actually care about, by exact path.
- The test that needs a tool runs IN the VM — check the VM, not the host.

**Origin (sess, 2026-06-14):** ran `find /` on clyde hunting an `fsx` binary;
user: "why would you do that on a system with nfs /data and nfs /src??? ...
you should never ever do it. Not ever. For any reason ever." Recorded as
absolute.
