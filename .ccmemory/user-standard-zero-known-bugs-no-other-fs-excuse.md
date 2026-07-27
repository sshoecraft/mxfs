---
name: user-standard-zero-known-bugs-no-other-fs-excuse
description: USER STANDARD (2026-07-20, emphatic): MXFS bar is ZERO known/reproducible defects. NEVER justify/tolerate an MXFS bug by citing that GFS2/OCFS2 or ot…
metadata:
  type: feedback
tags: [user-directive, quality-standard, no-mock-no-shrug, clustered-fs, correctness]
---

# MXFS quality standard: zero known defects — "other FSes have bugs" is NOT a valid excuse

User directive, 2026-07-20, emphatic. The user has long IT/infrastructure
experience and is promoting MXFS to the Proxmox team and toward Linux-kernel
inclusion ("seen by millions").

## The rule

**Do NOT justify, normalize, or tolerate an MXFS bug by pointing out that other
clustered filesystems (GFS2, OCFS2, etc.) also carry known issues.** The user's
point, verbatim intent: nobody wants to use GFS2 and especially OCFS2 *because*
they are buggy — so "mature clustered FSes have bugs too" is an argument for MXFS
to have ZERO, not a license to carry any. Matching the defect tolerance of the
systems people refuse to run is self-defeating for a project meant to beat them.

Claude invoked GFS2/OCFS2 as precedent to argue that "fix ALL bugs" is
unrealistic for a clustered FS. That framing was WRONG and the user rejected it.
Do not repeat it.

## The standard going forward

- Every **known, reproducible** bug gets FIXED and VERIFIED. No "documented
  limitation" / "rare, pre-existing, move on" shrug. Reproducible ⇒ fixable ⇒
  fix it. (Concrete open items at the time of this directive: the AGI-buffer
  umount wedge from fence_during_write — reproducible, must be fixed; the
  dir_reuse create-visibility race — drive to a real fix or genuine root-cause,
  not file-and-forget.)
- Method discipline (instrument → prove the cause → targeted fix → verify) is
  about doing the fix RIGHT, not a reason to defer. Distinguish "I'm being
  careful about how I fix it" from "it's acceptable to leave it." Only the first
  is legitimate.

## The ONE honest line that is NOT tolerance

Integrity of representation, not defect tolerance: never claim a bug is *fixed*
until it is *proven* fixed, and don't promise a filesystem will never surface a
NEW bug under a workload nobody has run. That is honesty about claims — it is
explicitly NOT permission to accept the bugs already known. Those get killed.

## How this squares with other standing rules

Consistent with the global "NO mock/fake data, no 'simple' stand-in functions,
no giving up and offering alternatives — keep working until solved" directives
and RULE 4 (troubleshoot to root cause). This memory sharpens them: the bar is
zero KNOWN defects, and comparisons to other buggy systems are never a defense.
