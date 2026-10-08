---
name: trap-parking-every-release-drain-parks-the-ancestor-directory-first-and-blocks-the-peers-path-walk
description: TRAP (0.90.103): dbg_bast_pause_ino=all parked only the run dir's release; the peer's lookups waited on it so 16 subdirs got no BAST. Walk ancestors…
metadata:
  type: feedback
---

tests/pve_released_grant_ghost.sh RELEASE_BY=pause: participant 0 created $G/d1..d16 (so it held $G EX too), all release drains parked (dbg_bast_pause_ino = 2^64-1), then participant 1 ran `ls -l $G/dN`. PARKED=1: the one parked drain was $G itself (ino 132); every path walk below it waited for that release, so no subdirectory was ever asked for and nothing was adopted — the lap read NOT EXERCISED.

Fix: have the peer walk the ancestors (`ls -f $G`) BEFORE arming the park, so the ancestor is already shared; use `ls -f` on the targets so only the directory grant is requested, not one stat per file. Then PARKED=16 and the control build reproduced the refusal deterministically.

General rule: any test that parks or delays one host's releases must first settle the grants on every ancestor the other host's lookups need, or the first parked release serialises everything behind it.
