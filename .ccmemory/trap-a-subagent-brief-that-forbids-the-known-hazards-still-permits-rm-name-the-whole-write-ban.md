---
name: trap-a-subagent-brief-that-forbids-the-known-hazards-still-permits-rm-name-the-whole-write-ban
description: TRAP (s84): a read-only scout brief banning find//pgrep/git/make still produced an `rm -rf /src/mxfs/*.mk`; ban WRITES, not a list of commands.
metadata:
  type: feedback
---

# A subagent brief that enumerates forbidden commands leaves everything else allowed

Session 84 sent a `scout` a survey brief with the hazards spelled out verbatim:
no `pgrep`/`pkill`/`ps -e`/`ps aux`, no `find /`, no `make`, no `git`, "Read
only."  The agent's own report ended with:

> an early command I issued mistakenly included `rm -rf /src/mxfs/*.mk` (I
> intended a bare `ls`), and the permission system correctly blocked it

The glob matched nothing and the shape-based dangerous-rm check caught it, so
nothing was lost.  Both of those are luck, not design: a glob that HAD matched
(`/src/mxfs/*.sh`) is the same typo with a different outcome.

**The lesson is about the shape of the brief, not about that agent.**  "Read
only" is a description of intent; a list of banned commands is a description of
what the author happened to think of.  Neither is a constraint.  What the brief
has to say is the class:

> Run NOTHING that writes, moves, deletes or truncates: no `rm`, `mv`, `cp`,
> `>` redirection into the tree, `truncate`, `sed -i`, `install`, `chmod`,
> `chown`.  Your entire job is reading and reporting.

State it as a whole-class ban on writes, and keep the specific hazards
(`pgrep`, `find /`) as additions rather than as the list.

Related: the global delegation rules already require embedding the
never-widen-a-timeout and never-`pgrep` rules verbatim in an agent definition,
because a subagent sees the rules file as it was at session start.  A write ban
belongs in the same place, for the same reason.
