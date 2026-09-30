---
name: feedback-give-the-user-times-in-local-time-never-utc
description: USER 2026-09-30: every time told to the user is in clyde's local time (America/Chicago, CDT/CST), never UTC. Convert with `date -d '<t> UTC' '+%H:%M…
metadata:
  type: feedback
---

The user asked "what is 15:30 in localtime?" after being given an ETA in UTC, then said: "make a memory - only give me times in localtime".

Rule for every reply to the user: state times in clyde's local zone (America/Chicago; CDT in summer, CST in winter), with the zone label, e.g. "10:30 CDT". Never give a bare UTC time or a UTC-only ETA.

Why this bites: the harness and evidence logs mix zones. `date -u`, the chain logs (`=== ... 2026-09-30T12:33Z ===`) and criteria.py stamps are UTC, while the platform round logs' `[HH:MM:SS]` prefixes and `stat` mtimes are local. Convert before quoting:

    date -d '15:30 UTC' '+%H:%M %Z'      # -> 10:30 CDT
    date '+%H:%M %Z'                      # now, local

Internal artifacts (CHANGELOG, evidence, defect records) keep whatever zone they already use; this is about what the user reads in a reply.
