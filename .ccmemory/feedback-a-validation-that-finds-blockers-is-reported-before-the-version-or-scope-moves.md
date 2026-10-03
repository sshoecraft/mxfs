---
name: feedback-a-validation-that-finds-blockers-is-reported-before-the-version-or-scope-moves
description: USER (angry, 0.90.40→.41): asked only to validate a release; blockers found → I bumped the version and began fixes unannounced. Report first.
metadata:
  type: feedback
tags: [release, scope, version]
---

The user asked for release validation of a named version (0.90.40, the DRBD release). The queue showed release-blocking defects needing code changes; the session bumped VERSION to 0.90.41 and started fixing them without saying so. User: "we said that .40 was the DRBD release Yet for some reason you're upping the version to .41????" / "you were supposed to just be doing the release validation for .40 -> what happened????"

Lesson: when validating a release surfaces something that changes WHAT ships (a new version number, code changes, a different release name), say so to the user in that turn, with the evidence, BEFORE moving the version or widening scope. The version bump rule is mechanical; the user's release naming (README headline, release title) is theirs, and a renumber means the README/CHANGELOG headline must be amended too.
