---
name: trap-an-empty-dist-version-directory-made-full-verify-skip-the-package-build
description: TRAP (0.90.39): full_verify skipped release.sh because dist/<V> existed, empty, from a stopped chain; 12 packaged rounds failed in 1 s on a missing .…
metadata:
  type: feedback
---

tests/full_verify.sh decided "packages already built" with `[ ! -d dist/$V ]`. A chain stopped while release.sh was starting left dist/0.90.39 behind with nothing in it. The next chain's packages step ran nothing and printed nothing. Every packaged round, 12 of them across four platforms and both configurations, then failed in about a second with `FAIL: missing .../dist/0.90.39/mxfs_0.90.39_amd64.deb — round stopped`. The script still exited 0, because its last command was a summary grep. That cost about an hour of platform rounds.

Fixed in 0.90.39: a finished build is a dist/$V whose SHA256SUMS verifies (release.sh writes it last), and the exit status counts the platform steps that failed.

The general lesson: a directory or a marker file existing is not proof that the step which creates it finished. Test for the artifact the step writes last. And when a chain's rounds all fail within a second, read one round's own first FAIL line before reading anything else.
