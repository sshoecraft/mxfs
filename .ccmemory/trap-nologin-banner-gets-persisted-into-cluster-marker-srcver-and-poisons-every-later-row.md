---
name: trap-nologin-banner-gets-persisted-into-cluster-marker-srcver-and-poisons-every-later-row
description: TRAP (sess567): a prep run while a node still boots stores pam's nologin banner as the marker's srcver and reports OK; every later row then fails wit…
metadata:
  type: feedback
tags: [trap, rig, prep, sess567, cluster-marker]
---

# The nologin banner can be PERSISTED as the cluster marker's srcver

## What happened (sess567)

A rig job started while `test1` was still booting. `prep_cluster` reported
success:

    --- prep OK: mxfs mounted on all 2 node(s), build 9C998A5AE312D6560AB83AA ---
    === prep_cluster OK @ 2/tcp (41s) — marker updated ===

Every subsequent row then refused to run, with no test output at all:

    ERROR: cluster is prepped for 2/tcp (srcver="Systemisbootingup.Unprivileged
    usersarenotpermittedtologinyet.Pleasecomebacklater.Fortechnicaldetails,see
    pam_nologin(8)."), you requested 2/tcp (srcver=9C998A5AE312D6560AB83AA).

The `cat /sys/module/mxfs/srcversion` over ssh returned **pam's nologin banner**
instead of a srcversion, and that string was written into
`.cluster_marker.json` as the cluster's identity.

## Why it is worse than the already-known version

`trap-death-lap-victim-still-booting-prep-build-check-reads-nologin-banner-as-srcversion-mismatch`
covers the prep's own build check failing. This is the other half:

- the prep **reports OK** and prints the *correct* build on its own line;
- the bad value is **persisted**, so it outlives the transient boot;
- every later row dies at the marker comparison, printing no test output, which
  reads like the harness is broken rather than like a stale marker.

Symptom to recognise instantly: a `run.sh <N> <dlm> <row>` invocation that emits
**nothing** for the row — no PASS, no FAIL, no verdict line at all.

## Fix when you hit it

Re-prep once both nodes genuinely answer. Gate on readiness first — not a single
poll, and not `/run/nologin` alone:

    test -e /run/nologin && echo BOOTING || cat /sys/module/mxfs/srcversion

and require the result to look like a srcversion (hex) before proceeding.

## The underlying harness defect

A prep that writes an unvalidated string as cluster identity and reports OK is
the same family this project keeps paying for — a mechanism reporting success
while quietly not working. The marker write should reject anything that is not a
hex srcversion rather than storing whatever the shell handed back.
