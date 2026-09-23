---
name: trap-a-rebooted-victim-has-no-src-export-so-insmod-off-the-nfs-path-fails-before-any-prep-runs
description: TRAP (s135): /src is mounted by prep_node.sh step 1, so a lap that reboots a node and insmods /src/mxfs/mxfs.ko itself gets rc=1 ENOENT.
metadata:
  type: feedback
tags: [rig, harness, insmod, nfs]
---

## What bit us

`tests/nonfallible_transition_stall.sh` brings the victim back as a *new
incarnation* without running a prep on it — deliberately, because a prep would
unload the module, remount, and let the incarnation recover its own
predecessor's slice, which is the protection that lap parks.

It then ran `insmod /src/mxfs/mxfs.ko` on the freshly started domain. It
returned **rc=1**, `/sys/module/mxfs` never appeared, and the lap ABORTed on an
empty srcversion (`ck ... was asked to judge an EMPTY value`) with insmod's
stderr discarded by `2>/dev/null`.

## Why

`/src` is an **NFS mount from the dev host**, and the thing that creates it is
**step 1 of `tests/setup/prep_node.sh`**:

    mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,...

A node that has just booted has no `/src` at all. Every path under it —
`/src/mxfs/mxfs.ko`, `/src/mxfs/tools/chk_mxfs`, `/src/mxfs/tools/slice_image.py`
— is absent until something mounts the export.

## What to do instead

Any harness that starts a node and then drives it **without** a prep must mount
the export itself (idempotently, same options), and then load the module from a
**node-local copy** rather than straight off the export — which is what prep
does, and for its own separate reason: the object is relinked in place on the
export and a client can hold mixed pages of it.

## The second half of the lesson

`insmod ...; echo RC=$?` with stderr thrown away turns a one-line cause into an
ABORT that says nothing. Keep insmod's own message and the kernel's last lines,
so the next run reports the cause instead of the symptom.
