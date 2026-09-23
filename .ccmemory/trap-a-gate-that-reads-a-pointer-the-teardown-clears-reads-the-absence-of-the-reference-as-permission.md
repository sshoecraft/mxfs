---
name: trap-a-gate-that-reads-a-pointer-the-teardown-clears-reads-the-absence-of-the-reference-as-permission
description: TRAP (s88, 0.89.21): the authority gate read mp->m_mxfs_dlm and NULL meant "not a clustered mount"; put_super clears it before the unmount record.
metadata:
  type: feedback
---

## What bit us

0.89.20 put the authority lease at the point of use in five mutating
producers. Every one of them had this shape:

    struct mxfs_v5_dlm *v5 = READ_ONCE(mp->m_mxfs_dlm);
    if (v5 && !mxfs_v5_dlm_write_admitted(v5)) { refuse; }

and `mxfs_v5_dlm_write_admitted(NULL)` returned `true` — "not a clustered
mount, nothing to own". That is right for a mount that never had a DLM. It is
wrong for a mount whose own teardown detached it.

`xfs_fs_put_super` does, in order: publish the AG grants as free, **set
`mp->m_mxfs_dlm = NULL`**, join the heartbeat thread, then run
`xfs_unmountfs`'s finish half — the log cover and the unmount record. So from
the detach onward every gate answered its own question, on a node that had
stopped proving liveness to anybody, and the one iclog that crosses that line
is the record that tells peers "I left cleanly and you need not replay my
slice".

Measured: `tail_admit=1` on an ordinary unmount. One submission, every time.

## The general shape

**A predicate written against the liveness of a pointer answers "is there a
context right now", not "may this work proceed".** When teardown clears the
pointer, the absence becomes permission. Look for it wherever:

- a subsystem pointer is NULLed "so a queued X no-ops" — that comment means
  the object is being used as a flag, and flags have a third state nobody
  planned for;
- a guard is `if (ptr && !ok(ptr))` rather than `if (must_check && !ok())`;
- the same teardown that clears the pointer is followed by more I/O.

The fix is not to move the NULL. It is to make the *question* answerable for
the whole life of the work: a property of the object the work belongs to
(here, `mp->m_mxfs_clustered`, set once and never cleared) plus a separately
allocated, reference-counted state object that outlives every other holder.

## Related

- `design-storage-authority-is-a-lease-held-to-a-deadline-not-a-loss-a-node-is-told-about`
- ruling: `docs/rulings/mount-owned-authority-and-what-a-lease-does-not-restore.md`
