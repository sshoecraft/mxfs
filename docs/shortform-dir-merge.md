# Shortform directory reconciliation: the three-way merge and its base

A shortform directory keeps its entries inside the inode, so the whole
directory is one image: the platter holds one, and every node that has the
inode in core holds one.  Only the node holding the directory's cluster grant
EX may change it, but a node's in-core image can lag or lead the platter, and
a peer's tenure can change the platter while this node's in-core image stands
still.  When such a node next mutates the directory, it must reconcile the two
images without losing either side's committed changes.

## Why a merge and not an adopt

Wholesale adoption of the platter image discards this node's own committed,
not-yet-durable changes (a rename or removal that is in the log but whose
image has not reached the inode's home yet).  Keeping the in-core image
wholesale discards a peer's adds and removes that landed while this node was
not the holder.  Neither is acceptable, so the reconciliation is a three-way
merge over names:

- **ours** — the in-core image;
- **theirs** — the coherent platter image, read for this purpose;
- **base** — the common ancestor: the image both sides started from.

For each name: if ours differs from base (the name was added, or its inode
changed, on this node) ours wins; if ours equals base, theirs wins (a peer's
removal is honoured); a name present in theirs but in neither ours nor base
is a peer's fresh add and is re-added.

## The base must be what the platter held when the peer's tenure began

The merge is exact only when base really is the common ancestor.  Two rules
make that so.

**The base advances at every EX release.**  When this node releases EX it has
published its last image; the peer's tenure builds on that image, so it is
the common ancestor of whatever this node's in-core image becomes and
whatever the peer publishes.  At the release the platter image is read back
and captured as the base.  Without this, entries this node added after the
last refresh-captured base and that a peer then deleted would read as "ours,
changed" and survive the peer's deletion.

**A platter image this node itself published in the current tenure is not
merged.**  A node's flushes land asynchronously, so a refresh inside a tenure
can read back this node's own previous image — the one from before its most
recent removals.  That image carries no peer change at all (a peer can only
modify while this node does not hold EX), yet under the merge the entries this
node removed since that flush are "in theirs, not in ours, not in base" and
would be re-added as a peer's fresh adds.  So the node keeps a small ring of
the shortform images it copied into its inode cluster buffer during the
current tenure; a platter image byte-identical to one of them makes the
in-core image authoritative, and the base advances to it.

The ring belongs to one tenure.  It is retired at the release, because a
peer's tenure can legitimately recreate an older image of ours byte for byte
(by removing exactly what we had added); an image from a previous tenure must
never be taken as evidence that nothing changed.  Inside a tenure it is kept
even when the base is captured from a platter image that is not ours: no
peer writes during our tenure, so such an image is the pre-tenure one, and
our own writes still in flight must stay recognisable when they land.

## What remains outside the merge

The merge covers shortform-to-shortform reconciliation only.  A directory
that changed format on the platter (shortform to block, or back) is adopted
through the ordinary reload path, and this node's own recently created
entries are re-applied from a separate pending list.  A merge whose result
would not fit the inode falls back to the adopt-or-keep decision the reload
path makes.
