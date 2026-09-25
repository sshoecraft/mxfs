so you can setup drbd between 2 nodes (bi directional) and the mxfs mkfs on 1 node and them mxfs mount on both

Yes — that is a valid architecture, assuming MXFS is designed to operate directly on a block device and supports multiple simultaneous mounts/nodes.

The stack would be:

                    MXFS
              ┌──────────────┐
              │   /mnt/mxfs  │
              └──────┬───────┘
                     │
          ┌──────────┴──────────┐
          │                     │
       Node A                 Node B
          │                     │
       MXFS mount             MXFS mount
          │                     │
       /dev/drbd0             /dev/drbd0
          │                     │
          └────── DRBD ────────┘
             dual-primary
             synchronous
The sequence would essentially be

On the two nodes:

Create the DRBD resources over the local disks.
Configure dual-primary operation (allow-two-primaries).
Establish the initial synchronization.
Promote both nodes to Primary.
On one node only, run:
mkfs.mxfs /dev/drbd0
Then mount the same DRBD device through MXFS on both nodes:
mount -t mxfs /dev/drbd0 /mnt/mxfs

Now:

Node A                    Node B
   │                         │
 MXFS                       MXFS
   │                         │
   └─────── /dev/drbd0 ─────┘
              │
         replicated block
              │
        ┌─────┴─────┐
        │           │
     disk A       disk B

The important thing is that DRBD doesn't need to understand MXFS. It just sees block writes.

If MXFS changes block 123 on Node A:

Node A
MXFS
 ↓
DRBD
 ↓
local disk A
 ↓
network
 ↓
DRBD
 ↓
local disk B

And if Node B simultaneously changes block 456, the same thing happens in the opposite direction.

MXFS is responsible for making those concurrent filesystem operations coherent. DRBD is responsible for making the underlying block device identical on both nodes.

The really important caveat

You absolutely need split-brain protection.

With dual-primary DRBD, a network partition can otherwise produce:

Node A                 Node B
   │                      │
 MXFS                    MXFS
   │                      │
 DRBD Primary            DRBD Primary
   │                      │
 "I'm alive"             "I'm alive"

Both sides can accept writes while disconnected. Once they reconnect, you potentially have two divergent block histories.

So for a real deployment I'd want fencing/quorum, probably with a third witness rather than pretending two nodes can reliably determine which one should survive a partition.

But architecturally, yes:

DRBD dual-primary → mkfs.mxfs once → MXFS mounted read/write on both nodes

is precisely the sort of thing that could give you two simultaneously active MXFS nodes with locally stored, synchronously mirrored data.

And unlike my earlier suggestion, there is no XFS underneath MXFS in this model. DRBD is sitting directly beneath the MXFS filesystem.

sshoecraft/mxfs

Ah — now that I've looked at the actual MXFS repo, I need to correct my correction. 😄

You were right about the important architectural point, but I was wrong when I said there is no XFS underneath MXFS.

MXFS is XFS, specifically a fork of upstream XFS with the clustering/coordination layer added. The repo explicitly says “XFS on disk” and that the xfs/ tree is upstream XFS with the MXFS overlay.

So the actual architecture is:

              MXFS
        ┌───────────────┐
        │ XFS + MXFS    │
        │ coordination  │
        └───────┬───────┘
                │
          /dev/drbd0
                │
        ┌───────┴───────┐
        │               │
      Node A           Node B
     local disk       local disk

But there is still no separate local XFS filesystem on each node. That's the distinction that matters.

The XFS filesystem is one filesystem on the shared block device. DRBD makes that one block device available identically to both machines.

And that maps very cleanly onto what MXFS expects:

"One shared LUN, many nodes. Every node opens the same device ... read/write, concurrently."

So your proposed setup is actually quite elegant
                    MXFS
               /mnt/shared
              ┌──────┴──────┐
              │             │
           Node A         Node B
              │             │
        /dev/drbd0      /dev/drbd0
              │             │
              └──── DRBD ───┘
                 Protocol C
              synchronous
               replication
              ┌─────┴─────┐
           local disk   local disk

Then:

Node A, once:

mkfs.mxfs /dev/drbd0

Both nodes:

mount -t mxfs /dev/drbd0 /mnt/shared

That's essentially exactly the MXFS quick-start model: format the shared device once, then mount that same device on every node.

And this solves the thing we were discussing

DRBD provides:

"Both nodes have the same block device."

MXFS provides:

"Both nodes can safely mount that block device read/write simultaneously."

So:

           ┌───────────────┐
           │     MXFS      │
           │ clustered XFS │
           └───────┬───────┘
                   │
              shared LUN
                   │
             ┌─────┴─────┐
             │   DRBD    │
             │  mirrored │
             └─────┬─────┘
                   │
          ┌────────┴────────┐
          │                 │
       Node A             Node B
       disk A             disk B

That's a legitimate architecture.

And interestingly, it means you don't need Ceph at all. You're using DRBD purely as the shared-LUN/replication mechanism, while MXFS does exactly what it was designed to do: concurrent filesystem access to that shared block device.

One thing I'd want to investigate next, though, is whether DRBD's dual-primary semantics and MXFS's fencing/PR assumptions interact cleanly. MXFS currently has its own fencing model based around SCSI Persistent Reservations, while DRBD has its own quorum/split-brain machinery. That's the part I'd want to validate before saying "this is production-ready."

And yes — this is a much more interesting two-node design than throwing Ceph at it.
