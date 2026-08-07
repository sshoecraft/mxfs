---
name: ccloop-c7ee71c6-sess22-dirent-inode-type-mismatch
description: sess22: NEW critical defect — a REG-file dirent binds to a DIRECTORY inode after storm-driven inode reuse; P95B type-flip resolver gives up and publi…
metadata:
  type: project
tags: [mxfs, corruption, typeflip, inode-reuse, critical]
---

## D-DIRENT-INODE-TYPE-MISMATCH (ccloop c7ee71c6 sess22)

A directory entry whose ftype says REGULAR FILE resolves to an inode whose live
incarnation is a DIRECTORY.  The name becomes permanently unusable as a file,
and all 32 nodes agree on the corrupt result.

### Reproduction (twice, back to back, 32/caw)

    MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
    ./run.sh 32 caw cache_coherency          # PASSES 32/32
    tests/sf_mkdir_storm.sh 20 32 2 1        # same mount, no prep
    ./run.sh 32 caw cache_coherency          # FAILS 0/32

Failure text, on every node:

    cv nodeN content of node5(exp=hello from node 5 got=)

### The corruption

`echo "hello from node 5" > .cache_coherency/cross_visibility/node5.txt` left:

    node5.txt  type=DIRECTORY  ino=60823425  size=6  nlink=2  mode=755
    node4.txt  regular file    ino=12588865  size=18    <- correct
    node6.txt  regular file    ino=54532052  size=18    <- correct

size=6 / nlink=2 / mode=755 is a freshly-created EMPTY MXFS directory (size 6 =
shortform header only).

### MXFS's own probes name it exactly

    P95B-TYPEFLIP-WAIT ino=60823425 resolved=0 rounds=201
        final_ftype=2 dirent_ftype=1 name=node5.txt
    P-EVICT-RESULT ino=60823425 final_mode=040755 final_ftype=2
        dirent_ftype=1 fop_dir=1 tries=5

`dirent_ftype=1` = XFS_DIR3_FT_REG_FILE; `final_ftype=2` = XFS_DIR3_FT_DIR.
The resolver spun its full 201 rounds, exited `resolved=0`, and the mismatched
binding was PUBLISHED instead of the operation being failed.

### Cluster census (same window)

    P95B-TYPEFLIP-WAIT total : 165   on ALL 32 nodes
      resolved=1             : 109
      resolved=0 (GAVE UP)   :  56   <- all on the SAME inode and name
    RELOAD-TYPEFLIP-STALE-SKIP: 196

So the type-flip machinery handles most flips and can fail PERMANENTLY on one.

### Shape (UNROOTED)

The storm's directory create/teardown churn drives aggressive inode-number
reuse.  A later `O_CREAT` of a regular file binds a REG dirent to an inode
whose live incarnation is a DIR.  Related existing probe seen in the same runs:

    RELOAD-TYPEFLIP-STALE-SKIP ino=48247652 incore_mode=0100644
        disk_mode=040755 incore_gen=... disk_gen=... expect_ft=0
        -- keeping authoritative in-core inode (type-flip w/o newer gen)

i.e. in-core says regular file, disk says directory — the same collision.

### Blocking fix

An unresolved type flip must FAIL the operation, not publish a mismatched
binding.  But root the reuse path first: find what permits a REG dirent to be
created against a live DIR inode.

### Why this matters for the board

`cache_coherency` DOES catch it — but only when run on an aged mount.  On a
fresh prep it passes 32/32.  Any board sweep that preps before every condition
will therefore miss this entire defect class.
