---
name: trap-fio-by-path-filename-colon-split-survives-one-escape-level-ssh-eats-backslash-fills-node-root-disk
description: TRAP (sess515): raw_fio_ceiling.sh escaped the by-path device's colons ONCE; the remote shell behind ssh ate the backslash, fio split the name into f…
metadata:
  type: feedback
---

# TRAP: fio's ':' filename split survives one level of escaping through ssh (sess515, 2026-09-05)

**Symptom chain.** sess507 chain s515h step 7 (raw ceiling on the QNAP by-path device `/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-iqn...:lun-0`) reported N=2 seqW=5000 MiB/s (impossible on 1 GbE iSCSI). Every following prep failed with `NODE_PREP_FAIL: mxfs.ko content never matched expected md5 ... (NFS staleness)` — NOT NFS: test2's `cp` of the module to /root produced a short/empty file because `/` was full: `/root/3260-iscsi-iqn.2004-04.com.qnap` = 22 GB, plus `ts-453pro`, `iscsi.target-0.f35772-lun-0` (test1 had 3 x 4.5 GB). fio's `--filename` splits on ':'; each fragment becomes a CREATED regular file in the ssh cwd (/root).

**Why the existing guard failed.** `scripts/raw_fio_ceiling.sh` already had `DEV="${DEV//:/\\:}"` (a 2026-07-25 lesson: cawd read 95 GiB/s from devtmpfs). The fio command is passed as one string to `ssh node "..."`; the REMOTE shell parses the unquoted word `\:` to `:` before fio runs. Fix: `${DEV//:/\\\\:}` (two backslashes in the string; the remote shell leaves one; fio unescapes it) + a post-run check for fragment files on every node.

**Rules.**
- Any device path with ':' handed to fio through ssh needs `\\:` in the command string, or resolve it on the node (`readlink -f`) inside the remote command.
- A 'md5 never matched (NFS staleness)' prep failure that repeats: check `df -h /` on the node FIRST (the copy target), then NFS.
- Bogus ceiling file moved to tests/evidence/raw_fio_ceiling.tcp.qnap.BOGUS_local_file_s515h.json; the qnap TCP ceiling must be re-measured before fio_perf_vs_xfs (wsrc=raw-ceiling) means anything.
