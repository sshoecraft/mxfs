#!/bin/bash
# tmpfile_churn.sh — O_TMPFILE create / linkat / unlink churn on N nodes.
#
# WHY (sess398, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN, design-consult ruling
# docs/rulings/insert-mode-iunlink-item.md):
#   an O_TMPFILE create is the one path that puts TWO iunlink items for the
#   SAME inode into ONE transaction — the create-path INSERT item
#   (xfs_inode_init, site 2, NULL->NULL) and xfs_iunlink's insert item.  The
#   ruling requires "multiple INSERT items in one txn" to be exercised.  No
#   rsync / dir_reuse workload uses O_TMPFILE, so nothing on the board covers
#   it.  This script does: each node runs ITERS rounds of
#     open(dir, O_TMPFILE|O_RDWR) -> write -> linkat(name) -> unlink(name)
#   and every 4th round leaves the tmpfile unlinked (close -> inactivate ->
#   free), all in ONE shared directory so the AGI buckets are contended
#   across nodes.  Pass iunl_fossil_inject>0 on the nodes beforehand to run
#   the injector matrix through the stacked-item path.
#
# budget: the budget is DERIVED, never padded.  Each node first runs the same
#   loop on its LOCAL root filesystem (native baseline, measured on the spot),
#   then on mxfs with timeout = 2 x native + 5 s (ssh/launch).  A timeout IS a
#   FAIL; a >2x-native wall IS a FAIL even with zero errors.
# the unkillable-wedge rule: every remote call is bounded (timeout) and captures its own rc.
#
# Usage: tests/tmpfile_churn.sh [nodes=32] [iters=200]
# Env:   MXFS_MNT (default /mnt/shared)   TMPC_OUT (dir for per-node logs)
#        TMPC_MODE=shared|pernode (default shared): shared = every node churns
#        in ONE directory (AGI-bucket + dir-EX contention across all nodes, the
#        sess398 shape); pernode = each node churns in its OWN subdirectory, so
#        the only cross-node resource is the AG itself — at 32 slots / 25 AGs
#        the two-owner AGs 0..6 still see two nodes alloc/free-churning one
#        AGI+inobt+finobt (the sess399 AGI-freecount +1 divergence shape).
# Exit:  0 all nodes PASS, 1 otherwise.  Prints one line per node:
#        testN rc=<rc> native=<s> mxfs=<s> budget=<s> errs=<n> done=<n> verdict=<PASS|FAIL>
#        done = iterations completed before the budget expired (progress is
#        reported every 25 iterations so a timed-out node still shows how far
#        it got and the per-iteration max latency).

NODES=${1:-32}
ITERS=${2:-200}
MNT=${MXFS_MNT:-/mnt/shared}
MODE=${TMPC_MODE:-shared}
OUT=${TMPC_OUT:-$(mktemp -d)}
cd "$(dirname "$0")/.." || exit 2
mkdir -p "$OUT"

# NOTE (sess398, measured): CPython os.link(..., follow_symlinks=True) calls
# plain link(), which never follows the /proc/self/fd magic link -> EXDEV on
# EVERY filesystem (ext4 on clyde and on the nodes, mxfs alike).  The correct
# primitive is linkat(fd, "", AT_FDCWD, name, AT_EMPTY_PATH); done via ctypes.
PY='import os,sys,time,errno,ctypes
d=sys.argv[1]; iters=int(sys.argv[2]); tag=sys.argv[3]
libc=ctypes.CDLL(None, use_errno=True); AT_FDCWD=-100; AT_EMPTY_PATH=0x1000
os.makedirs(d, exist_ok=True)
errs=0; t0=time.time(); maxit=0.0; done=0
for i in range(iters):
    ti=time.time()
    try:
        fd=os.open(d, os.O_TMPFILE|os.O_RDWR, 0o644)
    except OSError as e:
        errs+=1; print("ERR open_tmpfile", e, file=sys.stderr, flush=True); continue
    try:
        os.write(fd, b"x"*4096)
        if i % 4 != 3:
            name=os.path.join(d, "%s.%d" % (tag, i))
            if libc.linkat(fd, b"", AT_FDCWD, name.encode(), AT_EMPTY_PATH):
                e=ctypes.get_errno(); raise OSError(e, "linkat: "+os.strerror(e))
            os.unlink(name)
    except OSError as e:
        errs+=1; print("ERR", e, file=sys.stderr, flush=True)
    os.close(fd)
    done+=1; maxit=max(maxit, time.time()-ti)
    if done % 25 == 0:
        print("progress done=%d t=%.2f maxit=%.3f" % (done, time.time()-t0, maxit), file=sys.stderr, flush=True)
print("wall=%.2f errs=%d done=%d maxit=%.3f" % (time.time()-t0, errs, done, maxit), flush=True)'

fail=0
for i in $(seq 1 "$NODES"); do
	(
		# native baseline on the node's local root fs (same loop, same count)
		nat=$(timeout 120 tools/mxfs_sshpass.sh test$i \
			"D=\$(mktemp -d); python3 -c '$PY' \$D $ITERS n 2>&1 | tail -1; rm -rf \$D" 2>/dev/null |
			grep -av '^Unauthorized\|^Warning:\|^If you' | grep -o 'wall=[0-9.]*' | cut -d= -f2)
		nat=${nat:-0}
		budget=$(python3 -c "print(int(2*$nat+5+0.999))")
		dir=$MNT/tmpfile_churn
		[ "$MODE" = pernode ] && dir=$MNT/tmpfile_churn/test$i
		res=$(timeout $((budget + 10)) tools/mxfs_sshpass.sh test$i \
			"timeout $budget python3 -c '$PY' $dir $ITERS test$i 2>&1 | tail -4; echo rc=\${PIPESTATUS[0]}" 2>/dev/null |
			grep -av '^Unauthorized\|^Warning:\|^If you')
		rc=$(echo "$res" | grep -o 'rc=[0-9]*' | tail -1 | cut -d= -f2)
		mx=$(echo "$res" | grep -o 'wall=[0-9.]*' | cut -d= -f2)
		errs=$(echo "$res" | grep -o 'errs=[0-9]*' | tail -1 | cut -d= -f2)
		done=$(echo "$res" | grep -o 'done=[0-9]*' | tail -1 | cut -d= -f2)
		v=PASS
		[ "${rc:-1}" != 0 ] && v=FAIL
		[ "${errs:-1}" != 0 ] && v=FAIL
		[ -z "$mx" ] && v=FAIL
		if [ -n "$mx" ] && [ "$nat" != 0 ]; then
			python3 -c "import sys; sys.exit(0 if $mx <= 2*$nat else 1)" || v=FAIL
		fi
		echo "test$i rc=${rc:-none} native=${nat}s mxfs=${mx:-none}s budget=${budget}s errs=${errs:-none} done=${done:-0} verdict=$v" > "$OUT/test$i.line"
		echo "$res" > "$OUT/test$i.log"
	) &
done
wait
for i in $(seq 1 "$NODES"); do
	cat "$OUT/test$i.line"
	grep -q 'verdict=PASS' "$OUT/test$i.line" || fail=1
done
echo "logs: $OUT"
exit $fail
