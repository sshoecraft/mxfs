#!/bin/bash
# acq_release_deadlock_test.sh — build tests/tauth/acq_release_deadlock_test
# twice and run both:
#
#   fix      dlm/dlm.c as it is in the tree: the locally mastered queue path
#            calls dlm_acq_begin with may_release false, so its idle scan leaves
#            a record holding an adopted grant alone.  Must pass.
#   control  a copy of dlm/dlm.c with that one call site passing true again, the
#            code that self-deadlocked on the physical pair: the idle scan
#            releases the grant while the caller holds table_rwlock for
#            writing.  The user-mode PAL stops the process on the recursive
#            write lock (EDEADLK), so the control must abort with that line.
#
# Prints PASS and exits 0 only when the control fails exactly as predicted AND
# the fix passes; 1 otherwise, 2 when a build failed.  It builds on its own,
# not through this directory's Makefile, because the control compiles a
# modified copy of dlm.c; everything goes to a fresh directory under /tmp,
# which is printed.
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TOP=$(cd -- "$HERE/../.." && pwd)
OUT=$(mktemp -d /tmp/acq_release_deadlock.XXXXXX) || exit 2
CC=${CC:-cc}
# the flags this directory's Makefile uses for the same objects
STRICT="-O2 -g -std=gnu11 -Wall -Wextra -Werror"
ENGINE="-O2 -g -std=gnu11 -Wall"
# dlm/ too: the control's copy of dlm.c is compiled away from the headers it
# includes by its own directory
CPPFLAGS="-I$TOP -I$TOP/include -I$TOP/pal -I$TOP/dlm"
# One run: setup 7.0 s measured (formatting the ledger region and bringing two
# nodes up), one 1 s attempt to time out, the record's 15 s idle
# (MXFS_DLM_ACQ_IDLE_MS), one more 1 s attempt, then a few lock round trips —
# 23.4 s measured for the fix arm alone.  A timeout is a failure, never a
# reason to wait longer.
RUN_BUDGET=30
echo "acq_release_deadlock: build dir $OUT"

CALL='newlk->acq_seq = dlm_acq_begin(ctx, resource, mode, &acq_first, NULL, false);'
if [ "$(grep -cF -- "$CALL" "$TOP/dlm/dlm.c")" != 1 ]; then
    echo "acq_release_deadlock: the under-lock call site is not exactly once in dlm/dlm.c"
    exit 2
fi
sed 's/dlm_acq_begin(ctx, resource, mode, &acq_first, NULL, false);/dlm_acq_begin(ctx, resource, mode, \&acq_first, NULL, true);/' \
    "$TOP/dlm/dlm.c" > "$OUT/dlm_control.c" || exit 2
if [ "$(grep -cF -- "$CALL" "$OUT/dlm_control.c")" != 0 ] ||
   [ "$(grep -cF -- 'dlm_acq_begin(ctx, resource, mode, &acq_first, NULL, true);' "$OUT/dlm_control.c")" != 1 ] ||
   [ "$(diff "$TOP/dlm/dlm.c" "$OUT/dlm_control.c" | grep -c '^[<>]')" != 2 ]; then
    echo "acq_release_deadlock: the control copy does not differ by exactly that one call"
    exit 2
fi
echo "acq_release_deadlock: control differs from the tree by:"
diff "$TOP/dlm/dlm.c" "$OUT/dlm_control.c"

build() {   # build <object> <source> <flags>
    $CC $CPPFLAGS $3 -c -o "$OUT/$1.o" "$2" 2> "$OUT/$1.build.log" ||
        { cat "$OUT/$1.build.log"; echo "acq_release_deadlock: build of $2 failed"; exit 2; }
}
build dlm_fix "$TOP/dlm/dlm.c" "$ENGINE"
build dlm_control "$OUT/dlm_control.c" "$ENGINE"
build dlm_shared "$TOP/dlm/dlm_shared.c" "$ENGINE"
build tauth_ledger "$TOP/dlm/tauth_ledger.c" "$STRICT"
build tauth_store "$TOP/dlm/tauth_store.c" "$STRICT"
build pal_user "$TOP/pal/linux/user.c" "$STRICT"
build acq_release_deadlock_test "$HERE/acq_release_deadlock_test.c" "$ENGINE"
for arm in fix control; do
    $CC $STRICT -o "$OUT/test_$arm" "$OUT/dlm_$arm.o" "$OUT/dlm_shared.o" \
        "$OUT/tauth_ledger.o" "$OUT/tauth_store.o" "$OUT/pal_user.o" \
        "$OUT/acq_release_deadlock_test.o" -lpthread || exit 2
done

# One arm after the other.  Run together, both format their ledger image at
# once and each one's setup slowed from 7 s to as much as 14 s, which put a
# correct run at its budget (29.9 s measured with six copies running).
timeout "$RUN_BUDGET" "$OUT/test_fix" > "$OUT/run-fix.log" 2>&1; rc_fix=$?
timeout "$RUN_BUDGET" "$OUT/test_control" > "$OUT/run-control.log" 2>&1; rc_control=$?

DEADLOCK='mxfs_pal_rwlock_wrlock: pthread_rwlock_wrlock failed: Resource deadlock avoided'
bad=0
for arm in control fix; do
    log=$OUT/run-$arm.log
    eval "rc=\$rc_$arm"
    echo "--- $arm (rc=$rc, $(wc -l < "$log") log lines; whole log: $log)"
    grep -E '^===|^  (PASS|FAIL|INFO)|pthread_rwlock' "$log"
    if [ "$rc" = 124 ]; then
        echo "acq_release_deadlock: $arm ran past its ${RUN_BUDGET}s budget"
        bad=1
    elif [ "$arm" = control ]; then
        if [ "$rc" != 0 ] && grep -qF -- "$DEADLOCK" "$log"; then
            echo "acq_release_deadlock: control aborted on the recursive write lock, as predicted"
        else
            echo "acq_release_deadlock: control did NOT abort on the recursive write lock: the test does not reach the bug"
            bad=1
        fi
    elif [ "$rc" = 0 ] && ! grep -q 'pthread_rwlock' "$log"; then
        echo "acq_release_deadlock: fix passed"
    else
        echo "acq_release_deadlock: fix FAILED"
        bad=1
    fi
done
if [ "$bad" = 0 ]; then
    echo "acq_release_deadlock: PASS"
else
    echo "acq_release_deadlock: FAIL"
fi
exit $bad
