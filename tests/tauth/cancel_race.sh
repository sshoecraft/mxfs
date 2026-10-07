#!/bin/bash
# cancel_race.sh — build tests/tauth/cancel_race_test with AddressSanitizer and
# run it.  The sanitizer turns a read or a free of a freed cancellation record
# into an abort with the stack that did it, which is what the test's window
# (cancel_race_test.c) is made to provoke.
#
#   tests/tauth/cancel_race.sh            the DLM engine as it is: must pass
#   tests/tauth/cancel_race.sh control    the engine with the re-sends as they
#                                         were before their fixes: the 0.90.90
#                                         cancellation re-send
#                                         (control/cancel_retry_tick_0.90.90.c
#                                         for dlm_cancel_retry_tick) and the
#                                         0.90.82 release re-send
#                                         (control/release_retry_tick_0.90.82.c
#                                         for mxfs_dlm_release_retry_tick); each
#                                         phase must be stopped by the sanitizer
#
# It builds on its own, not through this directory's Makefile: every object it
# links has to be instrumented, and the control arm compiles a modified copy
# of dlm/dlm.c.  Objects and the binary go to obj/asan-<arm>/.
# Exit 0 when the arm behaved as it must (the engine passes, the control is
# stopped), 1 otherwise, 2 when the build failed.
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TOP=$(cd -- "$HERE/../.." && pwd)
ARM=${1:-engine}
case "$ARM" in engine|control) ;; *) echo "usage: $0 [control]"; exit 2 ;; esac
OUT=$HERE/obj/asan-$ARM
mkdir -p "$OUT" || exit 2
CC=${CC:-gcc}
CFLAGS="-O1 -g -std=gnu11 -Wall -fsanitize=address -fno-omit-frame-pointer"
# dlm/ too: the control arm's copy of dlm.c is compiled from obj/, away from
# the headers it includes by its own directory
CPPFLAGS="-I$TOP -I$TOP/include -I$TOP/pal -I$TOP/dlm"

DLM_SRC=$TOP/dlm/dlm.c
if [ "$ARM" = control ]; then
    DLM_SRC=$OUT/dlm_control.c
    python3 -I - "$TOP/dlm/dlm.c" "$DLM_SRC" \
        "static void dlm_cancel_retry_tick(struct mxfs_dlm_ctx *ctx, uint64_t now)" \
        "$HERE/control/cancel_retry_tick_0.90.90.c" \
        "void mxfs_dlm_release_retry_tick(struct mxfs_dlm_ctx *ctx)" \
        "$HERE/control/release_retry_tick_0.90.82.c" <<'PY' || exit 2
import sys

src, out = sys.argv[1:3]
text = open(src).read()
for i in range(3, len(sys.argv), 2):
    sig, old = sys.argv[i], sys.argv[i + 1]
    start = text.find(sig + "\n{\n")
    if start < 0:
        sys.exit("cancel_race: the definition of '%s' not found in %s" % (sig, src))
    # the definition ends at its first closing brace in column 0
    end = text.find("\n}\n", start)
    if end < 0:
        sys.exit("cancel_race: the end of '%s' not found" % sig)
    text = text[:start] + open(old).read() + text[end + 3:]
    print("control: '%s' replaced by %s" % (sig, old))
open(out, "w").write(text)
PY
fi

for pair in "$DLM_SRC:dlm" "$TOP/dlm/dlm_shared.c:dlm_shared" \
            "$TOP/dlm/tauth_ledger.c:tauth_ledger" "$TOP/dlm/tauth_store.c:tauth_store" \
            "$TOP/pal/linux/user.c:pal_user" "$HERE/cancel_race_test.c:cancel_race_test"; do
    $CC $CPPFLAGS $CFLAGS -c -o "$OUT/${pair##*:}.o" "${pair%%:*}" 2> "$OUT/${pair##*:}.build.log" \
        || { cat "$OUT/${pair##*:}.build.log"; echo "cancel_race: build of ${pair%%:*} failed"; exit 2; }
done
$CC $CFLAGS -o "$OUT/cancel_race_test" "$OUT/dlm.o" "$OUT/dlm_shared.o" "$OUT/tauth_ledger.o" \
    "$OUT/tauth_store.o" "$OUT/pal_user.o" "$OUT/cancel_race_test.o" -lpthread || exit 2

# Each phase on its own run, so the control shows each half stopped.  Leaks
# are not what this is about; the first bad access stops a run.
bad=0
for phase in cancel release; do
    log=$OUT/run-$phase.log
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/cancel_race_test" "$phase" > "$log" 2>&1
    rc=$?
    grep -E '^===|^  (PASS|FAIL|INFO)|ERROR: AddressSanitizer|^SUMMARY' "$log"
    if [ "$ARM" = engine ]; then
        if [ "$rc" = 0 ]; then
            echo "cancel_race: engine $phase PASSED"
        else
            echo "cancel_race: engine $phase FAILED (rc=$rc); whole report: $log"
            bad=1
        fi
    elif grep -q 'ERROR: AddressSanitizer' "$log"; then
        echo "cancel_race: control $phase stopped by the sanitizer as it must be (rc=$rc); report: $log"
    else
        echo "cancel_race: control $phase was NOT stopped (rc=$rc): the test does not reach the window; report: $log"
        bad=1
    fi
done
exit $bad
