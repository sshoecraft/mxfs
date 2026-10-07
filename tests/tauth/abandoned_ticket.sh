#!/bin/bash
# abandoned_ticket.sh — build tests/tauth/abandoned_ticket_test and run its
# three arms (active, prepared, live), each in its own process.
#
#   tests/tauth/abandoned_ticket.sh           the DLM engine as it is: every
#                                             arm must pass
#   tests/tauth/abandoned_ticket.sh control   the engine with dlm_store_fenced_cb
#                                             as it was through 0.90.91
#                                             (control/store_fenced_cb_0.90.91.c):
#                                             active and prepared must fail with
#                                             the defect's signature (not granted,
#                                             no takeover, the on-demand takeover's
#                                             last answer -EBUSY, the ticket still
#                                             on the platter); live must pass, since
#                                             what it checks did not change
#
# Built with AddressSanitizer, on its own rather than through this directory's
# Makefile, because the control arm compiles a modified copy of dlm/dlm.c.
# Objects and the binary go to obj/abandoned-<arm>/.  Exit 0 when the arm
# behaved as it must, 1 otherwise, 2 when the build failed.
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TOP=$(cd -- "$HERE/../.." && pwd)
ARM=${1:-engine}
case "$ARM" in engine|control) ;; *) echo "usage: $0 [control]"; exit 2 ;; esac
OUT=$HERE/obj/abandoned-$ARM
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
        "static bool dlm_store_fenced_cb(void *data, uint32_t node, uint64_t inc)" \
        "$HERE/control/store_fenced_cb_0.90.91.c" <<'PY' || exit 2
import sys

src, out, sig, old = sys.argv[1:5]
text = open(src).read()
start = text.find(sig + "\n{\n")
if start < 0:
    sys.exit("abandoned_ticket: the definition of '%s' not found in %s" % (sig, src))
# the definition ends at its first closing brace in column 0
end = text.find("\n}\n", start)
if end < 0:
    sys.exit("abandoned_ticket: the end of '%s' not found" % sig)
text = text[:start] + open(old).read() + text[end + 3:]
print("control: '%s' replaced by %s" % (sig, old))
open(out, "w").write(text)
PY
fi

for pair in "$DLM_SRC:dlm" "$TOP/dlm/dlm_shared.c:dlm_shared" \
            "$TOP/dlm/tauth_ledger.c:tauth_ledger" "$TOP/dlm/tauth_store.c:tauth_store" \
            "$TOP/pal/linux/user.c:pal_user" "$HERE/abandoned_ticket_test.c:abandoned_ticket_test"; do
    $CC $CPPFLAGS $CFLAGS -c -o "$OUT/${pair##*:}.o" "${pair%%:*}" 2> "$OUT/${pair##*:}.build.log" \
        || { cat "$OUT/${pair##*:}.build.log"; echo "abandoned_ticket: build of ${pair%%:*} failed"; exit 2; }
done
$CC $CFLAGS -o "$OUT/abandoned_ticket_test" "$OUT/dlm.o" "$OUT/dlm_shared.o" \
    "$OUT/tauth_ledger.o" "$OUT/tauth_store.o" "$OUT/pal_user.o" \
    "$OUT/abandoned_ticket_test.o" -lpthread || exit 2

# the defect's signature on a request that met a dead writer's ticket
DEFECT='granted=0 .* ticket_takeovers=0 ondemand_last=\{page=[0-9]+ rc=-16\} ticket_left=1$'
bad=0
for arm in active prepared live; do
    log=$OUT/run-$arm.log
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/abandoned_ticket_test" "$arm" > "$log" 2>&1
    rc=$?
    grep -E '^===|^  (PASS|FAIL|INFO|SIGNATURE)|ERROR: AddressSanitizer|^SUMMARY' "$log"
    if grep -q 'ERROR: AddressSanitizer' "$log"; then
        echo "abandoned_ticket: $ARM $arm stopped by the sanitizer (rc=$rc); whole report: $log"
        bad=1
    elif [ "$ARM" = engine ] || [ "$arm" = live ]; then
        if [ "$rc" = 0 ]; then
            echo "abandoned_ticket: $ARM $arm PASSED"
        else
            echo "abandoned_ticket: $ARM $arm FAILED (rc=$rc); whole report: $log"
            bad=1
        fi
    elif [ "$rc" = 1 ] && grep -qE "SIGNATURE arm=$arm $DEFECT" "$log"; then
        echo "abandoned_ticket: control $arm failed with the defect's signature, as it must"
    else
        echo "abandoned_ticket: control $arm did NOT show the defect (rc=$rc): the arm does not reach it; whole report: $log"
        bad=1
    fi
done
exit $bad
