#!/bin/bash
#
# rpm_post_dkms_failure.sh — what dnf reports when the RPM's DKMS build fails
#
# Usage: tests/rpm_post_dkms_failure.sh RPM [RPM ...]
#
# Installs each RPM with dnf in a fresh almalinux:9 container, in two cases:
#
#   fail      a kernel tree whose Makefile fails is present under /lib/modules,
#             so the %post DKMS build for that kernel fails as a build against
#             broken or mismatched headers does on a real host
#   noheaders no /lib/modules/<k>/build exists for any kernel (a container
#             has no kernel package; kernel-devel alone does not provide one)
#
# An install that leaves no module must not read as a successful one.  RPM
# cannot roll back from %post, so the requirement is that the scriptlet fails
# (rpm prints "scriptlet failed", dnf "Error in POSTIN scriptlet") and names
# the cause.  0.89.78's RPM printed Complete! with dkms status "added".
#
# Prints, per RPM and case: dnf_rc, the scriptlet-failure lines, the %post's
# own ERROR line, rpm -q and dkms status.  Verdict per case:
#   CASE_PASS  the scriptlet failure and an ERROR line naming the cause
#   CASE_FAIL  otherwise
# Exits 0 only if every case of every RPM passed.
#
# Budget: dnf pulls dkms (EPEL), kernel-devel and gcc into a bare image:
# ~90 s measured per container on clyde's host network, x2 -> 240 s each.
#
set -u

[ $# -ge 1 ] || { echo "usage: $0 RPM [RPM ...]" >&2; exit 2; }
CASE_S=240
FAILS=0

for rpm in "$@"; do
    [ -f "$rpm" ] || { echo "no such file: $rpm" >&2; exit 2; }
    dir=$(cd "$(dirname "$rpm")" && pwd)
    base=$(basename "$rpm")
    for c in fail noheaders; do
        echo "=== $base case=$c ==="
        out=$(timeout $CASE_S docker run --rm --network host -v "$dir:/rpms:ro" -e C="$c" -e RPM="/rpms/$base" \
            almalinux:9 bash -c '
                dnf -q -y install epel-release >/dev/null 2>&1 || echo "SETUP epel-release failed"
                if [ "$C" = fail ]; then
                    mkdir -p /lib/modules/0.0.0-mxfs-fail/build
                    printf "modules:\n\t@echo deliberately failing kernel tree >&2; false\n" > /lib/modules/0.0.0-mxfs-fail/build/Makefile
                fi
                dnf -y install "$RPM" 2>&1; echo "dnf_rc=$?"
                echo "rpm_q=$(rpm -q mxfs)"
                echo "dkms_status=$(dkms status mxfs 2>&1 | tr "\n" " ")"
            ' 2>&1)
        rc=$?
        echo "$out" | grep -E "dnf_rc=|rpm_q=|dkms_status=|scriptlet|POSTIN|^ERROR|NOTE|SETUP|Complete!|Bad return" | sed 's/^/  /'
        [ $rc = 124 ] && echo "  container over the ${CASE_S} s budget"
        if [ $rc != 124 ] && echo "$out" | grep -qE "scriptlet failed|Error in POSTIN" \
            && echo "$out" | grep -qE "^ERROR: (MXFS .* did not build|no installed kernel has headers)"; then
            echo "CASE_PASS $base $c"
        else
            echo "CASE_FAIL $base $c"
            FAILS=$((FAILS + 1))
        fi
    done
done

[ $FAILS = 0 ] && { echo "RESULT PASS"; exit 0; }
echo "RESULT FAIL ($FAILS cases)"
exit 1
