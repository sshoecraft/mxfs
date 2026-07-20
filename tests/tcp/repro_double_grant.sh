#!/bin/bash
# repro_double_grant.sh — reproduce + capture the tcp_dlm_scaling DOUBLE-GRANT.
#
# PROVEN ROOT (sess-tcp): tcp_dlm_scaling's ~50%-flaky durable leftover dirent is
# a TCP DLM double-grant of the parent-dir inode EX — both nodes hold EX
# concurrently and one durably reverts the other's rename+rm.  See ccmemory
# sess-tcp-double-grant-mechanism-refinement.
#
# This driver loops the STANDALONE test via the real harness (which reproduces,
# unlike a manual churn that lacks the MQTT-barrier timing), and on the first
# FAIL captures the decisive evidence: the leftover dirent + its parent-dir
# inode + the cross-node P106-EXGRANT/EXREL timeline that proves overlapping EX.
#
# IMPORTANT: per the Heisenbug finding, do NOT run with mxfs.lockwr=1 / instr=1
# while trying to REPRODUCE — per-lock printk closes the race (6/6 pass).  Use
# the default build.  To CONFIRM the mechanism, build the next session's
# lock-free event ring (no hot-path printk) instead.
#
# A FAIL wedges the FS, so this reboots+resets the VMs between attempts.
#
# Run ON clyde:  bash tests/tcp/repro_double_grant.sh [max_iters]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO"
S="$REPO/tools/mxfs_sshpass.sh"; P="${MXFS_PASS:-/tmp/.mxfs_pass}"
N1=test1; N2=test2; MAX="${1:-8}"
CLEAN='grep -vE "^Warning:|^Unauthorized|^If you"'
ssh1() { timeout 15 bash "$S" "$1" "$P" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

boot_wait() {
    for n in "$N1" "$N2"; do virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    sleep 2
    for n in "$N1" "$N2"; do virsh -c qemu:///system start "$n" >/dev/null 2>&1; done
    for i in $(seq 1 30); do
        ok=0; for n in "$N1" "$N2"; do timeout 6 bash "$S" "$n" "$P" true >/dev/null 2>&1 && ok=$((ok+1)); done
        [ "$ok" -eq 2 ] && return 0; sleep 5
    done
    echo "boot_wait: nodes did not come up"; return 1
}

for it in $(seq 1 "$MAX"); do
    echo "=== iter $it: reboot + reset + standalone tcp_dlm_scaling ==="
    boot_wait || exit 1
    timeout 260 bash tests/setup/reset2_tcp.sh >/dev/null 2>&1
    res=$(timeout 200 ./run.sh 2 tcp tcp_dlm_scaling 2>&1 | grep -E 'PASS  tcp|FAIL  tcp')
    echo "  $res"
    if echo "$res" | grep -q FAIL; then
        DIRINO=$(ssh1 "$N1" "stat -c %i /mnt/shared/.tcp_dlm_scaling" | grep -oE '^[0-9]+' | head -1)
        echo "*** DOUBLE-GRANT REPRO at iter $it (dir ino=$DIRINO) ***"
        echo "--- leftover (both nodes; both agree + nlink => on-disk) ---"
        for n in "$N1" "$N2"; do echo "  $n:"; ssh1 "$n" "for x in /mnt/shared/.tcp_dlm_scaling/*; do stat -c '    %n nlink=%h ino=%i' \"\$x\" 2>/dev/null; done"; done
        echo "--- P106 EX grant/release timeline for dir ino=$DIRINO (both UTC) ---"
        echo "    look for one node holding EX (EXGRANT, no EXREL) while the other EXGRANTs = overlap"
        for n in "$N1" "$N2"; do
            echo "  $n:"
            ssh1 "$n" "dmesg | grep -E 'P106-EX(GRANT|REL) ino=$DIRINO ' | sed -E 's/.*(P106-EX(GRANT|REL)).*realns=([0-9]+).*/    \3 \1/' | tail -16"
        done
        echo "NOTE: P106 lines require the dir-write probe; reset2_tcp loads default build."
        echo "      If absent, set MODARGS dirwr=1 in tests/setup/prep_node.sh for this CAPTURE"
        echo "      run only (it perturbs less than lockwr; lockwr/instr HIDE the race)."
        exit 0
    fi
done
echo "no repro in $MAX iters (it is ~50%/iter; run more)"
