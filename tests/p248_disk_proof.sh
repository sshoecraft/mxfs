#!/bin/bash
# tests/p248_disk_proof.sh — injected-departure DISK proof for
# D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK (designed sess157, scripted sess159).
#
# Proves ON DISK (not from log claims) that the teardown owed-drain's
# discharge actually landed: after a departure whose release_all was forced
# to leave one slot owed (K1 caw_inject_ra_casfail=2), the departing node's
# holder bit must be GONE from that slot on the LUN.  On 0.11.455 this exact
# procedure showed the defect: slot still MXCW-LIVE with holders_ex=0x1
# while the node claimed a clean departure.  On the fixed build the slot
# must read MXDL-TOMB or have every holder bit for the departed node clear.
#
# Method note (sess157): single-sector O_DIRECT reads through
# multipath/SCST return stale data; only the 1MB-granularity scan is valid
# disk evidence.  Scan = dd bs=1M skip=64 count=34; slot IDX lives at byte
# 40960+IDX*512 within the scan.  Validity control: slots the same
# departure released IN-LINE (P109 cas_rc=0) must read TOMB/cleared — if
# they read LIVE-with-bits the scan itself is stale and the run is INVALID.
#
# Preconditions: both nodes mounted on the tree's srcversion (run
# tests/p248_inject.sh prep first if unsure).  Leaves test1 UNMOUNTED.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NONCE=$$
WANT_SV=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')
cd "$REPO" || exit 2

fail() { echo "FAIL: $*"; exit 1; }

# ── preconditions ────────────────────────────────────────────────────────
for n in test1 test2; do
    sv=$(timeout 15 "$SSH" "$n" \
         "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null | tr -d '\r\n ')
    [ "$sv" = "$WANT_SV" ] || fail "$n srcversion '$sv' != tree '$WANT_SV'"
    timeout 15 "$SSH" "$n" "mountpoint -q $MNT" >/dev/null 2>&1 ||
        fail "$n not mounted"
done
timeout 15 "$SSH" test1 "
    for k in caw_inject_ra_casfail caw_inject_owed_enoent \
             caw_inject_dow_casfail caw_inject_pubfreeze_bump \
             caw_inject_wait_expire caw_drain_budget_ms; do
        echo 0 > /sys/module/mxfs/parameters/\$k 2>/dev/null
    done; true" >/dev/null 2>&1

# test1's node_slot from its latest CAW init line
T1SLOT=$(timeout 15 "$SSH" test1 \
    "dmesg | awk '/DLM initialized \(CAW, slot=/{s=\$0} END{print s}'" \
    2>/dev/null | grep -oE 'slot=[0-9]+' | head -1 | cut -d= -f2)
[ -n "$T1SLOT" ] || fail "cannot determine test1 node_slot"
echo "test1 node_slot=$T1SLOT (holder bit $((1 << T1SLOT)))"

# ── injected departure ───────────────────────────────────────────────────
timeout 15 "$SSH" test1 "echo 'P248DISK-$NONCE BEGIN' > /dev/kmsg" \
    >/dev/null 2>&1
timeout 30 "$SSH" test1 "mkdir -p $MNT/p248disk_$NONCE &&
    for i in \$(seq 1 20); do echo x > $MNT/p248disk_$NONCE/f\$i; done &&
    sync" >/dev/null 2>&1 || fail "workload"
timeout 15 "$SSH" test1 \
    "echo 2 > /sys/module/mxfs/parameters/caw_inject_ra_casfail" \
    >/dev/null 2>&1
timeout 45 "$SSH" test1 "umount $MNT" >/dev/null 2>&1 || fail "umount"
timeout 15 "$SSH" test1 "echo 'P248DISK-$NONCE END' > /dev/kmsg" \
    >/dev/null 2>&1

W=$(timeout 25 "$SSH" test1 \
    "dmesg | sed -n '/P248DISK-$NONCE BEGIN/,/P248DISK-$NONCE END/p'" \
    2>/dev/null)
echo "$W" | grep -E 'P109-CLR|P2(45|54|57|59|63|66|67|68|71)-' | sed 's/^/  /'

# the owed slot: P109 line with nonzero cas_rc; in-line controls: cas_rc=0
OWED_SLOT=$(echo "$W" | grep 'P109-CLR-RELEASE-ALL' |
    grep -v 'cas_rc=0' | grep -oE 'slot=[0-9]+' | head -1 | cut -d= -f2)
CTRL_SLOTS=$(echo "$W" | grep 'P109-CLR-RELEASE-ALL' | grep 'cas_rc=0' |
    grep -oE 'slot=[0-9]+' | cut -d= -f2 | head -3)
[ -n "$OWED_SLOT" ] || fail "no owed slot in window (K1 not consumed?)"
p271=$(echo "$W" | grep -c 'P271-OWED-DISCHARGE')
p267=$(echo "$W" | grep -c 'P267-RETIRE-SUM')
p259=$(echo "$W" | grep -c 'P259-DEPART-UNCLEAN')
echo "owed slot=$OWED_SLOT ctrl slots: $(echo $CTRL_SLOTS | tr '\n' ' ')"
echo "window: p271=$p271 p267=$p267 p259=$p259"
[ "$p271" -ge 1 ] || fail "no P271 discharge in window"
[ "$p259" -eq 0 ] || fail "departure was UNCLEAN (P259 x$p259)"

# ── disk scan from test2 ─────────────────────────────────────────────────
timeout 60 "$SSH" test2 \
    "dd if=$DEV of=/root/p248scan_$NONCE.bin bs=1M skip=64 count=34 \
     iflag=direct 2>/dev/null && ls -l /root/p248scan_$NONCE.bin" \
    2>/dev/null | sed 's/^/  scan: /' || fail "scan dd"

decode() { # slot-idx -> "magic gen hex hpw hpr hcw hcr" (LE u32/u32/u64x5)
    timeout 25 "$SSH" test2 "
        dd if=/root/p248scan_$NONCE.bin bs=512 \
           skip=\$(( (40960 + $1 * 512) / 512 )) count=1 2>/dev/null |
        od -A n -v -t x1 -N 80 | tr -d '\n'" 2>/dev/null |
    awk '{
        for (i = 1; i <= NF; i++) b[i-1] = $i
        le32 = ""; for (i = 3; i >= 0; i--) le32 = le32 b[i]
        gen  = ""; for (i = 7; i >= 4; i--) gen  = gen b[i]
        out = le32 " " gen
        # holders_ex..holders_cr at 40,48,56,64,72
        for (o = 40; o <= 72; o += 8) {
            v = ""; for (i = o+7; i >= o; i--) v = v b[i]
            out = out " " v
        }
        print out
    }'
}

check_slot() { # idx label expect_clear_bit -> 0 ok
    local f m gen hex hpw hpr hcw hcr v bit=$((1 << T1SLOT)) rc=0
    f=$(decode "$1"); read -r m gen hex hpw hpr hcw hcr <<< "$f"
    echo "  slot $1 [$2]: magic=$m gen=$gen ex=$hex pw=$hpw pr=$hpr cw=$hcw cr=$hcr"
    case "$m" in
    4d58444c)   ;;                       # MXDL-TOMB: cleared, done
    4d584357)                            # MXCW-LIVE: our bit must be gone
        for v in "$hex" "$hpw" "$hpr" "$hcw" "$hcr"; do
            # every mask must decode as exactly 16 hex chars — anything
            # else is an od/awk decode fault, which must NOT pass silently
            case "$v" in
            *[!0-9a-f]*|"") echo "    DECODE FAULT: mask '$v'"; return 2 ;;
            esac
            [ ${#v} -eq 16 ] || { echo "    DECODE FAULT: mask '$v'"; return 2; }
            [ $(( 0x$v & bit )) -eq 0 ] || rc=1
        done ;;
    00000000)   echo "    (unwritten sector)" ;;
    *)          echo "    UNRECOGNIZED magic"; rc=2 ;;
    esac
    return $rc
}

VALID=1; PROOF=1
for s in $CTRL_SLOTS; do
    check_slot "$s" ctrl || {
        echo "  CONTROL slot $s still holds test1 bits — SCAN STALE, run INVALID"
        VALID=0; }
done
check_slot "$OWED_SLOT" owed-proof || {
    echo "  PROOF FAILED: departed node's bit still on disk at slot $OWED_SLOT"
    PROOF=0; }

timeout 15 "$SSH" test2 "rm -f /root/p248scan_$NONCE.bin" >/dev/null 2>&1
timeout 15 "$SSH" test1 \
    "echo 0 > /sys/module/mxfs/parameters/caw_inject_ra_casfail" \
    >/dev/null 2>&1

[ "$VALID" -eq 1 ] || fail "scan validity control failed — no verdict"
[ "$PROOF" -eq 1 ] || fail "disk proof FAILED"
echo "=== p248_disk_proof PASS: slot $OWED_SLOT clear of node_slot $T1SLOT on the LUN (test1 left unmounted) ==="
