#!/bin/bash
# d0950_fence_guard.sh — does the live-member fence guard actually fire, and is
# it selective?
#
# WHAT IS BEING VERIFIED.  mxfs_scsipr_fence_node() now consults a guard before
# issuing any PREEMPT AND ABORT: "is this key carried RIGHT NOW by a LIVE member
# other than the incarnation being fenced?".  It exists because the PR key is
# derived per BOOT from {host, boot, LUN} and a host reaches the LUN over one
# I_T nexus, so a successor incarnation mounting in the same kernel re-registers
# the IDENTICAL key its dead predecessor left behind as the fence target — and
# the target cannot tell the two apart, so the P&A would strip the LIVE
# successor's registration and abort its task set.
#
# TWO ARMS, and the control is the point.  A guard that refuses EVERY fence
# would pass the positive arm while making recovery impossible, so:
#
#   live     the probe names the PEER's real, currently-registered key.
#            EXPECT: kind=KEY_HELD_BY_LIVE_MEMBER, proves_excl=0, the
#            P-PR-FENCE-KEY-LIVE-ELSEWHERE refusal logged, and — the assertion
#            that matters — the peer's registration STILL PRESENT on its own
#            nexus afterwards and the peer still able to write.
#
#   unheld   the probe names a key nobody holds.
#            EXPECT: the guard does NOT fire (any kind except
#            KEY_HELD_BY_LIVE_MEMBER).  This is what proves the guard
#            discriminates rather than blanket-refusing.
#
# READ FULL STATUS is the only view used to decide whose key is whose: READ KEYS
# reports that a key is registered somewhere and never says on which nexus.
#
# Usage: tests/d0950_fence_guard.sh <fencer> <peer>
# Exit 0 PASS, 1 FAIL, 2 INFRA-FAIL.
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
FENCER="${1:?usage: d0950_fence_guard.sh <fencer> <peer>}"
PEER="${2:?usage: d0950_fence_guard.sh <fencer> <peer>}"
MNT=/mnt/shared
KNOB=/sys/module/mxfs/parameters/dbg_fence_probe_key

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_d0950_fence_guard"
mkdir -p "$OUT"
FAILS=0
say() { echo "[guard] $*"; }
fail() { say "FAIL: $*"; FAILS=$((FAILS+1)); }

DEV=$(timeout 25 "$SSH" "$FENCER" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -n "$DEV" ] || { say "INFRA-FAIL: $FENCER has no mxfs mount"; exit 2; }
timeout 25 "$SSH" "$PEER" "mount -t mxfs | grep -q mxfs" 2>/dev/null || { say "INFRA-FAIL: $PEER has no mxfs mount"; exit 2; }
timeout 25 "$SSH" "$FENCER" "test -w $KNOB" 2>/dev/null || { say "INFRA-FAIL: $KNOB not present on $FENCER (build without the injector?)"; exit 2; }

fullstatus() { timeout 40 "$SSH" "$1" "sg_persist --in --read-full-status -d $DEV 2>&1" > "$OUT/$2.fs.txt" 2>&1; }

# the key registered on <host>'s OWN nexus, from READ FULL STATUS
own_key() { # <node> <tag> -> hex key or empty
    fullstatus "$1" "$2"
    awk -v want="$1-mxfs-node" '
        /[Kk]ey[ \t]*=[ \t]*0[xX][0-9a-fA-F]+/ {
            k=$0; sub(/.*[Kk]ey[ \t]*=[ \t]*/, "", k); sub(/[^0-9a-fA-FxX].*/, "", k); cur=k; next
        }
        index($0, want) > 0 && cur != "" { print cur; exit }
    ' "$OUT/$2.fs.txt"
}
# is <key> still on <host>'s own nexus?
key_on_own_nexus() { # <node> <tag> <key>
    local got; got=$(own_key "$1" "$2")
    [ -n "$got" ] && [ "$(printf '%s' "${got#0x}" | sed 's/^0*//' | tr 'A-F' 'a-f')" = \
                      "$(printf '%s' "${3#0x}" | sed 's/^0*//' | tr 'A-F' 'a-f')" ] && echo yes || echo no
}
write_ok() { timeout 30 "$SSH" "$1" "echo ok > $MNT/.guard_$1 && sync -f $MNT && rm -f $MNT/.guard_$1 && echo WRITE_OK" 2>/dev/null | grep -c WRITE_OK; }
hex2dec() { printf '%llu' "$1"; }

PEERKEY=$(own_key "$PEER" "peer_before")
FENCERKEY=$(own_key "$FENCER" "fencer_before")
[ -n "$PEERKEY" ] || { say "INFRA-FAIL: could not read $PEER's own key from READ FULL STATUS"; exit 2; }
say "dev=$DEV fencer=$FENCER key=$FENCERKEY peer=$PEER key=$PEERKEY"
[ "$PEERKEY" != "$FENCERKEY" ] || { say "INFRA-FAIL: both nodes report the same key — not the topology this tests"; exit 2; }

probe() { # <tag> <key-hex> -> sets PROBE_LINE, GUARD_LINE
    local tag="$1" k="$2" dec
    dec=$(hex2dec "$k")
    timeout 25 "$SSH" "$FENCER" "dmesg --clear; echo $dec > $KNOB; cat $KNOB" > "$OUT/$tag.arm.txt" 2>&1
    sleep 4
    timeout 25 "$SSH" "$FENCER" "dmesg" > "$OUT/$tag.dmesg.txt" 2>&1
    PROBE_LINE=$(grep -a 'P-DBG-FENCE-PROBE' "$OUT/$tag.dmesg.txt" | tail -1)
    GUARD_LINE=$(grep -a 'P-PR-FENCE-KEY-LIVE-ELSEWHERE' "$OUT/$tag.dmesg.txt" | head -1)
}

# ── arm 1: the peer's real live key ─────────────────────────────────────────
say "=== arm live: probing $FENCER's fence path with $PEER's LIVE key $PEERKEY ==="
probe live "$PEERKEY"
say "probe: ${PROBE_LINE:-<none>}"
say "guard: ${GUARD_LINE:-<none>}"
[ -n "$PROBE_LINE" ] || fail "the injected fence attempt never ran (no P-DBG-FENCE-PROBE)"
echo "$PROBE_LINE" | grep -q 'kind=KEY_HELD_BY_LIVE_MEMBER' || fail "guard did not fire on a LIVE peer key: $PROBE_LINE"
echo "$PROBE_LINE" | grep -q 'proves_excl=0' || fail "the refusal is being reported as proving exclusion: $PROBE_LINE"
[ -n "$GUARD_LINE" ] || fail "no P-PR-FENCE-KEY-LIVE-ELSEWHERE refusal logged"
# THE ASSERTION THAT MATTERS: the live peer was not touched.
STILL=$(key_on_own_nexus "$PEER" "peer_after_live" "$PEERKEY")
W=$(write_ok "$PEER")
say "after the refused fence: $PEER key on its own nexus=$STILL write_ok=$W"
[ "$STILL" = yes ] || fail "the LIVE peer's registration was removed — the guard did not prevent the preempt"
[ "$W" = 1 ] || fail "the LIVE peer cannot write after the refused fence"

# ── arm 2: control — a key nobody holds ─────────────────────────────────────
UNHELD=0x51d0950c0ffee001
say "=== arm unheld (control): probing with $UNHELD, which nobody holds ==="
probe unheld "$UNHELD"
say "probe: ${PROBE_LINE:-<none>}"
[ -n "$PROBE_LINE" ] || fail "control: the injected fence attempt never ran"
if echo "$PROBE_LINE" | grep -q 'kind=KEY_HELD_BY_LIVE_MEMBER'; then
    fail "control: the guard fired for a key NOBODY holds — it is blanket-refusing, which would stall every recovery: $PROBE_LINE"
else
    say "control: guard correctly did not fire (kind is not KEY_HELD_BY_LIVE_MEMBER)"
fi

# ── the fleet must be healthy afterwards ────────────────────────────────────
for n in "$FENCER" "$PEER"; do
    m=$(timeout 25 "$SSH" "$n" "grep -c mxfs /proc/mounts" 2>/dev/null | tr -dc '0-9')
    w=$(write_ok "$n")
    say "final $n: mounted=${m:-0} write_ok=$w"
    [ "${m:-0}" -ge 1 ] || fail "final: $n is not mounted"
    [ "$w" = 1 ] || fail "final: $n cannot write"
done
timeout 25 "$SSH" "$FENCER" "echo 0 > $KNOB" >/dev/null 2>&1

say "=== fails=$FAILS evidence=$OUT ==="
[ "$FAILS" -eq 0 ] && { say "PASS"; exit 0; }
exit 1
