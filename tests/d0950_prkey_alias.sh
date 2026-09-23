#!/bin/bash
# d0950_prkey_alias.sh — does a peer's certified fence of a dead incarnation
# remove the LIVE successor's PR registration on the same host?
#
# THE HYPOTHESIS, falsifiable:
#   The PR key is derived per BOOT from {host_uuid, boot_uuid, fs_uuid}
#   (dlm/prledger.c mxfs_prledger_derive_key), and one host has one I_T nexus,
#   so a successor incarnation mounting in the SAME kernel re-registers the
#   IDENTICAL key its dead predecessor left behind as the fence target.  A peer
#   that then expires the predecessor's record and certifies a fence issues
#   PREEMPT AND ABORT on that key.  The target cannot tell the two incarnations
#   apart, so the P&A lands on the LIVE successor: its registration is removed
#   and its outstanding commands are aborted while it believes itself mounted
#   and healthy.
#
#   PREDICTION IF TRUE  after the fence: the victim's key is gone from its own
#     nexus in READ FULL STATUS, its writes bounce with RESERVATION CONFLICT,
#     and it logs the fenced-self probes.
#   PREDICTION IF FALSE after the fence: the key is still registered on the
#     victim's nexus and the victim writes normally.
#
# WHY THIS SCRIPT EXISTS RATHER THAN tests/retire_pending_admission.sh race.
#   That arm drives exactly this interleaving and, in its peer-expiry-first
#   branch, REQUIRES both that the victim's remount succeeded (rc=0, i.e. it is
#   live on the re-derived key) and that a peer certified a fence of that
#   record.  It then checks only "no shutdown" and restores the fleet.  It
#   never asks whether the live successor survived its own fence — the
#   ordering-A assertions that do ask (P-PRKEY-FENCED == 0, "the derived key is
#   still registered after the remount") are not applied to that branch.  It
#   also requires three distinct hosts, which a two-node rig does not have.
#
# READ FULL STATUS, NOT READ KEYS.  READ KEYS reports that a key is registered
# somewhere; it does not say on which I_T nexus.  Every question here is
# "whose registration is this", so the primary view is READ FULL STATUS and
# READ KEYS is recorded only as a cross-check.  A conclusion drawn from READ
# KEYS alone about ownership is unsupported.
#
# Usage: tests/d0950_prkey_alias.sh <victim> <peer> [laps]
# Exit 0 PASS (hypothesis refuted: successor survived), 1 FAIL (hypothesis
# confirmed: live successor was fenced), 2 INFRA-FAIL, 3 INCONCLUSIVE (the
# peer-expiry-first ordering never occurred in the laps run — not a result).
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
VICTIM="${1:?usage: d0950_prkey_alias.sh <victim> <peer> [laps] [remount_at_s] [peer_delay_ms]}"
PEER="${2:?usage: d0950_prkey_alias.sh <victim> <peer> [laps] [remount_at_s] [peer_delay_ms]}"
LAPS="${3:-3}"
# Seconds after the dirty departure at which the successor remounts.  The
# aliasing window is bounded on one side by the peer deciding to expire the
# record (>= the 30 s grace) and on the other by the peer's PREEMPT AND ABORT
# completing.  Remounting too early lets the victim settle its OWN record first
# (P305-first: no fence, ordering never reached — measured on lap 1 of the
# first run at 29 s); too late and the fence has already landed before the
# successor registers.
REMOUNT_AT="${4:-32}"
# Widen that window deterministically: every PR IN READ KEYS on the PEER sleeps
# this long, so the bracket it must complete before issuing the P&A takes
# measurably longer while the successor is registering.  0 disables.
PEER_DELAY_MS="${5:-8000}"
MNT=/mnt/shared
PARAMS=/sys/module/mxfs/parameters
KNOB=$PARAMS/dbg_pr_unregister_fail
KNOB2=$PARAMS/dbg_retire_skip_restamp
ALL_KNOBS="dbg_pr_unregister_fail dbg_retire_skip_restamp dbg_pr_read_keys_fail dbg_pr_read_resv_fail dbg_pr_read_keys_trunc dbg_pr_read_keys_delay_ms dbg_pr_bracket_fail"
GRACE_S=30

[ "$VICTIM" = "$PEER" ] && { echo "FAIL: victim and peer must differ"; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_d0950_prkey_alias"
mkdir -p "$OUT"
say() { echo "[d0950/$VICTIM] $*"; }
VERDICT=inconclusive
FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS+1)); }

disarm_all() {
    local n k
    for n in "$VICTIM" "$PEER"; do
        ( for k in $ALL_KNOBS; do timeout 15 "$SSH" "$n" "echo 0 > $PARAMS/$k" >/dev/null 2>&1; done ) &
    done; wait
}
trap disarm_all EXIT

# ── preconditions ────────────────────────────────────────────────────────────
DEV=$(timeout 25 "$SSH" "$VICTIM" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -n "$DEV" ] || { say "INFRA-FAIL: $VICTIM has no mxfs mount"; exit 2; }
timeout 25 "$SSH" "$PEER" "mount -t mxfs | grep -q mxfs" 2>/dev/null || { say "INFRA-FAIL: $PEER has no mxfs mount"; exit 2; }
SV_V=$(timeout 25 "$SSH" "$VICTIM" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -d ' \r\n')
SV_P=$(timeout 25 "$SSH" "$PEER" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -d ' \r\n')
[ -n "$SV_V" ] && [ "$SV_V" = "$SV_P" ] || { say "INFRA-FAIL: srcversion mismatch victim=$SV_V peer=$SV_P"; exit 2; }
say "dev=$DEV srcversion=$SV_V laps=$LAPS out=$OUT"

# ── PR views.  full status is primary; read keys is the cross-check only. ─────
fullstatus() { # <node> <tag>
    timeout 40 "$SSH" "$1" "sg_persist --in --read-full-status -d $DEV 2>&1; echo RC=\$?" > "$OUT/$2.fs.txt" 2>&1
}
readkeys() { # <node> <tag>
    timeout 40 "$SSH" "$1" "sg_persist --in --read-keys -d $DEV 2>&1; echo RC=\$?" > "$OUT/$2.rk.txt" 2>&1
}
pr_snapshot() { # <tag>: both nodes, both views, in parallel
    local tag="$1"
    ( fullstatus "$VICTIM" "${tag}_victim" ) & ( fullstatus "$PEER" "${tag}_peer" ) &
    ( readkeys   "$VICTIM" "${tag}_victim" ) & ( readkeys   "$PEER" "${tag}_peer" ) &
    wait
}
# Is $KEY registered ON <host>'S OWN I_T NEXUS?  This is the question READ KEYS
# cannot answer and the reason this harness uses READ FULL STATUS: the target
# reports, per registration, the Transport Id of the initiator that holds it
# (iqn.2004-10.com.ubuntu:01:<host>-mxfs-node on this rig).  Presence of a key
# "somewhere" proves nothing about whose it is.
# Prints: on-own-nexus | on-other-nexus | absent | unknown
key_on_nexus() { # <tag_node_file> <key> <host>
    local f="$OUT/$1.fs.txt" k h blk
    k=$(printf '%s' "${2#0x}" | sed 's/^0*//' | tr 'A-F' 'a-f')
    h="$3"
    [ -s "$f" ] || { echo unknown; return; }
    grep -q 'RC=0' "$f" || { echo unknown; return; }
    # split into per-Key blocks; find the block whose key matches
    blk=$(awk -v want="$k" '
        /[Kk]ey[ \t]*=[ \t]*0[xX][0-9a-fA-F]+/ {
            if (inblk && found) exit
            line=$0
            sub(/.*[Kk]ey[ \t]*=[ \t]*0[xX]/, "", line)
            sub(/[^0-9a-fA-F].*/, "", line)
            cur=tolower(line); sub(/^0+/, "", cur)
            inblk=1; found=(cur==want); if (found) print; next
        }
        found { print }
    ' "$f")
    [ -n "$blk" ] || { echo absent; return; }
    if printf '%s' "$blk" | grep -qi -- "$h-mxfs-node"; then
        echo on-own-nexus
    elif printf '%s' "$blk" | grep -qi 'iqn\.'; then
        echo on-other-nexus
    else
        echo unknown
    fi
}
write_ok() { timeout 30 "$SSH" "$1" "echo ok > $MNT/.d0950_$1 && sync -f $MNT && rm -f $MNT/.d0950_$1 && echo WRITE_OK" 2>/dev/null | grep -c WRITE_OK; }
dmesg_of() { timeout 25 "$SSH" "$1" "dmesg" > "$OUT/$2.dmesg.txt" 2>&1; }
cnt() { grep -ac "$2" "$OUT/$1.dmesg.txt" 2>/dev/null | tr -dc '0-9'; }

# The module is already loaded on both nodes and both run the same srcversion
# (asserted in the preconditions), so the restore is a plain remount.  It must
# NOT go through prep_node.sh: that script insists on deploying a module from
# the repo and fails outright when the tree is unbuilt, which silently left the
# victim unmounted and made every following lap vacuous.
restore() {
    local L="$1" rc mounted
    disarm_all
    timeout 90 "$SSH" "$VICTIM" "mount -t mxfs | grep -q mxfs && timeout 60 umount $MNT; blockdev --flushbufs $DEV; timeout 120 mount -t mxfs $DEV $MNT; echo REMOUNT_RC=\$?; grep -c mxfs /proc/mounts" > "$OUT/restore_lap$L.log" 2>&1
    rc=$(sed -n 's/^REMOUNT_RC=//p' "$OUT/restore_lap$L.log" | tr -dc '0-9')
    mounted=$(tail -1 "$OUT/restore_lap$L.log" | tr -dc '0-9')
    if [ "${rc:-1}" != 0 ] || [ "${mounted:-0}" -lt 1 ]; then
        say "INFRA-FAIL: victim not restored after lap $L (rc=${rc:-?} mounted=${mounted:-0}) — later laps would be vacuous"
        return 2
    fi
    say "lap $L: victim restored (mounted)"
    return 0
}

# ── one lap ──────────────────────────────────────────────────────────────────
lap() {
    local L="$1" T_DEPART KEY rc own changed dirty exp cert
    say "--- lap $L ---"
    for n in "$VICTIM" "$PEER"; do ( timeout 20 "$SSH" "$n" "dmesg --clear" >/dev/null 2>&1 ) & done; wait
    pr_snapshot "lap${L}_before"
    if [ "$PEER_DELAY_MS" -gt 0 ]; then
        timeout 20 "$SSH" "$PEER" "echo $PEER_DELAY_MS > $PARAMS/dbg_pr_read_keys_delay_ms; cat $PARAMS/dbg_pr_read_keys_delay_ms" > "$OUT/lap${L}_peerdelay.txt" 2>&1
        [ "$(tail -1 "$OUT/lap${L}_peerdelay.txt" | tr -dc '0-9')" = "$PEER_DELAY_MS" ] || { say "INFRA-FAIL: peer READ KEYS delay not armed on lap $L"; return 2; }
    fi

    # dirty departure that KEEPS the key registered as the fence target
    timeout 20 "$SSH" "$VICTIM" "echo 1 > $KNOB; echo 1 > $KNOB2; cat $KNOB $KNOB2" > "$OUT/lap${L}_arm.txt" 2>&1
    [ "$(tr -d '[:space:]' < "$OUT/lap${L}_arm.txt" | tail -c 2)" = "11" ] || { say "INFRA-FAIL: knobs not armed on lap $L"; return 2; }

    T_DEPART=$(date +%s)
    timeout 90 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/lap${L}_depart.log" 2>&1
    KEY=$(grep -o 'P301-DEPARTURE-INCOMPLETE PR key 0x[0-9a-f]*' "$OUT/lap${L}_depart.log" | head -1 | grep -o '0x[0-9a-f]*')
    [ -n "$KEY" ] || { say "INFRA-FAIL: no retained key on lap $L (the crash model did not fire)"; return 2; }
    say "lap $L: departed dirty, retained key=$KEY"

    # Land the successor's REGISTER inside the peer's expire→P&A window.
    local delay=$(( T_DEPART + REMOUNT_AT - $(date +%s) ))
    [ "$delay" -gt 0 ] && sleep "$delay"
    say "lap $L: remounting at T_DEPART+$(( $(date +%s) - T_DEPART ))s (target ${REMOUNT_AT}s)"

    timeout 150 "$SSH" "$VICTIM" "dmesg --clear; blockdev --flushbufs $DEV; timeout 120 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg" > "$OUT/lap${L}_remount.log" 2>&1
    rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/lap${L}_remount.log")
    own=$(grep -c 'P305-RETIRE-SETTLED-OWN' "$OUT/lap${L}_remount.log")
    changed=$(grep -c 'P305-RETIRE-OWN-CHANGED' "$OUT/lap${L}_remount.log")
    dirty=$(grep -c 'P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P305-PR-PREDECESSOR-KEY-PRESENT' "$OUT/lap${L}_remount.log")
    say "lap $L: remount rc=${rc:-?} SETTLED-OWN=$own OWN-CHANGED=$changed dirty-refused=$dirty"

    if [ "${rc:-1}" != 0 ]; then
        say "lap $L: remount refused — the successor is not live on the key, ordering not reached"
        return 3
    fi
    if [ "$own" -ge 1 ]; then
        say "lap $L: resolved P305-first (victim settled its own record) — no peer fence expected, ordering not reached"
        return 3
    fi

    # peer-expiry-first with a LIVE successor on the re-derived key.  This is
    # the state tests/retire_pending_admission.sh race asserts must happen and
    # then stops looking at.  Wait, bounded, for the peer to certify the fence.
    local endw=$((SECONDS + 45))
    cert=0
    while [ $SECONDS -lt $endw ]; do
        dmesg_of "$PEER" "lap${L}_peerwatch"
        cert=$(cnt "lap${L}_peerwatch" 'P236-FENCE-CERTIFIED'); cert=${cert:-0}
        [ "$cert" -ge 1 ] && break
        sleep 5
    done
    dmesg_of "$PEER" "lap${L}_peer"
    exp=$(cnt "lap${L}_peer" 'P304-RETIRE-EXPIRED-WITHDRAWN'); exp=${exp:-0}
    say "lap $L: peer EXPIRED=$exp FENCE-CERTIFIED=$cert"
    if [ "$cert" -lt 1 ]; then
        say "lap $L: no fence certified within 45 s — ordering not reached"
        return 3
    fi

    # ── THE MEASUREMENT.  A fence fired against a key a LIVE mount holds. ──
    sleep 3
    pr_snapshot "lap${L}_afterfence"
    local vstate pstate w
    vstate=$(key_on_nexus "lap${L}_afterfence_victim" "$KEY" "$VICTIM")
    pstate=$(key_on_nexus "lap${L}_afterfence_peer" "$KEY" "$VICTIM")
    w=$(write_ok "$VICTIM")
    dmesg_of "$VICTIM" "lap${L}_victim_after"
    local selfgone insp withdrew prkf
    selfgone=$(cnt "lap${L}_victim_after" 'P305-RESV-SELF-GONE'); selfgone=${selfgone:-0}
    insp=$(cnt "lap${L}_victim_after" 'P277'); insp=${insp:-0}
    withdrew=$(cnt "lap${L}_victim_after" 'P277-FENCED-SELF-WITHDRAW'); withdrew=${withdrew:-0}
    prkf=$(cnt "lap${L}_peer" 'P-PRKEY-FENCED'); prkf=${prkf:-0}

    say "lap $L MEASURED: key=$KEY victim-view=$vstate peer-view=$pstate victim-write-ok=$w"
    say "lap $L MEASURED: victim SELF-GONE=$selfgone P277=$insp WITHDREW=$withdrew peer PRKEY-FENCED=$prkf"

    if [ "$vstate" = unknown ] || [ "$pstate" = unknown ]; then
        say "lap $L: READ FULL STATUS unusable (victim=$vstate peer=$pstate) — cannot decide this lap"
        return 3
    fi
    if [ "$vstate" != on-own-nexus ] || [ "$w" != 1 ]; then
        VERDICT=confirmed
        fail "lap $L: the fence of the DEAD incarnation removed the LIVE successor's registration — key $KEY is $vstate on $VICTIM (peer view: $pstate), write_ok=$w.  One host, one I_T nexus, one per-boot key: the target cannot tell the two incarnations apart"
        return 1
    fi
    VERDICT=refuted
    say "lap $L: successor survived the fence — key $KEY still on-own-nexus and the mount writes"
    return 0
}

# ── run ──────────────────────────────────────────────────────────────────────
REACHED=0
for L in $(seq 1 "$LAPS"); do
    lap "$L"; r=$?
    restore "$L" || { say "INFRA-FAIL: restore failed after lap $L; stopping rather than running vacuous laps"; exit 2; }
    case "$r" in
        0) REACHED=$((REACHED+1));;
        1) REACHED=$((REACHED+1)); break;;
        2) say "INFRA-FAIL on lap $L"; exit 2;;
        3) :;;
    esac
done

# the volume must still be usable when we are done — the campaign that produced
# this defect reported every lap clean and left the volume unmountable.
say "=== final: both nodes must still mount and write ==="
for n in "$VICTIM" "$PEER"; do
    m=$(timeout 25 "$SSH" "$n" "mount -t mxfs | grep -c mxfs" 2>/dev/null | tr -dc '0-9')
    w=$(write_ok "$n")
    say "final $n: mounted=${m:-0} write_ok=$w"
    [ "${m:-0}" -ge 1 ] || fail "final: $n is not mounted"
    [ "$w" = 1 ] || fail "final: $n cannot write"
done

say "=== verdict: $VERDICT (orderings reached: $REACHED of $LAPS laps) fails=$FAILS ==="
say "evidence: $OUT"
[ "$FAILS" -gt 0 ] && exit 1
[ "$REACHED" -eq 0 ] && { say "INCONCLUSIVE: the peer-expiry-first ordering never occurred; this is not a refutation"; exit 3; }
exit 0
