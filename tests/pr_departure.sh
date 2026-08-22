#!/bin/bash
# pr_departure.sh — D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377.
#
# THE INVARIANT UNDER TEST (sess377 RULE-5 ruling, ccmemory
# ccloop-c7ee71c6-sess377-GPT-ruling3-pr-unregister-leak-fix-shape):
#
#   Once MXFS declares an incarnation's storage authority retired, no
#   registration bearing that incarnation's PR key may remain.
#
# MXFS fences with SCSI persistent reservations and uses node_id as the PR
# key, so a registered key IS a node that can write to the shared LUN.  Before
# the fix, a mount registered its key on EVERY multipath nexus but a clean
# unmount removed only ONE of them and reported success — so every node that
# left kept write access to the device, silently.
#
# THIS TEST ONLY MEANS SOMETHING ON A MULTIPATH DEVICE.  The single-path case
# cannot expose the defect (one nexus, one registration), so the test refuses
# to claim a pass on one: it reports PRECONDITION-NOT-MET instead.
#
# Two arms:
#   A. round trip x3 — mount one node, unmount it cleanly, assert the
#      registration table returns EXACTLY to its pre-mount contents and the
#      node's key is absent.  Run three times because a leak that replaces its
#      own previous leftover looks stable if you only sample once.
#   B. fleet — mount N, assert every mounted node contributes registrations,
#      unmount all, assert the table returns to its pre-mount contents.
#
# Pre-existing debris from BEFORE the fix is not this test's business: arm A
# and arm B both compare against the table as it was immediately before the
# mount, and separately REPORT any leftovers so they cannot be mistaken for a
# pass.  A run on a device with leftovers still proves the fix; only a run
# that starts from an EMPTY table can also prove "no key remains after every
# node departs", and the test says which of the two it measured.
#
# Usage: tests/pr_departure.sh [N]        (N defaults to 1 = arm A only)
# Env:   PROBE_HOST (a node that stays unmounted and reads the table;
#        default test3), MXFS_DEV (default /dev/mapper/mpatha)
# Exit 0 PASS, 1 FAIL, 2 PRECONDITION-NOT-MET.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
CHK=/src/mxfs/tools/chk_mxfs
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
MNT=/mnt/shared
N="${1:-1}"
PROBE_HOST="${PROBE_HOST:-test3}"

DD=$(mktemp -d)
pass=1
fail() { echo "FAIL: $*"; pass=0; }

keys() {  # -> sorted key list, one per line (duplicates preserved: one per nexus)
    timeout 40 "$SSH" "$PROBE_HOST" "$CHK --pr-keys $DEV" 2>/dev/null \
        | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | sort
}

echo "=== pr_departure: N=$N probe=$PROBE_HOST dev=$DEV @ $(date -u +%FT%TZ) ==="

# ── precondition: multipath with >1 path, else the defect is unobservable ──
NPATH=$(timeout 30 "$SSH" "$PROBE_HOST" \
    "multipath -ll 2>/dev/null | grep -c 'active ready running'" \
    2>/dev/null | tail -1 | tr -d '[:space:]')
echo "--- usable paths to $DEV: ${NPATH:-?}"
if [ -z "${NPATH:-}" ] || [ "$NPATH" -lt 2 ] 2>/dev/null; then
    echo "PRECONDITION-NOT-MET: $DEV has ${NPATH:-0} usable path(s)."
    echo "  The leak is a per-nexus asymmetry, so a single-path device cannot"
    echo "  exhibit it and a pass here would be meaningless."
    exit 2
fi

# ── everything must start unmounted, or the baseline is not a baseline ──
mounted=0
for i in $(seq 1 32); do
    ( timeout 15 "$SSH" "test$i" "mountpoint -q $MNT && echo Y" 2>/dev/null \
        | tr -d '[:space:]' > "$DD/mp.$i" ) &
done
wait
for i in $(seq 1 32); do
    [ "$(cat "$DD/mp.$i" 2>/dev/null)" = "Y" ] && {
        echo "  still mounted: test$i"; mounted=$((mounted+1)); }
done
if [ "$mounted" -ne 0 ]; then
    echo "PRECONDITION-NOT-MET: $mounted node(s) still have $MNT mounted."
    exit 2
fi

keys > "$DD/base"
NBASE=$(wc -l < "$DD/base")
echo "--- registration table with the cluster fully unmounted: $NBASE key(s)"
[ "$NBASE" -gt 0 ] && {
    echo "    PRE-EXISTING LEFTOVERS (not produced by this run — a departed"
    echo "    incarnation still registered, i.e. the historical form of this"
    echo "    defect; no in-tree reaper removes them):"
    sed 's/^/      /' "$DD/base"
}

KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')

mount_node() {
    timeout 220 "$SSH" "$1" \
        "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh caw" \
        2>&1 | grep -E 'NODE_PREP' | tail -1
}
umount_node() {
    timeout 220 "$SSH" "$1" \
        "timeout 200 umount $MNT; mountpoint -q $MNT && echo STILL || echo UNMOUNTED" \
        2>/dev/null | tail -1
}

# ── arm A: three clean round trips on one node ────────────────────────────
VICT=test2
[ "$VICT" = "$PROBE_HOST" ] && VICT=test4
echo
echo "── arm A: clean mount/unmount round trip x3 on $VICT ──"
for lap in 1 2 3; do
    keys > "$DD/pre.$lap"
    r=$(mount_node "$VICT")
    case "$r" in
        *NODE_PREP_OK*) ;;
        *) echo "PRECONDITION-NOT-MET: lap $lap could not mount $VICT: $r"; exit 2 ;;
    esac
    keys > "$DD/on.$lap"
    NON=$(wc -l < "$DD/on.$lap")
    NPRE=$(wc -l < "$DD/pre.$lap")
    added=$(comm -13 "$DD/pre.$lap" "$DD/on.$lap" | sort -u | tr '\n' ' ')
    nadd=$(( NON - NPRE ))
    echo "  lap $lap: mounted — table $NPRE -> $NON (+$nadd), new key(s): ${added:-<none>}"
    if [ "$nadd" -lt 1 ]; then
        fail "lap $lap: mounting $VICT added no PR registration — it cannot be fenced at all"
    fi

    u=$(umount_node "$VICT")
    [ "$u" = "UNMOUNTED" ] || { echo "PRECONDITION-NOT-MET: lap $lap umount said '$u'"; exit 2; }
    sleep 3
    keys > "$DD/off.$lap"
    NOFF=$(wc -l < "$DD/off.$lap")
    echo "  lap $lap: unmounted cleanly — table $NON -> $NOFF (want $NPRE)"

    # THE ASSERTION.  The post-unmount table must be a SUBSET of the
    # pre-mount table: nothing this mount created may survive it.
    #
    # Removals are legitimate and are only reported, not failed.  A node's PR
    # key is per-INCARNATION, so when a node that leaked a registration in an
    # earlier life remounts, its new key REPLACES the old one on that nexus
    # (REGISTER AND IGNORE EXISTING KEY overwrites whatever the nexus held).
    # The stale entry therefore disappears — which is the mount cleaning up
    # after its own predecessor, not a third party being unregistered.
    left=$(comm -13 "$DD/pre.$lap" "$DD/off.$lap")
    gone=$(comm -23 "$DD/pre.$lap" "$DD/off.$lap")
    if [ -n "$gone" ]; then
        echo "    pre-existing entries reclaimed by this mount's own new key:"
        echo "$gone" | sed 's/^/      /'
    fi
    if [ -n "$left" ]; then
        echo "    LEFT BEHIND by this mount:"
        echo "$left" | sed 's/^/      /'
        fail "lap $lap: a clean unmount did not retire $VICT's registration(s) — the departed node can still write to the shared LUN"
    fi

    # Belt and braces: whatever key the mount added must not be present.
    for k in $added; do
        if grep -qx "$k" "$DD/off.$lap"; then
            fail "lap $lap: key $k is STILL REGISTERED after a clean unmount"
        fi
    done
done

# ── arm B: the fleet form ─────────────────────────────────────────────────
if [ "$N" -gt 1 ] 2>/dev/null; then
    echo
    echo "── arm B: mount $N node(s), unmount all, assert the table returns ──"
    keys > "$DD/bpre"
    NBPRE=$(wc -l < "$DD/bpre")
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$PROBE_HOST" ] && continue
        mount_node "test$i" >/dev/null &
    done
    wait
    up=0
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$PROBE_HOST" ] && continue
        ( timeout 15 "$SSH" "test$i" "mountpoint -q $MNT && echo Y" 2>/dev/null \
            | tr -d '[:space:]' > "$DD/bmp.$i" ) &
    done
    wait
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$PROBE_HOST" ] && continue
        [ "$(cat "$DD/bmp.$i" 2>/dev/null)" = "Y" ] && up=$((up+1))
    done
    keys > "$DD/bon"
    NBON=$(wc -l < "$DD/bon")
    echo "  $up node(s) mounted — table $NBPRE -> $NBON"
    [ "$up" -ge 1 ] || { echo "PRECONDITION-NOT-MET: arm B mounted nothing"; exit 2; }
    if [ "$NBON" -le "$NBPRE" ]; then
        fail "arm B: mounting $up node(s) added no registrations"
    fi

    for i in $(seq 1 "$N"); do
        [ "test$i" = "$PROBE_HOST" ] && continue
        umount_node "test$i" >/dev/null &
    done
    wait
    sleep 5
    keys > "$DD/boff"
    NBOFF=$(wc -l < "$DD/boff")
    echo "  all unmounted — table $NBON -> $NBOFF (want at most $NBPRE)"
    # Same subset rule as arm A: nothing this run created may survive.  Entries
    # that DISAPPEARED are pre-fix leftovers whose owner remounted and then
    # departed properly — the best possible outcome, not a failure.
    bleft=$(comm -13 "$DD/bpre" "$DD/boff")
    bgone=$(comm -23 "$DD/bpre" "$DD/boff")
    if [ -n "$bgone" ]; then
        echo "    pre-existing leftover(s) reclaimed and then properly retired:"
        echo "$bgone" | sed 's/^/      /'
    fi
    if [ -n "$bleft" ]; then
        echo "    LEFT BEHIND:"
        echo "$bleft" | sed 's/^/      /'
        fail "arm B: $(echo "$bleft" | wc -l) registration(s) survived a clean fleet unmount"
    fi
    if [ "$NBOFF" -eq 0 ]; then
        echo "  and the table is EMPTY: after every node departed, NOTHING can"
        echo "  write to this LUN.  That is the invariant."
    fi
fi

echo
echo "--- evidence kept in $DD"
if [ "$pass" -eq 1 ]; then
    if [ "$NBASE" -eq 0 ]; then
        echo "=== pr_departure PASS (from an empty table: departure retires the key) ==="
    else
        echo "=== pr_departure PASS (with $NBASE pre-existing leftover(s) reported above;"
        echo "    every registration created by THIS run was retired) ==="
    fi
    exit 0
fi
echo "=== pr_departure FAIL ==="
exit 1
