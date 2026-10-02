#!/bin/bash
# rig_fence_virsh.sh — the rig's fence authority: powers one rig VM off on
# behalf of its peer, and keeps it out until the survivor lets it back.  This
# is the node fence docs/fencing.md calls `hypervisor`, for the test VMs on
# clyde, shaped by docs/rulings/drbd-dual-primary-attachment.md:
#
#   - ONE WINNER PER EPISODE.  Fence requests are serialised under one lock,
#     and a requester that is itself fenced (inhibited) is refused.  In a split
#     both nodes ask at once; the first is granted, the second finds itself
#     already fenced.  A delay on one node is not arbitration; this is.
#   - CONTINUING EXCLUSION.  A fence leaves an inhibit on the target, named by a
#     fresh episode id.  `status` reports it, so a survivor can re-check before
#     every irreversible step that the peer is still off AND still inhibited
#     under the same episode.  A power-off alone is a point event.
#   - RELEASE IS THE SURVIVOR'S.  Only `release` with the episode id clears the
#     inhibit, and only for a requester that is not itself inhibited.
#
# It runs as the forced command of one ssh key in ~/.ssh/authorized_keys
# (installed by `scripts/drbd_rig.sh fence-setup`).  Verbs:
#
#   fence   <target> <requester>              power target off, inhibit it
#   status  <target>                          its domain state and inhibit
#   release <target> <episode> <requester>    clear the inhibit (rejoin)
#
# The requester names itself and must be connecting from that VM's own lab
# address.  Only rig VMs (test<N>) can be named; nothing here can touch the
# host or any other domain.
#
# One line out: FENCE_OK <target> shut off episode=<id> | STATE <target>
# <state> inhibit=<id>|none | RELEASED <target> episode=<id> | FENCE_FAIL ...
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
VIRSH="virsh -c qemu:///system"
STATE_DIR="${MXFS_FENCE_STATE:-$HOME/.local/state/mxfs-rig-fence}"
OFF_BUDGET=30   # a destroyed domain reads "shut off" within a second or two

read -r verb a1 a2 a3 extra <<<"${SSH_ORIGINAL_COMMAND:-$*}"
fail() { echo "FENCE_FAIL ${a1:-?} $*"; exit "${RC:-1}"; }
[ -z "${extra:-}" ] || RC=2 fail "too many arguments"
rigvm() { [[ "${1:-}" =~ ^test[0-9]+$ ]]; }
rigvm "${a1:-}" || RC=2 fail "not a rig VM (test<N>)"

mkdir -p "$STATE_DIR" || fail "cannot create $STATE_DIR"
exec {lockfd}>>"$STATE_DIR/.lock"
flock -w 90 "$lockfd" || fail "fence authority busy for 90 s"

state() { timeout 20 $VIRSH domstate "$1" 2>/dev/null | head -1; }
inhibit_of() { sed -n 's/^episode=\([^ ]*\).*/\1/p' "$STATE_DIR/$1.inhibit" 2>/dev/null; }
# The requester must be who it says: the ssh connection comes from its own
# lab address.  sshd sets SSH_ORIGINAL_COMMAND only when this runs as the
# key's forced command; run by hand on the host the check is moot (a login
# shell carries SSH_CONNECTION too, so that is not the test).
requester_ok() {
    rigvm "$1" || return 1
    [ -n "${SSH_ORIGINAL_COMMAND:-}" ] || return 0
    local want; want=$(. "$REPO/tools/mxfs_lab.sh"; lab_addr "$1" 2>/dev/null)
    [ -n "$want" ] && [ "${SSH_CONNECTION%% *}" = "$want" ]
}

case "${verb:-}" in
    status)
        s=$(state "$a1")
        [ -n "$s" ] || fail "no such domain (or libvirtd did not answer in 20 s)"
        echo "STATE $a1 $s inhibit=$(inhibit_of "$a1" | grep . || echo none)" ;;
    fence)
        req=${a2:-}
        requester_ok "$req" || RC=2 fail "requester '${req:-}' is not the rig VM this request came from"
        [ "$req" != "$a1" ] || RC=2 fail "a node does not fence itself"
        ep=$(inhibit_of "$req")
        [ -z "$ep" ] || fail "requester $req is itself fenced (episode $ep) — the other node won this episode"
        s=$(state "$a1")
        [ -n "$s" ] || fail "no such domain (or libvirtd did not answer in 20 s)"
        ep=$(inhibit_of "$a1")
        if [ -z "$ep" ]; then
            ep=$(cat /proc/sys/kernel/random/uuid)
            echo "episode=$ep by=$req at=$(date -u +%FT%TZ)" > "$STATE_DIR/$a1.inhibit" || fail "cannot record the inhibit"
            sync "$STATE_DIR/$a1.inhibit"
        fi
        # The inhibit is written BEFORE the power-off: a target that is off must
        # never be found without one.  The answer is the state read afterwards,
        # never the destroy's exit code.
        [ "$s" = "shut off" ] || timeout 60 $VIRSH destroy "$a1" >/dev/null 2>&1
        for i in $(seq 1 "$OFF_BUDGET"); do
            s=$(state "$a1")
            if [ "$s" = "shut off" ]; then
                echo "FENCE_OK $a1 shut off episode=$ep"
                logger -t mxfs-rig-fence "fenced $a1 for $req episode=$ep"
                exit 0
            fi
            sleep 1
        done
        fail "still '${s:-unknown}' ${OFF_BUDGET}s after destroy (inhibit episode=$ep left in place)" ;;
    release)
        ep=${a2:-}; req=${a3:-}
        requester_ok "$req" || RC=2 fail "requester '${req:-}' is not the rig VM this request came from"
        [ -z "$(inhibit_of "$req")" ] || fail "requester $req is itself fenced"
        cur=$(inhibit_of "$a1")
        [ -n "$cur" ] || { echo "RELEASED $a1 episode=none"; exit 0; }
        [ "$cur" = "$ep" ] || fail "inhibit is episode $cur, not $ep"
        unlink "$STATE_DIR/$a1.inhibit" || fail "cannot remove the inhibit"
        logger -t mxfs-rig-fence "released $a1 episode=$ep for $req"
        echo "RELEASED $a1 episode=$ep" ;;
    *)
        RC=2 fail "unknown verb '${verb:-}' (fence|status|release)" ;;
esac
