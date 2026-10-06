#!/bin/bash
# mxfs_drbd_fence_peer.sh — DRBD's fence-peer handler for an MXFS resource,
# installed on each node as /usr/sbin/mxfs-drbd-fence-peer (the packages ship
# it there, and the kernel admits a DRBD mount only with exactly that handler).
#
# DRBD runs it under `fencing resource-and-stonith` when a Primary loses its
# peer.  Until it returns, DRBD keeps all I/O to the resource suspended on
# this node (drivers/block/drbd/drbd_state.c: susp_fen), and only exit 7
# ("peer was stonithed") or 4 ("peer outdated") marks the peer's disk Outdated
# and resumes I/O (drbd_nl.c conn_try_outdate_peer).  So:
#
#   - it returns 7 only after the peer node is confirmed powered off by the
#     node fence named in the config; any other outcome is exit 1, which
#     leaves I/O frozen — a survivor that cannot prove its peer is off must
#     not write;
#   - in a partition both nodes run it at once and both ask the fence
#     authority to fence the other.  The authority serialises them and grants
#     one: the second requester finds itself already fenced and is refused
#     (tools/rig_fence_virsh.sh).  `delay` only makes the outcome predictable
#     on the rig; it is not the arbitration;
#   - the grant names an episode, and the peer stays inhibited under it until
#     the survivor releases it.  Every attempt appends one line to the fence
#     record, which MXFS's fence witness reads together with the authority's
#     live answer for the same episode.
#
# THE FENCE AUTHORITY.  Something outside both nodes that answers three verbs,
# one line each, and keeps its promise across both nodes' crashes:
#   fence <target> <requester>           -> FENCE_OK <target> shut off episode=<id>
#        power the target off and inhibit its restart under a fresh episode;
#        refuse a requester that is itself inhibited (one winner per episode)
#   status <target>                      -> STATE <target> <power state> inhibit=<id>|none
#   release <target> <episode> <requester> -> RELEASED <target> episode=<id>
# The rig's is tools/rig_fence_virsh.sh (libvirt on the hypervisor host).  A
# site writes its own for its power control (IPMI, a PDU, its hypervisor's
# API); what it must guarantee is in docs/attachment-methods.md.
#
# Config /etc/mxfs/drbd-fence.conf (absent = agent=self, the built-in default):
#   agent=self                  the pair's built-in authority, no node fence
#                               (/usr/sbin/mxfs-drbd-fence-self)
#   agent=ssh                   ssh to an authority's forced command (rig-virsh: older name)
#   host=192.168.120.1          ... on this host
#   user=steve
#   key=/etc/mxfs/fence_key
#   agent=exec                  or: run a local program that speaks the verbs
#   cmd=/usr/local/sbin/site-fence-authority
#   delay=0                     seconds to wait before fencing (0 on one node only)
#   self <this node's name at the authority>
#   peer <drbd peer address> <peer's name at the authority>
#
# DRBD 8.4 passes DRBD_RESOURCE and DRBD_PEER_ADDRESS in the environment.
set -u
CONF=/etc/mxfs/drbd-fence.conf
RECORD_DIR=/var/lib/mxfs
RES=${DRBD_RESOURCE:-unknown}
PEER_ADDR=${DRBD_PEER_ADDRESS:-}
RECORD="$RECORD_DIR/drbd-fence.$RES"
mkdir -p "$RECORD_DIR"

boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
record() {  # <result> <peer domain> <detail...>
    local r=$1 p=$2; shift 2
    echo "$(date -u +%s.%N) res=$RES peer_addr=${PEER_ADDR:-?} peer=$p result=$r boot_id=$boot_id $*" >> "$RECORD"
    sync "$RECORD" 2>/dev/null
    logger -t mxfs-drbd-fence "res=$RES peer=$p result=$r $*"
}

conf() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -1; }
# No node fence configured (no config, or agent=self): the pair's built-in
# authority decides, by its fixed tie-break, and records its own receipt
# (tools/mxfs_drbd_fence_self.py; docs/rulings/drbd-two-node-self-exclusion.md).
if [ ! -r "$CONF" ] || [ "$(conf agent)" = self ]; then
    exec /usr/sbin/mxfs-drbd-fence-self fence-peer
fi
agent=$(conf agent); host=$(conf host); user=$(conf user); key=$(conf key); delay=$(conf delay); cmd=$(conf cmd)
self=$(awk '$1 == "self" {print $2}' "$CONF" | tail -1)
[ -n "$self" ] || { record FAIL - "no 'self' in $CONF"; exit 1; }
peer=$(awk -v a="$PEER_ADDR" '$1 == "peer" && $2 == a {print $3}' "$CONF" | tail -1)
if [ -z "$peer" ]; then
    # one peer per resource: an address DRBD did not pass still names it
    [ "$(grep -c '^peer ' "$CONF")" = 1 ] && peer=$(awk '$1 == "peer" {print $3}' "$CONF")
fi
[ -n "$peer" ] || { record FAIL - "peer address '${PEER_ADDR:-}' not in $CONF"; exit 1; }

case "${delay:-0}" in ''|*[!0-9]*) delay=0 ;; esac
[ "$delay" -gt 0 ] && { record DELAY "$peer" "waiting ${delay}s before fencing"; sleep "$delay"; }

case "$agent" in
    ssh|rig-virsh)
        out=$(timeout 120 ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
                  -o ConnectTimeout=10 "$user@$host" "fence $peer $self" 2>&1 | tail -1) ;;
    exec)
        [ -x "$cmd" ] || { record FAIL "$peer" "agent=exec cmd '$cmd' is not executable"; exit 1; }
        out=$(timeout 120 "$cmd" fence "$peer" "$self" 2>&1 | tail -1) ;;
    *)
        record FAIL "$peer" "unknown agent '$agent'"; exit 1 ;;
esac

case "$out" in
    "FENCE_OK $peer shut off episode="*)
        record STONITHED "$peer" "episode=${out##*episode=} agent=$agent"
        # Tell the MXFS mount on the resource, once DRBD has this answer, so
        # it asks its witness now instead of after its lock link's timeout and
        # grace (a cue: the module judges the exclusion itself).
        ( sleep 1; m=$(drbdadm sh-minor "$RES" 2>/dev/null) && [ -w /proc/fs/mxfs/drbd_excluded ] \
            && echo "$m" > /proc/fs/mxfs/drbd_excluded ) </dev/null >/dev/null 2>&1 &
        exit 7 ;;
    *)
        record FAIL "$peer" "agent=$agent answer='$out'"
        exit 1 ;;
esac
