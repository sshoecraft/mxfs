#!/bin/bash
# tests/recov_takeover_doublefault_probe.sh — does a recovery whose elected
# replayer DIES MID-FLIGHT get taken over and finished?
#
# WHY THIS EXISTS (D-RECOVERY-TAKEOVER-UNREACHABLE)
#   sess91 proved mxfs_disklock_recovery_takeover() had ZERO callers: the CAS is
#   fully implemented, MXFS_RECOV_ABANDON_MS is defined, a comment in disklock.c
#   even says "abandoned recovery is resumed via recovery_takeover()" — and
#   nothing ever called it.  An elected replayer that dies mid-recovery wedged
#   the slice forever, with the victim's CAW grants frozen behind it.  Real
#   trigger, no injection needed: an ordinary double fault.
#
#   0.11.422 wires it into mxfs_v5_dlm_recovery_acquire().  This probe is the
#   positive test, and it is the reason the ledger entry cannot close on the
#   sess93 fence-evidence probe alone: that run took the single-fault path.
#
# WHY THE SESS91 PHANTOM-OWNER INJECTION DOES NOT TEST THIS
#   That probe rewrites desc.owner_node to a value no live node holds.  A
#   phantom is not in any survivor's PROVED-DEAD set, so 0.11.422 correctly
#   REFUSES to take over ("owner status unknown -> stay blocked") — a different
#   assertion.  Takeover requires an owner this node has itself fenced, which
#   means the owner has to be a real node that really dies.
#
# THE INJECTION IS ONLY IN THE TIMING — both deaths are real hard kills.
#   1. Destroy victim A.  Wait for a survivor to certify the fence and CLAIM the
#      execution lease (desc.stage >= FENCED and desc.owner_node != 0).
#   2. Destroy THAT owner, B, inside the few seconds before it publishes.
#   3. A third survivor C must: detect B dead, fence it, re-elect itself for A's
#      slot, find A's descriptor owned by a node it has proved dead, TAKE OVER,
#      and finish A's recovery.
#
#   Step 2 is a race against the replay (~8 s), so the poll reads the SCST
#   backing store DIRECTLY on this host with O_DIRECT and issues virsh destroy
#   from the same process — no ssh in the detect->kill path.  Verified coherent:
#   a live node's heartbeat sector changes across a 1.5 s host-side reread.
#
# WHAT IT ASSERTS
#   1. Some survivor logs P238-RECOV-TAKEOVER for A's slot naming B as owner.
#   2. It logs P238-RECOV-TAKEN — the takeover CAS succeeded.
#   3. P163-RECOVERY-COMPLETE for A's slot: the recovery actually FINISHES.
#      Wiring a takeover that then wedges elsewhere is not a fix.
#   4. Zero P238-COMPLETE-UNFENCED — nothing was published uncertified.
#
# TIMING (RULE 0 — derived, not chosen)
#   A declared dead   : DEAD_THRESHOLD(31) * HB_INTERVAL_MS(2000)   = 62s
#   claim appears     : fence + certify + elect + acquire           ~  3s
#   -> CLAIM_S 150 is that plus slack for a slow scan phase.
#   B declared dead   : another                                     = 62s
#   fence B + re-elect + takeover's ABANDON_MS(6000) + replay       ~ 25s
#   -> OBSERVE_S 200.
#   Total wall ~ 63 + 200 + harvest.
#
# NOTE: leaves TWO nodes destroyed.  Re-prep afterwards:
#   MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
#
# usage: recov_takeover_doublefault_probe.sh [victim=test32] [claim_s=150] [observe_s=200]
set -u
VICTIM="${1:-test32}"
CLAIM_S="${2:-150}"
OBSERVE_S="${3:-200}"
NODES_N="${MXFS_NODES:-32}"
IMG="${MXFS_BACKING_IMG:-/home/steve/disk.img}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
[ -r "$IMG" ] || { echo "probe: cannot read backing store $IMG" >&2; exit 2; }

MARK="TKOVER-$$-$(date -u +%s)"
echo "probe: victim=$VICTIM nodes=$NODES_N img=$IMG mark=$MARK"

# ── node_id -> host map, built BEFORE the kill (the owner is named by node id) ──
TD=$(mktemp -d)
for i in $(seq 1 "$NODES_N"); do
    ( $SSH "test$i" \
        "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
         journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
        2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1 > "$TD/claim.test$i" ) &
done
wait
: > "$TD/idmap"
: > "$TD/unmapped_hosts"
for i in $(seq 1 "$NODES_N"); do
    line=$(cat "$TD/claim.test$i" 2>/dev/null)
    id=$(printf '%s\n' "$line" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
    sl=$(printf '%s\n' "$line" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
    if [ -n "$id" ]; then
        printf '%s test%s %s\n' "$id" "$i" "${sl:--1}" >> "$TD/idmap"
    else
        printf 'test%s\n' "$i" >> "$TD/unmapped_hosts"
    fi
done

# The claim line is a BOOT-TIME log line and dmesg is a ring whose retention
# varies ~60x across nodes of one cluster (see tests/suite/lib.sh).  A long-lived
# node — typically slot 0, the first mounter — has usually rotated it out, and an
# unmapped id is fatal here because the owner is named ONLY by node id.
#
# Close the map from the platter instead: every ACTIVE heartbeat record carries
# its owner's node id, so the ids the cluster is actually using are knowable
# without any node's cooperation.  If exactly one host and exactly one on-disk id
# are left over, the pairing is forced and needs no guessing.
if [ -s "$TD/unmapped_hosts" ]; then
    IMG="$IMG" IDMAP="$TD/idmap" UNMAPPED="$TD/unmapped_hosts" python3 - <<'PYEOF'
import os, struct, mmap
IMG=os.environ['IMG']; MAGIC=0x4D584C4B; ACTIVE=1
known={int(l.split()[0]) for l in open(os.environ['IDMAP']) if l.split()}
hosts=[l.strip() for l in open(os.environ['UNMAPPED']) if l.strip()]
fd=os.open(IMG, os.O_RDONLY|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    os.preadv(fd,[mv[:n]],off); return bytes(mv[:n])
dloff,=struct.unpack_from('<Q',dread(0,4096),64)
spare=[]
for slot in range(64):
    r=dread(dloff+slot*512,512)
    magic,flags,nid=struct.unpack_from('<III',r,0)
    if magic==MAGIC and flags==ACTIVE and nid and nid not in known:
        spare.append((nid,slot))
if len(spare)==1 and len(hosts)==1:
    nid,slot=spare[0]
    with open(os.environ['IDMAP'],'a') as f:
        f.write('%d %s %d\n'%(nid,hosts[0],slot))
    print('probe: deduced %s = node %d (slot %d) from the platter'%(hosts[0],nid,slot))
else:
    print('probe: WARNING %d host(s) and %d on-disk id(s) unmapped — cannot deduce'
          %(len(hosts),len(spare)))
PYEOF
fi
echo "probe: mapped $(wc -l < "$TD/idmap") node ids"
[ "$(wc -l < "$TD/idmap")" -eq "$NODES_N" ] || {
    echo "probe: ABORT — incomplete node-id map; the owner would be unresolvable" >&2
    echo "logs: $TD"; exit 2; }

SLOT=$(awk -v h="$VICTIM" '$2==h{print $3}' "$TD/idmap")
NODEID=$(awk -v h="$VICTIM" '$2==h{print $1}' "$TD/idmap")
[ -n "${SLOT:-}" ] && [ "$SLOT" != -1 ] || { echo "probe: no slot for $VICTIM" >&2; exit 2; }
echo "probe: victim slot=$SLOT node=$NODEID"

SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
for n in "${SURV[@]}"; do ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done
wait

echo "probe: destroying victim $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy failed" >&2; exit 2; }

# ── poll the victim's sector on the HOST and kill the owner the instant it
#    appears.  Detection and kill are in one process: no ssh in the hot path. ──
OWNER=$(SLOT="$SLOT" IMG="$IMG" CLAIM_S="$CLAIM_S" IDMAP="$TD/idmap" python3 - <<'PYEOF'
import os, struct, mmap, time, subprocess, sys
SLOT=int(os.environ['SLOT']); IMG=os.environ['IMG']
CLAIM_S=float(os.environ['CLAIM_S'])
MAGIC=0x4D584C4B; GUARD=3; DESC_OFF=40; DESC_MAGIC=0x5643524D
ST_OFF=DESC_OFF+6          # struct mxfs_recov_desc.stage
OWN_OFF=DESC_OFF+44        # struct mxfs_recov_desc.owner_node
FENCED=2

idmap={}
for ln in open(os.environ['IDMAP']):
    p=ln.split()
    if len(p)>=2: idmap[int(p[0])]=p[1]

fd=os.open(IMG, os.O_RDONLY|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    os.preadv(fd,[mv[:n]],off)
    return bytes(mv[:n])
sup=dread(0,4096); dloff,=struct.unpack_from('<Q',sup,64)
off=dloff+SLOT*512

t0=time.time(); seen_guard=False
while time.time()-t0 < CLAIM_S:
    r=dread(off,512)
    magic,flags=struct.unpack_from('<II',r,0)
    dm,=struct.unpack_from('<I',r,DESC_OFF)
    if magic==MAGIC and flags==GUARD and dm==DESC_MAGIC:
        if not seen_guard:
            seen_guard=True
            print('GUARD at t+%.1fs'%(time.time()-t0), file=sys.stderr)
        stage,=struct.unpack_from('<H',r,ST_OFF)
        owner,=struct.unpack_from('<I',r,OWN_OFF)
        if stage>=FENCED and owner:
            host=idmap.get(owner)
            print('OWNER node=%u host=%s stage=%u at t+%.1fs'
                  %(owner,host,stage,time.time()-t0), file=sys.stderr)
            if host:
                subprocess.run(['virsh','-c','qemu:///system','destroy',host],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(host)
            else:
                print('UNMAPPED:%u'%owner)
            sys.exit(0)
    if magic!=MAGIC and not seen_guard:
        pass
    time.sleep(0.05)
print('NONE')
PYEOF
) || true

echo "probe: owner outcome = ${OWNER:-<empty>}"
case "$OWNER" in
    test*) echo "probe: destroyed owner $OWNER at $(date -u +%H:%M:%S)Z" ;;
    NONE)  echo "probe: ABORT — no owner claimed the recovery within ${CLAIM_S}s" >&2
           echo "logs: $TD"; exit 2 ;;
    *)     echo "probe: ABORT — owner not resolvable ($OWNER)" >&2
           echo "logs: $TD"; exit 2 ;;
esac

echo "probe: waiting ${OBSERVE_S}s for a third node to detect the owner dead, fence it, and take over"
sleep "$OBSERVE_S"

REST=()
for n in "${SURV[@]}"; do [ "$n" = "$OWNER" ] || REST+=("$n"); done
for n in "${REST[@]}"; do
    ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p'" > "$TD/$n.log" 2>/dev/null ) &
done
wait

count_nodes() {
    local pat="$1" n c=0 lst=""
    for n in "${REST[@]}"; do
        if grep -qa -- "$pat" "$TD/$n.log" 2>/dev/null; then c=$((c+1)); lst="$lst $n"; fi
    done
    printf '%d%s\n' "$c" "$lst"
}

TKO=$(count_nodes "P238-RECOV-TAKEOVER slot=$SLOT ")
TKN=$(count_nodes "P238-RECOV-TAKEN slot=$SLOT ")
DONE=$(count_nodes "P163-RECOVERY-COMPLETE slot=$SLOT ")
UNF=$(count_nodes "P238-COMPLETE-UNFENCED slot=$SLOT ")

echo
echo "=== takeover double-fault probe: victim slot=$SLOT node=$NODEID, owner=$OWNER ==="
printf '  takeover attempted (P238-RECOV-TAKEOVER) nodes=%s\n' "$TKO"
printf '  takeover succeeded (P238-RECOV-TAKEN)    nodes=%s\n' "$TKN"
printf '  recovery published (P163-RECOVERY-COMPLETE) nodes=%s\n' "$DONE"
printf '  UNGATED completes (must be 0)            nodes=%s\n' "$UNF"
echo
echo "--- the takeover lines ---"
grep -ha "P238-RECOV-TAKEOVER\|P238-RECOV-TAKEN\|P238-RECOV-OWNED\|P163-RECOVERY-COMPLETE slot=$SLOT \|P238-RECOV-LEASE slot=$SLOT " \
    "$TD"/*.log 2>/dev/null | sed 's/^/  /' | head -25

fail=0
[ "${TKO%% *}" -ge 1 ] || { echo "FAIL: no node attempted a takeover of the dead owner's recovery"; fail=1; }
[ "${TKN%% *}" -ge 1 ] || { echo "FAIL: no takeover succeeded"; fail=1; }
[ "${DONE%% *}" -ge 1 ] || { echo "FAIL: the victim's recovery never published — the slice is still wedged"; fail=1; }
[ "${UNF%% *}" = 0 ] || { echo "FAIL: ${UNF%% *} node(s) completed a recovery with NO certificate"; fail=1; }

echo
[ "$fail" = 0 ] && echo "PROBE PASS — abandoned recovery was taken over and finished" \
                || echo "PROBE FAIL — logs kept in $TD"
echo "logs: $TD"
exit "$fail"
