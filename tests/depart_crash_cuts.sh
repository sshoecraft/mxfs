#!/bin/bash
# tests/depart_crash_cuts.sh — sess460, design-consult review #5 condition 3 (ccmemory
# ccloop-c7ee71c6-sess456-GPT-ruling-review5-0611-NO-GO-untokened-failclosed-
# 6-conditions): the release/unregister CRASH-CUT STATE TABLE.
#
# The invariant under test: from the first operation that relinquishes the
# active heartbeat slot until fresh proof that the PR key is absent, the
# durable shared state must still IDENTIFY THAT KEY as a fence target.  The
# decisive fact is whether the release CAS image still names the key — the
# RETIRE_PENDING record keeps the identity block (ident.pr_key) byte for
# byte, only `flags` moves (dlm/disklock.c mxfs_disklock_release_slot).
#
# Each cut is a REAL crash: the victim's put_super parks at the cut
# (mxfs.dbg_depart_crash_cut=N, one-shot; mxfs.dbg_depart_crash_hold_ms)
# and prints P-DBG-DEPART-CUT; this harness then virsh-destroys the VM while
# it is parked (same model as the ICLUS relmark crash arms).  The victim's
# kernel log is captured BEFORE the destroy (node journald is volatile).
#
#   cut 1 precas    after the final flush + freeze/drain + quiescence check,
#                   BEFORE the release CAS.  Sector: ACTIVE, key named, key
#                   registered.  Peers: heartbeat stops -> stale death ->
#                   fence (P236-FENCE-CERTIFIED) -> recovery.
#   cut 2 postcas   after the release CAS landed (P304-RETIRE-PENDING-
#                   RELEASED), BEFORE the post-release flush.  Sector:
#                   RETIRE_PENDING naming the key; key registered.  Peers:
#                   P304-RETIRE-PENDING-SEEN -> (key present past the 30 s
#                   grace) P304-RETIRE-EXPIRED-WITHDRAWN -> fence -> recovery.
#   cut 3 preunreg  after the post-release flush, BEFORE the late unregister.
#                   Same durable state and peer action as cut 2.
#   cut 4           = "unregister failed": tests/pr_unregister_fail_restamp.sh
#                   restamp (re-stamp lands) and crash (re-stamp skipped) —
#                   not driven here.
#   cut 5 postunreg after a SUCCESSFUL late unregister, BEFORE release_finish.
#                   Sector: RETIRE_PENDING naming the key; key ABSENT.  Peers:
#                   a worker settles it EMPTY (P304-RETIRE-COMPLETED-BY-PEER),
#                   NO fence.
#   cut 6 (final EMPTY) is the terminal state of cut 5; cut 7 (PR/CAW
#                   capability lost) is tests/cas_nocaw_arms.sh.
#
# For every cut the row records: the decoded sector before the umount (S0),
# at the cut (S1) and after the peers acted (S2) — flags/state, node, epoch,
# fs_gen, ident.pr_key, sha256 of the 512 B; READ KEYS (chk_mxfs --pr-keys
# from the probe) at the same three points; the peer action lines; whether
# the victim's next mount (fresh boot, prep_node) is admitted.
#
# Usage: tests/depart_crash_cuts.sh <N> <victim> <probe> <cut> [dev]
# Exit 0 PASS, 1 FAIL, 2 INFRA.
# derived time budgets: arm+umount-to-cut <= 20 s; cut 1 peers 62 s stale + fence +
# recovery ~80 s (bound 130); cuts 2/3 30 s grace + lap + fence + recovery
# ~50 s (bound 130); cut 5 settle <= 10 s (bound 60); VM restart + ssh ~40 s
# (bound 120) + prep_node ~40 s (bound 120).  Whole arm <= 300 s (cut 5 ~200).
set -u
N=${1:?N}; VICTIM=${2:?victim}; PROBE=${3:?probe}; CUT=${4:?cut 1|2|3|5}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
MXFS_DEV=${5:-${MXFS_DEV:-}}; mxfs_dev_resolve "$PROBE"; DEV=$MXFS_DEV_RESOLVED
# sess53 (2-node TCP rig): the victim's fresh-boot remount goes through
# prep_node.sh, whose first argument is the transport; it was hardcoded to
# caw, which on a TCP fleet loads the module without force_transport=1 and
# the remount verdict is then about the wrong transport.
TRANSPORT=${MXFS_TRANSPORT:-caw}
MNT=/mnt/shared
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH=$REPO/tools/mxfs_sshpass.sh
CHK=/src/mxfs/tools/chk_mxfs
case "$CUT" in 1) CNAME=precas;; 2) CNAME=postcas;; 3) CNAME=preunreg;; 5) CNAME=postunreg;; *) echo "bad cut $CUT"; exit 2;; esac
OUT=$REPO/tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_crashcut${CUT}_$CNAME
mkdir -p "$OUT"
say() { echo "[crashcut$CUT/$CNAME] $*"; }
fails=0
fail() { say "FAIL: $*"; fails=$((fails+1)); }
echo "=== depart_crash_cuts cut=$CUT ($CNAME) N=$N victim=$VICTIM probe=$PROBE dev=$DEV @ $(date -u +%Y%m%dT%H%M%SZ) sv=$(modinfo /src/mxfs/mxfs.ko | awk '/srcversion/{print $2}') out=$OUT ==="
if [ "$(strings -a /src/mxfs/mxfs.ko | grep -c 'P-DBG-DEPART-CUT')" = 0 ]; then say "INFRA: mxfs.ko has no crash-cut injector"; exit 2; fi

nodes() { local i; for i in $(seq 1 "$N"); do echo "test$i"; done; }
peers() { local h; for h in $(nodes); do [ "$h" = "$VICTIM" ] || echo "$h"; done; }
fleet_do() { local tag="$1" cmd="$2" h; for h in $(peers); do ( timeout 25 "$SSH" "$h" "$cmd" > "$OUT/${tag}_$h.txt" 2>/dev/null; echo "rc=$?" >> "$OUT/${tag}_$h.txt" ) & done; wait; }
sweep() { fleet_do "$1" "dmesg"; }
count() { local tag="$1" m="$2" h s=0 c; for h in $(peers); do c=$(grep -ac -- "$m" "$OUT/${tag}_$h.txt" 2>/dev/null); s=$((s + ${c:-0})); done; echo "$s"; }
wait_count() { local tag="$1" m="$2" want="$3" end=$((SECONDS + $4)) c=0; while [ $SECONDS -lt $end ]; do sweep "$tag"; c=$(count "$tag" "$m"); [ "$c" -ge "$want" ] && break; sleep 3; done; echo "$c"; }
keys() { timeout 40 "$SSH" "$PROBE" "$CHK --pr-keys $DEV" 2>/dev/null | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | sort -u; }
normkey() { printf '0x%016x' "$(( $1 ))" 2>/dev/null; }
# decoded heartbeat sector of one slot, O_DIRECT from the probe (peers write
# these sectors; a buffered read returns a stale cached copy).  Layout: header
# 40 B (magic,flags,node,fs_gen,ts,epoch,lock_count), 320 B body, identity
# block at 360 (magic 4, ver 2, key_gen 2, host_uuid 16, boot_uuid 16,
# pr_key 8 @400, host_src 4, crc 4, reserved 8).
hb_slot() { # <slot> -> "flags=F state=S node=.. epoch=.. fsgen=.. ident_magic=.. pr_key=0x.. sha=.."
    timeout 30 "$SSH" "$PROBE" "python3 - <<'PYEOF'
import struct, os, mmap, hashlib
dev='$DEV'; slot=$1
f=os.open(dev, os.O_RDONLY)
dl=struct.unpack_from('<Q', os.pread(f,4096,0), 64)[0]
os.close(f)
f=os.open(dev, os.O_RDONLY|os.O_DIRECT)
m=mmap.mmap(-1, 64*512)
os.preadv(f, [m], dl)
d=m.read(64*512)
os.close(f)
r=d[slot*512:(slot+1)*512]
magic,flags,node,fsgen=struct.unpack_from('<IIII', r, 0)
ts,epoch=struct.unpack_from('<QQ', r, 16)
imagic,ver,kgen=struct.unpack_from('<IHH', r, 360)
prkey=struct.unpack_from('<Q', r, 400)[0]
st={0:'EMPTY',1:'ACTIVE',2:'WITHDRAWN',3:'RECOVERY_GUARD',4:'RETIRE_PENDING'}.get(flags,'flags%d'%flags)
print('flags=%d state=%s node=%u epoch=%u fsgen=%u magic=0x%x ident_magic=0x%x pr_key=0x%016x sha=%s' % (flags,st,node,epoch,fsgen,magic,imagic,prkey,hashlib.sha256(r).hexdigest()[:16]))
PYEOF" 2>/dev/null | grep -a '^flags='
}

# every ACTIVE slot whose identity block names <machine-id> (32 hex chars):
# "slot=N state=S node=.. host_uuid=<hex>" — the platter is the authority
# for slot identity when the kernel line is gone.
hb_scan_host() { # <machine-id-hex>
    timeout 30 "$SSH" "$PROBE" "python3 - <<'PYEOF'
import struct, os, mmap
dev='$DEV'; want=bytes.fromhex('$1')
f=os.open(dev, os.O_RDONLY)
dl=struct.unpack_from('<Q', os.pread(f,4096,0), 64)[0]
os.close(f)
f=os.open(dev, os.O_RDONLY|os.O_DIRECT)
m=mmap.mmap(-1, 64*512)
os.preadv(f, [m], dl)
d=m.read(64*512)
os.close(f)
st={0:'EMPTY',1:'ACTIVE',2:'WITHDRAWN',3:'RECOVERY_GUARD',4:'RETIRE_PENDING'}
for s in range(64):
    r=d[s*512:(s+1)*512]
    magic,flags,node,fsgen=struct.unpack_from('<IIII', r, 0)
    hu=r[368:384]
    if flags==0: continue
    print('slot=%d state=%s node=%u host_uuid=%s%s' % (s, st.get(flags,'flags%d'%flags), node, hu.hex(), ' MATCH' if hu==want else ''))
PYEOF" 2>/dev/null | grep -a '^slot='
}

# ── 0. identity of the victim's slot and key ──────────────────────────────
# sess462 (chain 86 cuts 3/5): the old lookup piped the victim's WHOLE
# `journalctl -k` through grep under a 20 s bound and discarded both stderr
# streams — it hit the bound (walls 21 s/20 s), printed INFRA and left an
# empty evidence dir.  Now: a pattern-indexed journal query + dmesg, every
# byte persisted; when the kernel line has rotated out of the volatile journal
# (trap sess429: the ring wraps within minutes under a board), fall back to
# the platter — the victim's /etc/machine-id is the host_uuid of its heartbeat
# identity block (dlm/hostid.c:106), so the slot is found by scanning the table.
vslot=""
{ timeout 40 "$SSH" "$VICTIM" "journalctl -k -b -o cat -g 'claimed heartbeat slot' --since -3h 2>&1 | tail -1; echo '== dmesg'; dmesg | grep -a 'claimed heartbeat slot' | tail -1"; echo "lookup_rc=$?"; } > "$OUT/vslot_lookup.txt" 2>&1
vslot=$(grep -aoE 'claimed heartbeat slot [0-9]+' "$OUT/vslot_lookup.txt" | tail -1 | grep -oE '[0-9]+$')
if [ -z "$vslot" ]; then
    mid=$(timeout 15 "$SSH" "$VICTIM" "cat /etc/machine-id" 2>>"$OUT/vslot_lookup.txt" | grep -aoE '^[0-9a-f]{32}$')
    echo "== platter scan machine-id=${mid:-none}" >> "$OUT/vslot_lookup.txt"
    if [ -n "$mid" ]; then
        hb_scan_host "$mid" >> "$OUT/vslot_lookup.txt"
        vslot=$(grep -a ' MATCH$' "$OUT/vslot_lookup.txt" | grep -a 'state=ACTIVE' | sed -n 's/^slot=\([0-9]*\) .*/\1/p' | head -1)
    fi
    say "victim slot from the platter (kernel line gone): slot=${vslot:-none} ($OUT/vslot_lookup.txt)"
fi
[ -n "$vslot" ] || { say "INFRA: cannot read the victim's heartbeat slot (see $OUT/vslot_lookup.txt: $(tr '\n' ' ' < "$OUT/vslot_lookup.txt" | cut -c1-300))"; exit 2; }
S0=$(hb_slot "$vslot"); K0=$(keys)
vkey=$(echo "$S0" | grep -oE 'pr_key=0x[0-9a-f]+' | cut -d= -f2)
say "victim slot=$vslot S0: $S0"
say "K0 keys=$(echo "$K0" | wc -w) victim_key_present=$(echo "$K0" | grep -c "^$(normkey "$vkey")$")"
echo "$S0" > "$OUT/S0.txt"; echo "$K0" > "$OUT/K0.txt"
echo "$S0" | grep -q 'state=ACTIVE' || fail "victim record is not ACTIVE before the umount"
echo "$K0" | grep -q "^$(normkey "$vkey")$" || fail "victim key $vkey is not in READ KEYS before the umount"

# ── 1. arm the cut and start the umount; wait for the park marker ─────────
fleet_do clear "dmesg --clear; echo cleared"
timeout 20 "$SSH" "$VICTIM" "dmesg --clear; echo 60000 > /sys/module/mxfs/parameters/dbg_depart_crash_hold_ms; echo $CUT > /sys/module/mxfs/parameters/dbg_depart_crash_cut; cat /sys/module/mxfs/parameters/dbg_depart_crash_cut" > "$OUT/arm.txt" 2>&1
grep -qx "$CUT" "$OUT/arm.txt" || { say "INFRA: could not arm the cut ($(cat "$OUT/arm.txt"))"; exit 2; }
T0=$(date +%s)
timeout 20 "$SSH" "$VICTIM" "nohup sh -c 'umount $MNT > /root/crashcut_umount.out 2>&1; echo rc=\$? >> /root/crashcut_umount.out' >/dev/null 2>&1 &" >/dev/null 2>&1
parked=0
while [ $(( $(date +%s) - T0 )) -lt 30 ]; do
    timeout 15 "$SSH" "$VICTIM" "dmesg" > "$OUT/victim_dmesg_at_cut.txt" 2>/dev/null
    if grep -aq "P-DBG-DEPART-CUT cut=$CUT " "$OUT/victim_dmesg_at_cut.txt"; then parked=1; break; fi
    sleep 1
done
T_PARK=$(( $(date +%s) - T0 ))
say "park marker=$parked after ${T_PARK}s: $(grep -a 'P-DBG-DEPART-CUT' "$OUT/victim_dmesg_at_cut.txt" | tail -1 | cut -c1-200)"
[ "$parked" = 1 ] || { say "INFRA: the victim never reached the cut (umount rc? $(timeout 10 "$SSH" "$VICTIM" "cat /root/crashcut_umount.out" 2>/dev/null | tail -2))"; exit 2; }
v_released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_dmesg_at_cut.txt")
v_quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$OUT/victim_dmesg_at_cut.txt")
v_unreg=$(grep -ac 'P-PR-UNREGISTER\|unregister.*verified\|P377-PR-UNREGISTERED' "$OUT/victim_dmesg_at_cut.txt")

# ── 2. the state AT the cut ────────────────────────────────────────────────
S1=$(hb_slot "$vslot"); K1=$(keys)
echo "$S1" > "$OUT/S1.txt"; echo "$K1" > "$OUT/K1.txt"
k1_present=$(echo "$K1" | grep -c "^$(normkey "$vkey")$")
say "S1 (at cut): $S1"
say "K1: keys=$(echo "$K1" | wc -w) victim_key_present=$k1_present | victim lines: quiesced=$v_quiesced released=$v_released"

# ── 3. crash the parked victim ─────────────────────────────────────────────
T_KILL=$(date +%s)
timeout 60 sudo virsh -c qemu:///system destroy "$VICTIM" > "$OUT/destroy.txt" 2>&1; echo "rc=$?" >> "$OUT/destroy.txt"
say "virsh destroy $VICTIM: $(tr '\n' ' ' < "$OUT/destroy.txt" | cut -c1-120) at +$(( T_KILL - T0 ))s"

# ── 4. peer action ─────────────────────────────────────────────────────────
case "$CUT" in
1)   term='P163-RECOVERY-COMPLETE'; bound=130 ;;
2|3) term='P163-RECOVERY-COMPLETE'; bound=130 ;;
5)   term='P304-RETIRE-COMPLETED-BY-PEER'; bound=60 ;;
esac
tn=$(wait_count peer "$term" 1 "$bound")
T_PEER=$(( $(date +%s) - T_KILL ))
seen=$(count peer 'P304-RETIRE-PENDING-SEEN'); expired=$(count peer 'P304-RETIRE-EXPIRED-WITHDRAWN')
wseen=$(count peer 'P163-WITHDRAW-SEEN'); fenced=$(count peer 'P236-FENCE-CERTIFIED'); rdone=$(count peer 'P163-RECOVERY-COMPLETE')
done_n=$(count peer 'P304-RETIRE-COMPLETED-BY-PEER'); wempty=$(count peer 'P304-RETIRE-WORKER slot=.*result=EMPTY')
nocaw=$(count peer 'P304-CAS-NOCAW'); unheld=$(count peer 'P-PR-SETTLE-UNHELD')
fence_key=$(grep -ah 'P236-FENCE-CERTIFIED' "$OUT"/peer_test*.txt 2>/dev/null | head -1 | cut -c1-220)
say "peers after ${T_PEER}s: RETIRE-PENDING-SEEN=$seen EXPIRED-WITHDRAWN=$expired WITHDRAW-SEEN=$wseen FENCE-CERTIFIED=$fenced RECOVERY-COMPLETE=$rdone COMPLETED-BY-PEER=$done_n worker_EMPTY=$wempty nocaw=$nocaw unheld=$unheld"
[ -n "$fence_key" ] && say "first fence: $fence_key"

# ── 5. the state AFTER the peers acted ─────────────────────────────────────
S2=$(hb_slot "$vslot"); K2=$(keys)
echo "$S2" > "$OUT/S2.txt"; echo "$K2" > "$OUT/K2.txt"
k2_present=$(echo "$K2" | grep -c "^$(normkey "$vkey")$")
say "S2 (after): $S2"
say "K2: keys=$(echo "$K2" | wc -w) victim_key_present=$k2_present"

# ── 6. restart the victim and record admission ─────────────────────────────
timeout 60 sudo virsh -c qemu:///system start "$VICTIM" > "$OUT/start.txt" 2>&1; echo "rc=$?" >> "$OUT/start.txt"
T_UP0=$(date +%s); up=0
while [ $(( $(date +%s) - T_UP0 )) -lt 120 ]; do
    if timeout 8 "$SSH" "$VICTIM" "uptime" >/dev/null 2>&1; then up=1; break; fi
    sleep 3
done
say "victim back: ssh=$up after $(( $(date +%s) - T_UP0 ))s"
admitted=0; p305=0; newslot=""
if [ "$up" = 1 ]; then
    # sess462 (chain 86 cuts 1/2, prep_rc=127): a fresh boot has no NFS /src
    # yet and prep_node.sh lives there — restore it first (run.sh:517 idiom,
    # tests/caw_pw_selftest.sh:194); without this the admission verdict was
    # never MXFS's, it was "No such file or directory".
    timeout 150 "$SSH" "$VICTIM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; echo NFS_RC=\$?; }; MXFS_DEV=$DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TRANSPORT; echo PREP_RC=\$?; dmesg" > "$OUT/victim_remount.log" 2>&1
    grep -q NODE_PREP_OK "$OUT/victim_remount.log" && admitted=1
    p305=$(grep -ac 'P305-PR-PREDECESSOR-KEY-PRESENT\|P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P-PR-QUARANTINE-REFUSED' "$OUT/victim_remount.log")
    newslot=$(grep -a 'claimed heartbeat slot' "$OUT/victim_remount.log" | tail -1 | grep -oE 'claimed heartbeat slot [0-9]+' | grep -oE '[0-9]+$')
fi
say "victim remount: admitted=$admitted refusal_lines=$p305 new_slot=${newslot:-none} prep_rc=$(sed -n 's/^PREP_RC=//p' "$OUT/victim_remount.log" 2>/dev/null | tail -1)"

# ── 7. verdict per cut ─────────────────────────────────────────────────────
s1_state=$(echo "$S1" | grep -oE 'state=[A-Z_]+' | cut -d= -f2); s1_key=$(echo "$S1" | grep -oE 'pr_key=0x[0-9a-f]+' | cut -d= -f2)
s2_state=$(echo "$S2" | grep -oE 'state=[A-Z_]+' | cut -d= -f2)
names_key=0; [ "$(normkey "$s1_key")" = "$(normkey "$vkey")" ] && names_key=1
case "$CUT" in
1)
    [ "$s1_state" = ACTIVE ] || fail "cut 1: sector at the cut is $s1_state, expected ACTIVE (no release CAS yet)"
    [ "$v_released" -eq 0 ] || fail "cut 1: the victim logged a release stamp before the cut"
    [ "$k1_present" = 1 ] || fail "cut 1: victim key absent at the cut"
    [ "$fenced" -ge 1 ] || fail "cut 1: peers did not fence the crashed ACTIVE record"
    [ "$rdone" -ge 1 ] || fail "cut 1: recovery did not complete"
    [ "$k2_present" = 0 ] || fail "cut 1: victim key still registered after the fence"
    ;;
2|3)
    [ "$s1_state" = RETIRE_PENDING ] || fail "cut $CUT: sector at the cut is $s1_state, expected RETIRE_PENDING"
    [ "$names_key" = 1 ] || fail "cut $CUT: THE DECISIVE FACT FAILED — the release CAS image does not name the key (ident.pr_key=$s1_key victim=$vkey)"
    [ "$v_released" -ge 1 ] || fail "cut $CUT: no P304-RETIRE-PENDING-RELEASED on the victim before the cut"
    [ "$k1_present" = 1 ] || fail "cut $CUT: victim key absent at the cut (unregister must not have run)"
    [ "$expired" -ge 1 ] || fail "cut $CUT: peers did not expire the RETIRE_PENDING record to WITHDRAWN"
    [ "$fenced" -ge 1 ] || fail "cut $CUT: peers did not fence the named key"
    [ "$rdone" -ge 1 ] || fail "cut $CUT: recovery did not complete"
    [ "$k2_present" = 0 ] || fail "cut $CUT: victim key still registered after the fence"
    [ "$done_n" -eq 0 ] || fail "cut $CUT: a peer settled the record EMPTY although the key was present"
    ;;
5)
    # sess466 (chain 92, tests/evidence/20260902T090001Z_crashcut5_postunreg):
    # the victim's release stamp and its late unregister land 17 ms apart, and
    # a peer's retire worker proves the key absent and settles the record
    # EMPTY inside its next heartbeat lap (~1-2 s) — BEFORE this harness can
    # poll the park marker over ssh and O_DIRECT-read the sector from the
    # probe.  The S1 snapshot therefore legitimately reads EMPTY at cut 5;
    # that is the design acting, not a failure.  The decisive fact (the
    # RETIRE_PENDING image named the key) is then proven by its consumer: the
    # peer's P304-RETIRE-PENDING-SEEN line carries key=<victim key> via=ident,
    # read from that very image, and the settled EMPTY image still carries
    # ident.pr_key (names_key stays derivable from S1).
    peer_seen_key=$(grep -ah 'P304-RETIRE-PENDING-SEEN slot='"$vslot"' ' "$OUT"/peer_test*.txt 2>/dev/null | grep -oE 'key=0x[0-9a-f]+ state=[A-Z_]+ via=ident' | grep -oE 'key=0x[0-9a-f]+' | cut -d= -f2 | sort -u | head -1)
    peer_named=0; [ -n "$peer_seen_key" ] && [ "$(normkey "$peer_seen_key")" = "$(normkey "$vkey")" ] && peer_named=1
    say "cut 5 key naming: S1=$s1_state names_key=$names_key peer_seen_key=${peer_seen_key:-none} peer_named=$peer_named"
    case "$s1_state" in
    RETIRE_PENDING) [ "$names_key" = 1 ] || fail "cut 5: the RETIRE_PENDING image does not name the key" ;;
    EMPTY) [ "$peer_named" = 1 ] || fail "cut 5: sector already EMPTY at the cut but no peer's SEEN line names the victim key via ident (settle without the naming proof)" ;;
    *) fail "cut 5: sector at the cut is $s1_state, expected RETIRE_PENDING (or EMPTY once a peer settled it)" ;;
    esac
    [ "$names_key" = 1 ] || [ "$peer_named" = 1 ] || fail "cut 5: neither the sector image nor a peer's SEEN line names the key"
    [ "$k1_present" = 0 ] || fail "cut 5: victim key still registered after a successful unregister"
    [ "$done_n" -eq 1 ] || fail "cut 5: the record must be settled EMPTY by exactly one peer (got $done_n)"
    [ "$fenced" -eq 0 ] || fail "cut 5: a fence ran although the key was proven absent"
    [ "$s2_state" = EMPTY ] || [ "$s2_state" = ACTIVE ] || fail "cut 5: sector after the settle is $s2_state"
    ;;
esac
[ "$nocaw" -eq 0 ] || fail "a CAS reported unsupported on a peer"
[ "$unheld" -eq 0 ] || fail "a settle ran without the departure mutex"
[ "$admitted" = 1 ] || fail "the victim's next mount was not admitted"

# ── 8. the table row ───────────────────────────────────────────────────────
row="| $CUT $CNAME | S1 $s1_state key_named=$names_key epoch=$(echo "$S1" | grep -oE 'epoch=[0-9]+' | cut -d= -f2) | READKEYS@cut present=$k1_present | peers: seen=$seen expired=$expired fenced=$fenced recov=$rdone empty=$done_n (${T_PEER}s) | S2 $s2_state | READKEYS@after present=$k2_present | admitted=$admitted slot=${newslot:-?} |"
echo "$row" | tee "$OUT/row.txt"
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS cut=$CUT ($CNAME) out=$OUT"; exit 0; else echo "VERDICT FAIL cut=$CUT ($CNAME) fails=$fails out=$OUT"; exit 1; fi
