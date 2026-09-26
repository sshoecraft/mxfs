#!/bin/bash
# tests/cas_nocaw_arms.sh — sess460, design-consult review #5 condition 4 (runtime
# CAW-loss fail-closed behaviour PER WRITER CLASS) and crash-cut 7 ("PR/CAW
# capability lost") of condition 3.
#
# 0.60.0 (D7 companion) removed every plain-FUA-write stand-in for a COMPARE
# AND WRITE that reports -EOPNOTSUPP: the exact-image record writers in
# dlm/disklock.c log P304-CAS-NOCAW slot= op= once per slot and leave the
# sector untouched.  The injector mxfs.dbg_cas_nocaw_ops (sticky bitmask,
# 0.61.6) makes the named writer classes' CAS return -EOPNOTSUPP on that
# node, so each class is exercised deterministically on a healthy LUN:
#   bit 1 heartbeat  2 release  4 withdraw  8 withdrawn(expiry)  16 restamp
#   32 complete-self  64 empty(peer settle)  128 settle-own(P305)
#   256 recovery-milestone  512 guard  1024 guard-refresh  2048 guard-zero
#
# Every arm asserts: exactly one P304-CAS-NOCAW op=<class> per (node, slot)
# on the injected node(s); the sector is BYTE-IDENTICAL (sha256 of the 512 B,
# O_DIRECT read from the probe) across the refusal window — i.e. no plain
# write emulated the CAS; the fail-closed disposition of that class; and
# that clearing the injector lets the cluster settle (the record moves only
# by a CAS that lands).
#
#   heartbeat  victim: its heartbeat cannot land; sector frozen; peers fence
#              it on the stale window and recover; victim rejoins after disarm.
#   release    victim: clean umount, release CAS refused -> DIRTY (no
#              RETIRE_PENDING stamp, P302 key retained, no unregister); sector
#              stays the ACTIVE image; peers fence + recover; rejoin after disarm.
#   restamp    victim: dbg_pr_unregister_fail=1 + restamp refused -> record
#              stays RETIRE_PENDING naming the key (P303-DEPARTURE-
#              INDETERMINATE); peers expire it WITHDRAWN after the 30 s grace,
#              fence, recover.
#   empty      ALL PEERS: victim's clean umount (key retired) cannot be
#              settled — every peer refuses (op=empty), the record stays
#              RETIRE_PENDING for 40 s, then disarm -> exactly one peer settles
#              it EMPTY.
#   settleown  victim: umount with dbg_pr_unregister_fail=1 +
#              dbg_retire_skip_restamp=1 (RETIRE_PENDING, key present), then an
#              immediate same-boot remount whose P305 own-settle CAS is refused
#              (op=settle-own): the mount must NOT be admitted on a record it
#              could not settle; disarm -> remount settles own + admitted.
#   guard      victim virsh-destroyed; ALL PEERS refuse the recovery GUARD
#              CAS (op=guard): no recovery starts (no P163-RECOVERY-COMPLETE)
#              while injected, victim's ACTIVE image byte-identical; disarm ->
#              guard lays, recovery completes; victim restarted + admitted.
#   milestone  as guard, bit 256: the guard lays, the recovery milestone CAS
#              is refused; recovery stalls at its stage; disarm -> completes.
#
# Usage: tests/cas_nocaw_arms.sh <N> <victim> <probe> <arm> [dev]
# Exit 0 PASS, 1 FAIL, 2 INFRA.
# derived time budgets: heartbeat/release = 62 s stale + fence + recovery ~80 s +
# prep 40 s -> 170; restamp = umount + 30 s grace + fence + recovery + prep
# ~120 s -> 170; empty = umount + 40 s hold + settle + prep ~100 s -> 140;
# settleown = umount + refused mount + remount ~40 s -> 90; guard/milestone =
# 62 s stale + 40 s hold + recovery + VM restart 40 s + prep 40 s ~200 -> 280.
set -u
N=${1:?N}; VICTIM=${2:?victim}; PROBE=${3:?probe}; ARM=${4:?arm}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
MXFS_DEV=${5:-${MXFS_DEV:-}}; mxfs_dev_resolve "$PROBE"; DEV=$MXFS_DEV_RESOLVED
MNT=/mnt/shared
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH=$REPO/tools/mxfs_sshpass.sh
CHK=/src/mxfs/tools/chk_mxfs
OUT=$REPO/tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_casnocaw_$ARM
mkdir -p "$OUT"
say() { echo "[casnocaw/$ARM] $*"; }
fails=0
fail() { say "FAIL: $*"; fails=$((fails+1)); }
echo "=== cas_nocaw_arms arm=$ARM N=$N victim=$VICTIM probe=$PROBE dev=$DEV @ $(date -u +%Y%m%dT%H%M%SZ) sv=$(modinfo /src/mxfs/mxfs.ko | awk '/srcversion/{print $2}') out=$OUT ==="
if [ "$(strings -a /src/mxfs/mxfs.ko | grep -c 'P-DBG-CAS-NOCAW')" = 0 ]; then say "INFRA: mxfs.ko has no dbg_cas_nocaw_ops injector"; exit 2; fi
case "$ARM" in heartbeat) BIT=1;; release) BIT=2;; restamp) BIT=16;; empty) BIT=64;; settleown) BIT=128;; guard) BIT=512;; milestone) BIT=256;; *) say "unknown arm $ARM"; exit 2;; esac

nodes() { local i; for i in $(seq 1 "$N"); do echo "test$i"; done; }
peers() { local h; for h in $(nodes); do [ "$h" = "$VICTIM" ] || echo "$h"; done; }
fleet_do() { local tag="$1" cmd="$2" h; for h in $(peers); do ( timeout 25 "$SSH" "$h" "$cmd" > "$OUT/${tag}_$h.txt" 2>/dev/null; echo "rc=$?" >> "$OUT/${tag}_$h.txt" ) & done; wait; }
sweep() { fleet_do "$1" "dmesg"; }
count() { local tag="$1" m="$2" h s=0 c; for h in $(peers); do c=$(grep -ac -- "$m" "$OUT/${tag}_$h.txt" 2>/dev/null); s=$((s + ${c:-0})); done; echo "$s"; }
wait_count() { local tag="$1" m="$2" want="$3" end=$((SECONDS + $4)) c=0; while [ $SECONDS -lt $end ]; do sweep "$tag"; c=$(count "$tag" "$m"); [ "$c" -ge "$want" ] && break; sleep 3; done; echo "$c"; }
keys() { timeout 40 "$SSH" "$PROBE" "$CHK --pr-keys $DEV" 2>/dev/null | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | sort -u; }
normkey() { printf '0x%016x' "$(( $1 ))" 2>/dev/null; }
vknob() { timeout 20 "$SSH" "$VICTIM" "echo $2 > /sys/module/mxfs/parameters/$1; cat /sys/module/mxfs/parameters/$1" 2>/dev/null | tail -1; }
peer_knob() { fleet_do knob "echo $2 > /sys/module/mxfs/parameters/$1 && cat /sys/module/mxfs/parameters/$1"; }
disarm_all() { fleet_do disarm "for k in dbg_cas_nocaw_ops dbg_pr_unregister_fail dbg_retire_skip_restamp; do echo 0 > /sys/module/mxfs/parameters/\$k 2>/dev/null; done; echo ok"; timeout 20 "$SSH" "$VICTIM" "for k in dbg_cas_nocaw_ops dbg_pr_unregister_fail dbg_retire_skip_restamp; do echo 0 > /sys/module/mxfs/parameters/\$k 2>/dev/null; done" >/dev/null 2>&1; }
hb_slot() { # <slot> -> decoded sector line (see depart_crash_cuts.sh)
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
prkey=struct.unpack_from('<Q', r, 400)[0]
st={0:'EMPTY',1:'ACTIVE',2:'WITHDRAWN',3:'RECOVERY_GUARD',4:'RETIRE_PENDING'}.get(flags,'flags%d'%flags)
print('flags=%d state=%s node=%u epoch=%u ts=%u fsgen=%u pr_key=0x%016x sha=%s' % (flags,st,node,epoch,ts,fsgen,prkey,hashlib.sha256(r).hexdigest()[:16]))
PYEOF" 2>/dev/null | grep -a '^flags='
}
sha_of() { echo "$1" | grep -oE 'sha=[0-9a-f]+' | cut -d= -f2; }
state_of() { echo "$1" | grep -oE 'state=[A-Z_]+' | cut -d= -f2; }
# frozen <slot> <seconds> <tag>: sample the sector every 2 s; prints "samples=N distinct_sha=M first=<line> last=<line>"
frozen() {
    local slot="$1" secs="$2" tag="$3" end=$((SECONDS + $2)) n=0 first="" last=""
    : > "$OUT/frozen_$tag.txt"
    while [ $SECONDS -lt $end ]; do
        last=$(hb_slot "$slot"); [ -z "$first" ] && first="$last"
        echo "$(date -u +%T) $last" >> "$OUT/frozen_$tag.txt"; n=$((n+1)); sleep 2
    done
    echo "samples=$n distinct_sha=$(grep -oE 'sha=[0-9a-f]+' "$OUT/frozen_$tag.txt" | sort -u | wc -l) first=[$first] last=[$last]"
}
victim_dmesg() { timeout 20 "$SSH" "$VICTIM" "dmesg" > "$OUT/$1.txt" 2>/dev/null; }
vcount() { grep -ac -- "$2" "$OUT/$1.txt" 2>/dev/null; }
restore_victim() { # remount through prep_node (insmod+mount); prints admitted=0/1
    # sess468 (chain 86 milestone arm, PREP_RC=127): a victim that was
    # virsh-destroyed comes back with no NFS /src, so prep_node.sh is not
    # there to run — restore the export first (same fix as
    # depart_crash_cuts.sh sess462), and keep the whole dmesg as evidence.
    timeout 160 "$SSH" "$VICTIM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; echo NFS_RC=\$?; }; dmesg --clear; MXFS_DEV=$DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh caw; echo PREP_RC=\$?; dmesg" > "$OUT/victim_restore.log" 2>&1
    grep -q NODE_PREP_OK "$OUT/victim_restore.log" && echo 1 || echo 0
}
hb_scan_host() { # <machine-id-hex> -> every occupied slot, ' MATCH' on the victim's host_uuid
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
# sess468 (chain 86: five of seven arms died here with 'cannot read the
# victim's heartbeat slot'): the old lookup piped the victim's whole
# `journalctl -k` through grep under a 20 s bound with stderr discarded, and
# the kernel line rotates out of the volatile journal within minutes under a
# board (trap sess429).  Same three-step lookup as depart_crash_cuts.sh: a
# pattern-indexed journal query + dmesg (every byte persisted), then the
# platter — the victim's /etc/machine-id is the host_uuid of its heartbeat
# identity block (dlm/hostid.c), so the slot is found by scanning the table.
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
S0=$(hb_slot "$vslot"); vkey=$(echo "$S0" | grep -oE 'pr_key=0x[0-9a-f]+' | cut -d= -f2)
say "victim slot=$vslot S0: $S0"
[ "$(state_of "$S0")" = ACTIVE ] || { say "INFRA: victim record not ACTIVE"; exit 2; }
fleet_do clear "dmesg --clear; echo cleared"; timeout 20 "$SSH" "$VICTIM" "dmesg --clear" >/dev/null 2>&1
disarm_all
T0=$(date +%s)

case "$ARM" in
heartbeat)
    [ "$(vknob dbg_cas_nocaw_ops $BIT)" = "$BIT" ] || { say "INFRA: knob"; exit 2; }
    fz=$(frozen "$vslot" 10 hb)
    victim_dmesg victim_hb
    say "sector over 10 s: $fz"
    say "victim: nocaw_heartbeat=$(vcount victim_hb 'P304-CAS-NOCAW slot=.* op=heartbeat') inject_lines=$(vcount victim_hb 'P-DBG-CAS-NOCAW') hb_lines=$(grep -ac 'HB-STALL\|HBFALSE\|P163-WITHDRAW\|shutdown\|withdraw' "$OUT/victim_hb.txt")"
    [ "$(echo "$fz" | grep -oE 'distinct_sha=[0-9]+' | cut -d= -f2)" = 1 ] || fail "the victim's sector changed while its heartbeat CAS was refused (plain write?)"
    [ "$(vcount victim_hb 'P304-CAS-NOCAW slot=.* op=heartbeat')" = 1 ] || fail "P304-CAS-NOCAW op=heartbeat not logged exactly once"
    rdone=$(wait_count peer 'P163-RECOVERY-COMPLETE' 1 150)
    say "peers after $(( $(date +%s) - T0 ))s: FENCE-CERTIFIED=$(count peer 'P236-FENCE-CERTIFIED') RECOVERY-COMPLETE=$rdone"
    [ "$rdone" -ge 1 ] || fail "peers did not fence + recover the node whose heartbeat could not land"
    victim_dmesg victim_after
    say "victim after: withdraw/shutdown lines=$(grep -ac 'P163-WITHDRAW-STAMP\|P236-WITHDRAW\|xfs_force_shutdown\|Filesystem has been shut down\|P304-CAS-NOCAW' "$OUT/victim_after.txt") (see $OUT/victim_after.txt)"
    vknob dbg_cas_nocaw_ops 0 >/dev/null
    timeout 90 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/victim_umount.log" 2>&1
    say "victim umount after disarm rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log")"
    adm=$(restore_victim); say "victim restored admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted after disarm"
    ;;
release)
    [ "$(vknob dbg_cas_nocaw_ops $BIT)" = "$BIT" ] || { say "INFRA: knob"; exit 2; }
    timeout 90 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    S1=$(hb_slot "$vslot"); fz=$(frozen "$vslot" 6 rel)
    nocaw=$(grep -ac 'P304-CAS-NOCAW slot=.* op=release' "$OUT/victim_umount.log"); rel=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log"); unreg=$(grep -ac 'P301-DEPARTURE-INCOMPLETE\|P303-' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s nocaw_release=$nocaw released=$rel key_retained=$retained unreg_lines=$unreg late_release=$(grep -a 'P278-LATE-RELEASE' "$OUT/victim_umount.log" | tail -1 | cut -c1-120)"
    say "S1 after umount: $S1 | 6 s window: $fz"
    [ "$nocaw" = 1 ] || fail "P304-CAS-NOCAW op=release not logged exactly once ($nocaw)"
    [ "$rel" = 0 ] || fail "a release stamp was reported although the CAS was refused"
    [ "$retained" -ge 1 ] || fail "PR key not retained (P302) after the refused release"
    [ "$(state_of "$S1")" = ACTIVE ] || fail "sector after the refused release is $(state_of "$S1"), expected the untouched ACTIVE image"
    [ "$(echo "$fz" | grep -oE 'distinct_sha=[0-9]+' | cut -d= -f2)" = 1 ] || fail "sector changed after the refused release (plain write?)"
    [ "$(keys | grep -c "^$(normkey "$vkey")$")" = 1 ] || fail "victim key not registered after the DIRTY departure"
    rdone=$(wait_count peer 'P163-RECOVERY-COMPLETE' 1 150)
    say "peers after $(( $(date +%s) - T0 ))s: FENCE-CERTIFIED=$(count peer 'P236-FENCE-CERTIFIED') RECOVERY-COMPLETE=$rdone key_after=$(keys | grep -c "^$(normkey "$vkey")$")"
    [ "$rdone" -ge 1 ] || fail "peers did not fence + recover the DIRTY departure"
    vknob dbg_cas_nocaw_ops 0 >/dev/null
    adm=$(restore_victim); say "victim restored admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted after disarm"
    ;;
restamp)
    [ "$(vknob dbg_cas_nocaw_ops $BIT)" = "$BIT" ] || { say "INFRA: knob"; exit 2; }
    vknob dbg_pr_unregister_fail 1 >/dev/null
    timeout 90 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    S1=$(hb_slot "$vslot"); fz=$(frozen "$vslot" 6 rst)
    nocaw=$(grep -ac 'P304-CAS-NOCAW slot=.* op=restamp' "$OUT/victim_umount.log"); rel=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    indet=$(grep -ac 'P303-DEPARTURE-INDETERMINATE' "$OUT/victim_umount.log"); restamped_ok=$(grep -ac 'P303-RETIRE-PENDING-RESTAMPED.*rc=0' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") nocaw_restamp=$nocaw released=$rel indeterminate=$indet restamp_rc0=$restamped_ok"
    say "S1: $S1 | 6 s window: $fz"
    [ "$nocaw" = 1 ] || fail "P304-CAS-NOCAW op=restamp not logged exactly once ($nocaw)"
    [ "$rel" -ge 1 ] || fail "no release stamp before the restamp"
    [ "$indet" -ge 1 ] || fail "the refused restamp was not reported as P303-DEPARTURE-INDETERMINATE"
    [ "$restamped_ok" = 0 ] || fail "the restamp reported rc=0 although the CAS was refused"
    [ "$(state_of "$S1")" = RETIRE_PENDING ] || fail "sector after the refused restamp is $(state_of "$S1"), expected RETIRE_PENDING"
    [ "$(echo "$S1" | grep -oE 'pr_key=0x[0-9a-f]+' | cut -d= -f2)" = "$vkey" ] || fail "the RETIRE_PENDING image does not name the key"
    [ "$(echo "$fz" | grep -oE 'distinct_sha=[0-9]+' | cut -d= -f2)" = 1 ] || fail "sector changed after the refused restamp (plain write?)"
    exp=$(wait_count peer 'P304-RETIRE-EXPIRED-WITHDRAWN' 1 70)
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 100)
    say "peers after $(( $(date +%s) - T0 ))s: EXPIRED-WITHDRAWN=$exp FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED') RECOVERY-COMPLETE=$rdone key_after=$(keys | grep -c "^$(normkey "$vkey")$")"
    [ "$exp" -ge 1 ] || fail "peers did not expire the un-restamped record to WITHDRAWN"
    [ "$rdone" -ge 1 ] || fail "recovery did not complete"
    vknob dbg_cas_nocaw_ops 0 >/dev/null
    adm=$(restore_victim); say "victim restored admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted after disarm"
    ;;
empty)
    peer_knob dbg_cas_nocaw_ops $BIT
    armed=$(grep -l "^$BIT$" "$OUT"/knob_test*.txt 2>/dev/null | wc -l)
    say "armed op=empty refusal on $armed peers"
    timeout 90 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    rel=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log"); retained=$(grep -ac 'P302-PR-KEY' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") released=$rel key_retained=$retained key_after=$(keys | grep -c "^$(normkey "$vkey")$")"
    [ "$rel" -ge 1 ] && [ "$retained" = 0 ] || fail "victim's departure was not clean (released=$rel retained=$retained)"
    fz=$(frozen "$vslot" 40 empty)
    sweep hold
    nocaw=$(count hold 'P304-CAS-NOCAW slot=.* op=empty'); done_n=$(count hold 'P304-RETIRE-COMPLETED-BY-PEER'); waiting=$(count hold 'P304-RETIRE-WORKER slot=.*result=WAITING')
    say "40 s hold: $fz | peers nocaw_empty=$nocaw completed=$done_n worker_waiting=$waiting"
    [ "$nocaw" -ge 1 ] || fail "no peer's settle CAS was refused (op=empty)"
    [ "$done_n" = 0 ] || fail "the record was settled EMPTY while every peer's CAS was refused"
    [ "$(echo "$fz" | grep -oE 'distinct_sha=[0-9]+' | cut -d= -f2)" = 1 ] || fail "the RETIRE_PENDING sector changed during the refusal window"
    [ "$(state_of "$(echo "$fz" | grep -oE 'last=\[[^]]*\]')")" = RETIRE_PENDING ] || fail "record is not RETIRE_PENDING at the end of the hold"
    peer_knob dbg_cas_nocaw_ops 0
    done_n=$(wait_count settle 'P304-RETIRE-COMPLETED-BY-PEER' 1 60)
    S2=$(hb_slot "$vslot")
    say "after disarm: COMPLETED-BY-PEER=$done_n in $(( $(date +%s) - T0 ))s S2: $S2"
    [ "$done_n" = 1 ] || fail "after disarm the record must be settled EMPTY exactly once (got $done_n)"
    adm=$(restore_victim); say "victim restored admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted"
    ;;
settleown)
    [ "$(vknob dbg_cas_nocaw_ops $BIT)" = "$BIT" ] || { say "INFRA: knob"; exit 2; }
    vknob dbg_pr_unregister_fail 1 >/dev/null; vknob dbg_retire_skip_restamp 1 >/dev/null
    timeout 120 "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_cycle.log" 2>&1
    S1=$(hb_slot "$vslot")
    m_rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/victim_cycle.log")
    nocaw=$(grep -ac 'P304-CAS-NOCAW slot=.* op=settle-own' "$OUT/victim_cycle.log"); own=$(grep -ac 'P305-RETIRE-SETTLED-OWN' "$OUT/victim_cycle.log")
    wf=$(grep -ac 'P305-RETIRE-OWN-WRITEFAIL' "$OUT/victim_cycle.log"); refuse=$(grep -a 'P305-RETIRE-UNSETTLED\|P305-RETIRE-OWN-UNPROVEN\|P-ADMIT-RETIRE-PENDING-HELD\|P305-PR-SAME-BOOT-RETIRE-PENDING' "$OUT/victim_cycle.log" | tail -2 | cut -c1-160)
    say "same-boot remount rc=$m_rc nocaw_settle_own=$nocaw settled_own=$own writefail=$wf | S1: $S1"
    say "mount lines: $refuse"
    [ "$nocaw" = 1 ] || fail "P304-CAS-NOCAW op=settle-own not logged exactly once ($nocaw)"
    [ "$own" = 0 ] || fail "SETTLED-OWN reported although the CAS was refused"
    [ "$m_rc" != 0 ] || fail "the same-boot remount was ADMITTED on a record it could not settle"
    [ "$(state_of "$S1")" = RETIRE_PENDING ] || fail "sector after the refused own-settle is $(state_of "$S1"), expected RETIRE_PENDING"
    vknob dbg_cas_nocaw_ops 0 >/dev/null
    timeout 120 "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_remount.log" 2>&1
    m2=$(sed -n 's/^MOUNT_RC=//p' "$OUT/victim_remount.log"); own2=$(grep -ac 'P305-RETIRE-SETTLED-OWN' "$OUT/victim_remount.log")
    say "after disarm remount rc=$m2 settled_own=$own2 expired_by_peers=$(count peer 'P304-RETIRE-EXPIRED-WITHDRAWN') S2: $(hb_slot "$vslot")"
    if [ "$m2" = 0 ]; then [ "$own2" -ge 1 ] || fail "remount admitted without settling its own record"; else
        # past the 30 s grace the peers may have expired + fenced it; then prep_node rejoins
        adm=$(restore_victim); say "victim restored via prep admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted after disarm"; fi
    ;;
guard|milestone)
    peer_knob dbg_cas_nocaw_ops $BIT
    say "armed op=$ARM refusal on $(grep -l "^$BIT$" "$OUT"/knob_test*.txt 2>/dev/null | wc -l) peers; destroying $VICTIM"
    timeout 60 sudo virsh -c qemu:///system destroy "$VICTIM" > "$OUT/destroy.txt" 2>&1; echo "rc=$?" >> "$OUT/destroy.txt"
    T_KILL=$(date +%s)
    opname=guard; [ "$ARM" = milestone ] && opname=recovery-milestone
    nc=$(wait_count peer "P304-CAS-NOCAW slot=.* op=$opname" 1 110)
    T_NC=$(( $(date +%s) - T_KILL ))
    say "first refused $opname CAS after ${T_NC}s (nocaw=$nc) fenced=$(count peer 'P236-FENCE-CERTIFIED') guard=$(count peer 'P99-GUARD') recov_complete=$(count peer 'P163-RECOVERY-COMPLETE')"
    [ "$nc" -ge 1 ] || fail "no peer's $opname CAS was refused within 110 s of the kill"
    fz=$(frozen "$vslot" 30 hold)
    sweep hold
    rc_hold=$(count hold 'P163-RECOVERY-COMPLETE')
    say "30 s hold: $fz | recovery_complete=$rc_hold nocaw=$(count hold "P304-CAS-NOCAW slot=.* op=$opname")"
    [ "$rc_hold" = 0 ] || fail "recovery COMPLETED while the $opname CAS was refused everywhere"
    [ "$(echo "$fz" | grep -oE 'distinct_sha=[0-9]+' | cut -d= -f2)" = 1 ] || fail "the victim's sector changed during the refusal window (plain write?)"
    peer_knob dbg_cas_nocaw_ops 0
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120)
    say "after disarm: RECOVERY-COMPLETE=$rdone guard=$(count recov 'P99-GUARD') in $(( $(date +%s) - T_KILL ))s since kill; S2: $(hb_slot "$vslot")"
    [ "$rdone" -ge 1 ] || fail "recovery did not complete after disarm"
    timeout 60 sudo virsh -c qemu:///system start "$VICTIM" > "$OUT/start.txt" 2>&1
    T_UP0=$(date +%s); up=0
    while [ $(( $(date +%s) - T_UP0 )) -lt 120 ]; do timeout 8 "$SSH" "$VICTIM" "uptime" >/dev/null 2>&1 && { up=1; break; }; sleep 3; done
    say "victim back: ssh=$up after $(( $(date +%s) - T_UP0 ))s"
    if [ "$up" = 1 ]; then adm=$(restore_victim); say "victim restored admitted=$adm"; [ "$adm" = 1 ] || fail "victim not readmitted"; else fail "victim did not come back"; fi
    ;;
esac
disarm_all
[ "$(count peer 'P-PR-SETTLE-UNHELD')" = 0 ] 2>/dev/null || fail "a settle ran without the departure mutex"
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS arm=$ARM out=$OUT"; exit 0; else echo "VERDICT FAIL arm=$ARM fails=$fails out=$OUT"; exit 1; fi
