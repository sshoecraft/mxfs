#!/bin/bash
# tests/recov_bmbt_reuse.sh <label> [S=test1] [V=test2]
#
# D-BUFFERS-THAT-LOG-RECOVERY-OF-A-DEAD-PEER-S: the survivor's replay of a
# dead peer's journal slice writes the peer's extent-tree (bmbt) and directory
# block images through the survivor's own buffer cache, where they stay
# cached (XBF_DONE) although no inode tenure on the survivor ever read them.
# The tenure-end eviction (0.87.6) retires only images read under a grant, so
# after the peer returns, deletes the file and builds a new tree over the
# freed addresses, the survivor's first access of the new file can be served
# a recovery image from its cache with no read — the D-0975 shape from a
# producer outside the grant discipline.  When the freed inode number is
# reused too, the stale leaf carries the right owner and a valid CRC and the
# owner check cannot refuse it.
#
#   1. V builds F: 20000 random 4 KiB O_DIRECT writes over a 1 GiB span
#      (tests/dwcd_prefill.py), a multi-level extent tree, then keeps writing
#      random blocks so its slice holds logged bmbt images at death.
#      S never touches F.
#   2. virsh destroy V mid-write.  S: death -> fence -> replay -> P163-RECOVERY-
#      COMPLETE.  Read on S: recov_tagged (buffers replay populated),
#      recov_bmbt_cached / recov_dir_cached (the census of those still cached
#      XBF_DONE at recovery end), recov_evicted (dropped by the fix).
#   3. V restarts and rejoins.  V: rm F; an empty file takes the freed inode
#      number (so F2 is a DIFFERENT inode: the survivor's acquire-time
#      eviction is keyed on the acquired inode's number and cannot see the
#      old images — with the same number it evicts them all, measured
#      nthisino=158, and proves nothing; SAMEINO=1 keeps that shape); build
#      F2 the same way over the freed addresses; V records F2's inode and
#      md5 and leaves its block list on the filesystem for the oracle.
#   4. S reads F2 whole and md5s it, then writes 64 random blocks of 'b'
#      into it; both nodes drop caches and check the final image against
#      the two writers' block lists (tests/d0532_img_check.py --wrote: every
#      written block holds its writer's byte, nothing else holds anything).
#      Read on S: recov_cache_hit (a recovery-populated image served from
#      the cache with no read, outside recovery), bmbt_lookup_bad (a stale
#      leaf refused at the btree owner check — the visible failure when the
#      inode number differs), CRC lines, write failures.
#      RETRYFAIL=<n> injects a retirement failure after n retirements on the
#      first attempt; the recovery must stay unpublished, retry, and retire
#      the rest.
#
# RESULT PASS   recovery completed; recov_bmbt_cached > 0 at recovery end
#               (the census proves replay populated the cache, else the lap
#               is INCONCLUSIVE); after the rebuild S was served no recovery
#               image from its cache (recov_cache_hit=0), no lookup refused,
#               S's md5 of F2 == V's, S's writes all succeeded, final images
#               identical and matching the oracle, no splat, no shutdown,
#               both nodes mounted.
# RESULT FAIL   any recov_cache_hit, lookup_bad, CRC line, md5 mismatch,
#               failed write, differing or oracle-failing final images, splat
#               or shutdown.
# RESULT INCONCLUSIVE  no recovery, V did not rejoin, or the census read 0.
# Control arm: recov_evict=0 on S before the kill (knob on the fix build)
# reproduces recov_cache_hit > 0, and with the different inode number the
# refused lookups (bmbt_lookup_bad > 0, S's md5 read fails).
#
# budget (derived): prefill 20000 measured ~25 s x 2, V writer 10 s, TCP death
# detection ~62 s + replay ~15 s (bounded 150 s), V reboot 40-90 s (bounded
# 120 s), rejoin ~30 s (bounded 90 s), S read 1 GiB sparse ~10 s, then the
# cold check: two unmounts 35-80 s each, chk_mxfs under 60 s, two remounts up
# to 80 s each.  Caller bound 900 s (540 s with MXFS_RECOV_COLDCHK=0).
# Leaves both nodes mounted.  Exit 0 PASS, 1 FAIL, 2 INFRA.
set -u
LABEL=${1:?label}
S=${2:-test1}; V=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_recovreuse_$LABEL
mkdir -p "$OUT"
fails=0; incon=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/prep_require (tests/lib/rig.sh): the
# kernel-log captures a verdict is counted from cross the boundary in the
# parent shell first; a failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
hd() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }   # polling only; never counted
hdm() { measure "$1" 20 "$2" '^DMESG_END$' "the kernel log on $1 from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"; }
cnt() { rs 15 "$1" "cat $P/$2 2>/dev/null || echo na"; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }

echo "=== recov_bmbt_reuse label=$LABEL S=$S V=$V out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
for n in "$S" "$V"; do
    info=$(rs 15 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "RESULT INFRA recovreuse: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"ft=1"* ]] || { echo "RESULT INFRA recovreuse: $n not on TCP ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]] || { echo "RESULT INFRA recovreuse: $n not mounted ($info)"; exit 2; }
done
DEV=$(rs 15 "$S" "awk '\$2==\"$MNT\" && \$3==\"mxfs\" {print \$1}' /proc/mounts")
[ -n "$DEV" ] || { echo "RESULT INFRA recovreuse: cannot read $S's device from /proc/mounts"; exit 2; }
knob=$(cnt "$S" recov_evict)
echo "  INFO dev=$DEV recov_evict(S)=$knob"
MARK="RECOVREUSE-$LABEL-$$"
for n in "$S" "$V"; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
for c in recov_tagged recov_queued recov_bmbt_cached recov_dir_cached recov_agbt_cached recov_other_cached recov_evicted recov_busy recov_localwork recov_cache_hit recov_hit_in_recovery bmbt_lookup_bad; do
    rs 12 "$S" "[ -w $P/$c ] && echo 0 > $P/$c" >/dev/null
done
# RETRYFAIL=<n>: the retirement fails after n retirements on the first
# attempt (dbg_recov_evict_fail_after, self-clearing); the recovery must
# stay unpublished, be retried, and retire the rest.
[ -n "${RETRYFAIL:-}" ] && rs 12 "$S" "echo ${RETRYFAIL} > $P/dbg_recov_evict_fail_after; echo inject=\$(cat $P/dbg_recov_evict_fail_after)" | sed 's/^/  INFO /'
F=$MNT/.recovreuse_$LABEL.dat
SPAN=262144   # 1 GiB in 4 KiB blocks

# 1. V builds the tree and keeps writing.
rs 120 "$V" "set -u
: > '$F' || { echo BUILD_FAIL; exit 1; }
python3 /src/mxfs/tests/dwcd_prefill.py '$F' $SPAN 20000 a | grep -a PREFILL
sync
echo ino=\$(stat -c %i '$F') size=\$(stat -c %s '$F')
python3 - '$F' $SPAN <<'EOF' > /dev/null 2>&1 &
import os, random, sys, mmap, time
p, span = sys.argv[1], int(sys.argv[2])
buf = mmap.mmap(-1, 4096); buf.write(b'v' * 4096)
fd = os.open(p, os.O_WRONLY | os.O_DIRECT)
t = time.time()
while time.time() - t < 120:
    os.pwrite(fd, buf, random.randrange(span) * 4096)
EOF
echo WRITER_STARTED" > "$OUT/v_build.txt"
cat "$OUT/v_build.txt" | sed 's/^/  V /'
grep -aq WRITER_STARTED "$OUT/v_build.txt" || { echo "RESULT INFRA recovreuse: V build failed: $(tr '\n' ' ' < "$OUT/v_build.txt" | cut -c1-200)"; exit 2; }
ino1=$(sed -n 's/.*ino=\([0-9]*\).*/\1/p' "$OUT/v_build.txt" | head -1)
sleep 10

# 2. Kill V mid-write; S recovers.
$VIRSH destroy "$V" >/dev/null 2>&1; echo "  INFO virsh destroy $V rc=$? at +$(el)s $(date -u +%T)"
tkill=$(date +%s)
rec=0; i=0
while [ $i -lt 150 ]; do
    if hd "$S" | grep -aq 'P163-RECOVERY-COMPLETE'; then rec=1; break; fi
    sleep 3; i=$((i+3))
done
trec=$(( $(date +%s) - tkill ))
echo "  INFO $S recovery complete=$rec after ${trec}s"
hdm "$S" "$OUT/dmesg_${S}_recovered.txt"
tagged=$(cnt "$S" recov_tagged); bcached=$(cnt "$S" recov_bmbt_cached); dcached=$(cnt "$S" recov_dir_cached)
[ -n "${RETRYFAIL:-}" ] && rs 12 "$S" "echo 0 > $P/dbg_recov_evict_fail_after" >/dev/null
acached=$(cnt "$S" recov_agbt_cached); ocached=$(cnt "$S" recov_other_cached)
evicted=$(cnt "$S" recov_evicted); busy=$(cnt "$S" recov_busy); lwork=$(cnt "$S" recov_localwork)
echo "  INFO $S at recovery end: recov_tagged=$tagged recov_bmbt_cached=$bcached recov_dir_cached=$dcached recov_agbt_cached=$acached recov_other_cached=$ocached recov_evicted=$evicted recov_busy=$busy recov_localwork=$lwork replay_lines=$(grep -ac 'P226-FR\|foreign replay' "$OUT/dmesg_${S}_recovered.txt")"
grep -a 'P-RECOV-IMAGE-EVICT' "$OUT/dmesg_${S}_recovered.txt" | tail -2 | sed 's/^/  /' | cut -c1-260
# D-0976: the replayed dinode images must reach the platter.  The survivor's
# inode-cluster write publishes the slots the recovery patched
# (P218-RECOV-OWNED); a write refused by the authority mask
# (P218-WRITE-REFUSED) is the dropped dinode, and the victim's first extent
# read after rejoin then shuts it down (P-BMBT-OVERCOUNT).
refused=$(grep -ac 'P218-WRITE-REFUSED' "$OUT/dmesg_${S}_recovered.txt")
owned=$(grep -ac 'P218-RECOV-OWNED' "$OUT/dmesg_${S}_recovered.txt")
echo "  INFO $S replay inode items: $(grep -a 'P77-FRINODE' "$OUT/dmesg_${S}_recovered.txt" | grep -ao 'verdict=[A-Z]*' | sort | uniq -c | tr -s ' ' | tr '\n' ';') cluster writes: recov_owned=$owned refused=$refused"
grep -a 'P218-RECOV-OWNED\|P218-WRITE-REFUSED' "$OUT/dmesg_${S}_recovered.txt" | head -2 | sed 's/^/  /' | cut -c1-220
[ "$rec" = 1 ] || { echo "RESULT INCONCLUSIVE recovreuse: $S never published P163-RECOVERY-COMPLETE within 150 s out=$OUT"; $VIRSH start "$V" >/dev/null 2>&1; exit 3; }

# 3. V restarts, rejoins, rebuilds over the freed addresses.
$VIRSH start "$V" >/dev/null 2>&1; echo "  INFO virsh start $V rc=$? at +$(el)s"
up=0
for i in $(seq 1 24); do
    rs 8 "$V" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }
    sleep 5
done
[ "$up" = 1 ] || { echo "RESULT INCONCLUSIVE recovreuse: $V not back on ssh within 120 s out=$OUT"; exit 3; }
rsx 90 "$V" "mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1" > "$OUT/v_rejoin.txt"
prep_require "$OUT/v_rejoin.txt" "the rejoin preparation on $V"
echo "  INFO $V rejoined at +$(el)s"
rs 12 "$V" "echo '$MARK' > /dev/kmsg" >/dev/null
F2=$MNT/.recovreuse_${LABEL}_2.dat
HOLD=$MNT/.recovreuse_${LABEL}_hold
WV=$MNT/.recovreuse_${LABEL}_wrote_v.txt
WS=$MNT/.recovreuse_${LABEL}_wrote_s.txt
# The freed inode number is taken by an empty file first, so F2 is a
# DIFFERENT inode reusing the freed tree blocks: the survivor's acquire-time
# eviction is keyed on the acquired inode's number and cannot see images
# that carry the old one (D-0975); with the same number it would evict them
# all (measured: nthisino=158 on the first control lap) and prove nothing.
# SAMEINO=1 keeps the same-number shape for comparison.
rs 150 "$V" "set -u
rm -f '$F' || { echo RM_FAIL; exit 1; }
sync
[ '${SAMEINO:-0}' = 1 ] || { : > '$HOLD'; echo hold_ino=\$(stat -c %i '$HOLD'); }
: > '$F2' || { echo BUILD2_FAIL; exit 1; }
python3 /src/mxfs/tests/dwcd_prefill.py '$F2' $SPAN 20000 a > '$WV'
grep -a PREFILL '$WV'
sync; echo 3 > /proc/sys/vm/drop_caches
echo ino2=\$(stat -c %i '$F2') size2=\$(stat -c %s '$F2')
echo md5_v1=\$(md5sum '$F2' | cut -d' ' -f1)
echo BUILD2_DONE" > "$OUT/v_build2.txt"
cat "$OUT/v_build2.txt" | sed 's/^/  V /'
grep -aq BUILD2_DONE "$OUT/v_build2.txt" || {
    # A rebuild that fails because V shut down over the recovered file is
    # the defect observed, not an infrastructure failure: keep both nodes'
    # kernel logs (S's replay verdicts, V's torn-pair report) and fail.
    hdm "$V" "$OUT/dmesg_${V}_build2.txt"; hdm "$S" "$OUT/dmesg_${S}_build2.txt"
    grep -a 'P-BMBT-OVERCOUNT\|corrupt dinode\|Metadata corruption\|Internal error\|Shutting down' "$OUT/dmesg_${V}_build2.txt" | head -4 | sed 's/^/  V /' | cut -c1-400
    echo "  INFO $S replay inode-item verdicts: $(grep -a 'P77-FRINODE' "$OUT/dmesg_${S}_recovered.txt" | grep -ao 'verdict=[A-Z]*' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
    sd=$(grep -aEc 'Shutting down filesystem|corrupt dinode|Corruption of in-memory|P-SESSION-POISON' "$OUT/dmesg_${V}_build2.txt")
    if [ "$sd" != 0 ]; then echo "RESULT FAIL recovreuse: $V shut down rebuilding over the recovered file ($(tr '\n' ' ' < "$OUT/v_build2.txt" | cut -c1-120)) out=$OUT"; exit 1; fi
    echo "RESULT INFRA recovreuse: V rebuild failed: $(tr '\n' ' ' < "$OUT/v_build2.txt" | cut -c1-200)"; exit 2; }
ino2=$(sed -n 's/.*ino2=\([0-9]*\).*/\1/p' "$OUT/v_build2.txt" | head -1)
md5_v1=$(sed -n 's/.*md5_v1=\([0-9a-f]*\).*/\1/p' "$OUT/v_build2.txt" | head -1)
echo "  INFO F ino=$ino1 F2 ino=$ino2 same_inode=$([ "$ino1" = "$ino2" ] && echo 1 || echo 0)"

# 4. S reads and writes F2; both compare.
hit0=$(cnt "$S" recov_cache_hit); hitr=$(cnt "$S" recov_hit_in_recovery); queued=$(cnt "$S" recov_queued)
echo "  INFO $S before its access: recov_cache_hit=$hit0 recov_hit_in_recovery=$hitr recov_queued=$queued"
rs 120 "$S" "set -u
m=\$(md5sum '$F2' 2>&1); echo md5_rc=\$? md5_s=\$(echo \"\$m\" | cut -d' ' -f1)
python3 /src/mxfs/tests/dwcd_prefill.py '$F2' $SPAN 64 b > '$WS' 2>&1; echo swrite_rc=\$?
grep -a PREFILL '$WS' | sed 's/PREFILL/SWRITE/'
sync
echo S_DONE" > "$OUT/s_access.txt"
cat "$OUT/s_access.txt" | sed 's/^/  S /' | cut -c1-200
md5_s=$(grep -aoE 'md5_s=[0-9a-f]{32}' "$OUT/s_access.txt" | head -1 | cut -d= -f2)
swrites=$(sed -n 's/.*SWRITE n=\([0-9]*\).*/\1/p' "$OUT/s_access.txt" | head -1)
# The oracle is the writers' own block lists, not the two nodes' agreement:
# every block V or S reported written must hold that writer's byte, and no
# other block may hold anything.
rs 60 "$S" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 /src/mxfs/tests/d0532_img_check.py '$F2' --wrote '$WV' '$WS'" > "$OUT/img_$S.txt"
rs 60 "$V" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 /src/mxfs/tests/d0532_img_check.py '$F2' --wrote '$WV' '$WS'" > "$OUT/img_$V.txt"
img_s=$(grep -a '^IMG' "$OUT/img_$S.txt" | head -1); img_v=$(grep -a '^IMG' "$OUT/img_$V.txt" | head -1)
ext_s=$(grep -a '^EXTCHK' "$OUT/img_$S.txt" | head -1); ext_v=$(grep -a '^EXTCHK' "$OUT/img_$V.txt" | head -1)
echo "  $S $img_s" | cut -c1-120; echo "  $S $ext_s"; echo "  $V $img_v" | cut -c1-120; echo "  $V $ext_v"
sleep 2
hdm "$S" "$OUT/dmesg_$S.txt"; hdm "$V" "$OUT/dmesg_$V.txt"
value_now_into hit "$S" 15 "$OUT/knob_hit.txt" '^(-?[0-9]+|na)$' "the recov_cache_hit counter on $S" "cat $P/recov_cache_hit 2>/dev/null || echo na"; value_now_into lbad "$S" 15 "$OUT/knob_lbad.txt" '^(-?[0-9]+|na)$' "the bmbt_lookup_bad counter on $S" "cat $P/bmbt_lookup_bad 2>/dev/null || echo na"
crc=$(grep -ac 'Metadata CRC error\|MEDIUM-NOT-BMBT' "$OUT/dmesg_$S.txt")
echo "  INFO $S after access: recov_cache_hit=$hit bmbt_lookup_bad=$lbad crc_lines=$crc lookup_bad_lines=$(grep -ac 'P975-BMBT-LOOKUP-BAD' "$OUT/dmesg_$S.txt") hit_by_class=$(grep -a 'P-RECOV-CACHE-HIT' "$OUT/dmesg_$S.txt" | sed 's/.*ops=\([^ ]*\) comm=\([^ ]*\).*/\1@\2/' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
grep -a 'P975-BMBT-LOOKUP-BAD' "$OUT/dmesg_$S.txt" | head -2 | sed 's/^/  /' | cut -c1-220
inj=$(grep -ac 'P-RECOV-EVICT-INJECT' "$OUT/dmesg_${S}_recovered.txt"); nev=$(grep -ac 'P-RECOV-IMAGE-EVICT' "$OUT/dmesg_${S}_recovered.txt")
rs 12 "$S" "rm -f '$F2' '$HOLD' '$WV' '$WS'" >/dev/null

# The cold structural check: only chk_mxfs on a QUIESCED device compares the
# two records of every allocated inode (the inode btree and the dinode) and
# the dinode against its extent tree; a replayed dinode that never landed
# (D-0976) shows as P-ALLOC-FREE-CORE or a torn extent count here and
# nowhere in the live counters.  Both nodes are unmounted for it and put
# back.  Budget: a 2-node TCP unmount measured 35-80 s each, the check well
# under 300 s, a remount up to 80 s.  MXFS_RECOV_COLDCHK=0 skips it.
ccfree=0; ccverdict=skipped
if [ "${MXFS_RECOV_COLDCHK:-1}" = 1 ]; then
    rs 180 "$V" "umount $MNT; echo CC_UMOUNT_V_RC=\$?" > "$OUT/coldchk_umount_v.txt" 2>&1
    rs 180 "$S" "umount $MNT; echo CC_UMOUNT_S_RC=\$?" > "$OUT/coldchk_umount_s.txt" 2>&1
    ccm=$(rs 30 "$S" "grep -c ' $MNT mxfs ' /proc/mounts"; rs 30 "$V" "grep -c ' $MNT mxfs ' /proc/mounts")
    if [ "$(echo "$ccm" | tr -d '\r' | tr '\n' ' ')" = "0 0 " ]; then
        rs 300 "$S" "/src/mxfs/tools/chk_mxfs -v $DEV 2>&1 | tail -60" > "$OUT/chk.txt" 2>&1
        ccfree=$(grep -ac 'P-ALLOC-FREE-CORE' "$OUT/chk.txt"); ccfree=${ccfree:-0}
        ccerr=$(grep -a '^chk_mxfs: ' "$OUT/chk.txt" | tail -1 | tr -d '\r')
        if echo "$ccerr" | grep -q 'filesystem clean'; then ccverdict=clean; else ccverdict="${ccerr:-NO VERDICT LINE}"; fi
        echo "  COLDCHK $(cat "$OUT/coldchk_umount_v.txt" "$OUT/coldchk_umount_s.txt" | tr -d '\r' | tr '\n' ' ')alloc_free_core=$ccfree verdict='$ccverdict'"
        grep -a 'ERROR' "$OUT/chk.txt" | head -6 | cut -c1-220 | sed 's/^/       /'
    else
        ccverdict="UNREADABLE: a node is still mounted ($(echo "$ccm" | tr '\n' ' '))"
        echo "  COLDCHK-READ: $ccverdict"
    fi
    rs 180 "$S" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_S_RC=\$?" > "$OUT/coldchk_remount_s.txt" 2>&1
    rs 180 "$V" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_V_RC=\$?" > "$OUT/coldchk_remount_v.txt" 2>&1
    echo "  COLDCHK restore $(cat "$OUT/coldchk_remount_s.txt" "$OUT/coldchk_remount_v.txt" | tr -d '\r' | tr '\n' ' ')"
fi

[ "$bcached" != na ] && [ "$bcached" != 0 ] || { echo "  INCONCLUSIVE the recovery census found no cached extent-tree image (recov_bmbt_cached=$bcached) — replay populated nothing to reuse"; incon=1; }
ck "no replayed inode-cluster write refused by the authority mask on $S (P218-WRITE-REFUSED)" "$refused" "0"
[ "$ccverdict" != skipped ] && ck "the quiesced volume checks clean (chk_mxfs, alloc_free_core=$ccfree)" "$ccverdict" "clean"
applied=$(grep -a 'P77-FRINODE' "$OUT/dmesg_${S}_recovered.txt" | grep -ac 'verdict=APPLY')
[ "$applied" -gt 0 ] && ck "$S published the recovery-patched dinode slots it applied (P218-RECOV-OWNED, applied=$applied)" "$([ "$owned" -gt 0 ] && echo 1 || echo "0:$owned")" "1"
ck "no recovery-populated image served from $S's cache after the rebuild (recov_cache_hit)" "${hit:-na}" "0"
ck "no cached extent-tree lookup refused on $S (bmbt_lookup_bad)" "${lbad:-na}" "0"
ck "no extent-tree read CRC failure on $S" "${crc:-na}" "0"
ck "$S read the image $V wrote (md5)" "$([ -n "$md5_s" ] && [ "$md5_s" = "$md5_v1" ] && echo same || echo "differ:${md5_s:-none}/${md5_v1:-none}")" "same"
ck "$S's 64 writes into F2 all completed" "${swrites:-0}" "64"
ck "final images identical on both nodes" "$([ -n "$img_s" ] && [ "${img_s#* md5=}" = "${img_v#* md5=}" ] && echo same || echo differ)" "same"
ck "$S's final image matches the writers' block lists (oracle: lost=0 stray=0 short=0)" "$(echo "$ext_s" | grep -ao 'lost=[0-9]* stray=[0-9]* short=[0-9]*')" "lost=0 stray=0 short=0"
ck "$V's final image matches the writers' block lists (oracle)" "$(echo "$ext_v" | grep -ao 'lost=[0-9]* stray=[0-9]* short=[0-9]*')" "lost=0 stray=0 short=0"
if [ -n "${RETRYFAIL:-}" ]; then
    ck "the injected retirement failure fired on $S" "$inj" "1"
    ck "$S ran the retirement at least twice (recovery retried after the injected failure)" "$([ "$nev" -ge 2 ] && echo 1 || echo "0:$nev")" "1"
fi
for n in "$S" "$V"; do
    sp=$(grep -aEc 'BUG:|Oops|WARNING: CPU|Shutting down filesystem|P-SESSION-POISON' "$OUT/dmesg_$n.txt"); ck "zero splats/shutdowns on $n" "$sp" "0"
    value_now_into m "$n" 15 "$OUT/rv_m_1.txt" '^[0-9]+$' "m on $n" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"; ck "$n still mounted" "${m:-0}" "1"
done
echo "=== recov_bmbt_reuse $LABEL: fails=$fails inconclusive=$incon wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ "$fails" -ne 0 ]; then echo "RESULT FAIL recovreuse: fails=$fails out=$OUT"; exit 1; fi
if [ "$incon" -ne 0 ]; then echo "RESULT INCONCLUSIVE recovreuse: census empty out=$OUT"; exit 3; fi
echo "RESULT PASS recovreuse: recovery populated $bcached extent-tree images, $S served none from cache after the rebuild, images identical, wall=$(el)s out=$OUT"
exit 0
