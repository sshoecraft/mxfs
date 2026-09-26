#!/bin/bash
# tcp_death_replay.sh — D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-0288
# verification on a SMALL cluster: a dirty node death on the TCP transport
# must be replayed by the survivor from the ledger-sourced fence-time
# manifest, and every write the victim had fsync-acknowledged must be
# readable from the survivor with the acknowledged content.
#
# Shape (2 nodes by default; W = survivor / elected replayer, V = victim):
#   1. V runs a writer: files of SIZE random bytes into $MNT/tdr_<label>/,
#      each fsync'd (file, then its directory) before the line
#      "OK <name> <md5>" is printed.  The lines stream to clyde over the
#      ssh session; the set received before the kill is the ACKNOWLEDGED set
#      (the victim's own logs die with the VM, so nothing is read from it).
#   2. After KILL_AFTER seconds V is virsh-destroyed mid-stream.
#   3. On W: heartbeat expiry (~62 s) -> fence -> SEAL + ledger collect ->
#      sealed manifest (flags 0x4) -> foreign replay with the manifest as the
#      authority -> recovery complete.  Every step has its probe line and is
#      asserted; the refusal shape (ATOMIC-SKIP -> TORN-UNPUBLISHED -> QUAR)
#      and the abort shape (POSTSEAL-MUTATION / LIVECHECK-ERR) each FAIL.
#   4. On W: every acknowledged file is md5summed (bounded: a quarantined
#      domain answers EIO only after the 60-retry budget, which is itself a
#      FAIL here) and must match; the directory must list at least that many.
#   5. V is virsh-started again; the rig is left with V UNMOUNTED — the next
#      run.sh / prep_cluster re-forms the cluster.
#
# the budget rule (derived): setup ~10 s + write KILL_AFTER s + death detection ~62 s
# + fence/snapshot/replay ~15-25 s (CAW shape ~70 s from the kill) + verify
# ~10 s + victim restart ~60 s => ~180 s; replay wait bound 150 s from the
# kill, caller bound 240 s.  A replay that has not completed by the bound is
# a FAIL, never a reason to wait longer.
#
# Usage: tests/tcp_death_replay.sh <label> [W] [V]
# Env:   TDR_VICTIM_AGINO=<n> — the inode-buffer replay guard, exercised at the
#          DURABLE WRITE.  Just before the kill V creates a small inode cluster,
#          arms mxfs.dbg_recov_inject_agino=<n> and unlinks the files while they
#          are open, so one logged di_next_unlinked carries an agino no AG of
#          this filesystem contains while the buffer on the platter stays
#          correct.  W's foreign replay must REFUSE that image by name rather
#          than adopt it.  Use an agino far outside any AG (agblocks * inopblock
#          bounds it; 2147483646 is safe on this rig).  The arm is vacuous
#          unless the kernel logs P-INJ-LOGGED-AGINO, which it asserts.
#        TDR_VICTIM_STRADDLE=1 — the same shape for the other 0.89.35 condition:
#          the logged image's daddr is moved so the cluster it names crosses an
#          AG boundary.  One substitution per lap; two at once and neither
#          refusal is attributable.
#        The control for both is a PLAIN lap (no env at all), whose replay must
#          COMPLETE — without it a refusal count proves only that something
#          refused.
# Env:   TDR_KILL_AFTER (s of writing before the kill, default 6)
#        TDR_SIZE (bytes per file, default 65536), TDR_MAX_FILES (default 4000)
#        MXFS_MNT (default /mnt/shared)
#        TDR_BLOCK_INJECT=1 — the RECOVERY_BLOCKED arm
#          (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904): before
#          the kill W gets fence_gate_inject_refuse=1 (the sole-survivor gate
#          is refused, so the absent-key attempt stays non-proving) and
#          fence_blocked_after_ms=$TDR_BLOCK_AFTER_MS (default 20000).  After
#          the kill the harness asserts, within BLOCK_BOUND of the kill: one
#          P238-FENCE-BLOCKED, the durable flag line, the debugfs reason
#          FENCE_BLOCKED, a bounded P304 retry count, no replay; then that a
#          path operation on W which needs the victim's grants fails fast
#          (EIO, seconds) instead of waiting out the acquire budget.  It then
#          clears the injection and the normal chain must complete from the
#          slow re-drive: P238-FENCE-UNBLOCKED, gate certify, replay, every
#          acknowledged file verified.  Budget: the normal lap + BLOCK_BOUND
#          + one 30 s re-drive => caller bound 400 s.
#        TDR_VERIFY_INJECT=1 — the write-verifier arm
#          (D-FOREIGN-REPLAY-WRITE-VERIFIER-FAILURE-SHUTS-DOWN-SURVIVOR-0904):
#          before the kill W gets freplay_inject_verify_fail=1, which flips a
#          byte of the next outgoing foreign-recovery image at submit so its
#          write verifier refuses it.  The replay must then FAIL (refused,
#          terminal outcome published, the victim's domain quarantined) and
#          the survivor must stay mounted: zero 'Shutting down filesystem',
#          zero 'Corruption of in-memory data', zero withdraw; and a create +
#          read outside the quarantined domain must succeed after the verdict.
#          The acknowledged-file verify is NOT run (the domain answers EIO by
#          design); the lap leaves a quarantined slice — re-prep before any
#          other test.  Budget: the plain lap (the refusal lands where the
#          verdict would).
#        TDR_BLOCK_UMOUNT=1 (with TDR_BLOCK_INJECT=1) — the umount-while-
#          blocked arm (D-TCP-UMOUNT-HANGS-UNINTERRUPTIBLY-WHILE-PEER-
#          RECOVERY-FENCE-BLOCKED-0904): once the blocked state is asserted,
#          W unmounts under a 60 s KILL bound with its task stack sampled
#          every 2 s; the umount must return 0 within 20 s.  The lap ends
#          there (W unmounted or hung, V restarted); budget: the blocked arm
#          to its verdict + 60 s => caller bound 300 s.
#        TDR_AGMASK_INJECT=1 — the AG-scoped refusal arm
#          (D-TCP-REFUSED-VICTIM-KEEPS-MASTERSHIP-OUT-OF-MASK-RESOURCES-
#          UNAVAILABLE-0910): before the kill W gets dbg_fr_taint_items_over=1,
#          so every multi-item transaction of the victim's slice takes the
#          whole-txn refusal and the terminal verdict is AG-MASK (the union of
#          the refused items' AGs), not TORN/FSWIDE.  The victim creates its
#          own directory (every node's directories land in its own AG) and
#          the writer skips the PRE vectors, so the refused tail transactions
#          touch only the victim's AG and AG 0 (the root) stays out of the
#          mask (measured s518g: ag_mask=0x2).  After the verdict W runs the
#          mastership probe: 8 mkdir+create pairs at the root, each op under a
#          10 s alarm; every directory is mapped to its AG from the superblock
#          geometry (chk_mxfs -v) and the outcome split by in-mask (EIO by
#          design) versus out-of-mask (must succeed).  The D-0910 assertion is
#          zero failures out of the mask; the containment assertion is zero
#          stalls (0.75.25 fail-fast).  The knob is cleared after the verdict.
#          Budget: the plain lap + probe <= 20 s (a stall costs 10 s per op,
#          at most 160 s) => caller bound 300 s.
#        TDR_AGFILL=1 (with TDR_AGMASK_INJECT=1) — the block-allocator arm
#          (D-AG-QUARANTINE-NOT-EXCLUDED-FROM-ALLOCATOR-RELOCATABLE-WRITE-EIO-
#          BY-LOTTERY-0538): after the mastership probe W fallocates ONE root
#          file of agblocks*blocksize + 256 MiB.  Its inode is in AG 0 (the
#          root's AG), so the extent walk starts in AG 0, exhausts it and
#          wraps into AG 1 — the quarantined AG on this rig (ag_mask=0x2).
#          The allocator must skip AG 1 like a full one and land the tail in
#          AG >= 2; the defect is an EIO from the quarantine gate on the wrap
#          (P240-QUAR-AG-EIO comm=fallocate).  filefrag -v maps the physical
#          extents to AGs.  A 64 MiB data write into the wrapped tail + fsync
#          then exercises the unwritten-extent conversion there.  Budget:
#          fallocate of ~2.3 GiB is metadata only (measured geometry: 24 AGs
#          of 541497 x 4 KiB) => 60 s bound on each step.
#        TDR_FALSE_APPLY=1 — the released-tenure image arm
#          (D-FOREIGN-REPLAY-UNGATED-IMAGES): the victim's slice holds an
#          image of a block that the SURVIVOR wrote LATER, under its own
#          grant.  The victim's PRE writes (new_0..4 into W's block-format
#          directory) log that directory's data block in V's slice; once
#          they are acknowledged W creates w_late_0..3 in the same directory
#          and fsyncs it — the BAST makes V publish its clean-release marker
#          and release the directory, W's add is logged in W's slice and
#          the block is now W's — and V is then killed with its older image
#          still in its slice.  A replay that applied that image over W's
#          block (the false-APPLY the record names: per-slice LSNs are
#          incomparable, so the upstream on-disk-LSN veto cannot save it)
#          would drop w_late_* from the directory.  The victim's PRE adds
#          are its LAST transactions (writer mode prestop, no stream after
#          them) and the kill follows W's writes at once (KILL_AFTER=0):
#          measured s593g with the stream running on, the slice held only
#          the stream's last two transactions and nothing of the PRE image
#          or its marker (relmarks=0), so the arm measured nothing.
#          Asserted from the evaluator's own counters (P273-SHADOW-EVAL on
#          W): the victim's clean-release marker was in its slice and seen
#          (relmarks >= 1), nothing was refused as not-held / stale-epoch /
#          wrong-lineage / untagged (a refusal fails the whole transaction
#          closed and quarantines the domain), REDUNDANT_CLEAN reported
#          (whether the old image is inside the replay window depends on
#          where the log tail sat when the marker was forced); w_late_*
#          read with their md5 at verdict time, after drop_caches=2, and
#          COLD after W unmounts and remounts alone (bound 120 s + 180 s:
#          the last member's remount takes its own pages over).
#        TDR_FALSE_APPLY=2 — the re-hold sub-arm: as above, and after W's
#          adds the victim takes the directory back, creates v_rehold_0 in
#          it (a NEW image of the block, under a new grant epoch, holding
#          W's names) and fsyncs, then dies holding it.  Additionally
#          asserted: that image was admitted (WOULD_APPLY >= 1) and
#          v_rehold_0 reads at verdict time and cold.  A stale-epoch
#          refusal of the older image would show as staleep >= 1 and a
#          refused replay.  Budget (both): the plain lap without the
#          KILL_AFTER window + the arm's creates (~2 s) + the cold remount
#          (<= 300 s) => caller bound 540 s.
#        TDR_FALSE_APPLY=3 — the pinned-tail sub-arm: as =1, but the
#          victim's released image is INSIDE its replay window.  Measured
#          s593h (=1): the release drain lands the image and the on-disk
#          log tail moves past it before the marker is forced, so the
#          window held nothing but the two markers (txn=0 buf=0 relmarks=2)
#          and the REDUNDANT_CLEAN verdict was never exercised on an image.
#          Here the writer first creates $D/pin and reports its inode
#          number; the harness sets mxfs.dbg_ail_pin_ino to it on the
#          victim (xfsaild never flushes that inode, so its log item pins
#          the tail) and the writer re-dirties + fsyncs it before the PRE
#          adds.  Every later record — the directory images, the markers —
#          stays in the window at the kill.  Additionally asserted: the pin
#          engaged on the victim (P-AILPIN-HOLD before the kill), images
#          reached the evaluator (P273 buf >= 1) and the released ones were
#          REDUNDANT_CLEAN (>= 1, P227-FR-REDUNDANT-SKIP >= 1), never
#          APPLY: w_late_* intact at verdict time and cold.  Budget: as =1
#          + the pin handshake (<= 5 s) => caller bound 540 s.
set -u
LABEL=${1:?label}
W=${2:-test1}; V=${3:-test2}
# The header has always documented a default for this, and there was never one.
# Every use sits behind a conditional arm, so under `set -u` a direct
# invocation did not fail at the top — it died in the middle of the gate arm at
# the one line that reads the target's PR state, leaving that measurement empty
# and its two assertions comparing against the empty string.  They then reported
# "exactly one registration ... got= want=1" and "WE-AR in force ... got=0
# want=1": two red lines about the reservation, produced by a harness variable,
# on a run whose gate had in fact certified and restored cleanly.  Measured
# s583neg 2026-09-09.  A default costs nothing and the sibling harnesses all
# carry the same one.
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$W"; MXFS_DEV=$MXFS_DEV_RESOLVED
KILL_AFTER=${TDR_KILL_AFTER:-6}
SIZE=${TDR_SIZE:-65536}
MAXF=${TDR_MAX_FILES:-4000}
BLOCK_INJECT=${TDR_BLOCK_INJECT:-0}
BLOCK_AFTER_MS=${TDR_BLOCK_AFTER_MS:-20000}
VERIFY_INJECT=${TDR_VERIFY_INJECT:-0}
BLOCK_UMOUNT=${TDR_BLOCK_UMOUNT:-0}     # with TDR_BLOCK_INJECT=1: umount W while blocked, then stop
AGMASK_INJECT=${TDR_AGMASK_INJECT:-0}
AGFILL=${TDR_AGFILL:-0}                 # with TDR_AGMASK_INJECT=1: the D-0538 block-allocator arm
FALSE_APPLY=${TDR_FALSE_APPLY:-0}       # the released-tenure image arm (D-FOREIGN-REPLAY-UNGATED-IMAGES)
# THE INODE-BUFFER REPLAY GUARD, exercised where the image becomes durable.
# Every other injection here is armed on the SURVIVOR, at the check.  These two
# are armed on the VICTIM, in the log copy its own commit writes, so the
# refusal under measurement is provoked by an image a corrupt or foreign
# producer could really have left behind — which is the only way to reach a
# guard that fires on a value this build never writes.
#   TDR_VICTIM_AGINO=<n>    plant agino <n> in a logged di_next_unlinked
#   TDR_VICTIM_STRADDLE=1   move a logged image's daddr across an AG boundary
VICTIM_AGINO=${TDR_VICTIM_AGINO:-0}
VICTIM_STRADDLE=${TDR_VICTIM_STRADDLE:-0}
VICTIM_INJECT=0
{ [ "$VICTIM_AGINO" != 0 ] || [ "$VICTIM_STRADDLE" != 0 ]; } && VICTIM_INJECT=1
[ "$VICTIM_AGINO" != 0 ] && [ "$VICTIM_STRADDLE" != 0 ] && {
    echo "ABORT: arm one substitution at a time — two at once and neither refusal is attributable"; exit 2; }
# REFUSED=1 on any arm whose replay is meant to be refused (the verifier
# arm: TORN/FSWIDE; the AG-mask arm: AG-MASK; the victim-side substitutions:
# the inode-buffer guard).  Gates what a refused lap shares.
REFUSED=0; { [ "$VERIFY_INJECT" = 1 ] || [ "$AGMASK_INJECT" = 1 ] || \
             [ "$VICTIM_INJECT" = 1 ]; } && REFUSED=1
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_tcpdr_$LABEL
mkdir -p "$OUT"
# rs/rsx/capture_require/capture_require_bg (tests/lib/rig.sh): every capture
# a verdict is taken from is proven to hold its tool's shape first; a failed
# acquisition is an ABORT, never a count of zero.  The survivor's kernel log
# is always taken from the lap marker, so the marker line IS its shape.
. "$(dirname "$0")/lib/rig.sh"
# --line-buffered: the writer's acknowledgements stream through this filter
# into a file, and a block-buffered grep held all 84 of s500a_l1's OK lines
# past the kill, so the harness counted 0 acknowledged files.
filt() { grep -a --line-buffered -v '^Unauthorized\|^Warning:\|^If you'; }
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# ckge: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
wd() { rsx 25 "$W" "dmesg | sed -n \"/$MARK/,\\\$p\""; }
# wdcap <file>: the survivor's log from the lap marker, validated
wdcap() { wd > "$1"; capture_require "$1" "$MARK" "the kernel log on $W from the lap marker (${1##*/})"; }
# wdcap_from <file> <marker>: the same, from a later marker the lap wrote
wdcap_from() { wd | awk "/$2/{f=1} f" > "$1"; capture_require "$1" "$2" "the kernel log on $W from the marker $2 (${1##*/})"; }
# probe <node> <timeout> <file> <shape> <what> <cmd>: a one-shot remote
# measurement whose lines feed a verdict, validated
probe() { rsx "$2" "$1" "$6" > "$3"; capture_require "$3" "$4" "$5"; }
t0=$(date +%s)

echo "=== tcp_death_replay label=$LABEL W=$W V=$V kill_after=${KILL_AFTER}s size=$SIZE out=$OUT $(date -u +%FT%TZ) ==="

# -- gates: same build as the tree, both on one transport, both mounted --
# The PLAIN arm also runs on CAW (force_transport=0): the death, the fence,
# the foreign replay and the verification of every acknowledged file are the
# same on both transports; only the TCP authority ledger (the seal, the
# ledger collect and the ledger-flagged manifest) does not exist on CAW, and
# those assertions are TCP's alone below.  Every injection arm measures a TCP
# mechanism and still requires TCP.
PLAIN=1
{ [ "$BLOCK_INJECT" != 0 ] || [ "$VERIFY_INJECT" != 0 ] || [ "$AGMASK_INJECT" != 0 ] || \
  [ "$FALSE_APPLY" != 0 ] || [ "$VICTIM_INJECT" != 0 ] || [ "${TDR_REJOIN:-0}" = 1 ]; } && PLAIN=0
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
FT=""
for n in "$W" "$V"; do
    info=$(timeout 15 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' mxfs ' /proc/mounts)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    nft=$(printf '%s' "$info" | grep -ao 'ft=[0-9]*' | cut -d= -f2)
    case $nft in
        1) ;;
        0) [ "$PLAIN" = 1 ] || { echo "ABORT: $n is on CAW and this arm measures a TCP mechanism ($info)"; exit 2; } ;;
        *) echo "ABORT: $n force_transport unreadable ($info)"; exit 2 ;;
    esac
    [ -z "$FT" ] || [ "$FT" = "$nft" ] || { echo "ABORT: $W and $V are on different transports ($info)"; exit 2; }
    FT=$nft
    [[ "$info" == *"m=1"* ]] || { echo "ABORT: $n not mounted ($info)"; exit 2; }
done
TRANSPORT=$([ "$FT" = 1 ] && echo tcp || echo caw)
echo "  INFO transport=$TRANSPORT plain=$PLAIN"
MARK="TDR-$LABEL-$$"
timeout 12 $SSH "$W" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# -- survivor-side cached state the victim will then change (the stale-view
#    vectors of D-SURVIVOR-SINGLE-NODE-BYPASS-...-0904): W creates and READS
#    $PRE/shared.txt (in-core inode + page cache + a positive dentry), and
#    stats $PRE/created_by_victim (a NEGATIVE dentry).  The victim's writer
#    then rewrites shared.txt at a DIFFERENT size and creates
#    created_by_victim before its own file loop; both are fsync-acknowledged
#    ("OK PRE:<name> <md5>") and verified from W like every other file.
#    Two further vectors: $PRE holds 40 small files so it is a BLOCK-format
#    directory whose data block W has read (readdir) and whose inode
#    cluster(s) W has cached (stat of every file); the victim rewrites
#    pre_0..pre_4 at a different size and adds new_0..new_4.  After the
#    verdict-time verify a second verify runs on W behind
#    drop_caches=2 (dentries + in-core inodes dropped, xfs_buf cache kept)
#    so a stale cached inode-cluster buffer answers the re-iget.
PRE="$MNT/tdr_pre_$LABEL"
PRE_N=40
probe "$W" 60 "$OUT/pre_info.txt" 'neg_rc=[0-9]+' "the survivor's pre-cache workload on $W" "mkdir -p '$PRE' && for i in \$(seq 0 $(( PRE_N - 1 ))); do head -c 1024 /dev/urandom > '$PRE/pre_'\$i || echo PRE_WRITE_FAIL_\$i; done && head -c $SIZE /dev/urandom > '$PRE/shared.txt' && sync -f '$PRE' && md5sum '$PRE/shared.txt' | cut -c1-32 && cat '$PRE/shared.txt' > /dev/null && echo listed=\$(ls -1 '$PRE' | wc -l) && stat '$PRE'/pre_* > /dev/null && stat '$PRE/created_by_victim' > /dev/null 2>&1; echo neg_rc=\$?"
pre_info=$(tr '\n' ' ' < "$OUT/pre_info.txt")
echo "  INFO pre-cached on $W: $pre_info"
# write-side stale-cluster detector on the survivor: every inode-cluster
# write is compared against the platter (P-DINO-CLOBBER on a regression)
timeout 12 $SSH "$W" "echo 1 > $P/dino_clobber_check" >/dev/null 2>&1
ck "survivor pre-cached $PRE ($PRE_N files + shared.txt written+read+stat'd, created_by_victim negative)" "$(echo "$pre_info" | grep -ac "listed=$(( PRE_N + 1 )) neg_rc=1")" "1"

# -- the RECOVERY_BLOCKED arm: arm the injection on W before the kill --
prior_after_ms=""
if [ "$BLOCK_INJECT" = 1 ]; then
    measure "$W" 12 "$OUT/rv_prior_after_ms_1.txt" '^armed=' "prior_after_ms on $W" "cat $P/fence_blocked_after_ms; echo 1 > $P/fence_gate_inject_refuse; echo $BLOCK_AFTER_MS > $P/fence_blocked_after_ms; echo armed=\$(cat $P/fence_gate_inject_refuse)/\$(cat $P/fence_blocked_after_ms)"; prior_after_ms=$(cat "$OUT/rv_prior_after_ms_1.txt" | tr '\n' ' ')
    echo "  INFO block-inject armed on $W: $prior_after_ms"
    ck "injection armed on $W (gate refused, blocked_after=${BLOCK_AFTER_MS}ms)" "$(echo "$prior_after_ms" | grep -ac "armed=1/$BLOCK_AFTER_MS")" "1"
    prior_after_ms=$(echo "$prior_after_ms" | awk '{print $1}')
fi

# -- the write-verifier arm: the next foreign-recovery image W submits is
#    corrupted at submit; the verifier must refuse it without a shutdown --
if [ "$VERIFY_INJECT" = 1 ]; then
    value_now_into varm "$W" 12 "$OUT/rv_varm_2.txt" '^armed=' "varm on $W" "echo 1 > $P/freplay_inject_verify_fail; echo armed=\$(cat $P/freplay_inject_verify_fail)"
    echo "  INFO verify-inject armed on $W: $varm"
    ck "verifier injection armed on $W (freplay_inject_verify_fail=1)" "$(echo "$varm" | grep -ac 'armed=1')" "1"
fi

# -- the AG-mask arm: every multi-item transaction of the slice is refused on
#    W, and the victim's writes are confined to one directory W created --
D="$MNT/tdr_$LABEL"
WRITER_MODE=pre
if [ "$AGMASK_INJECT" = 1 ]; then
    # s517f: the pre-created directory landed in AG 0, so the victim's
    # creates put AG 0 into the mask (ag_mask=0x3) and every root lookup was
    # refused (8/8 probes at ino 128).  New directories rotate across AGs
    # (the inode allocator's directory rotor): create candidates until one
    # lands in AG >= 1 and confine the victim to that one.
    # --geometry, not -v: W is mounted, and the full check is refused there
    # (0.89.6, O_EXCL); the geometry is mkfs-time constants
    geo=$(timeout 60 $SSH "$W" "/src/mxfs/tools/chk_mxfs --geometry $MXFS_DEV 2>/dev/null | grep -ao 'blocksize=[0-9]*\|agcount=[0-9]*\|agblocks=[0-9]*\|agblklog=[0-9]*\|inopblog=[0-9]*' | tr '\n' ' '" 2>/dev/null | filt | tail -1)
    agshift=$(( $(echo "$geo" | grep -ao 'agblklog=[0-9]*' | cut -d= -f2 | tr -dc '0-9') + $(echo "$geo" | grep -ao 'inopblog=[0-9]*' | cut -d= -f2 | tr -dc '0-9') ))
    echo "  INFO geometry on $W: ${geo:-<none>} ino>>$agshift = agno"
    ck "superblock geometry read (agblklog + inopblog)" "$([ "$agshift" -gt 3 ] && echo 1 || echo 0)" "1"
    # s518e/s518g: every directory a node creates lands in that node's OWN
    # allocation group (16 candidates on W -> ino 173..188, all AG 0), so a
    # directory W pre-creates always drags AG 0 into the mask (0x3).  The
    # victim creates D itself (the writer's os.makedirs) in its own AG:
    # measured ag_mask=0x2 with AG 0 spared.  Its root entry lands in the
    # writer's first transaction, which the acknowledged stream has long
    # since checkpointed before the kill; only the tail is refused.
    measure "$W" 30 "$OUT/rv_aarm_3.txt" '^armed=' "aarm on $W" "echo 1 > $P/dbg_fr_taint_items_over; echo armed=\$(cat $P/dbg_fr_taint_items_over)"; aarm=$(cat "$OUT/rv_aarm_3.txt" | tr '\n' ' ')
    echo "  INFO AG-mask arm on $W: $aarm (victim creates its own directory)"
    ck "whole-txn refusal armed on $W (dbg_fr_taint_items_over=1)" "$(echo "$aarm" | grep -ac 'armed=1')" "1"
    WRITER_MODE=nopre
fi
# the released-tenure image arms: the victim's PRE adds are its last
# transactions and the kill follows the survivor's (and the re-hold's)
# writes at once -- measured s593g: with the stream running on for
# KILL_AFTER=6 s the slice held none of the PRE image (relmarks=0,
# REDUNDANT_CLEAN=0) and the arm measured nothing about released tenures
if [ "$FALSE_APPLY" != 0 ]; then
    WRITER_MODE=prestop
    [ "$FALSE_APPLY" = 3 ] && WRITER_MODE=prestoppin
    KILL_AFTER=0
fi

# -- the D-0915 early arm needs the victim to hold an EX grant on a directory
#    the SURVIVOR masters at the moment of the verdict.  Which node masters a
#    resource is a hash over per-boot node ids, so any single directory (the
#    root included: s520a on 0.75.32 saw the victim take root EX and the
#    survivor's 39 early mkdirs go through untouched, because the victim
#    mastered ino 128 itself) is a coin flip per lap.  W creates HOLD_N
#    directories in its own allocation group (out of the eventual mask); the
#    writer takes a sticky EX on each with one mkdir and checkpoints with
#    sync(2) so those items leave the log tail long before the kill; the early
#    loop then creates under the root AND every candidate, so at least one
#    survivor-mastered dead-held directory is exercised with probability
#    1 - 2^-(HOLD_N+1).
HOLDS=""; HOLD_N=0; EARLY_PID=""
if [ "$AGMASK_INJECT" = 1 ] && [ "${TDR_AGMASK_EARLY:-0}" = 1 ]; then
    HOLD_N=7
    for i in $(seq 0 $(( HOLD_N - 1 ))); do HOLDS="$HOLDS $MNT/tdr_hold_${LABEL}_$i"; done
    value_now_into hinfo "$W" 60 "$OUT/rv_hinfo_4.txt" '^[0-9]+$' "hinfo on $W" "mkdir -p $HOLDS && sync -f '$MNT' && ls -d $HOLDS | wc -l"
    echo "  INFO D-0915 hold candidates created on $W: $hinfo of $HOLD_N"
    ck "D-0915 arm: $HOLD_N hold candidates created on the survivor" "$hinfo" "$HOLD_N"
    # The loop process is armed NOW, before the writer: it opens a directory
    # fd on the root and on every candidate and creates RELATIVE to the fd.
    # A path-walked mkdir first takes the root's PR for the lookup, and when
    # the victim masters the root (s520c: all 8 threads' only lock lines were
    # 'P-LKTIMEOUT-REMOTE ino=128 req=PR master=<victim>', 83 s each) no
    # thread ever reaches its held directory.  An fd holds no grant, so the
    # victim's later EX on each candidate is undisturbed.  The threads start
    # on a trigger file the harness touches right after the destroy: a mkdir
    # before the kill would BAST the victim's EX away and dissolve the shape.
    #
    # Timeline the loop must span (s520b/s520c, 0.75.32): verdict +0.0 s,
    # P-DEPART-REFUSED (out-of-domain purge) +4.4 s, takeover +8.6 s.  The
    # s518i shape is an acquire IN FLIGHT across the verdict: parked on the
    # pending recovery, then denied the moment the verdict imports.
    EPY='import os,sys,time,threading
label,secs,go=sys.argv[1],float(sys.argv[2]),sys.argv[3]; targets=sys.argv[4:]
fds=[os.open(t, os.O_RDONLY|os.O_DIRECTORY) for t in targets]
print("EARLY-ARMED fds=%d"%len(fds), flush=True)
while not os.path.exists(go): time.sleep(0.1)
t0=time.time(); lock=threading.Lock()
def run(ti,fd):
    k=0
    while time.time()-t0 < secs:
        p="tdr_early_%s_%d"%(label,k); t=time.time()
        try:
            os.mkdir(p, dir_fd=fd); rc="0"
        except OSError as e: rc=str(e.errno)
        with lock:
            print("EARLY k=%d t=%d at=%.1f rc=%s ms=%d"%(k, ti, t-t0, rc, int((time.time()-t)*1000)), flush=True)
        k+=1; time.sleep(0.5)
ths=[threading.Thread(target=run,args=(ti,fd),daemon=True) for ti,fd in enumerate(fds)]
for th in ths: th.start()
for th in ths: th.join(max(1.0, secs+30-(time.time()-t0)))
print("EARLY-DONE alive=%d"%sum(1 for th in ths if th.is_alive()), flush=True)
'
    EPYB=$(printf '%s' "$EPY" | base64 -w0)
    EARLY_SECS=140
    ( timeout $(( KILL_AFTER + EARLY_SECS + 90 )) $SSH "$W" "rm -f /root/tdr_early.go; echo $EPYB | base64 -d > /root/tdr_early.py; python3 /root/tdr_early.py '$LABEL' $EARLY_SECS /root/tdr_early.go '$MNT' $HOLDS" 2>"$OUT/early_probe.err" | filt > "$OUT/early_probe.txt" ) &
    EARLY_PID=$!
    sleep 2
    # the loop's ssh failing outright (its stderr says so) is an ABORT; the
    # loop merely not having armed yet is the timing FAIL below
    capture_require_bg "$OUT/early_probe.txt" "$OUT/early_probe.err" 'EARLY-ARMED' "the D-0915 early loop on $W" || true
    echo "  INFO D-0915 early loop armed on $W (1 thread per target: root + $HOLD_N held dirs, dir-fd relative, ${EARLY_SECS} s from the trigger): $(grep -a 'EARLY-ARMED' "$OUT/early_probe.txt" | tr -d '\n')"
    ck "D-0915 arm: the loop process opened its directory fds before the writer" "$(grep -ac "EARLY-ARMED fds=$(( HOLD_N + 1 ))" "$OUT/early_probe.txt")" "1"
fi

# -- the writer on V, streaming acknowledgements to clyde --
PY='import os,sys,hashlib,time
d=sys.argv[1]; n=int(sys.argv[2]); size=int(sys.argv[3]); pre=sys.argv[4]
nopre=len(sys.argv)>5 and sys.argv[5]=="nopre"
# prestop (the released-tenure image arms): the PRE vectors are this node
# last transactions -- nothing streams after them, so the image of the
# directory block they logged is still inside the slice window at the kill
# (a victim slice holds only its last few transactions: the destage kick
# lands everything within ms, sess446)
prestop=len(sys.argv)>5 and sys.argv[5] in ("prestop","prestoppin")
# prestoppin: a pin file whose inode item the harness keeps in the AIL
# (mxfs.dbg_ail_pin_ino) so this node log tail cannot move past the
# PRE adds -- their images stay in the window at the kill
pin=len(sys.argv)>5 and sys.argv[5]=="prestoppin"
holds=sys.argv[6:]
def put(path, data, dfd):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
    os.write(fd, data); os.fsync(fd); os.close(fd)
    os.fsync(dfd)
pfd=os.open(pre, os.O_RDONLY)
if prestop:
    os.makedirs(d, exist_ok=True)
if pin:
    pp=os.path.join(d, "pin"); dfd0=os.open(d, os.O_RDONLY)
    put(pp, os.urandom(4096), dfd0)
    print("PIN_INO %d"%os.stat(pp).st_ino, flush=True)
    go="/root/tdr_pin.go"; w=0
    while not os.path.exists(go) and w<300:
        time.sleep(0.1); w+=1
    if not os.path.exists(go):
        print("PIN_NOGO", flush=True); sys.exit(4)
    # re-dirty + fsync: the inode item is relogged at an LSN that precedes
    # every PRE add below, and from here xfsaild never flushes it
    put(pp, os.urandom(8192), dfd0)
    print("PIN_RELOG", flush=True)
def prewrite(name):
    data=os.urandom(size+4096)
    put(os.path.join(pre,name), data, pfd)
    print("OK PRE:%s %s"%(name, hashlib.md5(data).hexdigest()), flush=True)
# the AG-mask arm (nopre) skips the PRE vectors: they would put the PRE
# directory AG (normally AG 0) into the refused-item mask
if not nopre:
    for name in ["shared.txt", "created_by_victim"] + ["pre_%d"%i for i in range(5)]:
        prewrite(name)
    # checkpoint: syncfs pushes the AIL, so pre_0..4 land on the platter and
    # leave the log tail behind them; pre_5 (same inode cluster) is then logged
    # AFTER the tail -> the foreign replay on the survivor touches that cluster
    # and must not apply it onto a stale cached copy (which would revert pre_0..4)
    # NOTE: this block lives inside a single-quoted shell string: no apostrophes
    os.sync()
    for name in ["pre_5"] + ["new_%d"%i for i in range(5)]:
        prewrite(name)
if prestop:
    print("DONE", flush=True)
    sys.exit(0)
os.makedirs(d, exist_ok=True)
dfd=os.open(d, os.O_RDONLY)
# D-0915 arm: one mkdir per hold candidate takes (and sticky-caches) its EX
# grant on this node; sync(2) pushes those items off the log tail so the
# refused tail below never names their allocation group
for h in holds:
    os.mkdir(os.path.join(h, "held_by_victim"))
if holds:
    os.sync()
    print("HELD %d"%len(holds), flush=True)
for i in range(n):
    name="f%05d"%i
    data=os.urandom(size)
    put(os.path.join(d,name), data, dfd)
    print("OK %s %s"%(name, hashlib.md5(data).hexdigest()), flush=True)
print("DONE", flush=True)
'
PYB=$(printf '%s' "$PY" | base64 -w0)
# The ssh to the victim is left to die with the VM (its timeout reaps it): a
# kill of the subshell would not reach it, and every OK line it ever delivers
# was printed by the writer only after its fsyncs returned, so the file is the
# acknowledged set whenever it is read after the destroy.
( timeout $(( KILL_AFTER + 30 )) $SSH "$V" "rm -f /root/tdr_pin.go; echo $PYB | base64 -d > /root/tdr_writer.py; python3 /root/tdr_writer.py '$D' $MAXF $SIZE '$PRE' $WRITER_MODE $HOLDS" 2>"$OUT/writer.err" | filt > "$OUT/writer.txt" ) &
# -- the pinned-tail sub-arm: pin the writer's pin file on the victim before
#    it re-dirties it and goes on to the PRE adds --
if [ "$FALSE_APPLY" = 3 ]; then
    i=0
    while [ $i -lt 20 ] && ! grep -aq '^PIN_INO ' "$OUT/writer.txt"; do sleep 1; i=$((i+1)); done
    capture_require_bg "$OUT/writer.txt" "$OUT/writer.err" '^PIN_INO ' "the writer on $V (pin file)" || true
    pino=$(grep -a '^PIN_INO ' "$OUT/writer.txt" | head -1 | awk '{print $2}')
    ck "pinned-tail arm: the victim created its pin file and reported its inode number (within 20 s)" "$([ -n "$pino" ] && echo 1 || echo 0)" "1"
    measure "$V" 15 "$OUT/rv_pset_5.txt" '^go$' "pset on $V" "echo ${pino:-0} > $P/dbg_ail_pin_ino && echo pin=\$(cat $P/dbg_ail_pin_ino) && touch /root/tdr_pin.go && echo go"; pset=$(cat "$OUT/rv_pset_5.txt" | tr '\n' ' ')
    echo "  INFO pinned-tail arm: dbg_ail_pin_ino on $V: $pset"
    ck "pinned-tail arm: dbg_ail_pin_ino=$pino set on $V and the writer released" "$(echo "$pset" | grep -ac "pin=${pino:-0} go")" "1"
    i=0
    while [ $i -lt 20 ] && ! grep -aq '^PIN_RELOG' "$OUT/writer.txt"; do sleep 1; i=$((i+1)); done
    capture_require_bg "$OUT/writer.txt" "$OUT/writer.err" '^PIN_RELOG' "the writer on $V (pin relog)" || true
    ck "pinned-tail arm: the victim re-dirtied and fsynced the pin file after the pin (PIN_RELOG within 20 s)" "$(grep -ac '^PIN_RELOG' "$OUT/writer.txt")" "1"
fi
# -- the released-tenure image arm: once the victim's adds to W's block
#    directory are acknowledged (its slice now holds that data block's
#    image), W adds its own names to the same directory.  W's create BASTs
#    the victim's EX on the directory, so the victim publishes its
#    clean-release marker and releases; the block is W's from here and the
#    victim's image of it is an older, released-tenure image at the kill. --
if [ "$FALSE_APPLY" != 0 ]; then
    i=0
    while [ $i -lt 20 ] && ! grep -aq '^OK PRE:new_4 ' "$OUT/writer.txt"; do sleep 1; i=$((i+1)); done
    capture_require_bg "$OUT/writer.txt" "$OUT/writer.err" '^OK PRE:new_4 ' "the writer on $V (PRE adds)" || true
    ck "false-apply arm: the victim's adds to $PRE were acknowledged before W wrote there (OK PRE:new_4 within 20 s)" "$(grep -ac '^OK PRE:new_4 ' "$OUT/writer.txt")" "1"
    timeout 12 $SSH "$W" "echo 'TDR-WLATE-$LABEL' > /dev/kmsg" >/dev/null 2>&1
    twl=$(date +%s)
    # a write that fails is the measurement (fewer OK lines), so it is
    # reported as output, never as the invocation's exit status
    probe "$W" 60 "$OUT/wlate.txt" '^WLATE_RC=[0-9]+' "W's late adds to $PRE" "for i in 0 1 2 3; do head -c 2048 /dev/urandom > '$PRE/w_late_'\$i || echo WLATE_FAIL_\$i; done; sync -f '$PRE'; for i in 0 1 2 3; do echo OK PRE:w_late_\$i \$(md5sum '$PRE/w_late_'\$i | cut -c1-32); done; echo WLATE_RC=\$?"
    echo "  INFO false-apply arm: W's late adds to $PRE (wall $(( $(date +%s) - twl ))s): $(grep -ac '^OK PRE:w_late_' "$OUT/wlate.txt") acknowledged, $(grep -a 'WLATE_RC' "$OUT/wlate.txt")"
    ck "false-apply arm: W created and fsynced w_late_0..3 in the victim-logged directory" "$(grep -ac '^OK PRE:w_late_' "$OUT/wlate.txt")" "4"
    # the marker publisher prints only on FAILURE (P-RELMARK-FAIL); success
    # is a counter, so the victim's dmesg says nothing about a published
    # marker — the evaluator's relmarks= on W is the evidence
    probe "$V" 25 "$OUT/V_relmark_fail.txt" '^[0-9]+$' "the P-RELMARK-FAIL count on $V" "dmesg | grep -ac 'P-RELMARK-FAIL' || true"
    wlrel=$(head -1 "$OUT/V_relmark_fail.txt" | tr -dc '0-9')
    echo "  INFO false-apply arm: P-RELMARK-FAIL lines on $V so far: ${wlrel:-?}"
    ck "false-apply arm: the victim published its clean-release markers without failure (no P-RELMARK-FAIL on $V)" "${wlrel:-1}" "0"
    if [ "$FALSE_APPLY" = 3 ]; then
        # the victim's own evidence dies with it: read the pin's hit line now
        probe "$V" 25 "$OUT/V_ailpin.txt" '^hits=[0-9]+$' "the pin's hit line on $V" "dmesg | grep -a 'P-AILPIN-HOLD' | tail -1 | cut -c1-160; echo hits=\$(dmesg | grep -ac 'P-AILPIN-HOLD')"
        pinh=$(tr '\n' ' ' < "$OUT/V_ailpin.txt")
        echo "  INFO pinned-tail arm: on $V before the kill: $pinh"
        ckge "pinned-tail arm: xfsaild met the pinned inode item at least once before the kill (P-AILPIN-HOLD on $V)" "$(echo "$pinh" | grep -ao 'hits=[0-9]*' | cut -d= -f2)" 1
    fi
    if [ "$FALSE_APPLY" = 2 ]; then
        # the re-hold sub-arm: the victim takes the directory back (W's
        # names are now in the block), logs a NEW image of it under a new
        # grant epoch, and dies holding it.  The replay must APPLY that
        # image (held at death, exact epoch) and must not treat the OLDER
        # image of the same block — a released tenure — as anything but
        # REDUNDANT: a stale-epoch refusal would refuse the whole
        # transaction (fail closed) and quarantine the domain.
        probe "$V" 60 "$OUT/rehold.txt" '^REHOLD_RC=[0-9]+' "the victim's re-hold write" "head -c 2048 /dev/urandom > '$PRE/v_rehold_0' || echo REHOLD_FAIL; sync -f '$PRE'; echo OK PRE:v_rehold_0 \$(md5sum '$PRE/v_rehold_0' | cut -c1-32); echo REHOLD_RC=\$?"
        echo "  INFO false-apply arm (re-hold): $(tr '\n' ' ' < "$OUT/rehold.txt")"
        ck "false-apply arm (re-hold): the victim re-took the directory and fsynced v_rehold_0 in it" "$(grep -ac '^OK PRE:v_rehold_0' "$OUT/rehold.txt")" "1"
    fi
fi
sleep "$KILL_AFTER"
# the writer's ssh failing outright (its stderr says so) is an ABORT; a
# writer that acknowledged nothing in KILL_AFTER s is the FAIL below
capture_require_bg "$OUT/writer.txt" "$OUT/writer.err" '^(OK |HELD |PIN_INO |DONE)' "the writer on $V" || true
acked_before=$(grep -ac '^OK ' "$OUT/writer.txt")
echo "  INFO writer acked $acked_before files after ${KILL_AFTER}s (last: $(grep -a '^OK ' "$OUT/writer.txt" | tail -1))"
# -- the victim-side substitution, as late as it can be made --
# The knob is armed and the image it must land on is produced in ONE remote
# command, and the destroy follows immediately, so the substituted image is
# still in the log tail the survivor will replay rather than something a
# checkpoint has already carried past.  The unlink-while-open is what logs a
# di_next_unlinked; the creates before it are what the inode cluster is made
# of.  The knob clears itself ONLY when the substitution lands, so ARMED=0
# read back afterwards is the proof it fired here and not the proof it was
# never set — and the kernel line names the block and the value either way.
if [ "$VICTIM_INJECT" = 1 ]; then
    IDIR=$MNT/tdr_inj_$LABEL
    if [ "$VICTIM_AGINO" != 0 ]; then
        IKNOB="dbg_recov_inject_agino"; IVAL=$VICTIM_AGINO; IPROBE=P-INJ-LOGGED-AGINO
    else
        IKNOB="dbg_recov_inject_straddle"; IVAL=1; IPROBE=P-INJ-LOGGED-BLF
    fi
    # THE FD MUST NOT CLOSE BETWEEN THE UNLINKS, AND THAT IS THE WHOLE ARM.
    # Measured on 0.89.42: both arms read fired=0 with every image declined
    # "not an inode-buffer image", because the loop this replaces opened each
    # file, unlinked it and closed the fd before moving to the next one.  A
    # closed fd frees the inode immediately, so the AGI unlinked bucket was
    # empty again at every insert, and upstream logs NO dinode for an
    # empty-bucket insert (xfs/libxfs/xfs_inode_util.c, the note at the
    # sess395 fossil reset: "with an EMPTY bucket the fossil was kept,
    # upstream's empty-bucket path logged no dinode").  There was nothing to
    # substitute into; the injector was never at fault.  Holding all sixteen
    # fds open makes every insert after the first find a non-empty bucket, so
    # each one logs a di_next_unlinked into the inode cluster buffer -- which
    # is the image both knobs exist to alter.
    VIPY='
import os, sys, time
idir, parm, knob, val, done = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
n = 16
# PIN THE LOG TAIL FIRST, OR THE SUBSTITUTED IMAGE IS NEVER REPLAYED.
# Measured s115a: the substitution landed (P-INJ-LOGGED-AGINO, daddr 4370024)
# and the survivors replay covered TWO checkpoints and nineteen buffer images,
# none of them that block -- under the writers fsync stream xfsaild keeps the
# tail within a couple of checkpoints of the head, so a few seconds between
# the unlinks and the kill is enough for the cluster buffer to be flushed and
# the record carried past.  dbg_ail_pin_ino names one inode item xfsaild must
# never flush, which holds the tail below everything logged after it.
pinp = os.path.join(idir, "vinj_pin")
pfd = os.open(pinp, os.O_CREAT | os.O_WRONLY, 0o600)
os.write(pfd, b"p" * 4096)
os.fsync(pfd)
ino = os.fstat(pfd).st_ino
with open(os.path.join(parm, "dbg_ail_pin_ino"), "w") as k:
    k.write("%d" % ino)
# relog the pinned item now the knob is live, so the held item sits at an LSN
# below every unlink below it
os.lseek(pfd, 0, 0)
os.write(pfd, b"q" * 4096)
os.fsync(pfd)
print("VINJPIN ino=%d" % ino, flush=True)
# ARM BETWEEN THE LAST TWO UNLINKS, NOT BEFORE THE FIRST.
# Measured s115b: the substitution landed on the image formatted at unlink 14
# and the survivor replayed ONE image of that cluster carrying the TRUE value.
# A buffer log item is re-formatted on every relog, and each format replaces
# the log vector the previous one built, so only the LAST format before the
# checkpoint reaches the log.  Every unlink after the substituted one
# therefore erased it.  The arming is moved to just before the final unlink,
# and the log is forced immediately after it, so the substituted format is
# the one written.  The cumulative dirty map means that last image still
# carries every inode the whole run unlinked.
fds = [os.open(os.path.join(idir, "u%d" % i), os.O_RDONLY) for i in range(1, n + 2)]
for i in range(1, n + 1):
    os.unlink(os.path.join(idir, "u%d" % i))
with open(os.path.join(parm, knob), "w") as k:
    k.write(val)
os.unlink(os.path.join(idir, "u%d" % (n + 1)))
# Force the LOG, not the AIL: fsync drives the CIL checkpoint carrying the
# substituted image onto the platter log the survivor will walk, while the
# cluster buffer itself stays dirty in core so the log tail does not move
# past it and recovery has real work to do.
f = os.open(os.path.join(idir, "vinj_force"), os.O_CREAT | os.O_WRONLY, 0o600)
os.write(f, b"x")
os.fsync(f)
os.close(f)
open(done, "w").close()
# Hold every fd until the VM is destroyed.  Releasing them would free the
# inodes, empty the bucket and take apart the very list being tested -- and
# the inode-free would emit a cancellation record, which both injectors
# decline, so the lap would go vacuous at the last moment.
time.sleep(600)
'
    VIPYB=$(printf '%s' "$VIPY" | base64 -w0)
    measure "$V" 60 "$OUT/victim_inject.txt" '^VINJ ' \
        "the durable-write substitution on $V" \
        "mkdir -p $IDIR && for i in \$(seq 1 17); do : > $IDIR/u\$i; done && sync -f $MNT; \
         rm -f /root/tdr_vinj.done /root/tdr_vinj.log; echo $VIPYB | base64 -d > /root/tdr_vinj.py; \
         echo 0 > $P/$IKNOB; echo TDR-VINJ-$LABEL > /dev/kmsg; \
         nohup python3 /root/tdr_vinj.py $IDIR $P $IKNOB $IVAL /root/tdr_vinj.done </dev/null >/root/tdr_vinj.log 2>&1 & \
         for t in \$(seq 1 80); do [ -f /root/tdr_vinj.done ] && break; sleep 0.5; done; \
         cat /root/tdr_vinj.log; dmesg | grep -a '$IPROBE\|P-AILPIN-HOLD' | tail -5; \
         echo VINJ knob=$IKNOB set=$IVAL armed_after=\$(cat $P/$IKNOB) \
              pin=\$(cat $P/dbg_ail_pin_ino) \
              held=\$([ -f /root/tdr_vinj.done ] && echo 1 || echo 0) \
              fired=\$(dmesg | grep -ac '$IPROBE ') \
              declined=\$(dmesg | grep -ac ${IPROBE}-DECLINED)"
    vinj=$(grep -a '^VINJ ' "$OUT/victim_inject.txt" | tail -1)
    echo "  INFO victim-side substitution: $vinj"
    echo "  INFO injector lines on $V: $(grep -a "$IPROBE" "$OUT/victim_inject.txt" | tail -2 | tr '\n' ' ')"
    ck "the unlink-while-open holder reached its hold, so sixteen inodes are on the bucket at the kill" \
       "$(printf '%s' "$vinj" | grep -ao 'held=[0-9]*' | cut -d= -f2)" "1"
    ck "the log tail is pinned on $V, so the substituted image is still in the replay window at the kill" \
       "$(printf '%s' "$vinj" | grep -ao 'pin=[0-9]*' | cut -d= -f2 | awk '{print ($1>=1)?1:0}')" "1"
    ck "the substitution landed in a logged image on $V ($IPROBE)" \
       "$(printf '%s' "$vinj" | grep -ao 'fired=[0-9]*' | cut -d= -f2 | \
          awk '{print ($1>=1)?1:0}')" "1"
    ck "the one-shot cleared itself, so the refusal below was provoked by this lap" \
       "$(printf '%s' "$vinj" | grep -ao 'armed_after=[0-9]*' | cut -d= -f2)" "0"
    # declined is NOT asserted: the knob is armed across a live workload, so
    # every other dirty buffer formatted in that window reaches the injector
    # and is declined by design.  armed_after=0 is what proves it fired here;
    # the count is read as diagnostics, and its reason lines are captured
    # above so a fired=0 lap names its cause instead of being unreadable.
    echo "  INFO declined while armed (other images in the window): $(printf '%s' "$vinj" | grep -ao 'declined=[0-9]*' | cut -d= -f2)"
    [ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=victim-inject evidence=$OUT"
                        echo "  the substitution did not land, so nothing downstream measures the guard"
                        exit 2; }
else
    # THE CONTROL LAP MUST DISARM WHAT AN EARLIER LAP LEFT BEHIND.  Both knobs
    # are one-shot and clear themselves ONLY when the substitution lands, so a
    # lap that aborted before its image appeared leaves the victim armed — and
    # the next plain lap, whose whole job is to show a replay COMPLETING,
    # would silently inject instead and read as a regression.  Measured: s114a
    # exited at this stage with armed_after=2147483646 still set.
    measure "$V" 20 "$OUT/victim_disarm.txt" '^VDISARM ' \
        "the injector knobs cleared on $V before the control lap" \
        "echo 0 > $P/dbg_recov_inject_agino; echo 0 > $P/dbg_recov_inject_straddle; \
         echo 0 > $P/dbg_ail_pin_ino; \
         echo VDISARM agino=\$(cat $P/dbg_recov_inject_agino) straddle=\$(cat $P/dbg_recov_inject_straddle) pin=\$(cat $P/dbg_ail_pin_ino)"
    vdis=$(grep -a '^VDISARM ' "$OUT/victim_disarm.txt" | tail -1)
    echo "  INFO victim injector state: $vdis"
    ck "the control lap starts with no durable-write substitution armed on $V" \
       "$(printf '%s' "$vdis" | grep -c 'agino=0 straddle=0 pin=0')" "1"
fi
tkill=$(date +%s)
REPLAY_BOUND=150
$VIRSH destroy "$V" > "$OUT/virsh_destroy.txt" 2>&1; echo "  INFO virsh destroy $V rc=$? at $(date -u +%T)"
# -- D-0915 early arm: release the armed loop (see the arming block above)
if [ -n "$EARLY_PID" ]; then
    tearly=$(date +%s)
    timeout 12 $SSH "$W" "echo 'TDR-EARLY-$LABEL' > /dev/kmsg; touch /root/tdr_early.go" >/dev/null 2>&1
    echo "  INFO D-0915 early loop triggered on $W at $(date -u +%T) ($(( $(date +%s) - tkill )) s after the destroy)"
fi
sleep 3
grep -a '^OK ' "$OUT/writer.txt" > "$OUT/acked.txt"
# the false-apply arm: W's own late adds are verified like the victim's
# acknowledged files — they are what a false-APPLY would take away
[ "$FALSE_APPLY" != 0 ] && grep -a '^OK PRE:w_late_' "$OUT/wlate.txt" >> "$OUT/acked.txt"
[ "$FALSE_APPLY" = 2 ] && grep -a '^OK PRE:v_rehold_' "$OUT/rehold.txt" >> "$OUT/acked.txt"
acked=$(grep -ac . "$OUT/acked.txt")
acked_dir=$(grep -avc '^OK PRE:' "$OUT/acked.txt")	# those under $D
echo "  INFO acknowledged set: $acked files, $acked_dir under $D ($OUT/acked.txt)"
ckge "writer produced acknowledged files before the kill" "$acked" 1
if [ "$acked" -lt 1 ]; then
    echo "  INFO writer stderr: $(filt < "$OUT/writer.err" | tail -3 | tr '\n' ' ')"
fi

# -- the RECOVERY_BLOCKED arm: the bounded series must END in the blocked
#    state, path ops must fail fast, and clearing the injection must let the
#    slow re-drive complete the recovery --
tref=$tkill
if [ "$BLOCK_INJECT" = 1 ]; then
    # death declared ~40 s (tcp grace) or ~62 s (heartbeat) after the kill,
    # then BLOCK_AFTER_MS of non-proving attempts, then one backoff (<= 6 s)
    # + jitter before the arm that flips the state: 62 + 20 + 10 => 100 s,
    # bound 120 s.
    BLOCK_BOUND=120
    i=0; blk=""
    while [ $i -lt $BLOCK_BOUND ]; do
        blk=$(wd | grep -a 'P238-FENCE-BLOCKED ' | tail -1)
        [ -n "$blk" ] && break
        sleep 3; i=$((i+3))
    done
    # the poll above is never a verdict: an empty blk after the bound is only
    # a finding if the final window crossed the boundary
    [ -n "$blk" ] || { wdcap "$OUT/blk_final.txt"; blk=$(grep -a 'P238-FENCE-BLOCKED ' "$OUT/blk_final.txt" | tail -1); }
    tblock=$(( $(date +%s) - tkill ))
    wdcap "$OUT/dmesg_${W}_blocked.txt"
    echo "  INFO blocked after ${tblock}s from the kill: ${blk:-<none within ${BLOCK_BOUND}s>}"
    ck "P238-FENCE-BLOCKED within ${BLOCK_BOUND}s of the kill" "$([ -n "$blk" ] && echo 1 || echo 0)" "1"
    ck "exactly one P238-FENCE-BLOCKED transition" "$(grep -ac 'P238-FENCE-BLOCKED ' "$OUT/dmesg_${W}_blocked.txt")" "1"
    ck "the blocked verdict is durable (P304-FENCE-BLOCKED-DURABLE)" "$(grep -ac 'P304-FENCE-BLOCKED-DURABLE slot' "$OUT/dmesg_${W}_blocked.txt")" "1"
    ck "the injection was what kept the series non-proving (P238-FENCE-GATE-INJECT-REFUSED)" "$([ "$(grep -ac 'P238-FENCE-GATE-INJECT-REFUSED' "$OUT/dmesg_${W}_blocked.txt")" -ge 1 ] && echo 1 || echo 0)" "1"
    nretry=$(grep -ac 'P304-FENCE-RETRY slot' "$OUT/dmesg_${W}_blocked.txt")
    # the backoff table is 6 deep (~14 s) and the series ran BLOCK_AFTER_MS
    # at the 6 s ceiling: 6 + BLOCK_AFTER_MS/6000 + 2 slack
    retry_cap=$(( 6 + BLOCK_AFTER_MS / 6000 + 2 ))
    echo "  INFO P304-FENCE-RETRY count at the transition: $nretry (cap $retry_cap)"
    ck "retry count bounded at the transition (<= $retry_cap)" "$([ "$nretry" -le "$retry_cap" ] && echo 1 || echo 0)" "1"
    ck "zero replay verdicts while blocked" "$(grep -a 'foreign replay of' "$OUT/dmesg_${W}_blocked.txt" | grep -ac 'complete\|failed')" "0"
    probe "$W" 20 "$OUT/debugfs_blocked.txt" '^DBG_END$' "the recovery_blocked debugfs read on $W" "cat /sys/kernel/debug/mxfs/*/recovery_blocked 2>/dev/null | grep -a 'reason=\|ACTION'; echo DBG_END"
    dbg=$(grep -av '^DBG_END$' "$OUT/debugfs_blocked.txt" | tr '\n' ' ')
    echo "  INFO debugfs: $(echo "$dbg" | cut -c1-200)"
    ck "debugfs recovery_blocked names reason=FENCE_BLOCKED" "$(echo "$dbg" | grep -ac 'reason=FENCE_BLOCKED')" "1"
    # fail-fast: the victim died holding EX on $D (its create loop) — a
    # lookup/stat of $D from W needs that grant.  Bounded at 40 s; a pass is
    # an EIO within seconds, a wait to the timeout is the pre-0.74.0 stall.
    tff=$(date +%s)
    # a timeout here IS the stall under test, so the status is kept as the
    # measurement: only a missing lsrc= line WITHOUT a timeout is an ABORT
    rsx 40 "$W" "stat -c %i '$D' 2>&1; echo rc=\$?; ls -1 '$MNT' > /dev/null 2>&1; echo lsrc=\$?" > "$OUT/failfast_probe.txt"; ffrc=$?
    [ "$ffrc" = 124 ] || capture_require "$OUT/failfast_probe.txt" 'lsrc=[0-9]+' "the fail-fast probe on $W"
    ffo=$(grep -av "^$RS_STATUS_TAG " "$OUT/failfast_probe.txt" | tr '\n' ' ')
    tffw=$(( $(date +%s) - tff ))
    echo "  INFO fail-fast probe wall=${tffw}s: $(echo "$ffo" | cut -c1-200)"
    ck "path op on the victim's directory returned within 20s (no acquire-budget stall)" "$([ "$tffw" -le 20 ] && echo 1 || echo 0)" "1"
    ck "path op on the victim's directory failed EIO" "$(echo "$ffo" | grep -ac 'Input/output error')" "1"
    wdcap "$OUT/dmesg_${W}_blocked.txt"
    ckge "fail-fast probes fired (P240-RBLK-REFUSE / P240-RBLK-EIO-ABORT / P-RBLK-DENY / P-RBLK-COVERS-DEAD-{MASTER,HOLDER})" "$(grep -ac 'P240-RBLK-REFUSE\|P240-RBLK-EIO-ABORT\|P-RBLK-DENY\|P-RBLK-COVERS' "$OUT/dmesg_${W}_blocked.txt")" 1
    echo "  INFO refusal predicates: $(grep -a 'P240-QUAR-NSOP-REFUSE\|P-RBLK-COVERS' "$OUT/dmesg_${W}_blocked.txt" | sed 's/.*kernel: //; s/.*\] //' | cut -c1-120 | sort | uniq -c | tr '\n' '|' | cut -c1-400)"
    ck "zero shutdowns on $W while blocked" "$(grep -ac 'Shutting down filesystem' "$OUT/dmesg_${W}_blocked.txt")" "0"
    if [ "$BLOCK_UMOUNT" = 1 ]; then
        # D-TCP-UMOUNT-HANGS-UNINTERRUPTIBLY-WHILE-PEER-RECOVERY-FENCE-BLOCKED-0904:
        # the survivor must be able to LEAVE while the dead peer's recovery is
        # blocked.  A clean leave measures ~5 s; bound 20 s.  The umount runs
        # under nohup on W so a hung one is observable: its task stack is
        # sampled every 2 s into the evidence dir until it returns or 60 s
        # pass, then the state is left for the operator (virsh destroy is the
        # only exit today) and the lap ends here.
        echo "  INFO umount-while-blocked arm on $W at $(date -u +%T)"
        tum=$(date +%s)
        probe "$W" 90 "$OUT/umount_blocked_${W}.txt" '^(STILL_MOUNTED|UNMOUNTED)$' "the umount-while-blocked on $W" "rm -f /root/tdr_umount.rc; nohup sh -c 'timeout -s KILL 60 umount $MNT; echo \$? > /root/tdr_umount.rc' >/dev/null 2>&1 & for i in \$(seq 1 30); do sleep 2; [ -f /root/tdr_umount.rc ] && { echo UMOUNT_RC=\$(cat /root/tdr_umount.rc) AT=\$((i*2)); break; }; pid=\$(pidof umount | awk '{print \$1}'); [ -n \"\$pid\" ] && { echo \"--- t+\$((i*2))s umount pid \$pid state \$(awk '{print \$3}' /proc/\$pid/stat 2>/dev/null)\"; cat /proc/\$pid/stack 2>/dev/null; }; done; [ -f /root/tdr_umount.rc ] || echo UMOUNT_RC=HUNG; mountpoint -q $MNT && echo STILL_MOUNTED || echo UNMOUNTED"
        tumw=$(( $(date +%s) - tum ))
        umo=$(cat "$OUT/umount_blocked_${W}.txt")
        urc=$(echo "$umo" | grep -ao 'UMOUNT_RC=[A-Z0-9]*' | tail -1 | cut -d= -f2)
        echo "  INFO umount while blocked: rc=${urc:-?} wall=${tumw}s $(echo "$umo" | grep -a 'UMOUNT_RC\|MOUNTED' | tr '\n' ' ')"
        echo "  INFO first stack sample: $(echo "$umo" | grep -a -A6 '^--- t+' | head -8 | tr '\n' '|' | cut -c1-400)"
        ck "umount returned (not HUNG past 60 s) while the peer's recovery is blocked" "$([ "${urc:-HUNG}" != HUNG ] && echo 1 || echo 0)" "1"
        ck "umount succeeded (rc=0) while blocked" "${urc:-HUNG}" "0"
        ck "umount returned within 20 s while blocked" "$([ "${urc:-HUNG}" != HUNG ] && [ "$(echo "$umo" | grep -ao 'AT=[0-9]*' | tail -1 | cut -d= -f2)" -le 20 ] && echo 1 || echo 0)" "1"
        wdcap "$OUT/dmesg_${W}_umount.txt"
        ck "zero shutdowns on $W across the umount" "$(grep -ac 'Shutting down filesystem' "$OUT/dmesg_${W}_umount.txt")" "0"
        ck "$MNT unmounted on $W" "$(echo "$umo" | grep -ac '^UNMOUNTED')" "1"
        timeout 12 $SSH "$W" "echo 0 > $P/fence_gate_inject_refuse; echo ${prior_after_ms:-120000} > $P/fence_blocked_after_ms" >/dev/null 2>&1
        $VIRSH start "$V" > "$OUT/virsh_start.txt" 2>&1; echo "  INFO virsh start $V rc=$?"
        wall=$(( $(date +%s) - t0 ))
        if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL arm=umount_blocked wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL arm=umount_blocked fails=$fails wall=${wall}s evidence=$OUT"; fi
        echo "  INFO the rig is left with $W unmounted-or-hung and $V rebooting: the next prep_cluster re-forms the cluster (destroy $W by hand if STILL_MOUNTED)"
        exit $fails
    fi
    # lift the injection: the next slow re-drive (<= 30 s + jitter) takes
    # the gate and the normal chain runs from here
    timeout 12 $SSH "$W" "echo 0 > $P/fence_gate_inject_refuse" >/dev/null 2>&1
    tref=$(date +%s)
    echo "  INFO injection cleared on $W at $(date -u +%T); replay bound now runs from here"
fi

# -- wait for the survivor's replay verdict (bounded from the kill, or from
#    the injection clear on the blocked arm) --
REPLAY_BOUND=150
verdict=""; i=0
while [ $i -lt $REPLAY_BOUND ]; do
    r=$(wd | grep -a 'foreign replay of' | grep -a 'complete\|failed' | tail -1)
    if [ -n "$r" ]; then verdict="$r"; break; fi
    sleep 3; i=$((i+3))
done
treplay=$(( $(date +%s) - tref ))
if [ "$BLOCK_INJECT" = 1 ]; then
    wdcap "$OUT/dmesg_$W.txt"
    ck "P238-FENCE-UNBLOCKED once the re-drive certified" "$(grep -ac 'P238-FENCE-UNBLOCKED' "$OUT/dmesg_$W.txt")" "1"
    # the fail-fast must have cleared with the state: the same op succeeds
    probe "$W" 40 "$OUT/failfast_after.txt" '^rc=[0-9]+$' "the path-op probe on $W after the recovery" "stat -c %i '$D' > /dev/null 2>&1; echo rc=\$?"
    ffo2=$(tr -d '\n' < "$OUT/failfast_after.txt")
    ck "path op on the victim's directory succeeds after the recovery ($ffo2)" "$(echo "$ffo2" | grep -ac 'rc=0')" "1"
    timeout 12 $SSH "$W" "echo ${prior_after_ms:-120000} > $P/fence_blocked_after_ms" >/dev/null 2>&1
fi
if [ "$AGMASK_INJECT" = 1 ] && [ "${TDR_AGMASK_EARLY:-0}" = 1 ]; then
    # D-0915: the window between the refused verdict's import and the
    # departure worker's remaster (measured 9.3 s on s519a) still has the
    # victim's frozen EX on the root and the entry gates blind to a REFUSED
    # holder.  Start a root-mkdir loop NOW and keep it running through the
    # window: every attempt must return 0 or EIO, and nothing may commit the
    # root without EX (P58-DIRPIN-NONEX / P234-LOG-NOEX = the defect).
    ck "D-0915 arm: the victim took its EX grants on the hold candidates before the kill (HELD line acknowledged)" "$(grep -ac "^HELD $HOLD_N" "$OUT/writer.txt")" "1"
    wait $EARLY_PID
    tearlyw=$(( $(date +%s) - tearly ))
    wdcap_from "$OUT/dmesg_${W}_early.txt" "TDR-EARLY-$LABEL"
    eok=$(grep -ac 'rc=0' "$OUT/early_probe.txt"); eeio=$(grep -ac 'rc=5' "$OUT/early_probe.txt"); eall=$(grep -ac '^EARLY k' "$OUT/early_probe.txt")
    edeny=$(( $(grep -ac 'P-RBLK-DENY-LOCAL' "$OUT/dmesg_${W}_early.txt") + $(grep -ac 'P-RBLK-COVERS-DEAD-HOLDER' "$OUT/dmesg_${W}_early.txt") ))
    echo "  INFO early mkdir loop over root + $HOLD_N held dirs (${tearlyw}s from the kill, through the verdict, the purge and the takeover): attempts=$eall ok=$eok eio=$eeio other=$(( eall - eok - eeio )) $(grep -a 'EARLY-DONE' "$OUT/early_probe.txt" | tr -d '\n')"
    echo "  INFO per-target (rc:count, longest ms): $(python3 -c 'import sys,re,collections; c=collections.Counter(); mx={}
for l in open(sys.argv[1]):
    m=re.match(r"EARLY k=\d+ t=(\d+) at=\S+ rc=(\S+) ms=(\d+)",l)
    if m: c[(int(m.group(1)),m.group(2))]+=1; mx[int(m.group(1))]=max(mx.get(int(m.group(1)),0),int(m.group(3)))
print(" ".join("t%d:rc%s=%d"%(t,r,n) for (t,r),n in sorted(c.items())), "| max_ms", " ".join("t%d=%d"%(t,m) for t,m in sorted(mx.items())))' "$OUT/early_probe.txt")"
    echo "  INFO early window lines: P58-DIRPIN-NONEX=$(grep -ac 'P58-DIRPIN-NONEX' "$OUT/dmesg_${W}_early.txt") P234-LOG-NOEX=$(grep -ac 'P234-LOG-NOEX' "$OUT/dmesg_${W}_early.txt") RBLK-EIO-ABORT=$(grep -ac 'P240-RBLK-EIO-ABORT' "$OUT/dmesg_${W}_early.txt") NSOP-REFUSE=$(grep -ac 'P240-QUAR-NSOP-REFUSE' "$OUT/dmesg_${W}_early.txt") RBLK-NSOP-REFUSE=$(grep -ac 'P240-RBLK-NSOP-REFUSE' "$OUT/dmesg_${W}_early.txt") DENY-LOCAL=$(grep -ac 'P-RBLK-DENY-LOCAL' "$OUT/dmesg_${W}_early.txt") COVERS-DEAD-HOLDER=$(grep -ac 'P-RBLK-COVERS-DEAD-HOLDER' "$OUT/dmesg_${W}_early.txt") DEPART-REFUSED=$(grep -ac 'P-DEPART-REFUSED' "$OUT/dmesg_${W}_early.txt")"
    ckge "D-0915 arm: the early loop ran attempts through the window" "$eall" 8
    ckge "D-0915 arm: the dead-holder shape was exercised (a survivor-mastered directory held EX by the refused victim was denied at least once)" "$edeny" 1
    ck "D-0915: every early mkdir returned 0 or EIO (no stall, no other errno)" "$(( eall - eok - eeio ))" "0"
    # 0.75.32 measured (s520d): the four survivor-mastered held directories
    # were denied at the verdict (P-RBLK-DENY-LOCAL x8, P240-RBLK-EIO-ABORT
    # x4 on the in-flight lookups) and EVERY mkdir on them then returned 0
    # (eio=0) while the victim's frozen EX was still granted in the table —
    # the refused victim had left the view, the survivor was single-node,
    # the acquire was bypassed and both sensors (P58/P234) are guarded by
    # the single-node predicate.  The fixed build's entry gate sees the
    # refused holder and answers EIO until the purge retires the grant.
    ckge "D-0915: at least one mkdir on a dead-held directory was refused EIO in the window (the gate saw the refused holder)" "$eeio" 1
    ckge "D-0915: the gate named the refusal (P240-QUAR-NSOP-REFUSE rblk=1)" "$(grep -a 'P240-QUAR-NSOP-REFUSE' "$OUT/dmesg_${W}_early.txt" | grep -ac 'rblk=1')" 1
    ck "D-0915: zero 'dir committed WITHOUT EX authority' (P58-DIRPIN-NONEX) in the window" "$(grep -ac 'P58-DIRPIN-NONEX' "$OUT/dmesg_${W}_early.txt")" "0"
    ck "D-0915: zero P234-LOG-NOEX (inode logged without EX) in the window" "$(grep -ac 'P234-LOG-NOEX' "$OUT/dmesg_${W}_early.txt")" "0"
    timeout 60 $SSH "$W" "rmdir '$MNT'/tdr_early_${LABEL}_* 2>/dev/null; true" >/dev/null 2>&1
fi
wdcap "$OUT/dmesg_$W.txt"
echo "  INFO replay verdict after ${treplay}s from the $([ "$BLOCK_INJECT" = 1 ] && echo 'injection clear' || echo kill): ${verdict:-<none within ${REPLAY_BOUND}s>}"
ck "survivor reached a replay verdict within ${REPLAY_BOUND}s" "$([ -n "$verdict" ] && echo 1 || echo 0)" "1"
if [ "$REFUSED" = 1 ]; then
    ck "replay verdict is 'failed' (the injected refusal)" "$(echo "$verdict" | grep -ac 'failed')" "1"
    if [ "$VICTIM_INJECT" = 1 ]; then
        # The guard must name the SUBSTITUTED property, not merely refuse.
        # A refusal under some other name would mean the lap measured a
        # different check that happened to fire first.
        if [ "$VICTIM_AGINO" != 0 ]; then
            GUARDTXT='is not NULLAGINO and not a valid agino of AG'
        else
            GUARDTXT='straddles an AG boundary; refusing to replay it'
        fi
        ckge "the inode-buffer guard refused the substituted image by name ('$GUARDTXT')" \
             "$(grep -ac "$GUARDTXT" "$OUT/dmesg_$W.txt")" 1
        ckge "the refusal came from the inode-buffer replay path (Bad inode buffer log record)" \
             "$(grep -ac 'Bad inode buffer log record' "$OUT/dmesg_$W.txt")" 1
        ckge "the foreign replay failed rather than adopting the image (error -117)" \
             "$(grep -a 'foreign replay of' "$OUT/dmesg_$W.txt" | grep -ac 'error -117')" 1
        ck "zero 'foreign replay ... complete' for the substituted slice" \
           "$(grep -a 'foreign replay of slot' "$OUT/dmesg_$W.txt" | grep -ac 'complete')" "0"
        ck "the survivor did not shut its filesystem down over the refusal" \
           "$(grep -ac 'Shutting down filesystem' "$OUT/dmesg_$W.txt")" "0"
    elif [ "$VERIFY_INJECT" = 1 ]; then
        ck "the injection fired (P227-FR-INJECT-VERIFY-FAIL)" "$([ "$(grep -ac 'P227-FR-INJECT-VERIFY-FAIL' "$OUT/dmesg_$W.txt")" -ge 1 ] && echo 1 || echo 0)" "1"
        ckge "the verifier arm routed by provenance (P227-FR-VERIFY-FAIL, no shutdown)" "$(grep -ac 'P227-FR-VERIFY-FAIL' "$OUT/dmesg_$W.txt")" 1
        ckge "the completion arm failed the replay, not the mount (P227-FR-BUFFAIL)" "$(grep -ac 'P227-FR-BUFFAIL' "$OUT/dmesg_$W.txt")" 1
    else
        timeout 12 $SSH "$W" "echo 0 > $P/dbg_fr_taint_items_over" >/dev/null 2>&1
        ckge "the whole-txn refusal fired (P-DBG-FR-TAINT-INJECT)" "$(grep -ac 'P-DBG-FR-TAINT-INJECT' "$OUT/dmesg_$W.txt")" 1
        ckge "refused transactions took ATOMIC-SKIP (P227-FR-ATOMIC-SKIP)" "$(grep -ac 'P227-FR-ATOMIC-SKIP' "$OUT/dmesg_$W.txt")" 1
        echo "  INFO refused-item domain: $(grep -a 'slice replay refused' "$OUT/dmesg_$W.txt" | tail -1 | grep -oE 'refused=[0-9]+|malformed=[0-9]+|FSWIDE|AG-MASK|ag_mask=0x[0-9a-f]+' | tr '\n' ' ')"
    fi
    # These two read the AUTHORITY refusal's own publication.  The victim-side
    # substitution is refused earlier and by a different mechanism — the
    # recovery walk returns EFSCORRUPTED before any slice verdict is composed —
    # so asserting them there would fail a refusal that is working.  What that
    # arm owes instead is recorded, not assumed: whether an image refused this
    # way reaches a published terminal outcome at all.
    if [ "$VICTIM_INJECT" != 1 ]; then
        ck "exactly one refusing replayer (slice replay refused)" "$(grep -ac 'slice replay refused' "$OUT/dmesg_$W.txt")" "1"
        ckge "terminal outcome PUBLISHED" "$(grep -ac 'terminal outcome PUBLISHED' "$OUT/dmesg_$W.txt")" 1
    else
        echo "  INFO victim-inject arm: slice-replay-refused=$(grep -ac 'slice replay refused' "$OUT/dmesg_$W.txt") terminal-published=$(grep -ac 'terminal outcome PUBLISHED' "$OUT/dmesg_$W.txt") (recorded, not asserted — the refusal is an EFSCORRUPTED from the recovery walk, not an authority verdict)"
    fi
    echo "  INFO refusal: $(grep -a 'slice replay refused' "$OUT/dmesg_$W.txt" | tail -1 | sed 's/.*MXFS //' | cut -c1-220)"
else
    ck "replay verdict is 'complete'" "$(echo "$verdict" | grep -ac 'complete')" "1"
    # 0.74.1: an LSN-override image is a partial image of a state older than the
    # platter's; the replay must keep its recovered-buffer queue until the end of
    # the pass (drain_deferred >= 1) whenever it applied one, or the intermediate
    # reaches the write verifier (s507a: dir3 block refused, slice quarantined).
    ovr=$(echo "$verdict" | grep -ao 'buflsn_overrides=[0-9]*' | cut -d= -f2)
    ddef=$(echo "$verdict" | grep -ao 'drain_deferred=[0-9]*' | cut -d= -f2)
    echo "  INFO LSN overrides=${ovr:-?} drains deferred=${ddef:-?}"
    ck "recovered-buffer drains deferred to the end of the pass whenever an override applied" "$({ [ "${ovr:-0}" -gt 0 ] && [ "${ddef:-0}" -lt 1 ]; } && echo 0 || echo 1)" "1"
    ck "zero 'foreign replay ... failed'" "$(grep -a 'foreign replay of' "$OUT/dmesg_$W.txt" | grep -ac 'failed')" "0"
    ck "zero P227-FR-INJECT-VERIFY-FAIL (no injection on a plain lap)" "$(grep -ac 'P227-FR-INJECT-VERIFY-FAIL' "$OUT/dmesg_$W.txt")" "0"
fi

# -- the fence must certify before any of the authority chain can run --
fk=$(grep -a 'P236-FENCEKIND' "$OUT/dmesg_$W.txt" | tail -1)
echo "  INFO fence: retries=$(grep -ac 'P304-FENCE-RETRY' "$OUT/dmesg_$W.txt") absent=$(grep -ac 'P-PR-FENCE-ABSENT' "$OUT/dmesg_$W.txt") last: ${fk#*mxfs: }"
ckge "fence certified exclusion (a P236-FENCEKIND with proves_excl=1)" "$(grep -a 'P236-FENCEKIND' "$OUT/dmesg_$W.txt" | grep -ac 'proves_excl=1')" 1

# -- the authority chain, probe by probe --
snap=$(grep -a 'P-RMAN-SNAPSHOT slot=' "$OUT/dmesg_$W.txt" | tail -1)
if [ "$TRANSPORT" = tcp ]; then
    seal=$(grep -ac 'P-TAUTH-SEAL node=' "$OUT/dmesg_$W.txt")
    ckge "P-TAUTH-SEAL (victim sealed before the collect)" "$seal" 1
    coll=$(grep -a 'P-RMAN-COLLECT-TAUTH' "$OUT/dmesg_$W.txt" | tail -1)
    echo "  INFO $coll"
    ckge "P-RMAN-COLLECT-TAUTH present" "$(grep -ac 'P-RMAN-COLLECT-TAUTH' "$OUT/dmesg_$W.txt")" 1
    cent=$(echo "$coll" | grep -oE 'entries=[0-9]+' | head -1 | cut -d= -f2)
    ckge "ledger manifest has entries (the victim held EX at death)" "${cent:-0}" 1
    echo "  INFO $snap"
    ck "P-RMAN-SNAPSHOT sealed with the ledger flag (flags=0x4)" "$(echo "$snap" | grep -ac 'flags=0x4')" "1"
else
    # CAW: the fence-time manifest is taken from the on-disk lock table, so
    # there is no ledger seal or collect; the snapshot itself must exist
    echo "  INFO $snap"
    ckge "P-RMAN-SNAPSHOT taken for the victim's slot" "$(grep -ac 'P-RMAN-SNAPSHOT slot=' "$OUT/dmesg_$W.txt")" 1
fi
# 'P-RMAN-LOAD victim_slot=' and never the bare prefix: the disklock's own
# 'P-RMAN-LOADED' line shares it, and on CAW one lands AFTER the replay's load
# line, so a bare match's last line was the disklock's and read as a miss
load=$(grep -a 'P-RMAN-LOAD victim_slot=' "$OUT/dmesg_$W.txt" | tail -1)
echo "  INFO $load"
ck "P-RMAN-LOAD rc=0 no_caw=0" "$(echo "$load" | grep -ac 'rc=0 .*no_caw=0')" "1"
ev=$(grep -a 'P-RMAN-EVAL' "$OUT/dmesg_$W.txt" | tail -1)
echo "  INFO $ev"
if [ "$REFUSED" = 1 ]; then
    echo "  INFO P-RMAN-EVAL on the refused lap: $(echo "$ev" | grep -oE 'hits=[0-9]+|abort=[0-9]+' | tr '\n' ' ')"
    bads='P-RMAN-POSTSEAL-MUTATION P-RMAN-LIVECHECK-ERR P-RMAN-SNAPSHOT-FAIL P-TAUTH-COLLECT-INCOMPLETE P-TAUTH-SEAL-BUSY P-DINO-CLOBBER P-WITHDRAW P58-DIRPIN-NONEX P234-LOG-NOEX'
else
    # the released-tenure arms: the victim's window may hold nothing but
    # its clean-release markers (s593h: txn=0 buf=0 relmarks=2 — the drain
    # landed the image and the tail moved before the marker was forced);
    # then no image consults the manifest and the arm's own guard
    # (relmarks >= 1) is the vacuity check instead of this one
    p273buf=$(grep -a 'P273-SHADOW-EVAL' "$OUT/dmesg_$W.txt" | tail -1 | grep -oE ' buf=[0-9]+' | head -1 | cut -d= -f2)
    if [ "$FALSE_APPLY" != 0 ] && [ "${p273buf:-1}" = 0 ]; then
        echo "  INFO P-RMAN-EVAL manifest hits not required: the victim's window held no buffer image (P273 buf=0)"
    elif [ "$FALSE_APPLY" = 3 ]; then
        # a released resource is absent from the fence-time manifest by
        # definition, so a window of released images alone has no hits;
        # the arm's own REDUNDANT_CLEAN >= 1 is its vacuity check
        echo "  INFO P-RMAN-EVAL manifest hits not required on the pinned-tail arm: $(echo "$ev" | grep -oE 'lookups=[0-9]+|hits=[0-9]+' | tr '\n' ' ')"
    else
        ckge "P-RMAN-EVAL manifest hits" "$(echo "$ev" | grep -oE 'hits=[0-9]+' | cut -d= -f2)" 1
    fi
    ck "P-RMAN-EVAL abort=0" "$(echo "$ev" | grep -ac 'abort=0')" "1"
    bads='P227-FR-TORN-UNPUBLISHED P240-QUAR-IMPORT P-RMAN-POSTSEAL-MUTATION P-RMAN-LIVECHECK-ERR P-RMAN-SNAPSHOT-FAIL P-TAUTH-COLLECT-INCOMPLETE P-TAUTH-SEAL-BUSY P-DINO-CLOBBER P58-DIRPIN-NONEX P234-LOG-NOEX'
fi
se=$(grep -a 'P273-SHADOW-EVAL' "$OUT/dmesg_$W.txt" | tail -1)
echo "  INFO $(echo "$se" | grep -oE 'buf=[0-9]+|WOULD_APPLY=[0-9]+|ENFORCEABLE_WOULD_APPLY=[0-9]+|REDUNDANT_CLEAN=[0-9]+|notheld=[0-9]+|manerr=[0-9]+|wlineage=[0-9]+|staleep=[0-9]+|all_apply=[0-9]+|none=[0-9]+|mixed=[0-9]+' | tr '\n' ' ')"
for bad in $bads 'Shutting down filesystem' 'Corruption of in-memory'; do
    ck "zero '$bad' on $W" "$(grep -ac "$bad" "$OUT/dmesg_$W.txt")" "0"
done
echo "  INFO P-TAUTH-SEALED-RELEASE-REFUSED=$(grep -ac 'P-TAUTH-SEALED-RELEASE-REFUSED' "$OUT/dmesg_$W.txt") P163-RECOVERY-COMPLETE=$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/dmesg_$W.txt") ATOMIC-SKIP=$(grep -ac 'P227-FR-ATOMIC-SKIP' "$OUT/dmesg_$W.txt")"

# -- data integrity: every acknowledged file, from the survivor --
if [ "$REFUSED" = 1 ]; then
    # the refused slice's domain is quarantined by design; what must hold is
    # that the SURVIVOR is still a working filesystem: mounted, and able to
    # create and read back a file outside the victim's domain, bounded so a
    # hang is a FAIL and not a wait.
    OD="$MNT/tdr_out_$LABEL"
    tv=$(date +%s)
    # a hang here is the stall under test: the status is the measurement
    rsx 60 "$W" "grep -c ' mxfs ' /proc/mounts; mkdir -p '$OD' && head -c 4096 /dev/urandom > '$OD/probe' && sync -f '$OD' && md5sum '$OD/probe' | cut -c1-32 && cat '$OD/probe' | md5sum | cut -c1-32; echo rc=\$?" > "$OUT/survivor_probe.txt"; oprc=$?
    [ "$oprc" = 124 ] || capture_require "$OUT/survivor_probe.txt" '^rc=[0-9]+$' "the survivor probe outside the quarantined domain on $W"
    outp=$(grep -av "^$RS_STATUS_TAG " "$OUT/survivor_probe.txt" | tr '\n' ' ')
    tvw=$(( $(date +%s) - tv ))
    echo "  INFO survivor probe outside the quarantined domain wall=${tvw}s: $outp"
    ck "survivor still mounted after the refusal" "$(echo "$outp" | awk '{print $1}')" "1"
    # The domain the survivor imported decides what the probe may do.  A
    # TORN verdict refuses no individual item, so its mask is empty and the
    # verdict goes FSWIDE by design (xfs_log.c: fswide = refused_fswide ||
    # ag_mask == 0); and a mask that covers AG 0 covers the root directory
    # every create under $MNT must lock.  In either shape the probe's mkdir
    # MUST fail EIO fast (the zombie answers EIO, never stale content and
    # never a hang); only an AG mask that spares AG 0 can let it succeed.
    wdcap "$OUT/dmesg_${W}_quar.txt"
    qimp=$(grep -a 'P240-QUAR-IMPORT' "$OUT/dmesg_${W}_quar.txt" | tail -1)
    qfsw=$(echo "$qimp" | grep -oE 'fswide=[01]' | cut -d= -f2)
    qmask=$(echo "$qimp" | grep -oE 'ag_mask=0x[0-9a-f]+' | cut -d= -f2)
    echo "  INFO quarantine domain imported on $W: fswide=${qfsw:-?} ag_mask=${qmask:-?}"
    if [ "${qfsw:-1}" = 1 ] || [ $(( ${qmask:-1} & 1 )) -eq 1 ]; then
        ck "survivor create under the quarantined root failed EIO, not served (domain fswide=$qfsw ag_mask=$qmask)" "$(echo "$outp" | grep -ac 'rc=[1-9]')" "1"
        wdcap "$OUT/dmesg_${W}_quar.txt"
        ckge "the refusal was the quarantine gate's (P240-QUAR-NSOP-REFUSE ... quar_map=1)" "$(grep -ac 'P240-QUAR-NSOP-REFUSE .*quar_map=1' "$OUT/dmesg_${W}_quar.txt")" 1
    else
        ck "survivor create+fsync+read outside the quarantined domain succeeded (rc=0, md5 round-trip)" "$([ "$(echo "$outp" | awk '{print $2}')" = "$(echo "$outp" | awk '{print $3}')" ] && echo "$outp" | grep -aq 'rc=0' && echo 1 || echo 0)" "1"
    fi
    ck "that probe returned within 40 s (no acquire-budget stall)" "$([ "$tvw" -le 40 ] && echo 1 || echo 0)" "1"
    if [ "$AGMASK_INJECT" = 1 ]; then
        # D-0910: the refused victim keeps its mastership (1/N of every lock
        # resource by hash) for the life of the mount.  With an AG-scoped
        # verdict everything OUTSIDE the mask must stay in service; a resource
        # the dead node masters cannot be granted to anyone, so the probe
        # below measures how much of the out-of-mask namespace is lost.
        ck "AG-mask arm: the verdict is AG-scoped and spares AG 0 (fswide=$qfsw ag_mask=$qmask)" "$([ "${qfsw:-1}" = 0 ] && [ $(( ${qmask:-1} & 1 )) -eq 0 ] && echo 1 || echo 0)" "1"
        # geometry (agshift) was read when the arm was set up, before the kill
        AMPY='import os,sys,time,signal
mnt=sys.argv[1]; label=sys.argv[2]; n=int(sys.argv[3])
class TO(Exception): pass
def alarm(*a): raise TO()
signal.signal(signal.SIGALRM, alarm)
def op(f):
    t=time.time(); signal.alarm(10)
    try:
        r=f(); rc="0"
    except TO:
        r=None; rc="TIMEOUT"
    except OSError as e:
        r=None; rc=str(e.errno)
    finally:
        signal.alarm(0)
    return r, rc, int((time.time()-t)*1000)
for k in range(n):
    p="%s/tdr_am_%s_%d"%(mnt,label,k)
    r,mrc,mms=op(lambda: (os.mkdir(p), os.stat(p).st_ino)[1])
    if mrc=="0":
        def mk():
            fd=os.open(p+"/f", os.O_WRONLY|os.O_CREAT, 0o644); os.write(fd, b"x"*4096); os.fsync(fd); os.close(fd)
            dfd=os.open(p, os.O_RDONLY); os.fsync(dfd); os.close(dfd); return 1
        _,frc,fms=op(mk)
    else:
        frc="-"; fms=0
    print("AM k=%d ino=%s mkdir_rc=%s mkdir_ms=%d file_rc=%s file_ms=%d"%(k, r if r else 0, mrc, mms, frc, fms), flush=True)
'
        AMPYB=$(printf '%s' "$AMPY" | base64 -w0)
        timeout 12 $SSH "$W" "echo 'TDR-AM-$LABEL' > /dev/kmsg" >/dev/null 2>&1
        tam=$(date +%s)
        timeout 200 $SSH "$W" "echo $AMPYB | base64 -d > /root/tdr_agmask.py; python3 /root/tdr_agmask.py '$MNT' '$LABEL' 8" 2>"$OUT/agmask_probe.err" | filt > "$OUT/agmask_probe.txt"
        tamw=$(( $(date +%s) - tam ))
        wdcap_from "$OUT/dmesg_${W}_agmask.txt" "TDR-AM-$LABEL"
        # classify every directory by its AG against the imported mask
        python3 - "$OUT/agmask_probe.txt" "$agshift" "${qmask:-0x0}" "$OUT/dmesg_${W}_agmask.txt" > "$OUT/agmask_summary.txt" <<'PYEOF'
import sys,re
probe,shift,mask,dmesg=sys.argv[1],int(sys.argv[2]),int(sys.argv[3],16),sys.argv[4]
inm=outm={"n":0,"ok":0,"eio":0,"timeout":0,"other":0}
inm=dict(inm); outm=dict(outm); rows=[]
# 0.75.30 lap s519a: a mkdir that fails before the directory exists has no
# inode to classify by, but the quarantine gate names the AG it refused
# (P240-QUAR-AG-EIO agno=N comm=python3) -- the inode allocator's rotor chose
# an in-mask AG for the new directory.  Attribute such failures, in order, to
# the AG the gate printed; anything left over is a root-level (AG 0) refusal.
gate=[]
try:
    for l in open(dmesg, errors="replace"):
        g=re.search(r'P240-QUAR-AG-EIO agno=(\d+) comm=python3', l)
        if g: gate.append(int(g.group(1)))
except OSError:
    pass
for line in open(probe):
    m=re.match(r'AM k=(\d+) ino=(\d+) mkdir_rc=(\S+) mkdir_ms=(\d+) file_rc=(\S+) file_ms=(\d+)',line)
    if not m: continue
    k,ino,mrc,mms,frc,fms=m.groups(); ino=int(ino)
    if mrc!="0":
        # mkdir itself failed: the root (AG 0) or the allocation AG refused
        rc=mrc
        if mrc=="5" and gate:
            agno=gate.pop(0); bucket=inm if (mask>>agno)&1 else outm
        else:
            agno="?"; bucket=outm
    else:
        agno=ino>>shift; bucket=inm if (mask>>agno)&1 else outm; rc=frc
    bucket["n"]+=1
    if rc=="0": bucket["ok"]+=1
    elif rc=="5": bucket["eio"]+=1
    elif rc=="TIMEOUT": bucket["timeout"]+=1
    else: bucket["other"]+=1
    rows.append("k=%s ino=%d agno=%s in_mask=%d mkdir_rc=%s/%sms file_rc=%s/%sms"%(k,ino,agno,1 if bucket is inm else 0,mrc,mms,frc,fms))
print("IN_MASK n=%(n)d ok=%(ok)d eio=%(eio)d timeout=%(timeout)d other=%(other)d"%inm)
print("OUT_MASK n=%(n)d ok=%(ok)d eio=%(eio)d timeout=%(timeout)d other=%(other)d"%outm)
for r in rows: print(r)
PYEOF
        echo "  INFO AG-mask probe wall=${tamw}s: $(head -2 "$OUT/agmask_summary.txt" | tr '\n' ' ')"
        sed -n '3,$p' "$OUT/agmask_summary.txt" | sed 's/^/  INFO   /'
        echo "  INFO dead-master denies during the probe: $(grep -ac 'P-RBLK-DENY-DEAD-MASTER' "$OUT/dmesg_${W}_agmask.txt") ($(grep -ao 'P-RBLK-DENY-DEAD-MASTER type=[0-9]* ino=[0-9]* ag=[0-9]*' "$OUT/dmesg_${W}_agmask.txt" | sort | uniq -c | tr '\n' '|' | cut -c1-300)) quar_refusals=$(grep -ac 'P240-QUAR-NSOP-REFUSE\|P240-QUAR-REFUSE\|P240-QUAR-AG-EIO' "$OUT/dmesg_${W}_agmask.txt")"
        outn=$(grep -a '^OUT_MASK' "$OUT/agmask_summary.txt" | grep -ao 'n=[0-9]*' | cut -d= -f2)
        outok=$(grep -a '^OUT_MASK' "$OUT/agmask_summary.txt" | grep -ao 'ok=[0-9]*' | cut -d= -f2)
        ckge "AG-mask probe reached directories outside the mask" "${outn:-0}" 1
        ck "D-0910: every operation outside the quarantined AGs succeeded (out-of-mask ok=${outok:-?} of ${outn:-?})" "${outok:-0}" "${outn:-1}"
        ck "D-0910 containment: zero probe operations stalled past 10 s (fail-fast, not the acquire budget)" "$(grep -a '^IN_MASK\|^OUT_MASK' "$OUT/agmask_summary.txt" | grep -ao 'timeout=[0-9]*' | cut -d= -f2 | awk '{s+=$1} END{print s+0}')" "0"
        ck "AG-mask probe returned within 30 s" "$([ "$tamw" -le 30 ] && echo 1 || echo 0)" "1"
    fi
    if [ "$AGMASK_INJECT" = 1 ] && [ "$AGFILL" = 1 ]; then
        # D-0538: a fungible block allocation must relocate around a
        # quarantined AG, not fail on meeting it.  One root file (inode in AG
        # 0) sized past AG 0 forces the extent walk to wrap into AG 1.
        agblocks=$(echo "$geo" | grep -ao 'agblocks=[0-9]*' | cut -d= -f2 | tr -dc '0-9')
        bsz=$(echo "$geo" | grep -ao 'blocksize=[0-9]*' | cut -d= -f2 | tr -dc '0-9')
        fillsz=$(( ${agblocks:-541497} * ${bsz:-4096} + 256 * 1024 * 1024 ))
        FF="$MNT/tdr_fill_$LABEL.bin"
        timeout 12 $SSH "$W" "echo 'TDR-FILL-$LABEL' > /dev/kmsg" >/dev/null 2>&1
        tfl=$(date +%s)
        # A file's FIRST extent is placed by the per-mount rotor (anywhere);
        # every later extent is allocated NEAR the previous one, and the walk
        # from that AG runs upward.  Measured s519g: a bare fallocate started
        # at AG 9 and never met AG 1.  So seed files 1 MiB at a time until one
        # lands in AG 0 (at most agcount tries), then grow THAT file: its walk
        # exhausts AG 0 and must cross AG 1.
        seedpy='import os,subprocess,sys,re
mnt,label,agb=sys.argv[1],sys.argv[2],int(sys.argv[3])
for k in range(32):
    p="%s/tdr_seed_%s_%d"%(mnt,label,k)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT,0o644); os.write(fd,b"s"*1048576); os.fsync(fd); os.close(fd)
    out=subprocess.run(["filefrag","-v",p],capture_output=True,text=True).stdout
    m=re.search(r"\n\s*0:\s+\d+\.\.\s*\d+:\s+(\d+)\.\.",out)
    ag=int(m.group(1))//agb if m else -1
    print("seed k=%d ag=%d"%(k,ag))
    if ag==0:
        os.rename(p,"%s/tdr_fill_%s.bin"%(mnt,label)); print("SEED_OK k=%d"%k); break
'
        seedb=$(printf '%s' "$seedpy" | base64 -w0)
        probe "$W" 60 "$OUT/agfill_seed.txt" '^seed k=[0-9]+ ag=' "the AG-fill seed on $W" "echo $seedb | base64 -d > /root/tdr_seed.py; python3 /root/tdr_seed.py '$MNT' '$LABEL' ${agblocks:-541497} 2>&1"
        so=$(tr '\n' ' ' < "$OUT/agfill_seed.txt")
        echo "  INFO AG-fill seed: $(echo "$so" | cut -c1-300)"
        ck "D-0538 arm: a seed file with its first extent in AG 0 was found (the fill's walk starts in AG 0)" "$(echo "$so" | grep -ac 'SEED_OK')" "1"
        rsx 60 "$W" "fallocate -l $fillsz '$FF' 2>&1; echo fallocate_rc=\$?; stat -c 'ino=%i size=%s' '$FF' 2>&1" > "$OUT/agfill_fallocate.txt"; forc=$?
        [ "$forc" = 124 ] || capture_require "$OUT/agfill_fallocate.txt" 'fallocate_rc=[0-9]+' "the AG-fill fallocate on $W"
        fo=$(grep -av "^$RS_STATUS_TAG " "$OUT/agfill_fallocate.txt" | tr '\n' ' ')
        tflw=$(( $(date +%s) - tfl ))
        echo "  INFO AG-fill fallocate ($fillsz bytes = agblocks $agblocks x $bsz + 256 MiB) wall=${tflw}s: $fo"
        timeout 60 $SSH "$W" "filefrag -v '$FF' 2>&1" 2>/dev/null | filt > "$OUT/agfill_filefrag.txt"
        # physical block -> AG (filefrag reports blocks in the fs block size)
        python3 - "$OUT/agfill_filefrag.txt" "${agblocks:-541497}" > "$OUT/agfill_summary.txt" <<'PYEOF'
import sys,re
ff,agb=sys.argv[1],int(sys.argv[2])
ags={}
for l in open(ff, errors="replace"):
    m=re.match(r'\s*\d+:\s+\d+\.\.\s*\d+:\s+(\d+)\.\.\s*(\d+):\s+(\d+)', l)
    if not m: continue
    p0,p1,n=int(m.group(1)),int(m.group(2)),int(m.group(3))
    a0,a1=p0//agb,p1//agb
    for a in range(a0,a1+1): ags[a]=ags.get(a,0)+1     # extents touching AG a
print("AGS "+" ".join("%d:%d"%(a,ags[a]) for a in sorted(ags)))
print("in_ag1=%d" % (1 if 1 in ags else 0))
print("in_ag0=%d" % (1 if 0 in ags else 0))
print("max_ag=%d" % (max(ags) if ags else -1))
PYEOF
        echo "  INFO AG-fill extents by AG: $(head -1 "$OUT/agfill_summary.txt")"
        tdw=$(date +%s)
        rsx 60 "$W" "dd if=/dev/zero of='$FF' bs=1M count=64 seek=$(( fillsz / 1048576 - 64 )) conv=notrunc,fsync 2>&1 | tail -1; echo dd_rc=\${PIPESTATUS[0]}" > "$OUT/agfill_tailwrite.txt"; dwrc=$?
        [ "$dwrc" = 124 ] || capture_require "$OUT/agfill_tailwrite.txt" 'dd_rc=[0-9]+' "the AG-fill tail write on $W"
        dw=$(grep -av "^$RS_STATUS_TAG " "$OUT/agfill_tailwrite.txt" | tr '\n' ' ')
        tdww=$(( $(date +%s) - tdw ))
        echo "  INFO AG-fill tail write (64 MiB into the wrapped extent) wall=${tdww}s: $(echo "$dw" | cut -c1-160)"
        wdcap_from "$OUT/dmesg_${W}_agfill.txt" "TDR-FILL-$LABEL"
        echo "  INFO AG-fill quarantine refusals: AG-EIO=$(grep -ac 'P240-QUAR-AG-EIO' "$OUT/dmesg_${W}_agfill.txt") ($(grep -ao 'P240-QUAR-AG-EIO agno=[0-9]* comm=[a-z0-9_]*' "$OUT/dmesg_${W}_agfill.txt" | sort | uniq -c | tr '\n' '|' | cut -c1-200)) skips=$(grep -ac 'P538-AG-SKIP' "$OUT/dmesg_${W}_agfill.txt") ($(grep -ao 'P538-AG-SKIP agno=[0-9]* start=[0-9]* comm=[a-z0-9_]*' "$OUT/dmesg_${W}_agfill.txt" | sort | uniq -c | tr '\n' '|' | cut -c1-200))"
        ckge "D-0538: the extent walk met the quarantined AG and skipped it (P538-AG-SKIP agno=1 comm=fallocate)" "$(grep -a 'P538-AG-SKIP agno=1 ' "$OUT/dmesg_${W}_agfill.txt" | grep -ac 'comm=fallocate')" 1
        ck "D-0538: fallocate past the survivor's own AG succeeded (the walk relocated around the quarantined AG)" "$(echo "$fo" | grep -ac 'fallocate_rc=0')" "1"
        ck "D-0538 arm: the fill file has extents in AG 0 (its walk began there and exhausted it)" "$(grep -a '^in_ag0=' "$OUT/agfill_summary.txt" | cut -d= -f2)" "1"
        ck "D-0538: no extent of the fill file lies in the quarantined AG 1" "$(grep -a '^in_ag1=' "$OUT/agfill_summary.txt" | cut -d= -f2)" "0"
        ckge "D-0538: the fill wrapped past AG 1 (max AG of its extents)" "$(grep -a '^max_ag=' "$OUT/agfill_summary.txt" | cut -d= -f2)" 2
        ck "D-0538: zero P240-QUAR-AG-EIO from the fill (no allocation met the gate)" "$(grep -ac 'P240-QUAR-AG-EIO' "$OUT/dmesg_${W}_agfill.txt")" "0"
        ck "D-0538: the tail write + fsync into the wrapped extent returned 0" "$(echo "$dw" | grep -ac 'dd_rc=0')" "1"
        ck "AG-fill steps returned within 60 s each" "$([ "$tflw" -le 60 ] && [ "$tdww" -le 60 ] && echo 1 || echo 0)" "1"
        timeout 60 $SSH "$W" "rm -f '$FF' '$MNT'/tdr_seed_${LABEL}_*" >/dev/null 2>&1
    fi
    # the quarantined domain must answer EIO, never stale content: a stat of
    # the victim's directory is bounded and its outcome recorded
    tq=$(date +%s)
    rsx 100 "$W" "stat -c %i '$D' 2>&1; echo rc=\$?" > "$OUT/quar_probe.txt"; qrc=$?
    [ "$qrc" = 124 ] || capture_require "$OUT/quar_probe.txt" '^rc=[0-9]+$' "the quarantined-domain probe on $W"
    qo=$(grep -av "^$RS_STATUS_TAG " "$OUT/quar_probe.txt" | tr '\n' ' ')
    echo "  INFO quarantined-domain probe wall=$(( $(date +%s) - tq ))s: $(echo "$qo" | cut -c1-160)"
    wdcap "$OUT/dmesg_$W.txt"
    echo "  INFO quarantine probes on $W: REFUSE=$(grep -ac 'P240-QUAR-REFUSE' "$OUT/dmesg_$W.txt") AG-EIO=$(grep -ac 'P240-QUAR-AG-EIO' "$OUT/dmesg_$W.txt") EIO-ABORT=$(grep -ac 'P240-QUAR-EIO-ABORT' "$OUT/dmesg_$W.txt") TORN-UNPUBLISHED=$(grep -ac 'P227-FR-TORN-UNPUBLISHED' "$OUT/dmesg_$W.txt")"
    ck "zero 'Shutting down filesystem' on $W after the probes" "$(grep -ac 'Shutting down filesystem' "$OUT/dmesg_$W.txt")" "0"
    # 0.75.23: the zombie must still LEAVE.  Measured s515g on 0.75.22: the
    # survivor's umount sent 34 releases to the sealed dead master (19 never
    # acknowledged) and parked 5-10 s in the ack wait, and the next prep's
    # teardown gave up on the node.  A clean leave measures ~1-5 s; bound 20 s
    # and the sealed-master skip must be what made it so.
    # The umount runs under nohup and its task stack is sampled every 2 s
    # (s515h on 0.75.23: the skips fired only ~38 s into the umount — the
    # time before them is what the samples must name).
    tu=$(date +%s)
    probe "$W" 100 "$OUT/umount_quar_${W}.txt" '^MOUNTED_AFTER=[0-9]+$' "the survivor's umount under the quarantine on $W" "rm -f /root/tdr_qumount.rc; nohup sh -c 'timeout -s KILL 70 umount $MNT; echo \$? > /root/tdr_qumount.rc' >/dev/null 2>&1 & for i in \$(seq 1 40); do sleep 2; [ -f /root/tdr_qumount.rc ] && { echo UMOUNT_RC=\$(cat /root/tdr_qumount.rc) AT=\$((i*2)); break; }; pid=\$(pidof umount | awk '{print \$1}'); [ -n \"\$pid\" ] && { echo \"--- t+\$((i*2))s umount pid \$pid state \$(awk '{print \$3}' /proc/\$pid/stat 2>/dev/null)\"; cat /proc/\$pid/stack 2>/dev/null | head -14; }; done; [ -f /root/tdr_qumount.rc ] || echo UMOUNT_RC=HUNG; echo MOUNTED_AFTER=\$(grep -c ' mxfs ' /proc/mounts)"
    tuw=$(( $(date +%s) - tu ))
    uo=$(cat "$OUT/umount_quar_${W}.txt")
    wdcap "$OUT/dmesg_${W}_umount.txt"
    uat=$(echo "$uo" | grep -ao 'AT=[0-9]*' | tail -1 | cut -d= -f2)
    echo "  INFO survivor umount under the quarantine: $(echo "$uo" | grep -a 'UMOUNT_RC' | tr '\n' ' ') wall=${tuw}s | skips=$(grep -ac 'P-RBLK-RELEASE-SKIP-DEAD-MASTER' "$OUT/dmesg_${W}_umount.txt") relall=$(grep -ao 'P-RELALL-WIRED .*held_after=[0-9]*' "$OUT/dmesg_${W}_umount.txt" | tail -1 | cut -c1-90)"
    echo "  INFO umount stack samples: $(echo "$uo" | grep -a -A5 '^--- t+' | grep -av '^--$' | tr '\n' '|' | cut -c1-900)"
    ck "survivor umount under the quarantine returned rc=0" "$(echo "$uo" | grep -ac 'UMOUNT_RC=0')" "1"
    ck "survivor umount under the quarantine within 20 s (got ${uat:-HUNG}s)" "$([ "${uat:-99}" -le 20 ] && echo 1 || echo 0)" "1"
    ck "nothing mounted on $W afterwards" "$(echo "$uo" | grep -ao 'MOUNTED_AFTER=[0-9]*' | cut -d= -f2)" "0"
    ck "no release was left unacknowledged by the sealed master (P-TAUTH-RELEASE-WAIT)" "$(grep -ac 'P-TAUTH-RELEASE-WAIT ' "$OUT/dmesg_${W}_umount.txt")" "0"
    # 0.75.25 (measured s516a on 0.75.24): the umount's final SB summary lock
    # was sent to the sealed dead master 60 times over 42 s before the dirty
    # departure it takes anyway.  The refused victim now fails fast: zero
    # retry sends after 'Unmounting Filesystem', and the SB lock rc names it.
    echo "  INFO SB summary lock at umount: $(grep -ao 'P-SB-SUMMARY-LOCK slot=[0-9]* rc=-\?[0-9]*' "$OUT/dmesg_${W}_umount.txt" | tail -1) terminal=$(grep -ac 'P-RBLK-TERMINAL' "$OUT/dmesg_${W}.txt" "$OUT/dmesg_${W}_umount.txt" | awk -F: '{s+=$2} END{print s}')"
    ck "zero lock-request retries to the dead master during the umount" "$(awk '/Unmounting Filesystem/{f=1} f' "$OUT/dmesg_${W}_umount.txt" | grep -ac 'lock request to node')" "0"
elif [ "$acked" -ge 1 ]; then
    AB=$(base64 -w0 < "$OUT/acked.txt")
    VPY='import os,sys,hashlib
d=sys.argv[1]; pre=sys.argv[3]; ok=bad=missing=0
for line in open(sys.argv[2]):
    p=line.split()
    if len(p)!=3: continue
    path=os.path.join(pre,p[1][4:]) if p[1].startswith("PRE:") else os.path.join(d,p[1])
    try:
        h=hashlib.md5(open(path,"rb").read()).hexdigest()
    except FileNotFoundError:
        missing+=1; print("MISSING",p[1]); continue
    except OSError as e:
        bad+=1; print("ERR",p[1],e); continue
    if h==p[2]: ok+=1
    else:
        bad+=1; print("MISMATCH",p[1],h,p[2])
print("VERIFY ok=%d bad=%d missing=%d"%(ok,bad,missing), flush=True)
'
    VPYB=$(printf '%s' "$VPY" | base64 -w0)
    tv=$(date +%s)
    # a hang (124) is the EIO-budget stall the next assertion measures; any
    # other way of not producing the VERIFY line is a failed instrument
    rsx 90 "$W" "echo $AB | base64 -d > /root/tdr_acked.txt; echo $VPYB | base64 -d > /root/tdr_verify.py; ls -1 '$D' 2>/dev/null | wc -l; python3 /root/tdr_verify.py '$D' /root/tdr_acked.txt '$PRE'" > "$OUT/verify.txt"
    vrc=$?
    [ "$vrc" = 124 ] || capture_require "$OUT/verify.txt" '^VERIFY ok=[0-9]+ ' "the verify on $W"
    echo "  INFO verify rc=$vrc wall=$(( $(date +%s) - tv ))s listed=$(sed -n 1p "$OUT/verify.txt") $(grep -a '^VERIFY' "$OUT/verify.txt")"
    ck "verify completed on $W (no hang / EIO budget)" "$vrc" "0"
    listed=$(sed -n 1p "$OUT/verify.txt" | tr -dc '0-9')
    ckge "directory lists at least the acknowledged files" "${listed:-0}" "$acked_dir"
    vok=$(grep -a '^VERIFY' "$OUT/verify.txt" | grep -oE 'ok=[0-9]+' | cut -d= -f2)
    ck "every acknowledged file readable with its acknowledged md5" "${vok:-0}" "$acked"
    grep -a '^MISSING\|^MISMATCH\|^ERR' "$OUT/verify.txt" | head -5 | sed 's/^/  INFO /'
    # the survivor-cached vectors, named individually
    ck "pre-cached file shared.txt shows the victim's acknowledged content (stale inode/page vector)" "$(grep -ac 'PRE:shared.txt' "$OUT/verify.txt")" "0"
    ck "pre-cached negative dentry created_by_victim now resolves with its content (stale dentry vector)" "$(grep -ac 'PRE:created_by_victim' "$OUT/verify.txt")" "0"
    ck "pre-cached block-format dir: the victim's new_N entries resolve (stale cached dir block vector)" "$(grep -ac 'PRE:new_' "$OUT/verify.txt")" "0"
    ck "pre-cached stat'd files pre_0..4 show the victim's rewritten content (stale inode-cluster vector)" "$(grep -ac 'PRE:pre_' "$OUT/verify.txt")" "0"
    probe "$W" 25 "$OUT/pre_listed.txt" '^[0-9]+$' "the readdir count of $PRE on $W" "ls -1 '$PRE' | wc -l"
    plisted=$(head -1 "$OUT/pre_listed.txt" | tr -dc '0-9')
    ckge "readdir of the pre-cached block-format dir lists every entry" "${plisted:-0}" "$(( PRE_N + 7 ))"
    # phase 2: drop dentries + in-core inodes (NOT the xfs_buf cache) and
    # re-verify — a stale cached inode-cluster buffer now answers the re-iget
    rsx 90 "$W" "sync; echo 2 > /proc/sys/vm/drop_caches; python3 /root/tdr_verify.py '$D' /root/tdr_acked.txt '$PRE'" > "$OUT/verify_dropcaches.txt"; vdrc=$?
    [ "$vdrc" = 124 ] || capture_require "$OUT/verify_dropcaches.txt" '^VERIFY ok=[0-9]+ ' "the verify after drop_caches on $W"
    vokd=$(grep -a '^VERIFY' "$OUT/verify_dropcaches.txt" | grep -oE 'ok=[0-9]+' | cut -d= -f2)
    echo "  INFO after drop_caches=2: $(grep -a '^VERIFY' "$OUT/verify_dropcaches.txt")"
    ck "after drop_caches=2 every acknowledged file still reads its md5 (cached inode-cluster buffer vector)" "${vokd:-0}" "$acked"
    grep -a '^MISSING\|^MISMATCH\|^ERR' "$OUT/verify_dropcaches.txt" | head -5 | sed 's/^/  INFO dropcaches /'
    if [ "$FALSE_APPLY" != 0 ]; then
        # the victim's image of W's directory block is a released-tenure
        # image.  The evaluator's own counters are the evidence: its
        # clean-release marker must be in the slice and seen (relmarks),
        # nothing may be refused as not-held / stale-epoch / wrong-lineage
        # (a refusal fails the whole transaction closed), and whatever of
        # the old image is inside the window is REDUNDANT_CLEAN, never
        # APPLY over the block W has since written.  Whether the old image
        # is inside the window depends on where the log tail sat when the
        # marker was forced; REDUNDANT_CLEAN is reported, not required.
        p273=$(grep -a 'P273-SHADOW-EVAL' "$OUT/dmesg_$W.txt" | tail -1)
        p273f() { echo "$p273" | grep -oE "(^|[ ])$1=[0-9]+" | head -1 | cut -d= -f2; }
        echo "  INFO false-apply arm: P273 txn=$(p273f txn) buf=$(p273f buf) WOULD_APPLY=$(p273f WOULD_APPLY) REDUNDANT_CLEAN=$(p273f REDUNDANT_CLEAN) relmarks=$(p273f relmarks) notheld=$(p273f notheld) staleep=$(p273f staleep) wlineage=$(p273f wlineage) uncap_match=$(p273f uncap_match) untagged=$(p273f untagged) redundant_skipped=$(p273f redundant_skipped) REDUNDANT-SKIP lines=$(grep -ac 'P227-FR-REDUNDANT-SKIP' "$OUT/dmesg_$W.txt") overrides=$(echo "$verdict" | grep -ao 'buflsn_overrides=[0-9]*')"
        ckge "false-apply arm: the evaluator saw the victim's clean-release marker in its slice (P273 relmarks >= 1)" "$(p273f relmarks)" 1
        ck "false-apply arm: no image was refused as not held at death (P273 notheld)" "$(p273f notheld)" "0"
        ck "false-apply arm: no image was refused for a stale grant epoch (P273 staleep)" "$(p273f staleep)" "0"
        ck "false-apply arm: no image was refused for a wrong lineage (P273 wlineage)" "$(p273f wlineage)" "0"
        ck "false-apply arm: no untagged image reached the replay (P273 untagged)" "$(p273f untagged)" "0"
        ck "false-apply arm: W's late entries w_late_0..3 read with their md5 at verdict time (no false-APPLY of the victim's older block image)" "$(grep -ac 'PRE:w_late_' "$OUT/verify.txt")" "0"
        ck "false-apply arm: w_late_0..3 still read after drop_caches=2" "$(grep -ac 'PRE:w_late_' "$OUT/verify_dropcaches.txt")" "0"
        if [ "$FALSE_APPLY" = 2 ]; then
            ckge "false-apply arm (re-hold): the victim's held-at-death image of the directory was admitted (P273 WOULD_APPLY >= 1)" "$(p273f WOULD_APPLY)" 1
            ck "false-apply arm (re-hold): v_rehold_0 reads with its md5 at verdict time" "$(grep -ac 'PRE:v_rehold_' "$OUT/verify.txt")" "0"
        fi
        if [ "$FALSE_APPLY" = 3 ]; then
            ckge "pinned-tail arm: the victim's released images were inside the window (P273 buf >= 1)" "$(p273f buf)" 1
            ckge "pinned-tail arm: the released images were classified REDUNDANT_CLEAN (P273 REDUNDANT_CLEAN >= 1)" "$(p273f REDUNDANT_CLEAN)" 1
            ckge "pinned-tail arm: the replayer skipped them (P227-FR-REDUNDANT-SKIP >= 1)" "$(grep -ac 'P227-FR-REDUNDANT-SKIP' "$OUT/dmesg_$W.txt")" 1
            ck "pinned-tail arm: no transaction was refused whole (P227-FR-ATOMIC-SKIP)" "$(grep -ac 'P227-FR-ATOMIC-SKIP' "$OUT/dmesg_$W.txt")" "0"
        fi
    fi
    # Staleness window: when the verdict-time view is short, sample the
    # survivor's view every 2 s (root listing + the directory's count, each
    # sample preceded by a kmsg marker so dmesg correlates) until every
    # acknowledged file is listed or 90 s pass, then re-verify the md5s.
    # This measures HOW LONG a fsync-acknowledged file stays invisible after
    # the replay verdict; the verdict-time assertions above stay the bar.
    if [ "${vok:-0}" != "$acked" ]; then
        DN=$(basename "$D")
        i=0; vis=""
        while [ $i -lt 90 ]; do
            # order matters: a name LOOKUP (stat) before the root READDIR (ls),
            # then the lookup again — if only the readdir reloads the parent,
            # lookup1 fails, root lists the name, lookup2 succeeds.
            samp=$(timeout 20 $SSH "$W" "echo 'TDR-VIS-$LABEL-$i' > /dev/kmsg; l1=\$(stat -c %i '$D' >/dev/null 2>&1; echo \$?); r=\$(ls -1 '$MNT' 2>/dev/null | grep -c '^$DN\$'); l2=\$(stat -c %i '$D' >/dev/null 2>&1; echo \$?); echo lookup1_rc=\$l1 root=\$r lookup2_rc=\$l2 dir=\$(ls -1 '$D' 2>/dev/null | wc -l)" 2>/dev/null | filt | tr -d '\r')
            echo "  INFO vis t+${i}s $samp" | tee -a "$OUT/visibility.txt"
            cnt=$(echo "$samp" | grep -oE 'dir=[0-9]+' | cut -d= -f2)
            if [ "${cnt:-0}" -ge "$acked_dir" ]; then vis=$i; break; fi
            sleep 2; i=$((i+2))
        done
        echo "  INFO acknowledged files became visible on $W after ${vis:-more than 90} s from the verdict-time verify"
        rsx 90 "$W" "python3 /root/tdr_verify.py '$D' /root/tdr_acked.txt '$PRE'" > "$OUT/verify2.txt"; v2rc=$?
        [ "$v2rc" = 124 ] || capture_require "$OUT/verify2.txt" '^VERIFY ok=[0-9]+ ' "the re-verify on $W"
        vok2=$(grep -a '^VERIFY' "$OUT/verify2.txt" | grep -oE 'ok=[0-9]+' | cut -d= -f2)
        echo "  INFO re-verify: $(grep -a '^VERIFY' "$OUT/verify2.txt")"
        ck "every acknowledged file eventually readable with its acknowledged md5 (content survived; visibility was late)" "${vok2:-0}" "$acked"
    fi
fi

# -- the sole-survivor exclusive-write gate (D-0904), when the target purged
#    the victim's registration: the gate must have certified, the recovery
#    must publish, and WE-AR must be restored so the victim can rejoin --
if [ "$REFUSED" = 1 ]; then
    # a refused replay never reaches P163-RECOVERY-COMPLETE; the gate's fate
    # after a refusal is D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513's
    # question, recorded here, not asserted
    echo "  INFO gate after the refusal: $(grep -a 'P236-FENCEKIND' "$OUT/dmesg_$W.txt" | grep -ao 'kind=[A-Z_]*([0-9]*)' | tail -1) restore=$(grep -ac 'P-PR-GATE-RESTORE site=' "$OUT/dmesg_$W.txt") recovery_complete=$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/dmesg_$W.txt")"
elif grep -aq 'P-PR-GATE-ISSUE\|P-PR-GATE-ALREADY' "$OUT/dmesg_$W.txt"; then
    echo "  INFO gate path taken: $(grep -a 'P-PR-GATE ' "$OUT/dmesg_$W.txt" | tail -1 | sed 's/.*scsipr: //' | cut -c1-160)"
    ck "gate certified (P236-FENCEKIND kind=EXCLUSIVE_WRITE_GATE)" "$(grep -a 'P236-FENCEKIND' "$OUT/dmesg_$W.txt" | grep -ac 'EXCLUSIVE_WRITE_GATE')" "1"
    for bad in 'P-PR-GATE-MULTINEXUS' 'P-PR-GATE-VERIFY' 'P-PR-GATE-CONFLICT' 'P-PR-GATE-FAIL' 'P239-GATE-LAPSED' 'P239-GATE-SELFGONE'; do
        ck "zero '$bad' on $W" "$(grep -ac "$bad" "$OUT/dmesg_$W.txt")" "0"
    done
    # the restore follows P163-RECOVERY-COMPLETE; bounded wait from now
    i=0; restored=""
    while [ $i -lt 60 ]; do
        restored=$(wd | grep -a 'P-PR-GATE-RESTORE site=\|P-PR-GATE-RESTORE-PENDING' | tail -1)
        [ -n "$restored" ] && break
        sleep 3; i=$((i+3))
    done
    wdcap "$OUT/dmesg_$W.txt"
    echo "  INFO gate restore after ${i}s: ${restored:-<none within 60s>}"
    # the completion waits on the takeover of every ledger page the victim
    # owned (D-0962: ~13 ms per page, 7984 pages = 104 s on s594a); when the
    # wait above runs out, the pace is the attributable cause, so name it
    echo "  INFO completion pace: takeover pages so far=$(grep -ac 'P-TAUTH-TAKEOVER-RETIRE' "$OUT/dmesg_$W.txt") $(grep -a 'P-COMPLETE-TIMING' "$OUT/dmesg_$W.txt" | tail -1 | grep -oE 'handoff_ms=[0-9]+|ledger_ms=[0-9]+|disklock_purge_ms=[0-9]+' | tr '\n' ' ')"
    ck "P163-RECOVERY-COMPLETE published" "$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/dmesg_$W.txt")" "1"
    ck "gate restored (P-PR-GATE-RESTORE site=)" "$(grep -ac 'P-PR-GATE-RESTORE site=' "$OUT/dmesg_$W.txt")" "1"
    # A reading that did not come from the target is NOT a failed reservation
    # — it is a failed measurement, and reporting it as the former sends the
    # next session after a fencing defect that the run never observed.  Every
    # successful PERSISTENT RESERVE IN carries a 'PR generation=' header; an
    # error message does not, so that header is the capture's shape (an
    # absent device's error text is non-empty too, sess41).
    probe "$W" 25 "$OUT/pr_state.txt" 'PR generation=' "the PR state read on $W after the restore" "R=\$(readlink -f $MXFS_DEV); sg_persist -i -k \$R 2>&1 | grep -a 'PR generation=' | head -1; echo KEYS=\$(sg_persist -i -k \$R 2>&1 | grep -ac '^    0x'); sg_persist -i -r \$R 2>&1 | grep -a 'type:\|NO reservation'"
    prstate=$(tr '\n' ' ' < "$OUT/pr_state.txt")
    echo "  INFO PR state on $W after restore: $prstate"
    ck "exactly one registration (the survivor's) after the restore" "$(grep -ao '^KEYS=[0-9]*' "$OUT/pr_state.txt" | cut -d= -f2)" "1"
    ck "WE-AR reservation in force after the restore" "$(grep -ac 'all registrants' "$OUT/pr_state.txt")" "1"
fi

# -- the false-apply arm, cold: W leaves as the last member and remounts
#    alone, so every name is read from the platter, not from W's cache.
#    Bounds: the umount 120 s, the remount 180 s (the last member's own
#    pages are taken over at the remount), the verify 90 s. --
if [ "$FALSE_APPLY" != 0 ] && [ "$REFUSED" = 0 ] && [ "$acked" -ge 1 ]; then
    tc=$(date +%s)
    rsx 330 "$W" "s=\$(date +%s%N); umount $MNT; urc=\$?; e=\$(date +%s%N); echo UMOUNT_RC=\$urc ms=\$(( (e-s)/1000000 )); s=\$(date +%s%N); mount -t mxfs $MXFS_DEV $MNT; mrc=\$?; e=\$(date +%s%N); echo MOUNT_RC=\$mrc ms=\$(( (e-s)/1000000 )); ls -1 '$PRE' | wc -l; python3 /root/tdr_verify.py '$D' /root/tdr_acked.txt '$PRE'" > "$OUT/verify_cold.txt"; crc=$?
    [ "$crc" = 124 ] || capture_require "$OUT/verify_cold.txt" '^VERIFY ok=[0-9]+ ' "the cold remount and verify on $W"
    cold=$(grep -av "^$RS_STATUS_TAG " "$OUT/verify_cold.txt")
    echo "  INFO false-apply arm, cold remount of $W (wall $(( $(date +%s) - tc ))s): $(echo "$cold" | grep -a 'UMOUNT_RC\|MOUNT_RC\|^VERIFY' | tr '\n' ' ') listed=$(echo "$cold" | grep -aE '^[0-9]+$' | head -1)"
    ck "false-apply arm: W unmounted (last member) and remounted alone" "$(echo "$cold" | grep -ac 'UMOUNT_RC=0\|MOUNT_RC=0')" "2"
    ck "false-apply arm: cold, every acknowledged file (the victim's and w_late_0..3) reads with its md5" "$(echo "$cold" | grep -a '^VERIFY' | grep -oE 'ok=[0-9]+' | cut -d= -f2)" "$acked"
    ck "false-apply arm: cold, w_late_0..3 are in the directory (no false-APPLY reached the platter)" "$(echo "$cold" | grep -ac 'PRE:w_late_')" "0"
    echo "$cold" | grep -a '^MISSING\|^MISMATCH\|^ERR' | head -5 | sed 's/^/  INFO cold /'
fi

# -- the victim comes back --
$VIRSH start "$V" > "$OUT/virsh_start.txt" 2>&1; echo "  INFO virsh start $V rc=$?"
i=0; up=0
while [ $i -lt 120 ]; do
    if timeout 8 $SSH "$V" "true" >/dev/null 2>&1; then up=1; break; fi
    sleep 5; i=$((i+5))
done
echo "  INFO $V ssh reachable=$up after ${i}s (unmounted: the next prep_cluster re-forms the cluster)"
# 0.89.44: SSHD ANSWERING IS NOT BOOT FINISHED, and the difference is charged
# to the NEXT lap.  systemd keeps /run/nologin until the boot transaction
# completes; its banner ("System is booting up. Unprivileged users are not
# permitted to log in yet.") lands in the captured output of whatever runs
# next, and the following prep_cluster's srcversion probe read that banner
# ahead of the value: two laps of three reported
# 'PREP FAIL: bad nodes: test2(no usable srcversion — still booting?)' and
# 'ABORT: cluster prep failed' while BOTH nodes were healthy on the right
# build and the lap that followed passed with zero failures.  A prep that
# says FAIL about a healthy cluster is how a real prep failure gets waved
# through, and it also leaves the next lap's build identity unverified — so
# wait for the banner to go, not just for sshd.  Bound 90 s: the banner
# clears within tens of seconds of sshd on these guests, and the prep's own
# node probe already allows 180 s.
if [ "$up" = 1 ]; then
    j=0; booted=0
    while [ $j -lt 90 ]; do
        if timeout 8 $SSH "$V" "test ! -e /run/nologin" >/dev/null 2>&1; then booted=1; break; fi
        sleep 3; j=$((j+3))
    done
    echo "  INFO $V boot transaction complete=$booted after ${j}s (/run/nologin cleared)"
fi

# -- TDR_REJOIN=1: the victim rejoins the SAME generation (no re-mkfs) --
# D-ELECTED-REPLAYER-KEEPS-DEAD-SLOT-TRACKING-NEXT-CLAIMANT-READ-AS-RESTART-0911
# (found s516b/s516f1 on 0.75.25): the survivor that replayed V's slice kept
# V's old incarnation as slot N's tracked tenancy, so V's new mount in that
# slot read as 'node in slot N has restarted (detected epoch change ...)'
# — a second death of an identity recovered minutes earlier, the live
# successor's goodbye ignored, 40 s of view skew and REMASTER storms; in
# s516b the rejoining mount exhausted 60 REMASTER retries on the root inode
# and shut down.  This is the production shape (die, be recovered, reboot,
# remount) the chain never exercised because every lap is followed by a
# re-mkfs.  Budget: insmod+mount <= 30 s (a join measures 1-8 s), file work
# 5 s, umount 10 s.
if [ "${TDR_REJOIN:-0}" = 1 ] && [ "$up" = 1 ]; then
    echo "  INFO rejoin arm: $V remounts $MXFS_DEV in the same generation at $(date -u +%T)"
    RJ0=$(date +%s)
    timeout 12 $SSH "$W" "echo 'TDR-REJOIN-$LABEL' > /dev/kmsg" >/dev/null 2>&1
    probe "$V" 90 "$OUT/rejoin_$V.txt" '^MOUNT_RC=[0-9]+ WALL=' "the rejoin mount on $V" "M=\$(date +%s); modprobe libcrc32c 2>/dev/null; insmod /root/mxfs.ko.prep dyndbg=+p force_transport=1 target_cache_protected=1; echo INSMOD_RC=\$?; T0=\$(date +%s); timeout 30 mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$? WALL=\$(( \$(date +%s) - T0 )); mountpoint -q $MNT && { echo REJOIN_$LABEL > $MNT/rejoin_$LABEL.txt; sync -f $MNT/rejoin_$LABEL.txt; md5sum $MNT/rejoin_$LABEL.txt | cut -c1-32; }; journalctl -k --since @\$M --no-pager 2>/dev/null | grep -a 'DLM init: node_id=\|claimed heartbeat slot\|lock request failed\|unrecoverable\|Shutting down' | cut -c1-200; true"
    rjo=$(cat "$OUT/rejoin_$V.txt")
    rjrc=$(echo "$rjo" | grep -ao '^MOUNT_RC=[0-9]*' | cut -d= -f2)
    rjw=$(echo "$rjo" | grep -ao 'WALL=[0-9]*' | head -1 | cut -d= -f2)
    rjmd5=$(echo "$rjo" | grep -aoE '^[0-9a-f]{32}$' | head -1)
    rjslot=$(echo "$rjo" | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | awk '{print $NF}')
    echo "  INFO rejoin mount: rc=${rjrc:-?} wall=${rjw:-?}s slot=${rjslot:-?} md5=${rjmd5:-none} $(echo "$rjo" | grep -a 'lock request failed\|unrecoverable\|Shutting' | head -1 | cut -c1-120)"
    ck "rejoin: $V mounted the same generation (rc=0)" "${rjrc:-1}" "0"
    ck "rejoin: mount within 30 s (got ${rjw:-?}s)" "$([ "${rjw:-99}" -le 30 ] && echo 1 || echo 0)" "1"
    sleep 3
    wdcap "$OUT/dmesg_${W}_rejoin_full.txt"
    # only the lines after the rejoin marker: the lap's own death/recovery
    # lines precede it and must not be counted here
    awk "/TDR-REJOIN-$LABEL/{f=1} f" "$OUT/dmesg_${W}_rejoin_full.txt" > "$OUT/dmesg_${W}_rejoin.txt"
    capture_require "$OUT/dmesg_${W}_rejoin.txt" "TDR-REJOIN-$LABEL" "the kernel log on $W from the rejoin marker"
    echo "  INFO $W during the rejoin: retired=$(grep -ac 'P-SLOT-TENANCY-RETIRED' "$OUT/dmesg_${W}_rejoin_full.txt") kept=$(grep -ac 'P-SLOT-TENANCY-KEPT' "$OUT/dmesg_${W}_rejoin_full.txt") restarted=$(grep -ac 'has restarted' "$OUT/dmesg_${W}_rejoin.txt") pending=$(grep -ac 'P163-RECOVERY-PENDING' "$OUT/dmesg_${W}_rejoin.txt") automon=$(grep -ac 'P-EVICT-AUTOMON' "$OUT/dmesg_${W}_rejoin.txt") remaster_view=$(grep -ac 'P-TAUTH-REMASTER-VIEW' "$OUT/dmesg_${W}_rejoin.txt") lines=$(grep -ac . "$OUT/dmesg_${W}_rejoin.txt")"
    ck "rejoin: $W did not read the new tenancy as a restart of the recovered node ('has restarted')" "$(grep -ac 'has restarted' "$OUT/dmesg_${W}_rejoin.txt")" "0"
    ck "rejoin: no second recovery of the recovered identity on $W (P163-RECOVERY-PENDING)" "$(grep -ac 'P163-RECOVERY-PENDING' "$OUT/dmesg_${W}_rejoin.txt")" "0"
    ck "rejoin: $W retired the recovered incarnation's slot tracking (P-SLOT-TENANCY-RETIRED)" "$([ "$(grep -ac 'P-SLOT-TENANCY-RETIRED' "$OUT/dmesg_${W}_rejoin_full.txt")" -ge 1 ] && echo 1 || echo 0)" "1"
    # a failed md5sum (ENOENT, EIO) is the measurement: its text is output
    probe "$W" 25 "$OUT/rejoin_read_$W.txt" '.' "the read of the rejoined node's file on $W" "md5sum $MNT/rejoin_$LABEL.txt 2>&1 | cut -c1-32; true"
    rdm=$(head -1 "$OUT/rejoin_read_$W.txt")
    ck "rejoin: $W reads the rejoined node's file with its md5" "$rdm" "${rjmd5:-none}"
    timeout 12 $SSH "$W" "echo 'TDR-REJOIN-LEAVE-$LABEL' > /dev/kmsg" >/dev/null 2>&1
    probe "$V" 60 "$OUT/rejoin_leave_$V.txt" '^(UNLOADED|STILL_LOADED)$' "the rejoined node's departure on $V" "timeout 30 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED"
    rju=$(tr '\n' ' ' < "$OUT/rejoin_leave_$V.txt")
    sleep 3
    wdcap_from "$OUT/dmesg_${W}_rejoin_leave.txt" "TDR-REJOIN-LEAVE-$LABEL"
    echo "  INFO rejoin leave: $rju | $W: goodbye_rx=$(grep -ac 'P-GOODBYE-RX' "$OUT/dmesg_${W}_rejoin_leave.txt") goodbye_dead_ignored=$(grep -ac 'P-GOODBYE-DEAD-IGNORED' "$OUT/dmesg_${W}_rejoin_leave.txt") clean_depart=$(grep -ac 'P163-CLEAN-DEPART\|P304-RETIRE-COMPLETED-BY-PEER\|P304-RETIRE-PENDING-RELEASED' "$OUT/dmesg_${W}_rejoin_leave.txt")"
    ck "rejoin: $V left cleanly (UMOUNT_RC=0, module unloaded)" "$(echo "$rju" | grep -ac 'UMOUNT_RC=0.*UNLOADED')" "1"
    ck "rejoin: $W honoured the goodbye (P-GOODBYE-RX)" "$([ "$(grep -ac 'P-GOODBYE-RX' "$OUT/dmesg_${W}_rejoin_leave.txt")" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "rejoin: zero goodbyes ignored as a dead identity on $W (P-GOODBYE-DEAD-IGNORED)" "$(grep -ac 'P-GOODBYE-DEAD-IGNORED' "$OUT/dmesg_${W}_rejoin_leave.txt")" "0"
    echo "  INFO rejoin arm wall=$(( $(date +%s) - RJ0 ))s"
fi

wall=$(( $(date +%s) - t0 ))
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL acked=$acked replay_s=$treplay wall=${wall}s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails acked=$acked replay_s=$treplay wall=${wall}s evidence=$OUT"
fi
exit $fails
