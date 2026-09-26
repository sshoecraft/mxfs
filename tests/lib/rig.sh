#!/bin/bash
# tests/lib/rig.sh — the rig helpers a harness needs so that NO VERDICT IS
# TAKEN FROM AN UNVALIDATED MEASUREMENT.
#
# The hazard (D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS): the usual
# helper `rs() { timeout N $SSH host cmd 2>/dev/null | filt; }` discards the
# remote command's stderr and reports filt's status, so a remote command that
# fails outright (the tool is on an NFS share the node has not mounted yet;
# the device path belongs to another rig; a python exception; a timeout)
# leaves an EMPTY or PARTIAL capture.  A `grep -c` over it reads 0, and a
# ck/ckge turns that 0 into a statement about MXFS.  A zero from a broken
# instrument and a zero from a clean system are the same number; only one of
# them is a result.  Measured: s580f (20 minutes of rig time exited VACUOUS
# from a 0-byte platter dump), s54j/s54k (a probe on a node without /src
# printed nothing and the lap ran on to a verdict).
#
# The contract (design consult 2026-09-18): before a measurement feeds an
# assertion about the filesystem, the harness must establish that the
# invocation completed with an acceptable status, produced the tool's
# required structure, and belongs to this invocation.  Otherwise ABORT (exit
# 2), never FAIL, never VACUOUS, never PASS.
#
# Source it after LABEL and OUT are set:
#     . "$(dirname "$0")/lib/rig.sh"
# then acquire every counted measurement with rsx into its own file and
# validate it IN THE PARENT SHELL (an exit inside $(...) does not stop the
# harness) before any ck/ckge reads it:
#     rsx 60 test1 "python3 /src/mxfs/tools/x.py $DEV" > "$OUT/x.txt"
#     capture_require "$OUT/x.txt" '^slot [0-9]+ ' "the platter dump on test1"
#     ck "..." "$(cnt "$OUT/x.txt" 'flags=ACTIVE')" 1
#
# Plain bash; no dependency on tests/lib/common.sh.
SSH=${SSH:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)/tools/mxfs_sshpass.sh}
MNT=${MNT:-/mnt/shared}
RS_STATUS_TAG='MXFS-RS-STATUS'

# The login banner the nodes print on every ssh.
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }

# rs <timeout> <node> <cmd>: the legacy shape, for output that is NOT
# counted (progress, best-effort cleanup).  The remote command's stderr is
# DISCARDED and the status returned is filt's.  Never feed a verdict from it.
rs()  { timeout "$1" "$SSH" "$2" "$3" < /dev/null 2>/dev/null | filt; }

# rsx <timeout> <node> <cmd>: a MEASUREMENT.
#   - stdout is the remote command's stdout, banner-filtered, byte for byte
#     when the invocation succeeds;
#   - the remote command's stderr is kept SEPARATE, in
#     $OUT/rs_stderr/<node>_XXXXXX (never merged: error text can contain
#     any string a parser recognizes);
#   - when the invocation's status is non-zero (remote exit, ssh 255, the
#     timeout's 124, sshpass' own refusal) ONE record is appended on its own
#     line:  MXFS-RS-STATUS v=1 host=<node> rc=<n> err=<stderr file>
#     and the same status is returned.  The record means "the invocation
#     returned non-zero", never "MXFS failed".  On status zero nothing is
#     added.
# The timeout is owned here and its status observed here, not filt's.
# What cannot be covered: the harness itself being killed — then no
# capture exists at all, and capture_require's missing-file arm catches it.
rsx() {
    local t=$1 h=$2 c=$3 rc errd errf tmp seq
    errd=${OUT:-/tmp}/rs_stderr
    mkdir -p "$errd"
    # MXFS_FAULT_RSX_NTH=<n> (capture-contract verification only): the n-th
    # measurement of this lap is issued to a host that does not resolve — a
    # real ssh failure at a real acquisition — and the lap must then ABORT.
    # The sequence lives in a file because rsx runs inside $(...) and
    # background subshells, where a parent counter would not advance.  The
    # STAGE FAULT line on stderr is the proof the injection was reached.
    if [ -n "${MXFS_FAULT_RSX_NTH:-}" ]; then
        seq=$(( $(cat "${OUT:-/tmp}/.rsx_seq" 2>/dev/null || echo 0) + 1 ))
        echo "$seq" > "${OUT:-/tmp}/.rsx_seq"
        if [ "$seq" = "$MXFS_FAULT_RSX_NTH" ]; then
            echo "STAGE FAULT: measurement #$seq issued to an unresolvable host instead of $h" >&2
            h="$h-unreachable.invalid"
        fi
    fi
    # unique per call even when rsx runs inside $(...) (a subshell: no
    # counter in the parent survives), so no call's stderr overwrites another's
    errf=$(mktemp "$errd/${h//[^A-Za-z0-9._-]/_}_XXXXXX")
    tmp=$(mktemp "${OUT:-/tmp}/.rsx.XXXXXX")
    # stdin closed: an ssh that inherits the harness's stdin can swallow it
    timeout "$t" "$SSH" "$h" "$c" < /dev/null > "$tmp" 2> "$errf"
    rc=$?
    filt < "$tmp"
    rm -f "$tmp"
    if [ "$rc" != 0 ]; then
        # own line even if the remote stdout lacked a final newline
        printf '\n%s v=1 host=%s rc=%s err=%s\n' "$RS_STATUS_TAG" "${h//[^A-Za-z0-9._-]/_}" "$rc" "$errf" | sed '/^$/d'
    fi
    return "$rc"
}

cnt() { grep -ac "$2" "$1"; }

# ck <name> <got> <want> / ckge <name> <got> <min>: the assertion.  A got that
# is EMPTY while a value was wanted is not a measurement that disagreed; it is
# a value nothing produced — a field the summary no longer carries, a read
# that printed nothing — and the lap ABORTs on it instead of printing a FAIL
# about MXFS (s58h: d0947 printed nine FAILs with got= from a summary that
# had lost the fields its verdicts read).  Wanting the empty string is still
# a legitimate assertion of emptiness.  Both count into $fails, as the local
# copies they replace did.
ck() {
    if [ -z "$2" ] && [ -n "$3" ]; then
        echo "ABORT: '$1' was asked to judge an EMPTY value (want=$3): nothing was measured — a harness defect, never a filesystem verdict"
        echo "RESULT: ABORT label=${LABEL:-?} stage=empty-verdict evidence=${OUT:-?}"; exit 2
    fi
    if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi
}
ckge() {
    if [ -z "$2" ]; then
        echo "ABORT: '$1' was asked to judge an EMPTY value (want>=$3): nothing was measured — a harness defect, never a filesystem verdict"
        echo "RESULT: ABORT label=${LABEL:-?} stage=empty-verdict evidence=${OUT:-?}"; exit 2
    fi
    if [ "$2" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=$2 want>=$3"; fails=$((fails+1)); fi
}

# measure <node> <timeout> <file> <shape> <what> <cmd>: rsx into <file> and
# capture_require it, as one statement in the parent shell.  For the common
# case of a one-shot remote measurement whose lines feed a verdict.
measure() { rsx "$2" "$1" "$6" > "$3"; capture_require "$3" "$4" "$5"; }

# capture_require <file> <shape-regex> <what>: the capture must exist, be
# non-empty, carry no MXFS-RS-STATUS record (a valid-looking line followed by
# a failure or a timeout is a failure), and contain the SHAPE the tool always
# emits (anchored, per tool — not merely a word: an error message is
# non-empty too).  Otherwise print the failure text, name the stderr file,
# and exit 2 (ABORT).  Call it as a statement in the parent shell.
capture_require() {
    local f=$1 shape=$2 what=$3 st err
    if [ ! -f "$f" ]; then
        echo "ABORT: $what produced NO capture ($f is missing); nothing was measured"
        echo "RESULT: ABORT label=${LABEL:-?} stage=capture evidence=${OUT:-?}"; exit 2
    fi
    if grep -qa "^$RS_STATUS_TAG " "$f"; then
        st=$(grep -a "^$RS_STATUS_TAG " "$f" | head -1)
        err=$(echo "$st" | grep -oE 'err=[^ ]+' | cut -d= -f2)
        # the excerpt skips the login banner (it is the first 3 lines of every
        # stderr) so the 240 characters shown are the tool's own error
        echo "ABORT: $what did not complete: $st; stderr=[$( [ -n "$err" ] && [ -f "$err" ] && filt < "$err" | tr '\n' ' ' | cut -c1-240)]; stdout=[$(grep -av "^$RS_STATUS_TAG " "$f" | tr '\n' ' ' | cut -c1-160)]"
        echo "RESULT: ABORT label=${LABEL:-?} stage=capture evidence=${OUT:-?}"; exit 2
    fi
    if [ ! -s "$f" ]; then
        echo "ABORT: $what produced an EMPTY capture ($f); nothing was measured"
        echo "RESULT: ABORT label=${LABEL:-?} stage=capture evidence=${OUT:-?}"; exit 2
    fi
    if ! grep -qaE "$shape" "$f"; then
        echo "ABORT: $what returned no line matching '$shape', so nothing about MXFS was measured; raw=[$(tr '\n' ' ' < "$f" | cut -c1-200)]"
        echo "RESULT: ABORT label=${LABEL:-?} stage=capture evidence=${OUT:-?}"; exit 2
    fi
}

# count_file_into <var> <file> <pattern>: count <pattern> in a capture that
# has ALREADY crossed the boundary, into the variable named <var> (assigned
# in the parent: no $(...) between the count and the verdict).  grep's
# status 1 is "no match" and a legitimate zero; any other failure is an
# ABORT, and so is a value that is not a number.  The locals carry a prefix
# so printf -v cannot land on one of them when the caller names its own
# variable v, f or rc.
count_file_into() {
    local cfi_var=$1 cfi_f=$2 cfi_pat=$3 cfi_v cfi_rc
    cfi_v=$(LC_ALL=C grep -ac -- "$cfi_pat" "$cfi_f"); cfi_rc=$?
    if [ "$cfi_rc" != 0 ] && [ "$cfi_rc" != 1 ]; then
        echo "ABORT: counting '$cfi_pat' in $cfi_f failed (grep rc=$cfi_rc); no count was taken"
        echo "RESULT: ABORT label=${LABEL:-?} stage=count evidence=${OUT:-?}"; exit 2
    fi
    case $cfi_v in ''|*[!0-9]*)
        echo "ABORT: counting '$cfi_pat' in $cfi_f gave '$cfi_v', not a number"
        echo "RESULT: ABORT label=${LABEL:-?} stage=count evidence=${OUT:-?}"; exit 2 ;;
    esac
    printf -v "$cfi_var" '%s' "$cfi_v"
}

# window_count_into <var> <node> <timeout> <mark> <pattern> <tag>: the
# replacement for `cnt() { rs N node "dmesg | sed -n /MARK/,\$p | grep -ac X" }`,
# whose failed ssh read as a count of zero.  Acquires the kernel ring from
# <mark> on <node> into its own file ($OUT/win_<tag>_<seq>_<node>.txt, the
# sequence number owned by the parent so every call is a fresh capture),
# requires the window to have run to its end AND to contain the mark (a
# window whose mark is not in the ring is not a window: every count in it
# would read zero), then counts locally into <var>.  A statement in the
# parent shell, one per observation point; it keeps the harness's timing
# (each call re-reads the ring) and adds no per-assertion parser over ssh.
WIN_SEQ=0
window_count_into() {
    local wci_var=$1 wci_h=$2 wci_t=$3 wci_mark=$4 wci_pat=$5 wci_tag=$6 wci_f
    WIN_SEQ=$((WIN_SEQ + 1))
    wci_f=${OUT:-/tmp}/win_${wci_tag//[^A-Za-z0-9._-]/_}_${WIN_SEQ}_${wci_h//[^A-Za-z0-9._-]/_}.txt
    window_into "$wci_f" "$wci_h" "$wci_t" "$wci_mark"
    count_file_into "$wci_var" "$wci_f" "$wci_pat"
}

# window_into <file> <node> <timeout> [mark]: the kernel ring on <node> from
# <mark> (or the whole ring when no mark is given) into <file>, across the
# boundary: the invocation's status observed, the window run to its end
# (WINDOW_END), and the mark present in it.  For a harness that then
# EXTRACTS a line or a field from the window locally (`grep -a 'P226-X' |
# tail -1`, `grep -ao 'ms=[0-9]*'`) rather than counting a pattern: the
# extraction runs over a capture that has crossed, so an absent line is the
# kernel not having logged it, never an ssh that did not run.  A statement
# in the parent shell.
#
# The optional fifth argument names a FILE ON THE NODE to read instead of the
# ring: the one kmsg_follow_start (below) fills.  The ring on these nodes is
# 1 MiB, and a lap whose workload logs heavily for three minutes between its
# mark and its window loses the mark to the wrap and ABORTs at the read — two
# parked-log-waiter laps did on s138 (s138e, s138f) — so such a lap follows
# the ring into a file from the mark on and windows from the file.  The mark
# guard is the same either way: a window without its mark is not a window.
window_into() {
    local wi_f=$1 wi_h=$2 wi_t=$3 wi_mark=${4:-} wi_src=${5:-}
    local wi_from=dmesg
    [ -n "$wi_src" ] && wi_from="cat $wi_src"
    if [ -n "$wi_mark" ]; then
        measure "$wi_h" "$wi_t" "$wi_f" '^WINDOW_END$' "the kernel log on $wi_h from '$wi_mark'" "$wi_from | sed -n \"/$wi_mark/,\\\$p\"; echo WINDOW_END"
        if ! grep -qaF -- "$wi_mark" "$wi_f"; then
            echo "ABORT: the kernel log window on $wi_h does not contain its mark '$wi_mark'; the ring wrapped or the mark was never written, so nothing after it can be counted"
            echo "RESULT: ABORT label=${LABEL:-?} stage=window evidence=${OUT:-?}"; exit 2
        fi
    else
        measure "$wi_h" "$wi_t" "$wi_f" '^WINDOW_END$' "the kernel log on $wi_h" "$wi_from; echo WINDOW_END"
    fi
}

# kmsg_follow_start <node> <mark> <node-file>: write <mark> into the kernel
# log on <node> and start `dmesg --follow` into <node-file> there, detached
# from this ssh, so that every later line reaches the file whatever the ring
# does afterwards.  The follower's first act is to dump the ring, so the mark
# just written is in the file from the start; that is verified here (the mark
# must be in the file within 10 s) and a follower that cannot show it is an
# ABORT, because every window read from that file would be empty.  The pid is
# left in <node-file>.pid for a caller that wants to stop it; a node that is
# recycled takes it down with the boot.  A statement in the parent shell.
kmsg_follow_start() {
    local kfs_h=$1 kfs_mark=$2 kfs_file=$3 kfs_f kfs_i kfs_n
    kfs_f=${OUT:-/tmp}/kmsg_follow_${kfs_h//[^A-Za-z0-9._-]/_}.txt
    measure "$kfs_h" 20 "$kfs_f" '^FOLLOW_STARTED pid=[0-9]+$' "the kernel-log follower on $kfs_h" \
        "rm -f $kfs_file $kfs_file.pid; nohup dmesg --follow < /dev/null > $kfs_file 2>/dev/null & echo \$! > $kfs_file.pid; sleep 1; echo $kfs_mark > /dev/kmsg; echo FOLLOW_STARTED pid=\$(cat $kfs_file.pid)"
    kfs_i=0
    while [ "$kfs_i" -lt 10 ]; do
        kfs_n=$(rs 15 "$kfs_h" "grep -acF -- '$kfs_mark' $kfs_file" | tr -dc '0-9')
        [ "${kfs_n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 1; kfs_i=$((kfs_i + 1))
    done
    echo "ABORT: the kernel-log follower on $kfs_h (dmesg --follow into $kfs_file) does not carry the mark '$kfs_mark' 10 s after it was written; no window read from that file could be one"
    echo "RESULT: ABORT label=${LABEL:-?} stage=follow evidence=${OUT:-?}"; exit 2
}

# value_now_into <var> <node> <timeout> <file> <line-regex> <what> <cmd>: a
# SCALAR measurement (a size, an rc, a key) into the variable named <var>.
# The capture crosses the boundary, then exactly ONE line must match
# <line-regex> (the tool's complete result line, anchored: '^size=[0-9]+$');
# none or several is an ABORT.  The matching line is assigned whole, so the
# caller strips its own field name (${size#size=}).  An empty result from a
# failed producer can no longer compare equal to an expected 0 or "", and a
# producer that printed the value and then failed is caught by the status
# record.  A statement in the parent shell.
value_now_into() {
    local vni_var=$1 vni_h=$2 vni_t=$3 vni_f=$4 vni_re=$5 vni_what=$6 vni_cmd=$7 vni_n vni_v
    measure "$vni_h" "$vni_t" "$vni_f" "$vni_re" "$vni_what" "$vni_cmd"
    vni_n=$(grep -acE -- "$vni_re" "$vni_f")
    if [ "$vni_n" != 1 ]; then
        echo "ABORT: $vni_what returned $vni_n lines matching '$vni_re' where exactly one is the result; raw=[$(tr '\n' ' ' < "$vni_f" | cut -c1-200)]"
        echo "RESULT: ABORT label=${LABEL:-?} stage=value evidence=${OUT:-?}"; exit 2
    fi
    vni_v=$(grep -aE -- "$vni_re" "$vni_f")
    printf -v "$vni_var" '%s' "$vni_v"
}

# wait_for_into <var> <node> <bound-s> <mark> <pattern>: the replacement
# for `waitfor() { while ...; do [ "$(cnt node pat)" -ge 1 ] && ...; done;
# echo timeout; }`, whose "timeout" could not tell a line the kernel never
# logged from an ssh that never ran (every poll failing reads as a count of
# zero, and the harness then prints a FAIL about MXFS).  Polls the marked
# window on <node> every 2 s until <pattern> appears (var = seconds waited)
# or the bound is spent; THEN the final window crosses the boundary
# (window_into: status observed, WINDOW_END, mark present) and only a valid
# window that genuinely lacks the pattern yields var=timeout.  A statement
# in the parent shell; the caller's ck on "$var" != timeout is unchanged.
wait_for_into() {
    local wfi_var=$1 wfi_h=$2 wfi_bound=$3 wfi_mark=$4 wfi_pat=$5 wfi_i=0 wfi_c wfi_f
    while [ "$wfi_i" -lt "$wfi_bound" ]; do
        wfi_c=$(rs 20 "$wfi_h" "dmesg | sed -n \"/$wfi_mark/,\\\$p\" | grep -ac -- '$wfi_pat'" | tr -dc '0-9')
        if [ "${wfi_c:-0}" -ge 1 ] 2>/dev/null; then
            printf -v "$wfi_var" '%s' "$wfi_i"
            return 0
        fi
        sleep 2
        wfi_i=$((wfi_i + 2))
    done
    WIN_SEQ=$((WIN_SEQ + 1))
    wfi_f=${OUT:-/tmp}/wait_${wfi_var//[^A-Za-z0-9._-]/_}_${WIN_SEQ}_${wfi_h//[^A-Za-z0-9._-]/_}.txt
    window_into "$wfi_f" "$wfi_h" 20 "$wfi_mark"
    if grep -qa -- "$wfi_pat" "$wfi_f"; then
        # it landed between the last poll and the final capture
        printf -v "$wfi_var" '%s' "$wfi_bound"
    else
        printf -v "$wfi_var" '%s' timeout
    fi
}

# prep_require <file> <what>: a capture from a remote command list that ran
# tests/setup/prep_node.sh.  The preparation's own result record is
# required: NODE_PREP_OK present -> return; NODE_PREP_FAIL, or neither
# (a later successful command in the same list masks nothing here) -> ABORT
# with the FAIL text.  Acquire the list with `... prep_node.sh tcp 2>&1`
# so the FAIL reason (printed to stderr) is in the capture.
prep_require() {
    local pr_f=$1 pr_what=$2
    capture_require "$pr_f" '^NODE_PREP_(OK|FAIL)' "$pr_what"
    if ! grep -qa '^NODE_PREP_OK' "$pr_f"; then
        echo "ABORT: $pr_what did not prepare the node: $(grep -a '^NODE_PREP_FAIL' "$pr_f" | head -1 | cut -c1-240)"
        echo "RESULT: ABORT label=${LABEL:-?} stage=prep evidence=${OUT:-?}"; exit 2
    fi
}

# capture_require_bg <file> <stderr-file> <shape-regex> <what>: the boundary
# for a capture written by a BACKGROUND pipeline the harness itself started
# (`( timeout N $SSH host cmd 2> err | filt > file ) &`), whose stderr the
# harness already keeps in its own file.  The shape present: return 0.  The
# shape absent while the pipeline's stderr holds anything beyond the login
# banner: the acquisition failed, ABORT.  The shape absent and the stderr
# silent: the producer has not (yet) said it, which is the caller's timing
# verdict to make; return 1.  Call it as a statement in the parent shell.
capture_require_bg() {
    local f=$1 e=$2 shape=$3 what=$4 err
    [ -f "$f" ] && grep -qaE "$shape" "$f" && return 0
    err=$( [ -f "$e" ] && filt < "$e" | tr '\n' ' ' | cut -c1-240)
    if [ -n "$err" ]; then
        echo "ABORT: $what did not produce '$shape' and its stderr says why: [$err]; stdout=[$( [ -f "$f" ] && tr '\n' ' ' < "$f" | cut -c1-160)]"
        echo "RESULT: ABORT label=${LABEL:-?} stage=capture evidence=${OUT:-?}"; exit 2
    fi
    return 1
}

# require_epoch <value> <what>: a journal window is only a window if its mark
# was read; an empty mark makes `journalctl --since @` fail and the capture
# it feeds read as "nothing logged".  Call as a statement in the parent shell
# after   m=$(rsx 10 node 'date +%s' | tail -1).
require_epoch() {
    case $1 in
        ''|*[!0-9]*) echo "ABORT: $2 has no valid clock mark ('$1'); a journal window cannot be taken from it"; echo "RESULT: ABORT label=${LABEL:-?} stage=mark evidence=${OUT:-?}"; exit 2 ;;
    esac
}

# ensure_src_or_abort <node>...: the tree is on the NFS share and a node
# that has just booted has not mounted it; nothing under /src runs there
# until it has.  Checks the mount AND that the tools the harnesses use are
# reachable through it.  A prerequisite check, not a substitute for
# validating the probe itself (the mount can go away afterwards).
ensure_src_or_abort() {
    local n r
    for n in "$@"; do
        r=$(rs 150 "$n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src && [ -r /src/mxfs/tools/slice_image.py ] && [ -r /src/mxfs/tests/setup/prep_node.sh ] && echo SRC_OK" | tail -1)
        [ "$r" = SRC_OK ] || { echo "ABORT: /src with the tree is not reachable on $n, so nothing from the tree can run there"; echo "RESULT: ABORT label=${LABEL:-?} stage=src_mount node=$n evidence=${OUT:-?}"; exit 2; }
    done
}

# ---- the device under test: an identity, not a path -----------------------
# (ledger D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE-AND-REPORT-IT-AS-MXFS)
# A path is a locator; the instrument is the LUN.  /dev/mapper/mpatha exists
# on one rig only, /dev/sda is the LUN on this rig and a path member of a
# multipath map on another, and each node also has a root disk that answers
# every probe with well-formed output about the wrong thing.  So every rig
# declares its shared LUN's SCSI identifier in data/rigs.json under the tag
# tools/mxfs_rig_tag.sh prints (MXFS_LUN_WWID names it for one run), and
# nothing below measures or prepares a device that does not carry it,
# whatever path named it.  The identity is read ON the node by
# tests/setup/dev_identity.sh, shipped inline over ssh so a node without the
# share can still answer: the SCSI WWID, the MXFS envelope superblock's
# filesystem uuid (a format changes it; the WWID never does), the device's
# major:minor and the node's live mxfs mount.
#
# mxfs_dev_resolve <node>: sets MXFS_DEV_RESOLVED (the path on that node),
# MXFS_DEV_WWID, MXFS_DEV_FSID (`none` when the device carries no MXFS
# format) and MXFS_DEV_SOURCE, and prints one DEVICE line into the lap's
# log.  The candidate is, in order: MXFS_DEV when the caller set it; the
# device of the node's live mxfs mount; the declared LUN found by its own
# identifier (/dev/disk/by-id/wwn-0x<wwid>); the transport's rig default
# only when MXFS_TRANSPORT is set explicitly.  Whatever chose it, the
# candidate must be a block device on the node carrying the declared WWID,
# and when the node has a live mxfs mount the candidate must BE that mount's
# device (major:minor): a caller may not name another device on a node that
# is already measuring one.  A failed query, no identity evidence (a virtio
# disk has no wwid), an undeclared rig or any mismatch is an ABORT.  Call it
# as a statement (never inside $(...): the ABORT must stop the harness), and
# call it AGAIN after anything that moves the binding: a format changes the
# FSID, a VM restart or a target re-login can rename the path.
# mxfs_dev_check <node>: re-reads the identity of the bound path and ABORTs
# when the WWID or the FSID no longer match the binding — the step before a
# device-consuming command that follows a restart, a re-login or a format
# the harness did not perform itself.
# mxfs_dev_same <node>...: every node resolves to the declared LUN AND the
# same FSID (one format generation), or ABORT.
MXFS_DEV_RESOLVED=; MXFS_DEV_WWID=; MXFS_DEV_FSID=; MXFS_DEV_SOURCE=
MXFS_RIG_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mxfs_dev_abort() { echo "ABORT: $1"; echo "RESULT: ABORT label=${LABEL:-?} stage=device evidence=${OUT:-?}"; exit 2; }
mxfs_wwid_norm() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/^naa\.//; s/^0x//; s/^mpath-//' | tr -cd '0-9a-f'; }
# the declared LUN: MXFS_LUN_WWID, else data/rigs.json[<rig tag>].lun_wwid
mxfs_dev_declared() {
    local tag w
    if [ -n "${MXFS_LUN_WWID:-}" ]; then mxfs_wwid_norm "$MXFS_LUN_WWID"; return 0; fi
    tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || mxfs_dev_abort "the rig cannot be established (tools/mxfs_rig_tag.sh: no MXFS_RIG_TAG, no marker rig, no vendor), so no LUN identity is declared; set MXFS_RIG_TAG or MXFS_LUN_WWID"
    w=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("lun_wwid",""))' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
    [ -n "$w" ] || mxfs_dev_abort "rig '$tag' declares no LUN in data/rigs.json; add its lun_wwid there (or MXFS_LUN_WWID for one run) before anything measures a device on it"
    mxfs_wwid_norm "$w"
}
# mxfs_dev_ident <node> <path>: the IDENT line for <path> on <node>, or ABORT
# when the node did not answer with one (the query's status record is kept)
mxfs_dev_ident() {
    local n=$1 p=$2 b q
    b=$(base64 -w0 < "$MXFS_RIG_LIB_DIR/../setup/dev_identity.sh")
    q=$(rsx 25 "$n" "echo $b | base64 -d | sh -s '$p'")
    if echo "$q" | grep -qa "^$RS_STATUS_TAG "; then
        mxfs_dev_abort "could not read the identity of $p on $n: $(echo "$q" | grep -a "^$RS_STATUS_TAG ")"
    fi
    q=$(echo "$q" | grep -a '^IDENT ' | tail -1)
    [ -n "$q" ] || mxfs_dev_abort "no identity line for $p from $n"
    printf '%s\n' "$q"
}
mxfs_dev_field() { printf '%s\n' "$1" | sed -n "s/.*[ ]$2=\([^ ]*\).*/\1/p"; }
mxfs_dev_resolve() {
    local n=$1 d q src decl id w f mm live
    # the helpers ABORT inside $(...): their text is what they returned
    decl=$(mxfs_dev_declared) || { echo "$decl"; exit 2; }
    if [ -n "${MXFS_DEV:-}" ]; then
        d=$MXFS_DEV; src=MXFS_DEV
    else
        q=$(rsx 20 "$n" "awk '\$3==\"mxfs\"{print \$1}' /proc/mounts | sort -u")
        if echo "$q" | grep -qa "^$RS_STATUS_TAG "; then
            mxfs_dev_abort "could not read $n's mounts to resolve the MXFS device: $(echo "$q" | grep -a "^$RS_STATUS_TAG ")"
        fi
        if [ "$(echo "$q" | grep -ac .)" -gt 1 ]; then
            mxfs_dev_abort "$n has more than one mxfs mount ($(echo "$q" | tr '\n' ' ')); say which with MXFS_DEV"
        fi
        d=$(echo "$q" | head -1); src=live-mount
        if [ -z "$d" ]; then
            # no mount: the declared LUN by its own identifier, never a spelling
            d=/dev/disk/by-id/wwn-0x$decl; src=declared-wwid
            q=$(rsx 20 "$n" "test -e $d && echo BYID_OK")
            if [ "$(echo "$q" | tail -1)" != BYID_OK ]; then
                case ${MXFS_TRANSPORT:-} in
                    tcp) d=/dev/sda; src=transport-default ;;
                    caw*) d=/dev/mapper/mpatha; src=transport-default ;;
                    *) mxfs_dev_abort "no MXFS device basis on $n: no MXFS_DEV, no live mxfs mount, no /dev/disk/by-id/wwn-0x$decl, no MXFS_TRANSPORT" ;;
                esac
            fi
        fi
    fi
    id=$(mxfs_dev_ident "$n" "$d") || { echo "$id"; exit 2; }
    case $id in *' absent') mxfs_dev_abort "$d is not a block device on $n ($src)" ;; esac
    w=$(mxfs_dev_field "$id" wwid); f=$(mxfs_dev_field "$id" fsid); mm=$(mxfs_dev_field "$id" mm); live=$(mxfs_dev_field "$id" livemm)
    [ "$w" != none ] || mxfs_dev_abort "$d on $n carries no SCSI identity (wwid=none): it is not the declared LUN and there is nothing to compare — a path, a size or a model is not identity"
    [ "$(mxfs_wwid_norm "$w")" = "$decl" ] || mxfs_dev_abort "$d on $n is not the declared LUN: wwid=$w, declared $decl (source=$src)"
    [ "$live" = - ] || [ "$live" = "$mm" ] || mxfs_dev_abort "$d on $n ($mm) is not the filesystem under test: $n's live mxfs mount is on $live (source=$src)"
    [ "$f" != unreadable ] || mxfs_dev_abort "the envelope superblock of $d on $n could not be read"
    MXFS_DEV_RESOLVED=$d; MXFS_DEV_WWID=$w; MXFS_DEV_FSID=$f; MXFS_DEV_SOURCE=$src
    echo "DEVICE node=$n path=$d source=$src wwid=$w fsid=$f mounted=$(mxfs_dev_field "$id" mounted)"
}
mxfs_dev_check() {
    local n=$1 id w f
    [ -n "$MXFS_DEV_RESOLVED" ] || mxfs_dev_abort "mxfs_dev_check before any mxfs_dev_resolve"
    id=$(mxfs_dev_ident "$n" "$MXFS_DEV_RESOLVED") || { echo "$id"; exit 2; }
    case $id in *' absent') mxfs_dev_abort "the bound device $MXFS_DEV_RESOLVED is no longer a block device on $n" ;; esac
    w=$(mxfs_dev_field "$id" wwid); f=$(mxfs_dev_field "$id" fsid)
    [ "$w" = "$MXFS_DEV_WWID" ] || mxfs_dev_abort "the bound path $MXFS_DEV_RESOLVED on $n now carries wwid=$w, bound $MXFS_DEV_WWID: the binding moved (re-login or rename) — resolve again"
    [ "$f" = "$MXFS_DEV_FSID" ] || mxfs_dev_abort "the bound device $MXFS_DEV_RESOLVED on $n now carries fsid=$f, bound $MXFS_DEV_FSID: a format this harness did not perform — resolve again after your own formats only"
    echo "DEVICE-CHECK node=$n path=$MXFS_DEV_RESOLVED wwid=$w fsid=$f unchanged"
}
mxfs_dev_same() {
    local n f0= n0=
    for n in "$@"; do
        mxfs_dev_resolve "$n"
        if [ -z "$n0" ]; then f0=$MXFS_DEV_FSID; n0=$n
        elif [ "$MXFS_DEV_FSID" != "$f0" ]; then
            mxfs_dev_abort "$n sees fsid=$MXFS_DEV_FSID on the LUN while $n0 sees $f0: two format generations, not one filesystem"
        fi
    done
}

# ---- the platter from the HOST: a declared, identity-checked backing image
#
# 34 harnesses read the LUN's platter from a file on this host, defaulting
# to ~/disk.img (the SCST fileio image of an earlier rig).  On the
# qnap rig the LUN lives on the QNAP and no file on this host backs it, so
# every one of those reads was a well-formed measurement of some OTHER
# filesystem, printed as a verdict about the one under test (ledger
# D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE-AND-REPORT-IT-AS-MXFS, s70/s71:
# d_intents_2tcp_open_efi asserted "every obligation extent reads FREE on
# the platter" from the host image).  So a host-side image is a rig
# declaration, never a spelling: data/rigs.json[<tag>].host_image, or
# MXFS_HOST_IMAGE_PATH for one run, and it is used only after its envelope
# fsid was read direct from the file and found equal to the LUN's — the
# node's resolved device when a node is named, else the fsid the cluster
# marker recorded at prep.  A rig that declares none (the qnap) resolves
# nothing: the harness ABORTs there, and reads the platter from a node
# instead (mxfs_chk_on_node below, or tools/chk_mxfs --query-only on a
# mounted one).
#
# mxfs_host_image [node]: sets MXFS_HOST_IMAGE (the host path) and
# MXFS_HOST_IMAGE_FSID, prints one HOST-IMAGE line, or ABORTs.  A statement,
# never inside $(...) — callers without this library use
# tools/mxfs_host_image.sh, which prints the path alone on stdout.
MXFS_HOST_IMAGE=; MXFS_HOST_IMAGE_FSID=
mxfs_host_image_declared() {
    local tag p
    if [ -n "${MXFS_HOST_IMAGE_PATH:-}" ]; then printf '%s\n' "$MXFS_HOST_IMAGE_PATH"; return 0; fi
    tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || mxfs_dev_abort "the rig cannot be established (tools/mxfs_rig_tag.sh), so no host-side image of its LUN is declared; set MXFS_RIG_TAG or MXFS_HOST_IMAGE_PATH"
    p=$(python3 -c 'import json,os,sys
d=json.load(open(sys.argv[1])); print(os.path.expanduser((d.get(sys.argv[2]) or {}).get("host_image") or ""))' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
    [ -n "$p" ] || mxfs_dev_abort "rig '$tag' declares no host-side image of its LUN in data/rigs.json (host_image): the platter is not readable from this host — read it from a node (mxfs_chk_on_node, or tools/chk_mxfs --query-only on a mounted node)"
    printf '%s\n' "$p"
}
# the envelope fsid of a file or device on THIS host, read direct (the same
# 4 KiB sector-0 read tests/setup/dev_identity.sh does on a node)
mxfs_host_image_fsid() {
    local h u
    h=$(dd if="$1" bs=4096 count=1 iflag=direct 2>/dev/null | od -An -tx1 -N32 -v | tr -d ' \n')
    case "$h" in
        4d584653*) u=$(echo "$h" | cut -c33-64); echo "$(echo "$u" | cut -c1-8)-$(echo "$u" | cut -c9-12)-$(echo "$u" | cut -c13-16)-$(echo "$u" | cut -c17-20)-$(echo "$u" | cut -c21-32)" ;;
        '') echo unreadable ;;
        *) echo none ;;
    esac
}
mxfs_host_image() {
    local n=${1:-} p f ref refsrc
    p=$(mxfs_host_image_declared) || { echo "$p"; exit 2; }
    [ -r "$p" ] || mxfs_dev_abort "the declared host image $p is not readable on this host"
    if [ -n "$n" ]; then
        [ -n "$MXFS_DEV_RESOLVED" ] || mxfs_dev_resolve "$n"
        ref=$MXFS_DEV_FSID; refsrc="$n:$MXFS_DEV_RESOLVED"
    else
        ref=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("fsid") or "")' "$MXFS_RIG_LIB_DIR/../../.cluster_marker.json" 2>/dev/null)
        refsrc=cluster-marker
        [ -n "$ref" ] || mxfs_dev_abort "no reference identity for the host image: no node was named and the cluster marker records no fsid — name the node whose LUN the image must match"
    fi
    f=$(mxfs_host_image_fsid "$p")
    [ "$f" = "$ref" ] || mxfs_dev_abort "the host image $p carries fsid=$f while the LUN under test carries $ref ($refsrc): it is not the filesystem under test"
    MXFS_HOST_IMAGE=$p; MXFS_HOST_IMAGE_FSID=$f
    echo "HOST-IMAGE path=$p fsid=$f reference=$refsrc"
}

# mxfs_rig_pr_class: what the rig's target does with a node's persistent-
# reservation registration when that node's iSCSI session dies — "purged"
# (the QNAP: gone within tens of seconds, PR generation unchanged) or
# "persists" (SCST/LIO: the dead initiator's key stays as the fence target).
# A declaration, never an assumption: data/rigs.json[<tag>]
# .pr_registration_on_session_loss, measured by tests/pr_session_drop_probe.sh
# and carrying its evidence beside it; MXFS_PR_CLASS overrides for one run.  A
# harness that predicts PR state (fence_crash_cuts) reads it, because a
# prediction written for the other class was a false FAIL on every lap of
# sweep s71a.  Prints the class; ABORTs when the rig declares none.
mxfs_rig_pr_class() {
    local tag c
    if [ -n "${MXFS_PR_CLASS:-}" ]; then c=$MXFS_PR_CLASS
    else
        tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || mxfs_dev_abort "the rig cannot be established (tools/mxfs_rig_tag.sh), so its PR registration class is not declared; set MXFS_RIG_TAG or MXFS_PR_CLASS"
        c=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("pr_registration_on_session_loss") or "")' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
        [ -n "$c" ] || mxfs_dev_abort "rig '$tag' declares no pr_registration_on_session_loss in data/rigs.json: measure it with tests/pr_session_drop_probe.sh and declare it (purged|persists) before predicting PR state on it"
    fi
    case "$c" in purged|persists) printf '%s\n' "$c" ;; *) mxfs_dev_abort "pr_registration_on_session_loss='$c' is neither purged nor persists" ;; esac
}

# mxfs_rig_retirement_class: what the rig's target does with the writes it has
# ALREADY ACCEPTED from a node when that node's I_T nexus is lost.  This is a
# DIFFERENT question from the one above, and it is the one every recovery
# across a boot boundary actually depends on: the registration going away says
# the old incarnation cannot be ADMITTED to write again, and says nothing about
# whether the target has finished with what it already took from it.  A
# certificate authorises replaying the victim's slice, so a command still
# executable from the lost nexus would land under that replay.
#
# "retired-before-the-registration-purge" — measured: the platter went quiet at
# the power cut and stayed quiet, with the purge arriving afterwards, so a
# fence that keys on the purge is behind the retirement boundary rather than
# ahead of it.  "retired-after-the-registration-purge" or "unknown" mean a
# harness may NOT predict a clean recovery across a boot boundary.
#
# A declaration, never an assumption: data/rigs.json[<tag>]
# .task_retirement_on_nexus_loss, measured by tests/pr_retirement_probe.sh and
# carrying its evidence beside it; MXFS_RETIREMENT_CLASS overrides for one run.
# It is a property of one target, firmware, backend and session topology and is
# not a property of SPC targets in general — re-measure when any of those
# change.  Prints the class; ABORTs when the rig declares none, because an
# undeclared rig is exactly the case where assuming would be silent.
mxfs_rig_retirement_class() {
    local tag c
    if [ -n "${MXFS_RETIREMENT_CLASS:-}" ]; then c=$MXFS_RETIREMENT_CLASS
    else
        tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || mxfs_dev_abort "the rig cannot be established (tools/mxfs_rig_tag.sh), so its task-retirement class is not declared; set MXFS_RIG_TAG or MXFS_RETIREMENT_CLASS"
        c=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("task_retirement_on_nexus_loss") or "")' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
        [ -n "$c" ] || mxfs_dev_abort "rig '$tag' declares no task_retirement_on_nexus_loss in data/rigs.json: measure it with tests/pr_retirement_probe.sh and declare it before predicting a recovery that crosses a boot boundary on it"
    fi
    case "$c" in
        retired-before-the-registration-purge|retired-after-the-registration-purge|unknown)
            printf '%s\n' "$c" ;;
        *) mxfs_dev_abort "task_retirement_on_nexus_loss='$c' is not one of retired-before-the-registration-purge, retired-after-the-registration-purge, unknown" ;;
    esac
}

# mxfs_rig_retirement_contract: the deployment's retirement assertion for this
# rig, verbatim, in the five-field form the module compares against the LUN
# itself — <vendor>:<product>:<revision>:<lun designator>:<clause>.  The class
# above is for a harness deciding what it may predict; THIS is what the running
# module USED to require before it would certify a boot succession.  Since
# 0.89.16 no clause is accepted at all and no rig declares one, so this normally
# prints nothing; MXFS_RETIRE_CONTRACT still overrides it, which is how a harness
# loads a module WITH a contract to prove the refusal is in code.
#
# Scoped to the target, the FIRMWARE LEVEL and the LUN because a qualification
# is only as good as the hardware it was made on: change any of the three and
# the module stops matching, which is the point.  MXFS_RETIRE_CONTRACT
# overrides for one run (that is how a harness tests the refusal and the
# mismatch).  Prints the contract, or NOTHING when the rig declares none — an
# empty answer is a legitimate state that the module resolves by refusing, so
# this one does not abort.
mxfs_rig_retirement_contract() {
    local tag c
    if [ -n "${MXFS_RETIRE_CONTRACT:-}" ]; then
        printf '%s\n' "$MXFS_RETIRE_CONTRACT"
        return 0
    fi
    tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || return 0
    c=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("task_retirement_contract") or "")' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
    printf '%s\n' "$c"
}

# mxfs_rig_retirement_contract_withdrawn: the five-field string this rig USED to
# declare, kept verbatim in data/rigs.json under task_retirement_contract_withdrawn.
# No rig declares an active contract any more — the module accepts no clause as a
# retirement basis — and this exists for the arm that loads a module WITH the old
# string and requires it to be refused anyway.  That arm is what proves the
# withdrawal is in the code and not in the configuration.  Prints nothing when the
# rig never declared one.
mxfs_rig_retirement_contract_withdrawn() {
    local tag c
    tag=$("$MXFS_RIG_LIB_DIR/../../tools/mxfs_rig_tag.sh" 2>/dev/null) || return 0
    c=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("task_retirement_contract_withdrawn") or "")' "$MXFS_RIG_LIB_DIR/../../data/rigs.json" "$tag" 2>/dev/null)
    printf '%s\n' "$c"
}

# mxfs_rig_modargs: the module arguments a harness should load with on THIS rig
# — the transport and durability-domain declaration every fence-family harness
# already used, plus the rig's retirement contract in a form that survives the
# two parsers between here and the module.
#
# Those parsers are why this is a function and not a string.  A harness
# interpolates its MODARGS into an ssh payload, the remote shell re-parses it,
# and then the KERNEL joins insmod's argv into one string and splits THAT on
# whitespace (lib/cmdline.c next_arg).  This target's product id is "iSCSI
# Storage", so the contract has to reach the kernel carrying the double quotes
# next_arg understands, and has to reach insmod as a single argv element.  The
# single quotes below do the second job and preserve the double quotes for the
# first.  Measured without them: the module held "QNAP:iSCSI" and then refused
# every certificate over a product mismatch it had invented itself.
#
# A rig that declares no contract gets the plain arguments, and its module
# refuses to certify a boot succession — which is the intended state, not a
# harness failure to paper over.
#
# The transport follows MXFS_TRANSPORT (tcp unless it says caw), as the prep's
# does.  It used to be force_transport=1 always, so a lap that reloads the
# module after a reboot put a CAW node back on TCP, and the mount was refused
# as a transport mismatch before the path under test was reached
# (tests/evidence/20260926T065606Z_btk_btk_caw_s1: P-TRANSPORT-MISMATCH-REFUSED
# forced=tcp platter=caw).
mxfs_rig_modargs() {
    local c ft=1
    [ "${MXFS_TRANSPORT:-tcp}" = caw ] && ft=0
    c=$(mxfs_rig_retirement_contract)
    if [ -n "$c" ]; then
        printf '%s\n' "target_cache_protected=1 force_transport=$ft 'target_retire_contract=\"$c\"'"
    else
        printf '%s\n' "target_cache_protected=1 force_transport=$ft"
    fi
}

# mxfs_chk_on_node <node> <file> <what> [chk_mxfs args...]: the offline checker
# ON <node> against the node's resolved LUN, timing and status on the last
# line (CHK_RC=<rc> ms=<n>), as one statement that ABORTs when nothing was
# measured.  The node must not hold the device: the checker refuses a node
# whose module has it open (rc 4, "held open exclusively") and that refusal
# is a harness defect — the wrong node was asked — never a verdict, so it
# ABORTs here.  The checker's own rc (0 clean, non-zero errors) is left for
# the caller's assertion: mxfs_chk_rc <file>.
mxfs_chk_on_node() {
    local n=$1 f=$2 what=$3 args
    shift 3; args=${*:--v}
    [ -n "$MXFS_DEV_RESOLVED" ] || mxfs_dev_resolve "$n"
    mxfs_dev_check "$n"
    measure "$n" 300 "$f" '^CHK_RC=[0-9]+ ms=[0-9]+$' "$what" \
        "s=\$(date +%s%N); /src/mxfs/tools/chk_mxfs $args $MXFS_DEV_RESOLVED 2>&1; rc=\$?; e=\$(date +%s%N); echo CHK_RC=\$rc ms=\$(( (e-s)/1000000 ))"
    if [ "$(mxfs_chk_rc "$f")" = 4 ] && grep -qa 'held open exclusively' "$f"; then
        mxfs_dev_abort "$what: the checker was asked on $n while $n's module holds $MXFS_DEV_RESOLVED open — ask an unmounted node (or --query-only for a point read)"
    fi
}
mxfs_chk_rc() { grep -ao '^CHK_RC=[0-9]*' "$1" | head -1 | cut -d= -f2; }
