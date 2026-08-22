#!/bin/bash
# clyde_preflight.sh — HOST-SAFETY gate.  Run before any fleet work.
#
# WHY THIS EXISTS
# ---------------
# clyde was wedged unrecoverably twice inside 24h (2026-08-20 and 2026-08-21),
# both times requiring a manual reset.  Neither wedge was an MXFS filesystem
# bug; both were the host being driven into a state it could not come back
# from, and both had a cheap, observable precondition that nothing was
# checking:
#
#   2026-08-20  SCST's per-IO TRACE_BLOCKING debug prints had been left enabled
#               from an earlier debug session.  1,074,700 host kernel lines in
#               98 minutes went through journald onto clyde's root ext4 — the
#               same filesystem that holds the shared LUN and all 32 guest
#               images — and jbd2 deadlocked.  875 D-state threads, loadavg
#               870, nvme 1.6% busy.  Observable beforehand: the trace mask,
#               and the kernel log rate.
#
#   2026-08-21  A buffer overflow in SCST's PERSISTENT RESERVE IN / READ FULL
#               STATUS handler (fixed in +caw-abort-reclaim.4, see
#               tests/scst_pr_fullstatus_bounds.c) wrote iSCSI TransportID text
#               past the end of a command's data page and into a live QEMU
#               page-table page.  Observable beforehand: the SCST version.
#               Observable 38 minutes before the kill: the target's own
#               "Too big response data len" errors — which is what
#               tools/clyde_kmsg_guard.sh now watches for.
#
# Every check here is cheap, read-only, and RULE-2c-safe: it never runs
# `pgrep -f`, `ps aux`, or anything that reads /proc/<pid>/cmdline or maps.
#
# Usage:
#   scripts/clyde_preflight.sh            # gate: exit non-zero if unsafe
#   scripts/clyde_preflight.sh --report   # print findings, always exit 0
#
# Overrides (each logs loudly):
#   MXFS_PREFLIGHT_SKIP=1        skip the whole gate
#   MXFS_PREFLIGHT_ALLOW_TRACE=1 permit a non-default SCST trace mask
#                                (deliberate, time-boxed debug runs only)
#   MXFS_PREFLIGHT_KMSG_SECS=N   kernel-log sample window (default 3)
#   MXFS_PREFLIGHT_KMSG_MAX=N    max kernel lines/sec (default 40)
#   MXFS_PREFLIGHT_MIN_FREE_GB=N free-space floor (default 60)
#   MXFS_PREFLIGHT_MAX_USE_PCT=N used-space ceiling (default 90)
#   MXFS_PREFLIGHT_MAX_DSTATE=N  max pre-existing D-state tasks (default 20)
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MODE="${1:-gate}"
SCST_ROOT=/sys/kernel/scst_tgt
IMG="${MXFS_SCST_IMG:-/home/steve/disk.img}"
VMDIR="${MXFS_VM_DIR:-/home/steve/vms}"

KMSG_SECS="${MXFS_PREFLIGHT_KMSG_SECS:-3}"
KMSG_MAX="${MXFS_PREFLIGHT_KMSG_MAX:-40}"
# The LUN, the 32 guest images and the journal cannot be separated on this
# host (no local access, no spare device), so headroom is the ONLY lever left
# against the 2026-08-20 jbd2 wedge, and it is set tight on purpose.
# That wedge happened at 92% used with ~145G free — a 60G floor would not have
# caught it, but an 88% ceiling would.  Today: 81% used, 346G free.
MIN_FREE_GB="${MXFS_PREFLIGHT_MIN_FREE_GB:-120}"
MAX_USE_PCT="${MXFS_PREFLIGHT_MAX_USE_PCT:-88}"
MAX_DSTATE="${MXFS_PREFLIGHT_MAX_DSTATE:-20}"

fails=0
warns=0
ok()   { printf '  OK    %s\n' "$*"; }
warn() { printf '  WARN  %s\n' "$*"; warns=$((warns + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }

if [ "${MXFS_PREFLIGHT_SKIP:-0}" = 1 ]; then
    echo "clyde_preflight: SKIPPED by MXFS_PREFLIGHT_SKIP=1 — the host is unguarded."
    exit 0
fi

echo "=== clyde_preflight ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) ==="

# ---------------------------------------------------------------------------
# 0. Did the kmsg guard halt the rig?  It sets this when the kernel reported
#    damage; clearing it is a deliberate act, never a side effect of a rerun.
# ---------------------------------------------------------------------------
echo "-- rig halt flag"
HALT="${MXFS_RIG_HALT:-$REPO/.rig_halt}"
# Two locations: the repo flag (on /src, so it survives a host reset and is
# where the harness looks) and a host-local one written by the crash latch in
# case /src was not mounted at boot.  Either one halts the rig.
halted=0
for h in "$HALT" /var/lib/mxfs/rig_halt; do
    [ -f "$h" ] || continue
    halted=1
    bad "the rig is HALTED ($h):"
    sed 's/^/        /' "$h"
done
if [ "$halted" -eq 1 ]; then
    bad "  understand the cause, then: tools/clyde_kmsg_guard.sh clear"
else
    ok "no halt flag"
fi

# ---------------------------------------------------------------------------
# 1. Is the host kernel already damaged?
#
# A kernel that has already taken a bad-page or an oops has, by definition,
# had memory corrupted by something.  Layering a 32-node run on top of it is
# how a recoverable fault becomes an unkillable wedge: on 2026-08-21 the oops
# left a vCPU thread dead with irqs disabled, stop_machine never completed,
# and every subsequent RCU grace period stalled forever.
# ---------------------------------------------------------------------------
echo "-- kernel health"
taint=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
declare -A TAINT_BIT=( [5]="BAD_PAGE" [7]="DIE/oops" [14]="SOFTLOCKUP" [4]="MACHINE_CHECK" )
damaged=""
for b in 4 5 7 14; do
    if [ $(( (taint >> b) & 1 )) -eq 1 ]; then damaged="$damaged ${TAINT_BIT[$b]}"; fi
done
if [ -n "$damaged" ]; then
    bad "kernel is tainted:$damaged (tainted=$taint) — this host needs a reboot"
    bad "  RULE 2: a session never reboots clyde.  Report it and stop."
else
    ok "no BAD_PAGE / oops / soft-lockup / MCE taint (tainted=$taint)"
fi

# Uninterruptible-sleep tasks.  Read only /proc/<pid>/stat — never cmdline or
# maps (RULE 2c: those take each task's mmap_lock and hang forever on a task
# that is itself wedged holding it).
# The state is the field after the ")" that closes comm — comm itself may
# contain spaces and parentheses, so never index by whitespace from the left.
dcount=0
for s in /proc/[0-9]*/stat; do
    st=$(sed -e 's/.*) //' -e 's/ .*//' <"$s" 2>/dev/null) || continue
    [ "$st" = D ] && dcount=$((dcount + 1))
done
if [ "$dcount" -gt "$MAX_DSTATE" ]; then
    bad "$dcount tasks already in uninterruptible sleep (max $MAX_DSTATE) — a wedge is in progress"
else
    ok "$dcount tasks in uninterruptible sleep (max $MAX_DSTATE)"
fi

# ---------------------------------------------------------------------------
# 2. SCST target: does it carry the PR bounds fix, and is its trace mask sane?
# ---------------------------------------------------------------------------
echo "-- SCST target"
sver=$(modinfo scst 2>/dev/null | awk '/^version:/{print $2}')
if [ -z "$sver" ]; then
    warn "scst.ko not installed — nothing to check (no CAW rig on this host?)"
else
    minor=$(printf '%s' "$sver" | sed -n 's/.*+caw-abort-reclaim\.\([0-9]\+\)$/\1/p')
    if [ -z "$minor" ] || [ "$minor" -lt 4 ]; then
        bad "scst $sver predates the PR READ FULL STATUS bounds fix (.4)"
        bad "  that build corrupts host memory once the registrant list"
        bad "  outgrows an initiator's probe buffer — see tests/scst_pr_bounds_check.sh"
    else
        ok "scst $sver carries the PR bounds fix"
    fi
fi

if [ -f "$SCST_ROOT/trace_level" ]; then
    mask=$(head -1 "$SCST_ROOT/trace_level" 2>/dev/null)
    # ALLOWLIST, not a hazard list.  A hazard list has to name the dangerous
    # flag correctly and stay current: the first version of this check looked
    # for "blocking", while SCST's token for TRACE_BLOCKING is "block" — it
    # would have missed the exact flag that wedged clyde on 2026-08-20, and
    # would miss any flag added to SCST later.
    #
    # This is the union of SCST_DEFAULT_LOG_FLAGS for the debug and release
    # builds (scst/src/scst_priv.h).  Anything else was switched on by hand.
    ALLOWED=" out_of_mem minor pid line function special mgmt mgmt_dbg retry "
    hot=""
    for f in $(printf '%s' "$mask" | tr '|' ' '); do
        case "$f" in
            '['*) continue ;;   # sysfs appends a trailing "[key]" marker
        esac
        case "$ALLOWED" in *" $f "*) ;; *) hot="$hot $f" ;; esac
    done
    if [ -n "$hot" ]; then
        if [ "${MXFS_PREFLIGHT_ALLOW_TRACE:-0}" = 1 ]; then
            warn "high-volume SCST trace flags enabled:$hot (allowed by override)"
            warn "  turn them off the moment the investigation ends:"
            warn "  echo default | sudo tee $SCST_ROOT/trace_level"
        else
            bad "high-volume SCST trace flags enabled:$hot"
            bad "  this is what wedged clyde on 2026-08-20 (1.07M kernel lines/98min)"
            bad "  fix: echo default | sudo tee $SCST_ROOT/trace_level"
        fi
    else
        ok "SCST trace mask has no per-IO flags"
    fi
else
    ok "SCST not loaded (no trace mask to check)"
fi

# ---------------------------------------------------------------------------
# 3. Kernel log rate.  A runaway trace point is ~180 lines/s; the rig at rest
#    is well under 1/s.  Sample new messages only.
# ---------------------------------------------------------------------------
echo "-- kernel log rate"
# kernel.dmesg_restrict=1 on this host, so this needs root.  If the sample
# cannot be taken, say so and FAIL — an unreadable log reads exactly like a
# quiet one, and treating "cannot check" as "OK" is how the 2026-08-20 flood
# would sail through this gate.
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"
if ! $SUDO dmesg --follow-new --help >/dev/null 2>&1 &&
   ! $SUDO dmesg -W --help >/dev/null 2>&1; then
    probe_ok=0
else
    probe_ok=1
fi
lines=$($SUDO timeout "$KMSG_SECS" dmesg --follow-new --notime 2>/dev/null | wc -l)
if [ "$probe_ok" -eq 0 ] || ! $SUDO dmesg --notime >/dev/null 2>&1; then
    bad "cannot read the kernel log (dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null))"
    bad "  the log-rate check is the flood detector — run this with sudo"
    rate=-1
else
    rate=$(( lines / (KMSG_SECS > 0 ? KMSG_SECS : 1) ))
fi
if [ "$rate" -lt 0 ]; then
    :
elif [ "$rate" -gt "$KMSG_MAX" ]; then
    bad "kernel log is producing ~${rate} lines/s (max $KMSG_MAX) over ${KMSG_SECS}s"
    bad "  something is flooding dmesg; find it before starting a fleet run"
else
    ok "kernel log ~${rate} lines/s over ${KMSG_SECS}s (max $KMSG_MAX)"
fi

# ---------------------------------------------------------------------------
# 4. Free space on every filesystem the rig writes to.
#
# The shared LUN, all 32 guest qcow2 images and the persistent journal share
# ONE ext4 on clyde.  At 92% full that single jbd2 journal is what serialises
# the whole rig; it is also what deadlocked on 2026-08-20.
# ---------------------------------------------------------------------------
echo "-- filesystem headroom"
declare -A seen=()
# Two policies, because the risk is not the same.
#
# LOCAL filesystems on clyde share the jbd2 journal that carries the LUN, the
# guest images and the journal, and that is the thing that deadlocked on
# 2026-08-20 — they get the tight percentage + absolute limits.
#
# NETWORK filesystems (the /src NFS tree) cannot wedge this host's journal.
# A 12TB server sitting at 89% with 1.3TB free is fine; only genuinely running
# out of room there matters, because it breaks builds.  Applying the local
# percentage rule to it produces a blocking failure with no hazard behind it,
# which is exactly the kind of noise that gets a gate switched off.
NET_MIN_FREE_GB="${MXFS_PREFLIGHT_NET_MIN_FREE_GB:-20}"
check_fs() {
    local path="$1" label="$2" src fstype pct free_gb
    [ -e "$path" ] || return 0
    src=$(df -PT "$path" 2>/dev/null | awk 'NR==2{print $1}')
    fstype=$(df -PT "$path" 2>/dev/null | awk 'NR==2{print $2}')
    [ -n "$src" ] || return 0
    [ -n "${seen[$src]:-}" ] && return 0
    seen[$src]=1
    pct=$(df -P "$path" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    free_gb=$(df -PBG "$path" 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}')
    case "$fstype" in
        nfs|nfs4|cifs|smb3|fuse.sshfs)
            if [ "${free_gb:-0}" -lt "$NET_MIN_FREE_GB" ]; then
                bad "$label ($src, $fstype): only ${free_gb}G free (>=${NET_MIN_FREE_GB}G) — builds will fail"
            else
                ok "$label ($src, $fstype): ${pct}% used, ${free_gb}G free (remote — not a host-wedge risk)"
            fi
            ;;
        *)
            if [ "${pct:-100}" -ge "$MAX_USE_PCT" ] || [ "${free_gb:-0}" -lt "$MIN_FREE_GB" ]; then
                bad "$label ($src): ${pct}% used, ${free_gb}G free (limits: <${MAX_USE_PCT}%, >=${MIN_FREE_GB}G)"
                bad "  this filesystem carries the LUN/images/journal — see docs/host-safety.md"
            else
                ok "$label ($src): ${pct}% used, ${free_gb}G free"
            fi
            ;;
    esac
}
check_fs "$IMG"        "shared LUN"
check_fs "$VMDIR"      "guest images"
check_fs /var/log      "journal"
check_fs "$REPO"       "source tree"

# Structural warning: the coupling itself, which no threshold can remove.
lun_src=$(df -P "$IMG" 2>/dev/null | awk 'NR==2{print $1}')
vm_src=$(df -P "$VMDIR" 2>/dev/null | awk 'NR==2{print $1}')
log_src=$(df -P /var/log 2>/dev/null | awk 'NR==2{print $1}')
if [ -n "$lun_src" ] && [ "$lun_src" = "$vm_src" ] && [ "$lun_src" = "$log_src" ]; then
    # ACCEPTED CONSTRAINT, not an action item: the operator is not local to
    # this machine and cannot add a device, so the LUN, the guest images and
    # the journal stay on one filesystem with one jbd2 journal.  Stated as a
    # note rather than a warning — a warning that repeats every run and cannot
    # be acted on just teaches people to ignore warnings.  The compensating
    # controls are the tight headroom limits above, the trace-mask check, and
    # the kmsg guard's flood trip.
    printf '  NOTE  LUN + guest images + journal share %s (one jbd2 journal).\n' "$lun_src"
    printf '        Cannot be separated on this host; headroom limits above are\n'
    printf '        set tight because they are the only lever.\n'
fi

# ---------------------------------------------------------------------------
# 5. journald must be capped, so a log flood cannot eat the filesystem the
#    rig runs on even if it does get past the checks above.
# ---------------------------------------------------------------------------
echo "-- journald caps"
jconf=$(grep -hsvE '^\s*#|^\s*$' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null)
if printf '%s' "$jconf" | grep -qi '^SystemMaxUse='; then
    ok "journald has SystemMaxUse set ($(printf '%s' "$jconf" | grep -i '^SystemMaxUse=' | head -1))"
else
    warn "journald has no SystemMaxUse cap — a kernel log flood is unbounded on disk"
fi

echo
if [ "$MODE" = "--report" ]; then
    echo "clyde_preflight: $fails failure(s), $warns warning(s) (report mode — not gating)"
    exit 0
fi
if [ "$fails" -gt 0 ]; then
    echo "clyde_preflight: FAIL ($fails blocking, $warns warning) — DO NOT START A FLEET RUN"
    exit 1
fi
echo "clyde_preflight: PASS ($warns warning)"
exit 0
