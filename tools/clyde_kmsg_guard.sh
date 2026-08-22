#!/bin/bash
# clyde_kmsg_guard.sh — host-safety watchdog.  Tails the kernel log and halts
# the rig the moment the host starts reporting damage, instead of letting the
# damage escalate into an unrecoverable wedge.
#
# WHY
# ---
# Both times clyde wedged (2026-08-20, 2026-08-21) the kernel said so first,
# and nothing was listening:
#
#   2026-08-21 08:25:22  scst: ***ERROR***: Too big response data len 4496 (max 4096)
#   2026-08-21 08:52:58  scst: ***ERROR***: Too big response data len 4848 (max 4096)
#   2026-08-21 09:03:00  scst: ***ERROR***: Too big response data len 5024 (max 4096)
#   2026-08-21 09:05:24  BUG: Bad page map in process CPU 1/KVM  -> Oops -> host dead
#
# That is a 38-minute warning followed by a 2m24s warning.  Either window was
# more than enough to stop the workload and save the host.
#
# WHAT IT DOES
# ------------
#   PRECURSOR  (target/driver is misbehaving but memory is not known-corrupt):
#              write the halt flag + snapshot evidence.  The harness stops
#              starting work.  Nothing is killed — a false positive costs a
#              paused campaign, not a paused host.
#   CORRUPTION (bad page / BUG / Oops / soft lockup / RCU stall):
#              halt flag + evidence, then bound-pause the guests so they stop
#              driving I/O into a kernel that is already damaged.
#
# Deliberately NOT done, and why (RULE 2 / RULE 2c):
#   - never reboots or sysrqs clyde: host recovery is the user's call;
#   - never `virsh destroy`: it blocks in QMP/__fput/fs teardown on exactly the
#     domains that matter (measured 2026-08-20: every one timed out);
#   - never rmmod/unloads SCST, never dmsetup, never a global `sync` — each of
#     those joins the queue behind the stuck resource instead of relieving it;
#   - evidence goes to /src (NFS, a different server), never to clyde's root
#     ext4, which is the filesystem the wedge is usually about.
#
# Usage:
#   tools/clyde_kmsg_guard.sh run        # foreground (systemd calls this)
#   tools/clyde_kmsg_guard.sh status
#   tools/clyde_kmsg_guard.sh clear      # clear the halt flag, deliberately
#   tools/clyde_kmsg_guard.sh selftest   # inject a benign precursor, prove it trips
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
HALT="${MXFS_RIG_HALT:-$REPO/.rig_halt}"
EVID="${MXFS_EVIDENCE_DIR:-$REPO/.evidence}"
PAUSE_GUESTS="${MXFS_GUARD_PAUSE_GUESTS:-1}"
VIRSH_TIMEOUT="${MXFS_GUARD_VIRSH_TIMEOUT:-15}"
# Flood trip.  The 2026-08-20 wedge ran at ~182 lines/s for 98 minutes; clyde's
# own kernel log during a full 32-node campaign is ~1 line/s (measured: 25,130
# lines over 6.7h on 2026-08-21), so 60/s is ~60x headroom.
#
# Short windows with a consecutive-window requirement, not one long window: a
# fixed window that a flood starts in the middle of dilutes the measured rate
# below the threshold and the flood escapes (observed while testing this).  Two
# consecutive hot 5s windows catches a sustained flood in ~10s while ignoring a
# one-off burst.
FLOOD_RATE="${MXFS_GUARD_FLOOD_RATE:-60}"
FLOOD_WINDOW="${MXFS_GUARD_FLOOD_WINDOW:-5}"
FLOOD_WINDOWS_HOT="${MXFS_GUARD_FLOOD_WINDOWS_HOT:-2}"

# Anything here means "the host is telling us it is damaged".  Keep this list
# short and specific: a noisy guard gets disabled, and a disabled guard is how
# both wedges happened.
CORRUPTION_RE='Bad page map|BUG: unable to handle|Oops: |general protection fault|kernel BUG at|soft lockup|hard LOCKUP|rcu_preempt (self-)?detected|detected stalls on CPU|blocked for more than [0-9]+ seconds|list_del corruption|slab corruption|refcount_t: '
# Precursors: a driver reporting that it exceeded a buffer, or a filesystem
# aborting.  These precede corruption; they are not corruption themselves.
PRECURSOR_RE='Too big response data len|EXT4-fs error|JBD2: |I/O error, dev nvme|Remounting filesystem read-only'

now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

snapshot() {
    local why="$1" line="$2" dir
    dir="$EVID/guard_$(date -u '+%Y%m%d_%H%M%S')_$$"
    mkdir -p "$dir" 2>/dev/null || return 0
    {
        echo "when:    $(now)"
        echo "why:     $why"
        echo "trigger: $line"
        echo "uptime:  $(uptime)"
        echo "tainted: $(cat /proc/sys/kernel/tainted 2>/dev/null)"
    } > "$dir/trigger.txt" 2>/dev/null
    # Cheap and RULE-2c-safe.  No cmdline, no maps, no pgrep -f, no ps aux.
    cat /proc/loadavg               > "$dir/loadavg"  2>/dev/null
    grep -E 'MemTotal|MemAvailable|Dirty|Writeback' /proc/meminfo \
                                    > "$dir/meminfo"  2>/dev/null
    df -P                           > "$dir/df"       2>/dev/null
    cat /proc/diskstats             > "$dir/diskstats" 2>/dev/null
    for s in /proc/[0-9]*/stat; do
        st=$(sed -e 's/.*) //' -e 's/ .*//' <"$s" 2>/dev/null) || continue
        [ "$st" = D ] || continue
        p=${s%/stat}; p=${p#/proc/}
        echo "$p $(cat "/proc/$p/comm" 2>/dev/null)" >> "$dir/dstate" 2>/dev/null
        cat "/proc/$p/stack" >> "$dir/dstate_stacks" 2>/dev/null
    done
    timeout 20 dmesg --notime 2>/dev/null | tail -400 > "$dir/dmesg_tail" 2>/dev/null
    echo "$dir"
}

halt_rig() {
    local why="$1" line="$2" dir
    [ -f "$HALT" ] && return 0          # already halted; do not re-trigger
    dir=$(snapshot "$why" "$line")
    {
        echo "RIG HALTED $(now)"
        echo "reason:   $why"
        echo "trigger:  $line"
        echo "evidence: ${dir:-<none>}"
        echo
        echo "The host reported damage.  Do NOT start a fleet run until the"
        echo "cause is understood.  RULE 2: only the user reboots clyde."
        echo "Clear deliberately with: tools/clyde_kmsg_guard.sh clear"
    } > "$HALT" 2>/dev/null
    # Mirror host-locally, so the halt survives /src (NFS) being unreachable.
    mkdir -p /var/lib/mxfs 2>/dev/null
    cp -f "$HALT" /var/lib/mxfs/rig_halt 2>/dev/null
    logger -t mxfs-guard "RIG HALTED: $why: $line" 2>/dev/null
    echo "[$(now)] HALT ($why): $line" >&2
}

pause_guests() {
    local d
    echo "[$(now)] pausing guests (bounded ${VIRSH_TIMEOUT}s each, no destroy)" >&2
    for d in $(timeout "$VIRSH_TIMEOUT" sudo virsh -c qemu:///system list --name 2>/dev/null); do
        [ -n "$d" ] || continue
        # virsh suspend is QMP "stop": it freezes vCPUs without touching the
        # domain's file descriptors or block layer.  Bounded, never retried —
        # a domain that will not suspend is already wedged, and hammering it
        # only adds another stuck task (RULE 2c).
        timeout "$VIRSH_TIMEOUT" sudo virsh -c qemu:///system suspend "$d" \
            >/dev/null 2>&1 &
    done
    wait
}

run() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "clyde_kmsg_guard: must run as root (kernel.dmesg_restrict=1)" >&2
        exit 2
    fi
    mkdir -p "$EVID" 2>/dev/null
    echo "[$(now)] clyde_kmsg_guard watching (halt flag: $HALT)" >&2
    local win_start=$SECONDS count=0 elapsed rate hot=0
    # Matching is done with bash's own =~ and $SECONDS, never `grep`/`date`
    # subshells: under the very flood this is meant to catch (measured
    # 2026-08-20 at 182 lines/s) a fork-per-line watcher would add hundreds of
    # processes per second to a host that is already in trouble.
    #
    # --follow-new: only messages produced from now on.  Never re-reads the
    # ring, so a restart cannot re-trigger on an old, already-handled event.
    dmesg --follow-new --notime 2>/dev/null | while IFS= read -r line; do
        if [[ $line =~ $CORRUPTION_RE ]]; then
            halt_rig CORRUPTION "$line"
            [ "$PAUSE_GUESTS" = 1 ] && pause_guests
        elif [[ $line =~ $PRECURSOR_RE ]]; then
            halt_rig PRECURSOR "$line"
        fi

        # Sustained kernel-log flood.  This is wedge A in one line: the volume
        # itself is the hazard, because every message journald persists is a
        # transaction on the root ext4 that also carries the LUN and all 32
        # guest images.  Nothing legitimate on this host logs at this rate.
        count=$((count + 1))
        elapsed=$((SECONDS - win_start))
        if [ "$elapsed" -ge "$FLOOD_WINDOW" ]; then
            rate=$((count / elapsed))
            if [ "$rate" -gt "$FLOOD_RATE" ]; then
                hot=$((hot + 1))
                if [ "$hot" -ge "$FLOOD_WINDOWS_HOT" ]; then
                    halt_rig FLOOD "kernel log at ~${rate} lines/s for ${hot} consecutive ${elapsed}s windows (max $FLOOD_RATE) — last: $line"
                    hot=0
                fi
            else
                hot=0
            fi
            win_start=$SECONDS
            count=0
        fi
    done
}

case "${1:-status}" in
run)   run ;;
status)
    rc=0
    for h in "$HALT" /var/lib/mxfs/rig_halt; do
        [ -f "$h" ] || continue
        echo "RIG HALTED ($h):"; sed 's/^/  /' "$h"; rc=1
    done
    [ "$rc" -eq 0 ] && echo "rig not halted"
    exit "$rc"
    ;;
clear)
    # Clears both the repo flag and the host-local one the crash latch writes.
    cleared=0
    for h in "$HALT" /var/lib/mxfs/rig_halt; do
        [ -f "$h" ] || continue
        echo "clearing $h; it said:"; sed 's/^/  /' "$h"
        rm -f "$h" && cleared=1
    done
    [ "$cleared" -eq 1 ] && echo "cleared." || echo "no halt flag to clear."
    ;;
selftest)
    # Injects a benign line that matches the PRECURSOR pattern and checks the
    # guard trips.  Proves the watcher is alive without corrupting anything.
    [ "$(id -u)" -eq 0 ] || { echo "selftest must run as root" >&2; exit 2; }
    echo "mxfs guard selftest: Too big response data len 1 (max 0) (dev selftest)" \
        > /dev/kmsg
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -f "$HALT" ] && { echo "selftest: guard tripped."; sed 's/^/  /' "$HALT"; exit 0; }
        sleep 1
    done
    echo "selftest: guard did NOT trip within 10s — is it running?" >&2
    exit 1
    ;;
*) echo "usage: $0 {run|status|clear|selftest}" >&2; exit 2 ;;
esac
