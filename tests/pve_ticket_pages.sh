#!/bin/bash
# pve_ticket_pages.sh — every lock-ledger page that carries a commit ticket on
# a two-host Proxmox pair running MXFS on DRBD, and whether a lock request on
# such a page still gets through.
#
# A ledger commit claims the page's spare copy with a ticket, writes under it
# and publishes; a writer that dies in between leaves its ticket there.  Until
# 0.90.92 the store let a later writer take that ticket over only when THIS
# mount had recovered the dead one, so once that mount was gone the page could
# never be written again and every lock routed to it failed (the physical pair,
# 0.90.91: pages 9762, 10942 and 13005, a survivor's mkdir EAGAIN).
#
# On participant 0: list the ticketed page copies (tools/tauth_page_auth.py
# --tickets, read O_DIRECT from the device), walk the mount for every inode
# whose lock routes to one of those pages (--route-inodes), and make a request
# on each, timed on its own: a stat (the inode's shared lock), and for a
# directory a mkdir and rmdir inside it (its exclusive lock).  Then the census
# again.  Fails when a request fails or takes longer than OP_BUDGET_MS, or
# when a ticket is still on a page a request reached.  Exit 0 pass, 1 fail,
# 2 setup refused, 3 not exercised (no ticket, or no inode of the mount routes
# to a ticketed page).
#
# Usage: tests/pve_ticket_pages.sh
# Env:
#   PVE_PAIR       "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#                  participant 0 is the lower address
#   RES / MNT      DRBD resource and mount point (default mxfs, /mnt/shared)
#   OP_BUDGET_MS   the longest one request may take (default 30000: a guest's
#                  own I/O timeout)
#   WALK_BUDGET    seconds for the walk of the mount (default 120)
#
# Evidence: tests/evidence/pve_ticket_pages/<UTC stamp>-<participant 0>/.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
TOOL="$REPO/tools/tauth_page_auth.py"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_ticket_pages: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
OP_BUDGET_MS=${OP_BUDGET_MS:-30000}
WALK_BUDGET=${WALK_BUDGET:-120}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}
else
    P0=${PAIR[1]}
fi
OUT=$REPO/tests/evidence/pve_ticket_pages/$(date -u +%Y%m%dT%H%M%SZ)-$P0
mkdir -p "$OUT" || exit 2
T0=$(date +%s)
say() { echo "[$(date +%H:%M:%S) +$(( $(date +%s) - T0 ))s] $*"; }
on() {  # <cmd> <timeout> [stdin file]
    timeout "$2" "$SSHP" "$P0" "$1" < "${3:-/dev/null}" 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

dev=$(on "drbdadm sh-dev $RES" 20)
case "$dev" in /dev/*) ;; *) echo "pve_ticket_pages: no DRBD device for $RES on $P0: $dev"; exit 2 ;; esac
on "awk '\$2 == \"$MNT\" && \$3 == \"mxfs\"' /proc/mounts | grep -q ." 20 \
    || { echo "pve_ticket_pages: $MNT is not an MXFS mount on $P0"; exit 2; }
say "$P0: $(on "echo build=\$(cat /sys/module/mxfs/srcversion) ver=\$(cat /sys/module/mxfs/version)" 20) device $dev"

census() {  # <file>
    on "python3 -I - $dev --tickets" 120 "$TOOL" > "$1"
    grep -E '^TICKET ' "$1" | sed 's/^/  /'
    grep -E '^TICKETS ' "$1" | sed 's/^/  /'
}
say "tickets before:"
census "$OUT/tickets.before"
mapfile -t PAGES < <(sed -n 's/^TICKET page=\([0-9]*\) .*/\1/p' "$OUT/tickets.before" | sort -un)
if [ "${#PAGES[@]}" = 0 ]; then
    say "NOT EXERCISED: no ticket on any page, nothing to request; evidence $OUT"
    exit 3
fi

# every inode of the mount, by number and by path; /dev/shm because /run on a
# Proxmox host is noexec and the tool reads the list as a plain file there
on "timeout $WALK_BUDGET find $MNT -xdev -printf '%i %y %p\n' > /dev/shm/mxfs-ticket-walk; echo WALK_RC=\$?; cut -d' ' -f1 /dev/shm/mxfs-ticket-walk > /dev/shm/mxfs-ticket-inodes; wc -l < /dev/shm/mxfs-ticket-inodes" \
    $((WALK_BUDGET + 30)) > "$OUT/walk.out"
grep -q 'WALK_RC=0' "$OUT/walk.out" || { say "FAIL: the walk of $MNT did not finish: $(tr '\n' ' ' < "$OUT/walk.out")"; exit 1; }
say "walked $(tail -1 "$OUT/walk.out") inodes"
on "python3 -I - $dev --route-inodes /dev/shm/mxfs-ticket-inodes" 120 "$TOOL" > "$OUT/route.out"
want=" $(printf '%s ' "${PAGES[@]}")"
grep -E '^ROUTE ' "$OUT/route.out" | while read -r _ ino page _rest; do
    p=${page#page=}
    case "$want" in *" $p "*) echo "${ino#ino=} $p" ;; esac
done > "$OUT/targets"
say "inodes routed to a ticketed page: $(wc -l < "$OUT/targets") ($(cut -d' ' -f2 "$OUT/targets" | sort -un | tr '\n' ' '))"
if [ ! -s "$OUT/targets" ]; then
    on "rm -f /dev/shm/mxfs-ticket-walk /dev/shm/mxfs-ticket-inodes" 20 >/dev/null
    say "NOT EXERCISED: no inode of $MNT routes to a ticketed page, so no request can reach one; evidence $OUT"
    exit 3
fi

# the requests, timed one by one on the host: a stat, and for a directory a
# mkdir and rmdir inside it
python3 -I - "$OUT/targets" > "$OUT/requests.py" <<'PY'
import sys
targets = [l.split() for l in open(sys.argv[1]) if l.strip()]
print("import os, sys, time")
print("walk = {}")
print("for l in open('/dev/shm/mxfs-ticket-walk'):")
print("    f = l.rstrip('\\n').split(' ', 2)")
print("    if len(f) == 3: walk[f[0]] = (f[1], f[2])")
print("def timed(fn, *a):")
print("    t = time.monotonic()")
print("    try:")
print("        fn(*a); err = ''")
print("    except OSError as e:")
print("        err = '%s(%d)' % (e.strerror, e.errno)")
print("    return (time.monotonic() - t) * 1000.0, err")
print("for ino, page in %r:" % (targets,))
print("    kind, path = walk.get(ino, ('?', ''))")
print("    if not path:")
print("        print('REQ ino=%s page=%s op=lookup ms=0 err=not-in-walk' % (ino, page)); continue")
print("    ms, err = timed(os.stat, path)")
print("    print('REQ ino=%s page=%s op=stat ms=%.0f err=%s path=%s' % (ino, page, ms, err or '-', path))")
print("    if kind == 'd':")
print("        probe = os.path.join(path, '.mxfs-ticket-probe-%d' % os.getpid())")
print("        ms, err = timed(os.mkdir, probe)")
print("        print('REQ ino=%s page=%s op=mkdir ms=%.0f err=%s path=%s' % (ino, page, ms, err or '-', probe))")
print("        if not err:")
print("            ms, err = timed(os.rmdir, probe)")
print("            print('REQ ino=%s page=%s op=rmdir ms=%.0f err=%s path=%s' % (ino, page, ms, err or '-', probe))")
PY
n=$(wc -l < "$OUT/targets")
on "python3 -I -" $(( n * 3 * OP_BUDGET_MS / 1000 + 60 )) "$OUT/requests.py" > "$OUT/requests.out"
grep -E '^REQ ' "$OUT/requests.out" | cut -c1-200 | sed 's/^/  /'
bad=$(awk -v b="$OP_BUDGET_MS" '/^REQ / { ms = $5; sub("ms=", "", ms); err = $6; if (err != "err=-" || ms + 0 > b) n++ } END { print n + 0 }' "$OUT/requests.out")
reqs=$(grep -c '^REQ ' "$OUT/requests.out")

say "tickets after:"
census "$OUT/tickets.after"
left=0
for p in $(cut -d' ' -f2 "$OUT/targets" | sort -un); do
    if grep -qE "^TICKET page=$p " "$OUT/tickets.after"; then
        say "FAIL: page $p still carries a ticket after a request reached it"
        left=$((left + 1))
    fi
done
on "rm -f /dev/shm/mxfs-ticket-walk /dev/shm/mxfs-ticket-inodes" 20 >/dev/null
if [ "$bad" != 0 ] || [ "$reqs" = 0 ] || [ "$left" != 0 ]; then
    say "FAIL: $bad of $reqs requests failed or overran ${OP_BUDGET_MS} ms; $left requested page(s) still ticketed; evidence $OUT"
    exit 1
fi
say "PASS: $reqs requests on ${#PAGES[@]} ticketed page(s) went through; no requested page still ticketed; evidence $OUT"
