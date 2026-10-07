#!/bin/bash
# pve_unwritten_live.sh — does a host see the blocks its peer wrote into an
# unwritten extent, when no change count moved between its two reads?
#
# A reload of an inode a host already has in core keeps the loaded extent map
# when the platter's dinode matches it on mode, generation, change count,
# nlink, format, size and extent count (P-RELOAD-IDENTICAL).  A write that
# converts the part of an unwritten extent right after a written one only
# grows the written extent: the extent count and size stay as they were, and
# the transaction logs the data fork alone, which on a clustered mount does
# not move di_changecount.  So a host that loaded the map between two such
# writes of its peer's would keep it, and read zeros where the peer wrote.
#
# Participant 1 fallocates a file and writes block 0 (O_DIRECT, fdatasync);
# participant 0 reads block 0, loading the map; participant 1 writes blocks 1
# .. COUNT-1 after it, each followed by fdatasync; participant 0 reads them
# all.  No host is reset: this runs beside other work on the pair.
#
# Usage: tests/pve_unwritten_live.sh
# Env:   PVE_PAIR (default the physical pair "192.168.1.80 192.168.1.81";
#        participant 0 is the lower address), COUNT (32), BLOCK (65536),
#        STRIDE (65536: back to back)
# Evidence: tests/evidence/pve_unwritten_live/<UTC stamp>-<participant 0>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PROG="$REPO/tests/pve_unwritten_replay.py"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_unwritten_live: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
COUNT=${COUNT:-32}
BLOCK=${BLOCK:-65536}
STRIDE=${STRIDE:-65536}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
EVID="$REPO/tests/evidence/pve_unwritten_live/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
die() { say "FAIL: $*"; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
on_prog() {  # <host> <args> [timeout]: the program fed on stdin
    timeout "${3:-60}" "$SSHP" "$1" "python3 - $2" <"$PROG" 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
build0=$(on "$P0" "cat /sys/module/mxfs/srcversion" 20); build1=$(on "$P1" "cat /sys/module/mxfs/srcversion" 20)
[ -n "$build0" ] && [ "$build0" = "$build1" ] || die "the hosts do not run one MXFS build: '$build0' / '$build1'"
say "unwritten live: participant 1 $P1 writes, participant 0 $P0 reads; build $build0; $COUNT blocks of $BLOCK bytes, $STRIDE apart; evidence $EVID"

F=$MNT/uwr/live-$STAMP
# An unwritten tail stays past the last block written: the write that reached
# the end would merge the two extents into one, change the extent count, log
# the core and move the change count, and nothing after it would be tested.
ino=$(on "$P1" "mkdir -p $MNT/uwr && fallocate -l $(( (COUNT + 8) * STRIDE )) $F && sync -f $MNT/uwr && stat -c %i $F" 60 | tail -1)
[ -n "$ino" ] && [ "$ino" -gt 0 ] 2>/dev/null || die "$P1 could not fallocate $F: $ino"
on_prog "$P1" "write $F 0 1 $BLOCK $STRIDE 0" 60 > "$EVID/writer0.out"
grep -q '^DURABLE 0$' "$EVID/writer0.out" || die "$P1 could not write block 0: $(tail -2 "$EVID/writer0.out")"
on_prog "$P0" "read $F $BLOCK $STRIDE 0" 60 > "$EVID/read0.$P0"
grep -q '^REGION 0 OK ' "$EVID/read0.$P0" || die "$P0 does not read block 0 as written: $(cat "$EVID/read0.$P0")"
say "  $P1 fallocated $F (inode $ino) and wrote block 0; $P0 read it back intact (map loaded)"
on_prog "$P1" "write $F 1 $(( COUNT - 1 )) $BLOCK $STRIDE 0" 120 > "$EVID/writer1.out"
nd=$(grep -c '^DURABLE ' "$EVID/writer1.out")
[ "$nd" = $(( COUNT - 1 )) ] || die "$P1 wrote $nd of $(( COUNT - 1 )) blocks: $(tail -2 "$EVID/writer1.out")"
say "  $P1 wrote blocks 1..$(( COUNT - 1 )), each fdatasync'ed"
on_prog "$P0" "read $F $BLOCK $STRIDE $(seq -s ' ' 0 $(( COUNT - 1 )))" 120 > "$EVID/read.$P0"
on_prog "$P1" "read $F $BLOCK $STRIDE $(seq -s ' ' 0 $(( COUNT - 1 )))" 120 > "$EVID/read.$P1"
v0=$(awk '{print $3}' "$EVID/read.$P0" | sort | uniq -c | tr '\n' ' ')
v1=$(awk '{print $3}' "$EVID/read.$P1" | sort | uniq -c | tr '\n' ' ')
say "  $P0 reads the $COUNT blocks: $v0"
say "  $P1 reads the $COUNT blocks: $v1"
n0=$(grep -c ' OK ' "$EVID/read.$P0"); n1=$(grep -c ' OK ' "$EVID/read.$P1")
[ "$n0" = "$COUNT" ] && [ "$n1" = "$COUNT" ] || die "$P0 reads $n0 of $COUNT blocks as written ($v0), $P1 reads $n1 ($v1); first bad on $P0: $(grep -v ' OK ' "$EVID/read.$P0" | head -2 | tr '\n' ' ')"
on "$P1" "rm -f $F" 30 >/dev/null
say "PASS: $P0 reads every block $P1 wrote after $P0 had loaded the file's map"
