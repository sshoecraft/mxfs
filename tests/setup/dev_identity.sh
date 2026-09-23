#!/bin/sh
# tests/setup/dev_identity.sh — what IS this block device?  Runs ON a node.
#
# A path is a locator, not an instrument: /dev/sda is the shared LUN on one
# rig and a path member of a multipath map on another, /dev/mapper/mpatha
# exists on one rig only, and a path that names another valid device (the
# root disk) answers every probe with well-formed output about the wrong
# thing.  This prints the device's identity so the caller can compare it with
# what the rig declares (data/rigs.json) instead of trusting the spelling:
#
#   IDENT path=<resolved> mm=<major:minor> wwid=<naa...|none> fsid=<uuid|none|unreadable> mounted=<mountpoint|-> livemm=<major:minor of the node's live mxfs mount|->
#
# wwid: the SCSI identifier from /sys/block/<disk>/device/wwid; for a
# device-mapper multipath map the map's dm uuid (mpath-<wwid>); for a
# partition its parent disk's.  `none` when the device carries no such
# identity (a virtio disk): that is the absence of evidence, and the caller
# treats it as a refusal, never as a fallback to path, size or model.
# fsid: the MXFS envelope superblock's copy of the XFS uuid, read with a
# direct 4 KiB read of sector 0 (magic "MXFS" little-endian at byte 0, the
# uuid at byte 16), so a format is visible immediately and the page cache
# cannot answer for the platter; `none` when there is no MXFS magic (an
# unformatted or foreign device), `unreadable` when the read itself failed.
# mounted: where THIS device is mounted as mxfs on the node, if anywhere.
# livemm: the node's live mxfs mount whatever device backs it, so the caller
# can tell "the candidate is not the filesystem under test" from "nothing is
# mounted".
#
# Usage: dev_identity.sh <path>            (exit 0 always; the line is the answer;
#                                           an absent path prints "IDENT path=<p> absent")
P=${1:?path}
d=$(readlink -f "$P" 2>/dev/null)
if [ -z "$d" ] || [ ! -b "$d" ]; then echo "IDENT path=$P absent"; exit 0; fi
b=${d#/dev/}
w=$(cat "/sys/block/$b/device/wwid" 2>/dev/null)
[ -n "$w" ] || w=$(sed -n 's/^mpath-//p' "/sys/block/$b/dm/uuid" 2>/dev/null)
if [ -z "$w" ]; then
    parent=$(echo "$b" | sed 's/p\{0,1\}[0-9]*$//')
    [ "$parent" != "$b" ] && w=$(cat "/sys/block/$parent/device/wwid" 2>/dev/null)
fi
mm=$(( 0x$(stat -Lc %t "$d") )):$(( 0x$(stat -Lc %T "$d") ))
h=$(dd if="$d" bs=4096 count=1 iflag=direct 2>/dev/null | od -An -tx1 -N32 -v | tr -d ' \n')
case "$h" in
    4d584653*) u=$(echo "$h" | cut -c33-64); f="$(echo "$u" | cut -c1-8)-$(echo "$u" | cut -c9-12)-$(echo "$u" | cut -c13-16)-$(echo "$u" | cut -c17-20)-$(echo "$u" | cut -c21-32)" ;;
    '') f=unreadable ;;
    *) f=none ;;
esac
# mountinfo: <id> <parent> <major:minor> <root> <mountpoint> <opts> [tags...] - <fstype> <source> <superopts>
m=$(awk -v mm="$mm" '{fst=""; for (i = 7; i <= NF; i++) if ($i == "-") { fst = $(i + 1); break } } $3 == mm && fst == "mxfs" { print $5; exit }' /proc/self/mountinfo)
lm=$(awk '{fst=""; for (i = 7; i <= NF; i++) if ($i == "-") { fst = $(i + 1); break } } fst == "mxfs" { print $3; exit }' /proc/self/mountinfo)
echo "IDENT path=$d mm=$mm wwid=$(echo "${w:-none}" | tr -d ' ') fsid=$f mounted=${m:--} livemm=${lm:--}"
