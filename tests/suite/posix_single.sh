#!/bin/bash
# posix_single — single-node POSIX semantics on one mount point. Agnostic:
# takes only the mount point ($1, default /mnt/shared). No coordination.
#
# Exercises the core POSIX operations a filesystem must get right and verifies
# each: create/read/write/append, size & truncate, rename, hard/sym links,
# permissions, unlink semantics, fifo, directory ops, timestamps, fsync, and a
# multi-MB write→read integrity round-trip.

SUITE_TEST_NAME=posix_single
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

W="$MNT/.suite_posix_single.$(hostname).$$"
rm -rf "$W" 2>/dev/null
if ! mkdir -p "$W"; then
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=cannot mkdir $W"
    exit 1
fi
trap 'rm -rf "$W" /tmp/posix_single.$$.* 2>/dev/null' EXIT

# --- directory create/remove ---
mkdir "$W/d1";                 ck  "mkdir"            test -d "$W/d1"
rmdir "$W/d1";                 ck  "rmdir"            test ! -e "$W/d1"

# --- file content / size ---
printf 'ABC' > "$W/f";         ckeq "write content"  "ABC" "$(cat "$W/f")"
ckeq "size==3"                 "3"   "$(stat -c %s "$W/f")"
printf 'DE' >> "$W/f";         ckeq "append content" "ABCDE" "$(cat "$W/f")"
ckeq "append size==5"          "5"   "$(stat -c %s "$W/f")"

# --- truncate grow / shrink ---
truncate -s 100 "$W/f";        ckeq "trunc grow"     "100" "$(stat -c %s "$W/f")"
truncate -s 2 "$W/f";          ckeq "trunc shrink sz" "2"  "$(stat -c %s "$W/f")"
ckeq "trunc shrink data"       "AB"  "$(cat "$W/f")"

# --- rename ---
mv "$W/f" "$W/g";              ck  "rename dst"       test -f "$W/g"
ck  "rename src gone"          test ! -e "$W/f"

# --- hard link (same inode, nlink=2) ---
ln "$W/g" "$W/h"
ckeq "hardlink inode"          "$(stat -c %i "$W/g")" "$(stat -c %i "$W/h")"
ckeq "hardlink nlink"          "2"   "$(stat -c %h "$W/g")"

# --- symlink ---
ln -s "g" "$W/s";              ck  "symlink is link"  test -L "$W/s"
ckeq "readlink target"         "g"   "$(readlink "$W/s")"

# --- permissions ---
chmod 600 "$W/g";              ckeq "chmod 600"       "600" "$(stat -c %a "$W/g")"
chmod 755 "$W/g";              ckeq "chmod 755"       "755" "$(stat -c %a "$W/g")"

# --- unlink semantics: removing g leaves hardlink h with intact data ---
rm "$W/g"
ck  "unlink removes name"      test ! -e "$W/g"
ck  "hardlink survives"        test -f "$W/h"
ckeq "hardlink data intact"    "AB"  "$(cat "$W/h")"
ckeq "nlink back to 1"         "1"   "$(stat -c %h "$W/h")"

# --- fifo ---
mkfifo "$W/p" 2>/dev/null;     ck  "mkfifo"           test -p "$W/p"

# --- nested dirs + entry count ---
mkdir -p "$W/a/b/c";           ck  "nested mkdir"     test -d "$W/a/b/c"
ckeq "nested dir count"        "3"   "$(find "$W/a" -type d | wc -l)"   # a, a/b, a/b/c

# --- many small files ---
md="$W/many"; mkdir "$md"
for i in $(seq 1 200); do : > "$md/file_$i"; done
ckeq "200 files created"       "200" "$(ls -1 "$md" | wc -l)"

# --- directory rename with contents ---
mv "$md" "$W/many2"
ckeq "dir rename keeps count"  "200" "$(ls -1 "$W/many2" | wc -l)"

# --- mtime updates on write ---
t1="$W/mt"; : > "$t1"; m1=$(stat -c %Y "$t1"); sleep 1; echo x >> "$t1"; m2=$(stat -c %Y "$t1")
ck  "mtime advances on write"  test "$m2" -gt "$m1"

# --- fsync path (synchronous write) ---
ck  "synchronous write"        dd if=/dev/zero of="$W/sync" bs=4096 count=1 oflag=dsync status=none

# --- multi-MB write -> read integrity round-trip ---
src="/tmp/posix_single.$$.src"
head -c $((8*1024*1024)) /dev/urandom > "$src"
cp "$src" "$W/big"
ckeq "8MB md5 round-trip"      "$(md5sum < "$src" | awk '{print $1}')" "$(md5sum < "$W/big" | awk '{print $1}')"

finish
