#!/bin/bash
# integrity_filetypes — exercises file/dir shapes a filesystem must handle:
# sparse files, a large file round-trip, deep directory nesting, awkward
# filenames (255-char, spaces/specials), hardlink fan-out, dangling symlinks,
# xattrs (if the tools exist), and cross-directory rename. Agnostic: $1 = mount.

SUITE_TEST_NAME=integrity_filetypes
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

W="$MNT/.suite_integrity.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || {
    echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=cannot mkdir $W"; exit 1; }
trap 'rm -rf "$W" /tmp/intf.$$.* 2>/dev/null' EXIT

# --- sparse file: 256MB apparent, ~1 byte allocated ---
sp="$W/sparse"
dd if=/dev/zero of="$sp" bs=1 count=1 seek=$((256*1024*1024 - 1)) status=none
ckeq "sparse apparent size" "$((256*1024*1024))" "$(stat -c %s "$sp")"
blk=$(stat -c %b "$sp")
ck "sparse allocation small" test $((blk * 512)) -lt $((16*1024*1024))

# --- large file 128MB write -> read integrity ---
src="/tmp/intf.$$.src"
head -c $((128*1024*1024)) /dev/urandom > "$src"
cp "$src" "$W/big"
ckeq "128MB size" "$((128*1024*1024))" "$(stat -c %s "$W/big")"
ckeq "128MB md5" "$(md5sum < "$src" | awk '{print $1}')" "$(md5sum < "$W/big" | awk '{print $1}')"

# --- deep directory nesting (50 levels) ---
deep="$W"; for i in $(seq 1 50); do deep="$deep/d$i"; done
mkdir -p "$deep"; echo ok > "$deep/leaf"
ckeq "deep-tree leaf read" "ok" "$(cat "$deep/leaf")"

# --- 255-char filename ---
long=$(printf 'n%.0s' $(seq 1 255))
: > "$W/$long"; ck "255-char filename" test -f "$W/$long"

# --- filename with spaces / specials ---
weird='weird name (x) #1 & y'
echo hi > "$W/$weird"; ckeq "spaces in name" "hi" "$(cat "$W/$weird")"

# --- hardlink fan-out: 50 links + original => nlink 51 ---
hl="$W/hl"; : > "$hl"
for i in $(seq 1 50); do ln "$hl" "$W/hl_$i"; done
ckeq "hardlink nlink 51" "51" "$(stat -c %h "$hl")"

# --- dangling symlink ---
ln -s /no/such/path "$W/dang"
ck "dangling is symlink" test -L "$W/dang"
ck "dangling target absent" test ! -e "$W/dang"

# --- cross-directory rename ---
mkdir "$W/da" "$W/db"; echo m > "$W/da/m"; mv "$W/da/m" "$W/db/m"
ck "cross-dir rename dst" test -f "$W/db/m"
ck "cross-dir rename src gone" test ! -e "$W/da/m"

# --- xattr (only if tools present) ---
if command -v setfattr >/dev/null 2>&1 && command -v getfattr >/dev/null 2>&1; then
    : > "$W/xf"
    setfattr -n user.suite -v hello "$W/xf" 2>/dev/null
    ckeq "xattr set/get" "hello" "$(getfattr --only-values -n user.suite "$W/xf" 2>/dev/null)"
else
    echo "note: xattr tools (setfattr/getfattr) absent — xattr check skipped"
fi

finish
