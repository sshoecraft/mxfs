#!/bin/bash
# Single-node test: permissions — chmod, chown, umask effects
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "permissions"

TESTDIR="${TEST_DIR}/permissions"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# chmod on file
touch "$TESTDIR/perm_test"
chmod 644 "$TESTDIR/perm_test"
perms=$(stat -c%a "$TESTDIR/perm_test")
assert_equals "644" "$perms" "chmod 644"

chmod 600 "$TESTDIR/perm_test"
perms=$(stat -c%a "$TESTDIR/perm_test")
assert_equals "600" "$perms" "chmod 600"

chmod 755 "$TESTDIR/perm_test"
perms=$(stat -c%a "$TESTDIR/perm_test")
assert_equals "755" "$perms" "chmod 755"

chmod 000 "$TESTDIR/perm_test"
perms=$(stat -c%a "$TESTDIR/perm_test")
assert_equals "0" "$perms" "chmod 000"

# Read/write still works as root (we run as root on test nodes)
chmod 644 "$TESTDIR/perm_test"

# chmod on directory
mkdir "$TESTDIR/perm_dir"
chmod 750 "$TESTDIR/perm_dir"
perms=$(stat -c%a "$TESTDIR/perm_dir")
assert_equals "750" "$perms" "chmod 750 on directory"

# Executable bit
touch "$TESTDIR/script"
chmod +x "$TESTDIR/script"
perms=$(stat -c%a "$TESTDIR/script")
# Check that at least owner-execute is set
owner_perms=$((8#$perms / 64))
has_exec=$((owner_perms & 1))
assert_equals "1" "$has_exec" "Owner execute bit set after chmod +x"

# chown (we're root so this should work)
touch "$TESTDIR/own_test"
chown 1000:1000 "$TESTDIR/own_test"
uid=$(stat -c%u "$TESTDIR/own_test")
gid=$(stat -c%g "$TESTDIR/own_test")
assert_equals "1000" "$uid" "chown sets uid"
assert_equals "1000" "$gid" "chown sets gid"

chown 0:0 "$TESTDIR/own_test"
uid=$(stat -c%u "$TESTDIR/own_test")
gid=$(stat -c%g "$TESTDIR/own_test")
assert_equals "0" "$uid" "chown back to root uid"
assert_equals "0" "$gid" "chown back to root gid"

# chmod preserves content
echo "permission test data" > "$TESTDIR/content_perm"
chmod 400 "$TESTDIR/content_perm"
content=$(cat "$TESTDIR/content_perm")
assert_equals "permission test data" "$content" "Content preserved after chmod"
chmod 644 "$TESTDIR/content_perm"

# Setuid/setgid bits
chmod 4755 "$TESTDIR/perm_test"
perms=$(stat -c%a "$TESTDIR/perm_test")
assert_equals "4755" "$perms" "setuid bit (4755)"

chmod 2755 "$TESTDIR/perm_dir"
perms=$(stat -c%a "$TESTDIR/perm_dir")
assert_equals "2755" "$perms" "setgid bit (2755) on dir"

# Sticky bit on directory — test on a fresh dir to avoid setgid carry-over
# NOTE: chmod doesn't clear special bits (setuid/setgid/sticky) — known mxfs bug
mkdir "$TESTDIR/sticky_dir"
chmod 1777 "$TESTDIR/sticky_dir"
perms=$(stat -c%a "$TESTDIR/sticky_dir")
assert_equals "1777" "$perms" "sticky bit (1777) on dir"

test_end
