#!/bin/bash
# Single-node test: create many files in a single directory, verify count and listing
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "many_files"

TESTDIR="${TEST_DIR}/many_files"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Create 500 files
FILE_COUNT=500
log_info "Creating ${FILE_COUNT} files..."
for i in $(seq 1 $FILE_COUNT); do
    echo "content_${i}" > "$TESTDIR/file_$(printf '%04d' $i)"
done

# Verify count via ls
actual=$(ls "$TESTDIR" | wc -l)
actual=$(echo "$actual" | tr -d ' ')
assert_equals "$FILE_COUNT" "$actual" "Created ${FILE_COUNT} files"

# Verify a sample of files have correct content
content=$(cat "$TESTDIR/file_0001")
assert_equals "content_1" "$content" "First file content"

content=$(cat "$TESTDIR/file_0250")
assert_equals "content_250" "$content" "Middle file content"

content=$(cat "$TESTDIR/file_0500")
assert_equals "content_500" "$content" "Last file content"

# Verify readdir returns all entries
readdir_count=$(ls -1 "$TESTDIR" | wc -l)
readdir_count=$(echo "$readdir_count" | tr -d ' ')
assert_equals "$FILE_COUNT" "$readdir_count" "readdir returns all ${FILE_COUNT} files"

# Delete half and verify
log_info "Deleting first 250 files..."
for i in $(seq 1 250); do
    rm "$TESTDIR/file_$(printf '%04d' $i)"
done

remaining=$(ls "$TESTDIR" | wc -l)
remaining=$(echo "$remaining" | tr -d ' ')
assert_equals "250" "$remaining" "250 files remain after deleting half"

# Recreate deleted files
log_info "Recreating 250 files..."
for i in $(seq 1 250); do
    echo "new_content_${i}" > "$TESTDIR/file_$(printf '%04d' $i)"
done

total=$(ls "$TESTDIR" | wc -l)
total=$(echo "$total" | tr -d ' ')
assert_equals "$FILE_COUNT" "$total" "Back to ${FILE_COUNT} files after recreation"

test_end
