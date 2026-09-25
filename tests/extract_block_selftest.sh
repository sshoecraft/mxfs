#!/bin/bash
#
# extract_block_selftest.sh -- prove scripts/extract_block.py moves a block
# without changing what the program does, and refuses what it must.
#
# tests/extract_block_selftest.c's work() holds one block of each construct
# the tool handles.  Each block is extracted alone, and then all of them one
# after another; after every step the program is compiled at -O0 and -O2 and
# its output compared with the untouched original's.  The two REFUSE blocks
# must be refused.
#
# Usage: tests/extract_block_selftest.sh [PYTHON]
#   PYTHON: an interpreter with the libclang bindings (default: python3)
# Exit 0 only if every comparison matched and both refusals held.
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${1:-python3}"
TOOL="$HERE/scripts/extract_block.py"
SRC="$HERE/tests/extract_block_selftest.c"
W=$(mktemp -d)
# libclang ships no resource headers here; gcc's own provide stddef.h and co.
CFLAGS="-std=gnu11 -isystem $(gcc -print-file-name=include)"
FAILS=0

build_run() {   # FILE TAG -> output of the program, or FAIL
	local f=$1 tag=$2 o
	for o in -O0 -O2; do
		if ! gcc $o -Wall -o "$W/bin_$tag$o" "$f" 2> "$W/cc_$tag$o.log"; then
			echo "COMPILE-FAIL"
			sed 's/^/    /' "$W/cc_$tag$o.log" >&2
			return
		fi
		"$W/bin_$tag$o" > "$W/out_$tag$o.txt"
	done
	if cmp -s "$W/out_$tag-O0.txt" "$W/out_$tag-O2.txt"; then
		cat "$W/out_$tag-O0.txt"
	else
		echo "O0-O2-DIFFER"
	fi
}

line_after() {  # FILE MARKER -> the line after the marker comment inside work()/refusals()
	awk -v m="$2" 'index($0, m) { print NR + 1; exit }' "$1"
}

build_run "$SRC" orig > "$W/expected.txt"
if grep -q 'FAIL\|DIFFER' "$W/expected.txt"; then
	echo "FAIL: the untouched self-test program does not build and run"; exit 1
fi

# each block alone
for b in A B C D E F; do
	cp "$SRC" "$W/one_$b.c"
	ln=$(line_after "$W/one_$b.c" "/* block $b:")
	if ! "$PY" "$TOOL" "$W/one_$b.c" work "$ln" "moved_$b" --cflags "$CFLAGS" --apply > "$W/x_$b.log" 2>&1; then
		echo "FAIL: block $b was not extracted: $(tail -1 "$W/x_$b.log")"; FAILS=$((FAILS + 1)); continue
	fi
	if build_run "$W/one_$b.c" "one_$b" | cmp -s - "$W/expected.txt"; then
		echo "PASS: block $b alone ($(head -1 "$W/x_$b.log" | sed 's/.*; //'))"
	else
		echo "FAIL: block $b alone changed the program's output"; FAILS=$((FAILS + 1))
	fi
done

# all of them, one after another in the same file
cp "$SRC" "$W/all.c"
moved=0
for b in A B C D E F; do
	ln=$(line_after "$W/all.c" "/* block $b:")
	if "$PY" "$TOOL" "$W/all.c" work "$ln" "moved_$b" --cflags "$CFLAGS" --apply > "$W/xa_$b.log" 2>&1; then
		moved=$((moved + 1))
	else
		echo "FAIL: block $b not extracted after the others: $(tail -1 "$W/xa_$b.log")"; FAILS=$((FAILS + 1))
	fi
done
if [ $moved != 6 ]; then
	echo "FAIL: only $moved of 6 blocks moved; the combined comparison would prove nothing"
	FAILS=$((FAILS + 1))
elif build_run "$W/all.c" all | cmp -s - "$W/expected.txt"; then
	echo "PASS: all six blocks moved out of work(), output unchanged"
else
	echo "FAIL: moving all six blocks changed the program's output"; FAILS=$((FAILS + 1))
fi

# the refusals
for m in "REFUSE: the break" "REFUSE: names __func__"; do
	cp "$SRC" "$W/ref.c"
	ln=$(line_after "$W/ref.c" "/* $m")
	if "$PY" "$TOOL" "$W/ref.c" refusals "$ln" moved_r --cflags "$CFLAGS" --apply > "$W/r.log" 2>&1; then
		echo "FAIL: '$m' was extracted"; FAILS=$((FAILS + 1))
	elif grep -q REFUSED "$W/r.log" && cmp -s "$SRC" "$W/ref.c"; then
		echo "PASS: $m -> $(grep REFUSED "$W/r.log")"
	else
		echo "FAIL: '$m' errored rather than refusing: $(tail -1 "$W/r.log")"; FAILS=$((FAILS + 1))
	fi
done

echo "evidence: $W"
[ $FAILS = 0 ] && echo "RESULT PASS" || echo "RESULT FAIL ($FAILS)"
[ $FAILS = 0 ]
