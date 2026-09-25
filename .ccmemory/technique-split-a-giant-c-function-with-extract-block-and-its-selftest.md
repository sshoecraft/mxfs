---
name: technique-split-a-giant-c-function-with-extract-block-and-its-selftest
description: TECHNIQUE (0.89.90): scripts/extract_block.py moves a block of a kernel function into a static helper from clang's AST, or refuses. Needs libclang py…
metadata:
  type: feedback
tags: [refactor, libclang, tooling, extract_block]
---

To split a long MXFS function into phase helpers, use `scripts/extract_block.py` rather than hand-editing. It parses the file with the kernel build's own flags (read from the object's .cmd; build the module first) and either moves a statement block exactly or refuses.

Setup: `python3 -m venv V; V/bin/pip install clang==18.1.8` (libclang-18 is installed from llvm-18; no system bindings). Run with `V/bin/python`.

Use:
- `extract_block.py FILE FUNC --list --min 60` — every movable block with verdict and the passing modes.
- `extract_block.py FILE FUNC --batch LIST --apply` — LIST lines `LINE<TAB>NAME[<TAB>DOC]`, applied bottom-up (each helper lands above the function, so remaining targets shift by its length). A block with no comment above it needs a DOC.
- After any change to the tool: `tests/extract_block_selftest.sh V/bin/python` must print RESULT PASS.

Traps found building it, each of which produced wrong code before being fixed:
- libclang offsets are BYTES; the sources hold UTF-8 dashes/arrows. Read and write the file as latin-1 so indices are byte offsets.
- A token from a macro ARGUMENT reports its expansion location (the macro name); use clang_getSpellingLocation to find where the argument is written.
- A macro that uses its argument twice gives two DeclRefExprs at the same spelling offset — dedupe, or the by-reference rewrite is applied twice (`(*x_ref)x_ref)`).
- `rc ? MXFS_LOG_WARN : MXFS_LOG_INFO` — the first arm is not always the success arm (same lesson applies to log_demote_sites.py).

The helper's parameter naming tells a reader how each local travels: plain name = by value, `<v>_io` = copied in/out, `<v>_ref` = by reference (address taken in the parent, or a function-local static). docs/xfs-dlm-layout.md explains.
