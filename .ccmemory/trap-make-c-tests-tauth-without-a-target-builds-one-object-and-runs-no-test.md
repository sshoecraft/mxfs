---
name: trap-make-c-tests-tauth-without-a-target-builds-one-object-and-runs-no-test
description: TRAP: tests/tauth/Makefile's first rule is obj/unowned_page_test.o, so a bare `make -C tests/tauth` exits 0 in 4 ms having tested nothing; run `make…
metadata:
  type: feedback
tags: [tests, build, trap]
---

`make -C tests/tauth` with no target runs the FIRST rule in tests/tauth/Makefile, which is `$(OBJDIR)/unowned_page_test.o` (the explicit object rules come before `all:`). It returned rc 0 in 0.004 s after a dlm/dlm.c change (0.90.87) and looked like a passing user-mode build of the DLM.

**Why it matters:** dlm/ must build in user mode, and these binaries are the only user-mode build of dlm.c and the ledger; a "green" bare make proves neither the compile nor any test.

**How to apply:** always `make -C tests/tauth test` (builds every binary, then runs tauth, ledger, dlm_ledger, formation, concurrent_release, unowned_page, bootstrap_race, view_format, stale_image_release chained with &&). Measured 1 m 38 s wall on clyde after a dlm.c change. Each test prints `=== <name> RESULT PASS fails=0 ===`; the make's rc is the chain's. If a store/ledger header changed, see the stale-object trap for tauth_store.h too (`make -C tests/tauth clean` first).
