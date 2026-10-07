---
name: trap-tauth-test-objects-do-not-depend-on-tauth-store-h-so-a-store-struct-change-leaves-them-stale
description: TRAP: tests/tauth/Makefile test objects list tauth_ledger.h, not tauth_store.h; a store struct change left them stale and 3 tests failed on garbage f…
metadata:
  type: feedback
---

**What happened (0.90.85, 2026-10-07):** after adding two fields to `struct mxfs_tauth_store` (dlm/tauth_store.h), `make all` in tests/tauth rebuilt obj/dlm.o and the changed test, but NOT obj/dlm_ledger_test.o, concurrent_release_test.o, stale_image_release_test.o. Their Makefile rules depend on dlm/tauth_ledger.h and dlm/dlm.h only, yet `struct mxfs_tauth_ledger` EMBEDS `struct mxfs_tauth_store` (l->store), so the stale objects read ledger fields (commits, gen_refusals, recommits...) at the old offsets.

**How it showed:** deterministic, plausible-looking failures — `FAIL 1 one commit at the master (A commits=0 B commits=0)` while the grant was on the platter, `FAIL 7b the master's purge is PARTIAL rc=1`, `gen_refusals +0`, `recommits=0`, and dlm_ledger_test running into its 300 s timeout. An A/B that toggled only the .c change showed the same failures both ways, which is what pointed at the build rather than the code.

**Do this:** after ANY change to dlm/tauth_store.h, dlm/tauth_ledger.h, dlm/dlm.h or include/mxfs/mxfs_tauth.h, rebuild the unit tests with `make -B all` in tests/tauth before reading a result. With a clean rebuild all 9 tests passed (ledger 113, dlm_ledger 72, concurrent_release 60, stale_image_release 68 ...).

Do not "fix" the Makefile unasked — the global rules forbid editing a Makefile unless told to in that turn; just force the rebuild.
