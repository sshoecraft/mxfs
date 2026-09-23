---
name: trap-a-grant-identity-struct-built-per-path-leaves-a-new-field-unassigned-on-the-re-affirm-and-an-exclusive-re-grant-that-adopts-it-frees-an-open-file
description: TRAP (D-0977, 0.89.1): the master's REAFFIRM built dlm_grant_ids field-by-field and never set open_holders; the holder's mirror adopted the zero mask…
metadata:
  type: feedback
tags: [dlm, tcp, open-unlink, D-0977, ledger]
---

# The re-affirm sent an unassigned mask and the mirror believed it

## What bit
0.89.0 put open-holder marks on the TCP authority ledger: the EX grant carries the record's mask (`dlm_grant_ids.open_holders` → `LOCK_GRANT.open_holders`), the grantee's mirror keeps it, the destructive-inactivation guard reads it. The lap (s64a, `tests/evidence/20260919T050109Z_d0977`) still reused the inode under the peer's two open descriptors.

The instruments (P74-GRANT `oh=` on the grantee, P977-REL-MARK on the master, P87-OPEN-CHECK at the guard) showed: gen 15 PR oh=0x2, gen 17 EX oh=0x2, gen 18 EX oh=0x0 with prov=0 have_mirror=1 — and the ledger still said 0x2 in every later commit. The master's own `P-DGEX ... active_b4=1 handoff=0 gen=18` names the path: a re-grant with no intervening release, i.e. the REAFFIRM arm of process_remote_request (dlm/dlm.c, "REAFFIRM-REMOTE"). That arm declares `struct dlm_grant_ids ids;` and assigns auth_epoch, grant_seq, lineage, req_id — the 0.89.0 field was never added to it. The holder-side mirror update adopted any exclusive grant's mask unconditionally.

Why the re-affirm fires at all: the unlinker's inactivation certifies its EX with an idempotent re-acquire (P-INACT-CERT try=N) — every unlink on TCP takes this path, so the defect was deterministic, not a race.

## The lesson
- A struct that is built field-by-field at N sites has N chances to miss a new field, and an uninitialized stack field reads as a *valid* value on the wire. When adding a field to `dlm_grant_ids` (or any per-path-built identity), grep every `struct dlm_grant_ids` declaration and every `send_grant(` caller — there were 8 — and decide each one.
- A receiver that adopts a message's value unconditionally turns a sender's omission into the unsafe verdict. The fail-closed receiver rule for a snapshot that can only legitimately shrink through a fence purge: replace on a NEW durable grant id, OR on a re-affirm of the same id.
- The takeover import (`dlm_import_holder`) is the other chain-construction path with no commit behind it; it had the same omission.

## Fix (0.89.1)
dlm/dlm.c: REAFFIRM sends `ids.open_holders = lk->open_holders`; `dlm_import_holder` stamps `lk->open_holders = e->open_holders`; the grantee's mirror update replaces the snapshot only when `grant_seq64`/`authority_epoch` differ from the mirrored ones, else ORs. Design: docs/tcp-authority-ledger.md "Every path that constructs a grant carries the snapshot". Astra ruling 2026-09-19 concurred (chain stamp valid for a continuously held EX; OR is the conservative merge; do not OR across fresh commits or fenced bits pin reclamation for ever).
