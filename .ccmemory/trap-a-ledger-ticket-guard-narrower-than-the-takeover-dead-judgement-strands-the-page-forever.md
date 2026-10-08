---
name: trap-a-ledger-ticket-guard-narrower-than-the-takeover-dead-judgement-strands-the-page-forever
description: TRAP (0.90.91→92): tauth store took over a dead writer's commit ticket only if THIS mount purged it; takeover judged it dead → -EBUSY forever, mkdir…
metadata:
  type: feedback
tags: [tauth, ledger, takeover, drbd, trap]
---

A tauth ledger commit claims the page's spare copy with a ticket (CAW of sector 0), writes the body, then publishes. A ticket left by another writer refuses the commit (-EBUSY) unless `store.fenced_cb` says the writer is fenced.

Through 0.90.91 `dlm_store_fenced_cb` accepted only `dlm_owner_purged` (purged by THIS mount). The page takeover (`dlm_takeover_page`, on-demand in `dlm_page_acquire`) judges a departed authority/target dead by the broader `dlm_authority_dead` (purged, settled by name, or previous era: slot moved on and not in view). So once the mount that recovered a writer which died between ticket swap and publish was gone, the takeover kept judging the page takeable while its own prepare commit hit the ticket and got -EBUSY, forever: `P960-STALLED-PAGE ... target{dead=1} ondemand_last{page=N rc=-16}`, every lock routed to the page failed after the 30 s transition stall (mkdir EAGAIN). Physical DRBD pair, pages 9762/10942/13005; it survived reboots of both hosts.

**Why:** two judgements of "is this incarnation gone" that disagree make one path promise progress the other refuses. Any guard on a step inside a takeover must be at least as permissive as the judgement that started the takeover, or the takeover can never complete.

**How to apply:**
- When a takeover/recovery path stalls with a dead=1 judgement but a refusal deeper in, compare the two predicates first.
- `tools/tauth_page_auth.py <dev> --tickets` (read O_DIRECT on a node, fed over ssh stdin) lists every ticketed page copy and its writer; on a quiescent LUN every ticket is abandoned.
- `tests/tauth/abandoned_ticket.sh [control]` reproduces it in usermode (the store knob `ticket_fail_once_rc` + `ticket_fail_landed` leaves a real ticket); `tests/pve_ticket_pages.sh` drives a request onto every ticketed page in the field.
- The mesh harness (`tests/tauth/dlm_mesh.h`) has no slot map unless `vocc_on` is set before `node_up`; without it `dlm_authority_dead` never judges a previous era dead.
