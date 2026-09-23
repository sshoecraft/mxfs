<!-- sess426 RULE-5 ruling (D-0347): tauth page write must be a conditional commit — CAW ticket on the spare copy, exact base token, ticket-before-body, f… -->
# sess426 GPT ruling — tauth conditional commit (D-0347)

Proven (tests/tauth/bootstrap_race_test): two "bootstrap" nodes both claimed one UNOWNED page; the late writer's image (based on a stale read) became the highest seq and erased the other's activation + committed grant. Root: `mxfs_tauth_page_write` ties nothing to the image the caller patched; readback only proves "my copy validates now".

## Ruled design: P1 — ticket on the spare copy via SCSI COMPARE AND WRITE (sector 0), NOT proposal (3) (retire the committed copy: mutates the truth, still needs a lock, worse recovery).
1. Read both copies; pick unique highest valid; return BASE TOKEN {fs_gen, page_id, seq, write_nonce, copy_index} + the exact 512 B sector 0 of the spare copy (even if invalid).
2. Revalidate immediately before commit: highest valid must match the whole base token (not just seq) else -ESTALE.
3. Acquire the spare with CAW: compare = recorded spare sector 0; write = self-validating TICKET sector {page_id, fs_gen, proposed_seq, base_seq, base_nonce, writer_node, writer_inc, ticket_nonce, IN_PROGRESS, ticket_crc} that makes the 4 KiB image INVALID. Miscompare = -ESTALE. Ticket durable (CAW+FUA / flush) BEFORE any body write.
4. Write sectors 1..7 with FUA; all durable before publication.
5. Publish: CAW sector 0 compare = exact ticket sector, write = final header (valid whole-page CRC); durable, then flush. Miscompare here normally -ESTALE; if ownership was stolen without fencing → fatal protocol/fencing error.
6. Adopt/cache MINE only after the outcome is resolved as committed.

## Conditions
- ABA closed by: seq never wraps within fs_gen; write_nonce unique per publication/ticket; reformat changes fs_gen; nothing writes headers outside the protocol.
- Two writers same spare: one ticket CAW wins. Third writer during a LIVE ticket: -EBUSY/wait, never replace it just because CAW would compare.
- Crash after ticket: old committed copy stays truth; a recovery writer may CAW over the abandoned ticket ONLY after the ticket owner's exact incarnation is durably fenced from LUN I/O (store needs a fencing/purge callback from the DLM; membership purge alone is insufficient unless it guarantees no more storage commands). If fencing cannot be proved: reads OK, writes -EBUSY.
- Ambiguous completion (final CAW/flush timeout): re-read — own final nonce present → committed; own ticket still present → resumable; old base highest and own ticket absent → not committed; later valid seq exists → resolve by nonce/base chain or idempotency, never overwrite from the stale base. Readback mismatch after later commits is NOT proof of failure; CAW completion is the publication event.
