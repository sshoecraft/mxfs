<!-- sess438 RULE-5 ruling on whole-cluster-restart build item 2 (64-bit per-boot PR key): NOT SAFE as proposed — ledger cannot be deferred; 9 fixes -->
# sess438 GPT ruling — item 2 (64-bit per-boot PR key + HB identity block)

Proposed: carve evict ring 23->19, 64 B mxfs_hb_identity @360 (tail 424/456/500 unchanged); key drawn once per module load; READ KEYS collision redraw; victim key latched per slot in the monitor; proto_gen 11->12 without a format flag; registrant ledger deferred to item 5.

Verdict: NOT SAFE as proposed. Offset arithmetic OK (40+320=360, tail 424). Fixes required:
1. victim_key latch must live INSIDE the frozen incarnation/death snapshot {slot,node,epoch,pr_key,key_gen}, copied before successor adoption; never looked up via current slot state in the callback. A different key for the same {node,epoch} = protocol violation (fatal), never an update.
2. WITHDRAWN records: a valid WITHDRAWN record of the exact tracked incarnation may supply the key (monitor may never have seen ACTIVE). Preserve the frozen key across ACTIVE->WITHDRAWN. NEVER take a victim key from a GUARD identity block (it names the guard writer).
3. "Once per module load" != once per host boot per LUN: module reload / repeated mount attempts / concurrent mounts can pick a second key while PTPL keeps the first. Serialize key selection per LUN and PERSIST/RECOVER the selected key for this boot (ledger). All path additions/retries reuse the selected LUN key.
4. Collision check exactly ONCE before the first registration under a per-LUN lock; READ KEYS does not say which nexus owns a key, so on retry/path expansion seeing our own key must NOT redraw. Verify with READ FULL STATUS after registration.
5. LEDGER CANNOT BE DEFERRED: crash after REGISTER before slot claim leaves a durable PTPL registration with no durable owner. Land at least the minimal CAW-protected ledger now: write a PREPARED {pr_key, host_uuid, boot_uuid, key_gen, fs identity} entry BEFORE REGISTER, transition after verified registration/claim.
6. The GUARD descriptor's crc must bind fence_victim_key to victim {slot,node,epoch,key_gen}; refuse GUARD creation if no exact-incarnation victim key was frozen.
7. Identity crc must also bind slot number, fs/LUN identity (fs_uuid), record flags, key_gen (plus host/boot uuid, pr_key, host_src, fs_gen, node_id, epoch). CRC is transplant detection, not authenticity.
8. key_gen = generation of the selected key for this {host boot, LUN}, incremented only when the key changes; stored in ledger, HB identity, victim intent. Key change for an observed {node,epoch} is fatal. 16-bit OK only if wrap is forbidden per boot/LUN.
9. Keep an explicit on-disk incompat bit (MXFS_FORMAT_F_PRKEY64) — proto_gen equality alone is a tool convention.
