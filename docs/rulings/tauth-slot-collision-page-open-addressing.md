<!-- sess426 RULE-5 ruling (D-0348): page-local open addressing keyed by full resource id + mkfs-sized bigger region; page-full = LEDGER_CAPACITY_WAIT nev… -->
# sess426 GPT ruling — tauth slot-hash collisions (D-0348)

Measured: 8000 live inode locks → 44 P-TAUTH-COLLISION refusals → -EIO to file ops (dlm.c ~3452 turns MXFS_ERR_LEDGER into -EIO).

## Ruled: (a) page-local open addressing + a substantially larger mkfs-sized region. Rejected: (b) cross-page probing (multi-master), (c) wait behind an unrelated tenure, (d) bigger direct-mapped table alone, simple (f) cuckoo (two masters can create duplicates); (e) deferred.
Rule: a resource hashes deterministically to ONE home page (`home_page = hash(hash_version, seed, resource) % page_count`, master = active_nodes[home_page % N]); that page's master exclusively finds/creates/updates/deletes the record among the page's 31 entries by FULL key {type, ino, ag}; allocate the lowest-index EMPTY/FREE; CAW-commit the page; no reusable entry → `LEDGER_CAPACITY_WAIT` (retryable, capped backoff / waiter registration, loud health event), never -EIO; two occupied entries for one resource = corruption (quarantine). ACTIVE and UNKNOWN consume capacity; never relocate an occupied entry.

## Identity split (the current `slot` is overloaded)
`home_page` (routing) / `entry_index` (0..30) / locator {ledger_generation, home_page, entry_index}; grant/release handles carry resource_id + locator + lineage + grant_seq (+ node/inc/epochs). RELEASE_PR must validate page+entry, full resource id, occupied, lineage/grant_seq, holder node+inc, holder bit — never {lineage, hash_slot, node, inc} alone (stale locator → reused entry). P-lines print `home_page= entry= hash= resource= lineage= grant_seq=`, not `slot=`.

## Capacity
Now: 2115 pages × 31 = 65,565 records (~16.5 MiB dual). 300k tenures → mean 142/page vs cap 31: categorically undersized; even ~40k fills tails. 1M entries ≈ 32,259 pages ≈ 252 MiB dual. Size from PEAK simultaneously occupied records (mean occupancy ≪ 31, e.g. 300k over 1M positions ≈ 9.3/page). Telemetry: occupied total, page-occupancy max/histogram, page-full events/waiters, longest capacity wait, geometry + utilization. Callers must not sleep on capacity while holding tenures that can form a lock-order cycle (unwind + retry).

## Format/migration
On-disk + wire change: TAUTH format version, hash algorithm + seed, page_count/entries_per_page, region geometry, locator fields; bump fs/proto gen; mixed nodes refused. Migration offline (or full ledger quiescence): read old records, rehash into new home pages, build both shadow regions, atomically publish geometry/version, then allow tenures. Never reinterpret/move active old-format records live. Geometry = generous mkfs-time parameter (changing page_count rehashes everything).
