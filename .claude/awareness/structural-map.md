# Structural Map — mxfs

**Generated**: 2026-08-21
**Source files scanned**: 483
**Approximate token count**: 70751
**Parser**: regex

## Notation

```
[path/to/file.ext]
  fn function_name(params) -> return_type
    calls: fn1, fn2, fn3
    called_by: fn4, fn5
  struct StructName { field1, field2 }
  enum EnumName { VAL1, VAL2 }
```

- `calls:` lists functions this function directly invokes (project-internal only)
- `called_by:` lists functions that directly invoke this function
- Only PUBLIC / EXPORTED symbols listed unless internal symbols cross file boundaries
- Call graph edges are best-effort — static analysis only

## Map

```
[compat/linux/fserror.h]
  enum fserror_type { FSERR_BUFFERED_READ, FSERR_BUFFERED_WRITE, FSERR_DIRECTIO_READ, FSERR_DIRECTIO_WRITE, FSERR_DATA_LOST, FSERR_METADATA }
  struct fserror_event { work, sb, inode, pos, len, type, error }

[dlm/discovery.c]
  fn static seen_find(struct mxfs_discovery_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: seen_update
  fn static seen_update(struct mxfs_discovery_ctx *ctx, mxfs_node_id_t node_id, uint64_t ts) -> int
    calls: mxfs_pal_log, seen_find
    called_by: mxfs_discovery_recv_fn
  fn static mxfs_discovery_send_fn(void *arg) -> void
    calls: mxfs_discovery_stop, mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_udp_sendto
  fn static mxfs_discovery_recv_fn(void *arg) -> void
    calls: mxfs_le16_to_cpu, mxfs_le32_to_cpu, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, mxfs_pal_udp_recvfrom, seen_update
  fn mxfs_discovery_create(mxfs_node_id_t node_id, const uint8_t *node_uuid, const uint8_t *volume_uuid, mxfs_volume_id_t volume_id, uint16_t tcp_port, const char *mcast_addr, uint16_t disc_port, bool use_broadcast) -> struct mxfs_discovery_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_destroy(struct mxfs_discovery_ctx *ctx) -> void
    calls: mxfs_discovery_stop, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_udp_close
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_discovery_start_recv_only(struct mxfs_discovery_ctx *ctx) -> int
    calls: mxfs_pal_log
    called_by: mxfs_mount
  fn mxfs_discovery_start(struct mxfs_discovery_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_thread_join
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_stop(struct mxfs_discovery_ctx *ctx) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join, mxfs_pal_udp_shutdown
    called_by: mxfs_discovery_destroy, mxfs_discovery_send_fn, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_shutdown_withdraw
  fn mxfs_discovery_set_peer_cb(struct mxfs_discovery_ctx *ctx, mxfs_discovery_peer_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_set_transport(struct mxfs_discovery_ctx *ctx, uint8_t transport) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init

[dlm/discovery.h]
  fn mxfs_discovery_create(mxfs_node_id_t node_id, const uint8_t *node_uuid, const uint8_t *volume_uuid, mxfs_volume_id_t volume_id, uint16_t tcp_port, const char *mcast_addr, uint16_t disc_port, bool use_broadcast) -> struct mxfs_discovery_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_destroy(struct mxfs_discovery_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_discovery_start(struct mxfs_discovery_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_start_recv_only(struct mxfs_discovery_ctx *ctx) -> int
    called_by: mxfs_mount
  fn mxfs_discovery_stop(struct mxfs_discovery_ctx *ctx) -> void
    called_by: mxfs_discovery_destroy, mxfs_discovery_send_fn, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_shutdown_withdraw
  fn mxfs_discovery_set_peer_cb(struct mxfs_discovery_ctx *ctx, mxfs_discovery_peer_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_discovery_set_transport(struct mxfs_discovery_ctx *ctx, uint8_t transport) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  struct mxfs_discovery_announce { magic, version, flags, node_uuid, node_id, tcp_port, dlm_transport, pad, volume_uuid, volume_id }
  struct mxfs_discovery_seen { node_id, last_seen }
  typedef_fn mxfs_discovery_peer_cb
  struct mxfs_discovery_ctx { sock, local_announce, mcast_addr, send_addr, port, use_broadcast, seen, seen_count, seen_lock, sender_thread }

[dlm/disklock.c]
  fn static dl_inject_take(int *knob) -> bool
    calls: mxfs_pal_log
    called_by: closure_read_gate_sector
  fn static resource_hash(const struct mxfs_resource_id *res) -> uint32_t
    called_by: dg_grant_ex, dlm_lock_impl, find_lock_slot, mxfs_disklock_write_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_unlock_gen
  fn static resource_equal(const struct mxfs_resource_id *a, const struct mxfs_resource_id *b) -> bool
    called_by: collect_post_promotion_basts, dg_grant_ex, dg_release, dlm_lock_impl, find_conflicting_waiter, find_lock_slot, held_insert, held_remove, mxfs_dlm_audit_double_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb
  fn static lock_slot_offset(struct mxfs_disklock_ctx *ctx, uint32_t slot) -> uint64_t
    called_by: find_lock_slot, mxfs_disklock_clear_grant, mxfs_disklock_purge_node, mxfs_disklock_read_all, mxfs_disklock_write_grant, validate_lockstate
  fn static hb_slot_offset(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node) -> uint64_t
    called_by: validate_lockstate
  fn static read_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset, void *buf) -> int
    calls: mxfs_pal_bdev_read
    called_by: closure_read_gate_sector, find_lock_slot, mxfs_disklock_purge_node, mxfs_disklock_read_all, mxfs_disklock_write_grant, mxfs_journal_open, mxfs_journal_replay, mxfs_journal_slot_mark_clean, mxfs_journal_slot_mark_dirty, mxfs_journal_slot_open, read_entry_at, scan_disk_for_node_slot, validate_lockstate
  fn static write_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset, const void *buf) -> int
    calls: mxfs_pal_bdev_write
    called_by: flush_slot_header, mxfs_disklock_clear_grant, mxfs_disklock_write_grant, mxfs_journal_format, mxfs_journal_replay, mxfs_journal_slot_mark_clean, mxfs_journal_slot_mark_dirty, purge_cas_zero
  fn static write_sector_fua(struct mxfs_disklock_ctx *ctx, uint64_t offset, const void *buf) -> int
    calls: mxfs_pal_bdev_write_fua
    called_by: hb_cas_own_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_release_slot, mxfs_disklock_unguard, mxfs_disklock_withdraw, recov_cas_durable
  fn static hb_gen_foreign(const struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb) -> bool
    called_by: disklock_hb_fn, hb_clean_empty_match, hb_foreign_kind, hb_prov_derive, hb_report_claim_exhausted, hb_still_dead_stamp, mxfs_disklock_claim_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_get_slot_node_id, mxfs_disklock_get_stale_slot_mask, mxfs_disklock_guard_slot, mxfs_disklock_join_gate, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_slot_status, mxfs_disklock_slot_holds_incarnation
  fn static hb_draw_incarnation(void) -> mxfs_epoch_t
    calls: mxfs_pal_get_random_bytes
    called_by: mxfs_disklock_claim_slot, mxfs_disklock_create
  fn static inc_valid(mxfs_epoch_t e) -> bool
    calls: mxfs_pal_log
    called_by: hb_clean_empty_match, mxfs_disklock_claim_slot, mxfs_disklock_clear_recovery_pending, mxfs_disklock_create, mxfs_disklock_mark_recovery_pending, mxfs_disklock_mount_identity, mxfs_disklock_recovery_slot_status, mxfs_disklock_slot_holds_incarnation
  fn static inc_eq(mxfs_epoch_t a, mxfs_epoch_t b) -> bool
    called_by: disklock_hb_fn, hb_clean_empty_match, mxfs_disklock_clear_recovery_pending, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_retryable, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_slot_status, purge_recov_gate, recov_desc_names_inc
  fn static recov_tok_eq(uint64_t a, uint64_t b) -> bool
  fn static hb_feature_crc(uint32_t fs_gen, mxfs_node_id_t node_id, mxfs_epoch_t epoch, const struct mxfs_hb_feature *ft) -> uint32_t
    calls: mxfs_pal_crc32c
    called_by: hb_feature_fill, hb_feature_state
  fn static hb_feature_fill(const struct mxfs_disklock_ctx *ctx, struct mxfs_disklock_heartbeat *hb) -> void
    calls: hb_feature_crc
    called_by: disklock_hb_fn, mxfs_disklock_claim_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_guard_slot, mxfs_disklock_withdraw
  fn static hb_feature_state(const struct mxfs_disklock_heartbeat *hb) -> int
    calls: hb_feature_crc
    called_by: disklock_hb_fn, hb_victim_snlocal, mxfs_disklock_join_gate, mxfs_disklock_recovery_slot_status
  fn static hb_victim_snlocal(const struct mxfs_disklock_heartbeat *hb) -> bool
    calls: hb_feature_state
  fn static hb_prov_crc(uint32_t fs_gen, mxfs_node_id_t node_id, mxfs_epoch_t epoch, const struct mxfs_hb_provenance *pv) -> uint32_t
    calls: mxfs_pal_crc32c
    called_by: hb_prov_derive
  fn static hb_prov_valid(const struct mxfs_disklock_heartbeat *hb) -> bool
    called_by: disklock_hb_fn, hb_prov_derive
  fn static hb_clean_empty_match(const struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node, mxfs_epoch_t epoch) -> bool
    calls: hb_gen_foreign, inc_eq, inc_valid
    called_by: disklock_hb_fn
  fn static hb_prov_derive(struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *consumed, bool fresh_claim) -> void
    calls: hb_gen_foreign, hb_prov_crc, hb_prov_valid, mxfs_pal_get_random_bytes
    called_by: mxfs_disklock_claim_slot, mxfs_disklock_claim_slot_noncaw
  fn static recov_desc_crc(uint32_t fs_gen, mxfs_node_id_t node_id, mxfs_epoch_t epoch, const struct mxfs_recov_desc *d) -> uint32_t
    called_by: recov_desc_seal
  fn static recov_desc_present(const struct mxfs_disklock_heartbeat *hb) -> bool
    called_by: hb_report_claim_exhausted, mxfs_disklock_guard_slot, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_retryable, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_read, mxfs_disklock_recovery_refresh, mxfs_disklock_recovery_slot_status, mxfs_disklock_recovery_takeover, recov_lease_covers_inc, recov_lease_covers_node, recov_outcome_structural
  fn static recov_outcome_crc(uint32_t fs_gen, mxfs_node_id_t node_id, mxfs_epoch_t epoch, const struct mxfs_recov_outcome *oc) -> uint32_t
    calls: mxfs_pal_crc32c
  fn static recov_outcome_present(const struct mxfs_disklock_heartbeat *hb) -> bool
    calls: mxfs_pal_log
    called_by: mxfs_disklock_recovery_backfill_legacy, recov_outcome_structural
  fn static recov_outcome_structural(const struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb, int slot, const struct mxfs_recov_outcome **oc_out) -> int
    calls: hb_gen_foreign, recov_desc_present, recov_outcome_present
    called_by: disklock_hb_fn, mxfs_disklock_recovery_read_outcome
  fn static recov_desc_names_node(const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node) -> bool
    called_by: mxfs_disklock_find_node_slot, recov_lease_covers_node
  fn static recov_desc_names_inc(const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node, mxfs_epoch_t epoch) -> bool
    calls: inc_eq
    called_by: recov_lease_covers_inc
  fn static recov_lease_covers_node(const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node) -> bool
    calls: recov_desc_names_node, recov_desc_present
    called_by: mxfs_disklock_slot_unclaimed, purge_recov_gate
  fn static recov_lease_covers_inc(const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node, mxfs_epoch_t epoch) -> bool
    calls: recov_desc_names_inc, recov_desc_present
  fn static hb_still_dead_stamp(const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t pn, mxfs_epoch_t pe) -> bool
    calls: hb_gen_foreign, mxfs_disklock_clear_recovery_pending, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: disklock_hb_fn
  fn static fs_identity_changed(struct mxfs_disklock_ctx *ctx, void *buf) -> int
    calls: mxfs_pal_bdev_read
    called_by: disklock_hb_fn
  fn static find_lock_slot(struct mxfs_disklock_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, int *empty_out) -> int
    calls: lock_slot_offset, read_sector, resource_equal, resource_hash
    called_by: mxfs_disklock_clear_grant, mxfs_disklock_write_grant
  fn static validate_lockstate(struct mxfs_disklock_ctx *ctx) -> int
    calls: hb_slot_offset, lock_slot_offset, mxfs_pal_log, read_sector
    called_by: mxfs_disklock_create
  fn static hb_own_record(const struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *cur) -> bool
    calls: hb_foreign_kind, mxfs_pal_free, mxfs_pal_log
    called_by: hb_cas_own_slot, mxfs_disklock_release_slot, mxfs_disklock_withdraw
  fn static hb_foreign_kind(const struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *cur) -> const char
    calls: hb_gen_foreign
    called_by: hb_cas_own_slot, hb_own_record, mxfs_disklock_release_slot, mxfs_disklock_withdraw
  fn static hb_cas_own_slot(struct mxfs_disklock_ctx *ctx, uint64_t off, const struct mxfs_disklock_heartbeat *want, struct mxfs_disklock_heartbeat *scratch) -> int
    calls: hb_foreign_kind, hb_own_record, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_log, write_sector_fua
    called_by: disklock_hb_fn
  fn static hb_stage_set(struct mxfs_disklock_ctx *ctx, int stage) -> void
    calls: mxfs_pal_time_ms
    called_by: disklock_hb_fn
  fn static hb_stage_name(int stage) -> const char
    called_by: disklock_hb_watchdog_fn
  fn static disklock_hb_watchdog_fn(void *arg) -> void
    calls: hb_stage_name, mxfs_pal_cond_timedwait, mxfs_pal_dump_task_stack, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
  fn static hb_blind_clear(const char *reason) -> void
    calls: mxfs_pal_log
    called_by: disklock_hb_fn
  fn static hb_blind_gate(struct mxfs_disklock_ctx *ctx, int hb_rc) -> bool
    called_by: disklock_hb_fn
  fn static disklock_hb_fn(void *arg) -> void
    calls: fs_identity_changed, hb_blind_clear, hb_blind_gate, hb_cas_own_slot, hb_clean_empty_match, hb_feature_fill, hb_feature_state, hb_gen_foreign, hb_prov_valid, hb_stage_set, hb_still_dead_stamp, inc_eq, mxfs_disklock_clear_recovery_pending, mxfs_disklock_monitor_node, mxfs_disklock_stop_heartbeat
  fn mxfs_disklock_create(mxfs_bdev_t *dev, uint64_t disklock_offset, mxfs_node_id_t local_node) -> struct mxfs_disklock_ctx
    calls: hb_draw_incarnation, inc_valid, mxfs_pal_alloc, mxfs_pal_cond_create, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy, validate_lockstate
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_set_snlocal(struct mxfs_disklock_ctx *ctx, bool snlocal) -> void
    calls: mxfs_pal_log
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_slot_limit(struct mxfs_disklock_ctx *ctx, uint32_t limit) -> void
    calls: mxfs_pal_log
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx) -> void
    calls: mxfs_disklock_stop_heartbeat, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_disklock_start_heartbeat(struct mxfs_disklock_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_thread_pid
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_stop_heartbeat(struct mxfs_disklock_ctx *ctx) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join, mxfs_pal_thread_join_timeout
    called_by: disklock_hb_fn, mxfs_disklock_destroy, mxfs_disklock_withdraw, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_disklock_release_slot(struct mxfs_disklock_ctx *ctx) -> int
    calls: hb_foreign_kind, hb_own_record, mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, write_sector_fua
    called_by: mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_disklock_write_grant(struct mxfs_disklock_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t mode, mxfs_epoch_t epoch) -> int
    calls: find_lock_slot, lock_slot_offset, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, read_sector, resource_hash, write_sector
  fn mxfs_disklock_clear_grant(struct mxfs_disklock_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner) -> int
    calls: find_lock_slot, lock_slot_offset, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, write_sector
  fn static purge_cas_zero(struct mxfs_disklock_ctx *ctx, uint64_t off, const void *expect, const void *zerobuf, int *nonatomic) -> int
    calls: mxfs_pal_bdev_compare_and_write, write_sector
    called_by: mxfs_disklock_purge_node
  fn static purge_recov_gate(struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node_id) -> int
    calls: inc_eq, recov_lease_covers_node
    called_by: mxfs_disklock_purge_node, purge_hb_zeroable
  fn static purge_hb_zeroable(struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb, mxfs_node_id_t node_id) -> int
    calls: purge_recov_gate
    called_by: mxfs_disklock_purge_node
  fn mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: lock_slot_offset, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, purge_cas_zero, purge_hb_zeroable, purge_recov_gate, read_sector
    called_by: disklock_expire_cb, lease_expire_cb, mxfs_v5_dlm_recovery_complete, peer_disconnect_cb, v5_handle_node_death
  fn mxfs_disklock_read_all(struct mxfs_disklock_ctx *ctx, struct mxfs_disklock_record *records, int max, int *count) -> int
    calls: lock_slot_offset, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, read_sector
  fn mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx) -> void
    calls: hb_feature_fill, hb_foreign_kind, hb_own_record, mxfs_disklock_stop_heartbeat, mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, write_sector_fua
    called_by: mxfs_v5_dlm_shutdown_withdraw
  fn mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_recovered_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_clean_depart_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_clean_depart_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_vergate_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_vergate_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_recov_outcome_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_recov_outcome_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx, uint32_t timeout_ms) -> int
    calls: hb_feature_state, hb_gen_foreign, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t victim_epoch) -> void
    calls: inc_valid, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_v5_dlm_mount_pending_recovery, v5_defer_slice_recovery, v5_settle_resolve, v5_start_slice_recovery
  fn mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot) -> bool
    called_by: mxfs_v5_dlm_mount_pending_recovery, mxfs_v5_dlm_recovery_complete, v5_defer_slice_recovery, v5_dispatch_late_deaths, v5_settle_resolve, v5_start_slice_recovery
  fn mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t victim_epoch) -> int
    calls: inc_eq, inc_valid, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: disklock_hb_fn, hb_still_dead_stamp, mxfs_v5_dlm_recovery_complete
  fn mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_node_id_t
    called_by: mxfs_v5_dlm_mount_pending_recovery, mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_dispatch_late_deaths
  fn mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx, int prev, mxfs_node_id_t *node) -> int
    called_by: v5_dispatch_slice_recovery
  fn mxfs_disklock_pending_epoch(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_epoch_t
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_exclusion_recheck
  fn static recov_cas_durable(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_disklock_heartbeat *expect, const struct mxfs_disklock_heartbeat *want) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_flush, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, write_sector_fua
    called_by: mxfs_disklock_recovery_advance, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_refresh
  fn static recov_desc_seal(struct mxfs_disklock_heartbeat *want) -> void
    calls: recov_desc_crc
    called_by: mxfs_disklock_recovery_advance, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_refresh
  fn static recov_stamp_after(uint64_t prev) -> uint64_t
    calls: mxfs_pal_time_ms
    called_by: mxfs_disklock_recovery_advance, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_refresh
  fn static recov_auth_issue(struct mxfs_recov_auth *auth, const struct mxfs_recov_desc *d) -> void
    called_by: mxfs_disklock_recovery_claim
  fn static recov_auth_holds(const struct mxfs_disklock_ctx *ctx, const struct mxfs_recov_desc *d, const struct mxfs_recov_auth *auth) -> bool
    calls: mxfs_pal_log
    called_by: mxfs_disklock_recovery_advance, mxfs_disklock_recovery_refresh
  fn mxfs_disklock_recovery_begin(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, uint16_t slice_idx, uint16_t slice_count, uint32_t flags, struct mxfs_recov_auth *out_auth) -> int
  fn mxfs_disklock_recovery_advance(struct mxfs_disklock_ctx *ctx, int slot, unsigned int stage, const struct mxfs_recov_auth *auth) -> int
    calls: inc_eq, mxfs_disklock_recovery_fence_certify, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_auth_holds, recov_cas_durable, recov_desc_present, recov_desc_seal, recov_stamp_after
    called_by: mxfs_v5_dlm_recovery_complete
  fn static recov_outcome_fill(struct mxfs_disklock_heartbeat *want, const struct mxfs_recov_desc *d, uint16_t reason, uint16_t domain_kind, uint64_t ag_mask, bool digest_valid, uint64_t slice_digest, uint64_t publish_seq, uint32_t refused, uint32_t malformed) -> void
    called_by: mxfs_disklock_recovery_backfill_legacy
  fn mxfs_disklock_recovery_publish_refusal(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, const struct mxfs_recov_refusal_info *info, struct mxfs_recov_outcome *oc_out) -> int
    called_by: mxfs_v5_dlm_recovery_publish_refusal
  fn static closure_gate_predicate(struct mxfs_disklock_ctx *ctx, const struct mxfs_disklock_heartbeat *hb, int slot, const struct mxfs_recov_auth *auth, bool check_auth, mxfs_node_id_t *victim, uint64_t *ag_mask) -> int
    called_by: mxfs_disklock_closure_gate_snapshot, mxfs_disklock_terminal_gate_check
  fn static closure_read_gate_sector(struct mxfs_disklock_ctx *ctx, int slot, uint8_t *buf) -> int
    calls: dl_inject_take, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, read_sector
    called_by: mxfs_disklock_closure_gate_snapshot, mxfs_disklock_terminal_gate_check
  fn mxfs_disklock_closure_gate_snapshot(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, mxfs_node_id_t *victim, uint64_t *ag_mask) -> int
    calls: closure_gate_predicate, closure_read_gate_sector, mxfs_pal_alloc, mxfs_pal_free
  fn mxfs_disklock_closure_gate_revalidate(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, mxfs_node_id_t victim, uint64_t ag_mask) -> int
    called_by: v5_closure_gate
  fn mxfs_disklock_terminal_gate_check(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t *victim, uint64_t *ag_mask) -> int
    calls: closure_gate_predicate, closure_read_gate_sector, mxfs_disklock_slot_live, mxfs_pal_alloc, mxfs_pal_free
    called_by: v5_closure_scrub
  fn mxfs_disklock_recovery_backfill_legacy(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_outcome *oc_out) -> int
    calls: hb_gen_foreign, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_cas_durable, recov_desc_present, recov_outcome_fill, recov_outcome_present
    called_by: mxfs_v5_dlm_recovery_backfill_legacy
  fn mxfs_disklock_recovery_read_outcome(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_outcome *oc_out) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_outcome_structural
    called_by: mxfs_v5_dlm_recovery_read_outcome, mxfs_v5_dlm_recovery_scan_outcomes
  fn mxfs_disklock_recovery_refresh(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_auth_holds, recov_cas_durable, recov_desc_present, recov_desc_seal, recov_stamp_after
  fn mxfs_disklock_recovery_read(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_desc *out) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_desc_present
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_victim_recovery_read, mxfs_v5_dlm_victim_untagged_authority
  fn mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_auth *out_auth) -> int
    calls: mxfs_pal_log, recov_desc_present
    called_by: mxfs_disklock_guard_slot, mxfs_v5_dlm_recovery_acquire
  fn static recov_fence_auth_issue(struct mxfs_recov_fence_auth *auth, const struct mxfs_recov_desc *d) -> void
    called_by: mxfs_disklock_recovery_fence_takeover
  fn static recov_fence_auth_holds(const struct mxfs_disklock_ctx *ctx, const struct mxfs_recov_desc *d, const struct mxfs_recov_fence_auth *auth) -> bool
    calls: mxfs_pal_log
    called_by: mxfs_disklock_recovery_fence_arm_submit
  fn mxfs_recov_cert_proves_exclusion(const struct mxfs_recov_desc *d, uint32_t fs_gen, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, const char **why) -> bool
    calls: mxfs_pal_log
    called_by: mxfs_disklock_recovery_claim
  fn mxfs_disklock_recovery_fence_intent(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, uint64_t victim_key, uint16_t slice_idx, uint16_t slice_count, uint32_t flags, struct mxfs_recov_fence_auth *out_auth) -> int
  fn mxfs_disklock_recovery_fence_arm_submit(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_fence_auth *auth) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, recov_cas_durable, recov_desc_present, recov_desc_seal, recov_fence_auth_holds
    called_by: v5_fence_arm_submit_cb
  fn mxfs_disklock_recovery_fence_retryable(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t *out_victim, mxfs_epoch_t *out_epoch) -> int
    calls: inc_eq, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_desc_present
    called_by: v5_fence_retry_one, v5_fence_retry_worker_fn
  fn mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_fence_auth *auth, uint16_t fence_kind, uint16_t fence_resv_type, uint64_t fence_victim_key, uint32_t fence_pr_gen) -> int
    called_by: mxfs_disklock_recovery_advance
  fn mxfs_disklock_recovery_fence_takeover(struct mxfs_disklock_ctx *ctx, int slot, uint64_t victim_key, struct mxfs_recov_fence_auth *out_auth) -> int
    calls: inc_eq, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, recov_cas_durable, recov_desc_present, recov_desc_seal, recov_fence_auth_issue, recov_stamp_after
    called_by: mxfs_v5_dlm_recovery_acquire
  fn mxfs_disklock_recovery_claim(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, struct mxfs_recov_auth *out_auth) -> int
    calls: inc_eq, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_recov_cert_proves_exclusion, recov_auth_issue, recov_cas_durable, recov_desc_present, recov_desc_seal, recov_stamp_after
    called_by: mxfs_v5_dlm_recovery_acquire
  fn mxfs_disklock_recovery_slot_status(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch) -> int
    calls: hb_feature_state, hb_gen_foreign, inc_eq, inc_valid, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_desc_present
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, const struct mxfs_recov_auth *auth, const char *site, uint16_t *out_fence_kind) -> int
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_exclusion_recheck
  fn mxfs_disklock_set_expire_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_expire_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx, const uint8_t *fs_uuid) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_fence_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_conflict_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_conflict_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_evict_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_evict_cb cb, void *data) -> void
  fn mxfs_disklock_note_freed(struct mxfs_disklock_ctx *ctx, uint64_t ino, uint32_t gen, uint32_t type) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_v5_dlm_note_dir_modified, mxfs_v5_dlm_note_inode_freed
  fn mxfs_disklock_monitor_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> void
    calls: mxfs_disklock_find_node_slot, mxfs_pal_log
    called_by: discovery_peer_cb, disklock_hb_fn, peer_connect_cb
  fn mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx, uint32_t timeout_ms) -> void
    calls: mxfs_pal_log
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot) -> bool
    called_by: mxfs_disklock_terminal_gate_check, v5_caw_holders_alive
  fn mxfs_disklock_slot_holds_incarnation(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t epoch, bool *out_read_ok) -> bool
    calls: hb_gen_foreign, inc_valid, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx, int skip_slot) -> int
    called_by: v5_dispatch_slice_recovery, v5_exclusion_recheck, v5_resv_health_tick
  fn mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> void
    calls: mxfs_pal_log
    called_by: purge_node_dlm, remove_node
  fn mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: first, mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_free, recov_desc_names_node
    called_by: mxfs_disklock_monitor_node, v5_handle_node_death
  fn mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_node_id_t
    calls: hb_gen_foreign, mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_free
    called_by: mxfs_v5_dlm_init
  fn static hb_claim_slot_bound(const struct mxfs_disklock_ctx *ctx) -> uint32_t
    called_by: mxfs_disklock_claim_slot, mxfs_disklock_claim_slot_noncaw
  fn static hb_report_claim_exhausted(struct mxfs_disklock_ctx *ctx, uint32_t slot_max) -> void
    calls: hb_gen_foreign, mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_free, mxfs_pal_log, mxfs_unclaimed_bucket_scan, recov_desc_present
    called_by: mxfs_disklock_claim_slot, mxfs_disklock_claim_slot_noncaw
  fn static mxfs_disklock_claim_slot_noncaw(struct mxfs_disklock_ctx *ctx) -> int
    calls: hb_claim_slot_bound, hb_feature_fill, hb_gen_foreign, hb_prov_derive, hb_report_claim_exhausted, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, write_sector_fua
    called_by: mxfs_disklock_claim_slot
  fn mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx) -> int
    calls: claim, hb_claim_slot_bound, hb_draw_incarnation, hb_feature_fill, hb_gen_foreign, hb_prov_derive, hb_report_claim_exhausted, inc_valid, mxfs_disklock_claim_slot_noncaw, mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_local_slot
  fn mxfs_disklock_mount_identity(struct mxfs_disklock_ctx *ctx, uint32_t *slot, mxfs_node_id_t *node, mxfs_epoch_t *epoch) -> bool
    calls: inc_valid
    called_by: mxfs_v5_dlm_mount_identity
  fn static hb_guard_abandoned(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_disklock_heartbeat *first) -> bool
    called_by: mxfs_disklock_guard_slot, mxfs_disklock_slot_unclaimed
  fn mxfs_disklock_guard_slot(struct mxfs_disklock_ctx *ctx, int slot) -> int
    calls: hb_feature_fill, hb_gen_foreign, hb_guard_abandoned, mxfs_disklock_recovery_takeover, mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, recov_desc_present, write_sector_fua
    called_by: mxfs_v5_dlm_guard_slot
  fn mxfs_disklock_guard_refresh(struct mxfs_disklock_ctx *ctx) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, write_sector_fua
    called_by: mxfs_v5_dlm_guard_refresh
  fn mxfs_disklock_unguard(struct mxfs_disklock_ctx *ctx) -> void
    calls: mxfs_pal_alloc, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, write_sector_fua
    called_by: mxfs_v5_dlm_unguard_slot
  fn mxfs_disklock_slot_unclaimed(struct mxfs_disklock_ctx *ctx, int slot) -> int
    calls: hb_gen_foreign, hb_guard_abandoned, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, recov_lease_covers_node
    called_by: mxfs_v5_dlm_slot_unclaimed
  fn mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx) -> bool
    called_by: mxfs_v5_dlm_slice_adopted
  fn mxfs_disklock_get_stale_slot_mask(struct mxfs_disklock_ctx *ctx, uint64_t threshold_ms, int skip_slot, uint64_t *out_mask) -> int
    calls: hb_gen_foreign, mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_get_withdrawn_slots(struct mxfs_disklock_ctx *ctx, int skip_slot, uint64_t *out_mask, mxfs_node_id_t *out_node, mxfs_epoch_t *out_epoch) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_get_recovery_pending_slots(struct mxfs_disklock_ctx *ctx, int skip_slot, uint64_t *out_mask, mxfs_node_id_t *out_node, mxfs_epoch_t *out_epoch) -> int
    called_by: mxfs_v5_dlm_mount_pending_recovery
  fn mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx, uint64_t candidate_mask, const mxfs_node_id_t *expect_node, uint32_t samples, const volatile int *cancel, uint64_t *out_confirmed, mxfs_epoch_t *out_epoch) -> int
    called_by: v5_settle_resolve

[dlm/disklock.h]
  fn mxfs_disklock_create(mxfs_bdev_t *dev, uint64_t disklock_offset, mxfs_node_id_t local_node) -> struct mxfs_disklock_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_disklock_set_snlocal(struct mxfs_disklock_ctx *ctx, bool snlocal) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_slot_limit(struct mxfs_disklock_ctx *ctx, uint32_t limit) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_start_heartbeat(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_stop_heartbeat(struct mxfs_disklock_ctx *ctx) -> void
    called_by: disklock_hb_fn, mxfs_disklock_destroy, mxfs_disklock_withdraw, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_disklock_release_slot(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_disklock_write_grant(struct mxfs_disklock_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t mode, mxfs_epoch_t epoch) -> int
  fn mxfs_disklock_clear_grant(struct mxfs_disklock_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner) -> int
  fn mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: disklock_expire_cb, lease_expire_cb, mxfs_v5_dlm_recovery_complete, peer_disconnect_cb, v5_handle_node_death
  fn mxfs_disklock_read_all(struct mxfs_disklock_ctx *ctx, struct mxfs_disklock_record *records, int max, int *count) -> int
  fn mxfs_disklock_set_expire_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_expire_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx) -> void
    called_by: mxfs_v5_dlm_shutdown_withdraw
  fn mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_recovered_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_clean_depart_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_clean_depart_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t victim_epoch) -> void
    called_by: mxfs_v5_dlm_mount_pending_recovery, v5_defer_slice_recovery, v5_settle_resolve, v5_start_slice_recovery
  fn mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot) -> bool
    called_by: mxfs_v5_dlm_mount_pending_recovery, mxfs_v5_dlm_recovery_complete, v5_defer_slice_recovery, v5_dispatch_late_deaths, v5_settle_resolve, v5_start_slice_recovery
  fn mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t victim_epoch) -> int
    called_by: disklock_hb_fn, hb_still_dead_stamp, mxfs_v5_dlm_recovery_complete
  fn mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_node_id_t
    called_by: mxfs_v5_dlm_mount_pending_recovery, mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_dispatch_late_deaths
  fn mxfs_disklock_pending_epoch(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_epoch_t
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_exclusion_recheck
  fn mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx, int prev, mxfs_node_id_t *node) -> int
    called_by: v5_dispatch_slice_recovery
  fn mxfs_disklock_recovery_begin(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, uint16_t slice_idx, uint16_t slice_count, uint32_t flags, struct mxfs_recov_auth *out_auth) -> int
  fn mxfs_disklock_recovery_advance(struct mxfs_disklock_ctx *ctx, int slot, unsigned int stage, const struct mxfs_recov_auth *auth) -> int
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_disklock_recovery_refresh(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth) -> int
  fn mxfs_disklock_recovery_read(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_desc *out) -> int
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_victim_recovery_read, mxfs_v5_dlm_victim_untagged_authority
  fn mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_auth *out_auth) -> int
    called_by: mxfs_disklock_guard_slot, mxfs_v5_dlm_recovery_acquire
  fn mxfs_disklock_recovery_fence_intent(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, uint64_t victim_key, uint16_t slice_idx, uint16_t slice_count, uint32_t flags, struct mxfs_recov_fence_auth *out_auth) -> int
  fn mxfs_disklock_recovery_fence_arm_submit(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_fence_auth *auth) -> int
    called_by: v5_fence_arm_submit_cb
  fn mxfs_disklock_recovery_fence_retryable(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t *out_victim, mxfs_epoch_t *out_epoch) -> int
    called_by: v5_fence_retry_one, v5_fence_retry_worker_fn
  fn mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_fence_auth *auth, uint16_t fence_kind, uint16_t fence_resv_type, uint64_t fence_victim_key, uint32_t fence_pr_gen) -> int
    called_by: mxfs_disklock_recovery_advance
  fn mxfs_disklock_recovery_fence_takeover(struct mxfs_disklock_ctx *ctx, int slot, uint64_t victim_key, struct mxfs_recov_fence_auth *out_auth) -> int
    called_by: mxfs_v5_dlm_recovery_acquire
  fn mxfs_disklock_recovery_claim(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, struct mxfs_recov_auth *out_auth) -> int
    called_by: mxfs_v5_dlm_recovery_acquire
  fn mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, const struct mxfs_recov_auth *auth, const char *site, uint16_t *out_fence_kind) -> int
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_exclusion_recheck
  fn mxfs_disklock_recovery_slot_status(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch) -> int
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_recov_cert_proves_exclusion(const struct mxfs_recov_desc *d, uint32_t fs_gen, int slot, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, const char **why) -> bool
    called_by: mxfs_disklock_recovery_claim
  fn mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx, const uint8_t *fs_uuid) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_fence_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_set_conflict_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_conflict_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_note_freed(struct mxfs_disklock_ctx *ctx, uint64_t ino, uint32_t gen, uint32_t type) -> void
    called_by: mxfs_v5_dlm_note_dir_modified, mxfs_v5_dlm_note_inode_freed
  fn mxfs_disklock_set_evict_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_evict_cb cb, void *data) -> void
  fn mxfs_disklock_monitor_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> void
    called_by: discovery_peer_cb, disklock_hb_fn, peer_connect_cb
  fn mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> void
    called_by: purge_node_dlm, remove_node
  fn mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_local_slot
  fn mxfs_disklock_mount_identity(struct mxfs_disklock_ctx *ctx, uint32_t *slot, mxfs_node_id_t *node, mxfs_epoch_t *epoch) -> bool
    called_by: mxfs_v5_dlm_mount_identity
  fn mxfs_disklock_guard_slot(struct mxfs_disklock_ctx *ctx, int slot) -> int
    called_by: mxfs_v5_dlm_guard_slot
  fn mxfs_disklock_guard_refresh(struct mxfs_disklock_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_guard_refresh
  fn mxfs_disklock_unguard(struct mxfs_disklock_ctx *ctx) -> void
    called_by: mxfs_v5_dlm_unguard_slot
  fn mxfs_disklock_slot_unclaimed(struct mxfs_disklock_ctx *ctx, int slot) -> int
    called_by: mxfs_v5_dlm_slot_unclaimed
  fn mxfs_disklock_set_vergate_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_vergate_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_recovery_publish_refusal(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, const struct mxfs_recov_refusal_info *info, struct mxfs_recov_outcome *oc_out) -> int
    called_by: mxfs_v5_dlm_recovery_publish_refusal
  fn mxfs_disklock_closure_gate_snapshot(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, mxfs_node_id_t *victim, uint64_t *ag_mask) -> int
  fn mxfs_disklock_closure_gate_revalidate(struct mxfs_disklock_ctx *ctx, int slot, const struct mxfs_recov_auth *auth, mxfs_node_id_t victim, uint64_t ag_mask) -> int
    called_by: v5_closure_gate
  fn mxfs_disklock_terminal_gate_check(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t *victim, uint64_t *ag_mask) -> int
    called_by: v5_closure_scrub
  fn mxfs_disklock_recovery_backfill_legacy(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_outcome *oc_out) -> int
    called_by: mxfs_v5_dlm_recovery_backfill_legacy
  fn mxfs_disklock_recovery_read_outcome(struct mxfs_disklock_ctx *ctx, int slot, struct mxfs_recov_outcome *oc_out) -> int
    called_by: mxfs_v5_dlm_recovery_read_outcome, mxfs_v5_dlm_recovery_scan_outcomes
  fn mxfs_disklock_set_recov_outcome_cb(struct mxfs_disklock_ctx *ctx, mxfs_disklock_recov_outcome_cb cb, void *data) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx, uint32_t timeout_ms) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx) -> bool
    called_by: mxfs_v5_dlm_slice_adopted
  fn mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: mxfs_disklock_monitor_node, v5_handle_node_death
  fn mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx, int slot) -> mxfs_node_id_t
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot) -> bool
    called_by: mxfs_disklock_terminal_gate_check, v5_caw_holders_alive
  fn mxfs_disklock_slot_holds_incarnation(struct mxfs_disklock_ctx *ctx, int slot, mxfs_node_id_t node, mxfs_epoch_t epoch, bool *out_read_ok) -> bool
  fn mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx, int skip_slot) -> int
    called_by: v5_dispatch_slice_recovery, v5_exclusion_recheck, v5_resv_health_tick
  fn mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx, uint32_t timeout_ms) -> void
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_get_stale_slot_mask(struct mxfs_disklock_ctx *ctx, uint64_t threshold_ms, int skip_slot, uint64_t *out_mask) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_get_withdrawn_slots(struct mxfs_disklock_ctx *ctx, int skip_slot, uint64_t *out_mask, mxfs_node_id_t *out_node, mxfs_epoch_t *out_epoch) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_disklock_get_recovery_pending_slots(struct mxfs_disklock_ctx *ctx, int skip_slot, uint64_t *out_mask, mxfs_node_id_t *out_node, mxfs_epoch_t *out_epoch) -> int
    called_by: mxfs_v5_dlm_mount_pending_recovery
  fn mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx, uint64_t candidate_mask, const mxfs_node_id_t *expect_node, uint32_t samples, const volatile int *cancel, uint64_t *out_confirmed, mxfs_epoch_t *out_epoch) -> int
    called_by: v5_settle_resolve
  struct mxfs_disklock_record { magic, flags, resource, owner, mode, state, pad, granted_at_ms, epoch, reserved }
  struct mxfs_evict_entry { ino, gen, type }
  struct mxfs_evict_ring { magic, head_seq, count, pad, entry }
  struct mxfs_mepoch_rec { epoch, member_mask, fenced_mask, magic, self_incarnation, voter_slots, flags, crc32c }
  struct mxfs_recov_desc { magic, version, stage, victim_epoch, owner_epoch, recovery_gen, owner_stamp_ms, victim_node, owner_node, victim_fs_gen }
  struct mxfs_recov_auth { victim_node, victim_epoch, recovery_gen, owner_term, victim_slot, stage }
  struct mxfs_recov_fence_auth { victim_node, victim_epoch, recovery_gen, victim_key, fence_term, victim_slot }
  struct mxfs_recov_outcome { magic, version, outcome, reason, domain_kind, victim_slot, owner_slot, victim_epoch, owner_epoch, recovery_gen }
  struct mxfs_recov_refusal_info { reason, domain_kind, ag_mask, slice_digest, refused, malformed, digest_valid }
  struct mxfs_recov_body { desc, outcome, pad }
  struct mxfs_hb_feature { magic, proto_gen, feat_flags, crc32c }
  struct mxfs_hb_provenance { magic, prev_node, prev_epoch, slot_seq, chain_len, crc32c }
  struct mxfs_disklock_heartbeat { magic, flags, node_id, fs_gen, timestamp_ms, epoch, lock_count, evict, recov, prov }
  struct mxfs_disklock_node_track { last_timestamp, last_epoch, changed_samples, equal_samples, live, last_evict_seq, evict_seen, last_seq, seq_seen }
  typedef_fn mxfs_disklock_expire_cb
  typedef_fn mxfs_disklock_recovered_cb
  typedef_fn mxfs_disklock_clean_depart_cb
  typedef_fn mxfs_disklock_fence_cb
  typedef_fn mxfs_disklock_conflict_cb
  typedef_fn mxfs_disklock_evict_cb
  typedef_fn mxfs_disklock_vergate_cb
  enum mxfs_quar_disposition { MXFS_QUAR_NOT_TERMINAL, nothing, terminal, here, MXFS_QUAR_VALID_AG, validated, TERMINAL_REFUSED, AG, scoped, MXFS_QUAR_VALID_FSWIDE }
  typedef_fn mxfs_disklock_recov_outcome_cb
  enum mxfs_hb_stage { MXFS_HB_STAGE_SLEEP, MXFS_HB_STAGE_IDCHECK, MXFS_HB_STAGE_LOCKWAIT, MXFS_HB_STAGE_CASWRITE, MXFS_HB_STAGE_MONITOR }
  struct mxfs_disklock_ctx { dev, base_offset, local_node, local_slot, slot_limit, slice_adopted, snlocal, hb_thread, hb_stage, hb_stage_ms }

[dlm/dlm.c]
  fn static mode_name(uint8_t mode) -> const char
    called_by: dg_grant_ex, dlm_lock_impl, do_scsi_read_fua, fire_bast_records, main, mxfs_dlm_audit_double_grant, mxfs_dlm_lock_retries, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen, promote_waiters
  fn static dlm_view_confirmed(struct mxfs_dlm_ctx *ctx) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: dlm_lock_impl
  fn static dlm_membership_settling(struct mxfs_dlm_ctx *ctx) -> bool
    calls: mxfs_pal_sleep_ms
    called_by: dlm_lock_impl, mxfs_dlm_is_single_node
  fn mxfs_dlm_get_view_sig(struct mxfs_dlm_ctx *ctx, uint32_t *count) -> uint64_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: v5_view_sig_provider
  fn mxfs_dlm_report_peer_view(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node, uint32_t count, uint64_t hash) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: v5_view_report_cb
  fn static mxfs_lkt_record(const char *act, const struct mxfs_resource_id *res, uint32_t owner, uint8_t mode) -> void
    calls: mxfs_pal_time_ms
  fn mxfs_dlm_lkt_dump(uint64_t want_ino) -> void
    calls: mxfs_pal_log
    called_by: mxfs_lktdump_set
  fn static state_name(uint8_t state) -> const char
    called_by: mxfs_dlm_process_remote_release, mxfs_dlm_unlock_gen
  fn static resource_hash(const struct mxfs_resource_id *res, uint32_t bucket_count) -> uint32_t
    calls: resource_hash_raw
    called_by: dg_grant_ex, dlm_lock_impl, find_lock_slot, mxfs_disklock_write_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_unlock_gen
  fn static pending_hash(const struct mxfs_resource_id *res) -> uint32_t
    calls: resource_hash_raw
    called_by: pending_insert, pending_remove
  fn static lock_alloc(const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t mode, uint8_t state, uint32_t flags) -> struct mxfs_lock
    calls: atomic_inc_return, lock_free, mxfs_pal_alloc, mxfs_pal_log, mxfs_pal_time_ms
    called_by: dlm_lock_impl
  fn static lock_free(struct mxfs_lock *lk) -> void
    calls: atomic_inc_return, mxfs_pal_free, mxfs_pal_log
    called_by: dlm_lock_impl, lock_alloc, mxfs_dlm_destroy, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_unlock_gen
  fn static pending_alloc(const struct mxfs_resource_id *resource) -> struct mxfs_dlm_pending
    calls: mxfs_pal_alloc, mxfs_pal_cond_create, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy
    called_by: dlm_lock_impl
  fn static pending_free(struct mxfs_dlm_pending *p) -> void
    calls: mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: dlm_lock_impl
  fn static pending_complete(struct mxfs_dlm_pending *p, uint8_t mode, int status) -> void
    called_by: fail_all_pending
  fn static pending_wait(struct mxfs_dlm_pending *p, uint64_t timeout_ms) -> int
    calls: mxfs_pal_cond_timedwait, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: dlm_lock_impl, mxfs_dlm_purge_node, mxfs_dlm_update_active_nodes
  fn static pending_insert(struct mxfs_dlm_ctx *ctx, struct mxfs_dlm_pending *p) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, pending_hash
    called_by: dlm_lock_impl
  fn static pending_remove(struct mxfs_dlm_ctx *ctx, struct mxfs_dlm_pending *p) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, pending_hash
    called_by: dlm_lock_impl
  fn static pending_signal_resource(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, int status, mxfs_epoch_t epoch) -> bool
    called_by: fail_all_pending, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn static fail_all_pending(struct mxfs_dlm_ctx *ctx) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, pending_complete, pending_signal_resource
    called_by: mxfs_dlm_lock_retries, mxfs_dlm_purge_node, mxfs_dlm_update_active_nodes
  fn static fire_bast_records(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, struct mxfs_bast_record *recs, int count) -> void
    calls: atomic_inc_return, mode_name, mxfs_pal_log
    called_by: dlm_lock_impl, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn static collect_grantee_bast_if_waiters(struct mxfs_lock *chain, const struct mxfs_resource_id *resource, mxfs_node_id_t grantee, uint8_t grantee_mode, struct mxfs_bast_record *rec) -> int
    called_by: dlm_lock_impl
  fn static mxfs_dlm_audit_double_grant(struct mxfs_lock *chain, const struct mxfs_resource_id *resource) -> int
    calls: atomic_inc_return, mode_name, resource_equal
    called_by: dlm_lock_impl, promote_waiters
  fn static waiter_cmp(const void *a, const void *b) -> int
  fn static find_conflicting_waiter(struct mxfs_lock *chain, const struct mxfs_resource_id *resource, mxfs_node_id_t requester, uint8_t mode) -> struct mxfs_lock
    calls: resource_equal
    called_by: dlm_lock_impl
  fn static promote_waiters(struct mxfs_dlm_ctx *ctx, struct mxfs_lock *chain, const struct mxfs_resource_id *resource) -> struct mxfs_lock
    calls: atomic_inc_return, dlm_next_gen, first, mode_name, mxfs_dlm_audit_double_grant, mxfs_pal_log, mxfs_pal_time_ms, resource_equal
    called_by: mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn static collect_post_promotion_basts(struct mxfs_lock *chain, const struct mxfs_resource_id *resource, uint8_t *blocked_mode_out) -> struct mxfs_lock
    calls: resource_equal
    called_by: mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn static dlm_next_gen(struct mxfs_dlm_ctx *ctx) -> uint32_t
    called_by: dlm_lock_impl, promote_waiters
  fn static send_grant(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target, const struct mxfs_resource_id *resource, uint8_t mode, uint8_t status_code, uint16_t msg_type, mxfs_epoch_t epoch, uint32_t grant_gen, uint8_t handoff, uint32_t dir_epoch) -> void
    called_by: mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn mxfs_dlm_modes_compatible(uint8_t held, uint8_t requested) -> int
  fn mxfs_dlm_create(mxfs_node_id_t local_node) -> struct mxfs_dlm_ctx
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_rwlock_create
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_destroy(struct mxfs_dlm_ctx *ctx) -> void
    calls: lock_free, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_rwlock_destroy, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn static dlm_lock_impl(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode) -> int
    calls: atomic_inc_return, collect_grantee_bast_if_waiters, deny, dg_grant_ex, dlm_membership_settling, dlm_next_gen, dlm_view_confirmed, find_conflicting_waiter, fire_bast_records, lock_alloc, lock_free, mode_name, mxfs_dlm_audit_double_grant, mxfs_dlm_resource_master, mxfs_pal_log
    called_by: mxfs_dlm_lock_retries
  fn mxfs_dlm_lock(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode) -> int
    calls: mxfs_dlm_lock_retries
    called_by: dlm_lock_tcp_wrapper, mxfs_dlm_purge_node, mxfs_dlm_update_active_nodes, mxfs_unmount, mxfs_v5_dlm_ag_lock, mxfs_v5_dlm_ag_lock_nb, mxfs_v5_dlm_iclus_lock, mxfs_v5_dlm_inode_lock, mxfs_v5_dlm_inode_lock_try
  fn mxfs_dlm_lock_retries(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, int max_retries) -> int
    calls: atomic_inc_return, dlm_lock_impl, fail_all_pending, mode_name, mxfs_pal_dump_stack, mxfs_pal_log, mxfs_pal_sleep_ms
    called_by: mxfs_dlm_lock, mxfs_v5_dlm_inode_lock_retries
  fn mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t expected_gen) -> int
    calls: atomic_inc_return, collect_post_promotion_basts, dg_grant_ex, dg_release, fire_bast_records, lock_free, mode_name, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_resource_master, mxfs_pal_log, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, mxfs_pal_sleep_ms, pending_signal_resource, promote_waiters
    called_by: mxfs_dlm_unlock, mxfs_v5_dlm_iclus_unlock_gen, mxfs_v5_dlm_inode_unlock_free, mxfs_v5_dlm_inode_unlock_open
  fn mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_unlock_gen
    called_by: dlm_unlock_tcp_wrapper, mxfs_dlm_withdraw_release_all, mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_resource_master
    called_by: mxfs_dlm_release_orphan_if_unheld, mxfs_v5_dlm_inode_release_unconditional
  fn mxfs_dlm_release_orphan_if_unheld(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_send_unconditional_release, mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_dlm_unlock_gen, mxfs_v5_dlm_ag_orphan_nak
  fn mxfs_dlm_lock_convert(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t new_mode) -> int
    calls: collect_post_promotion_basts, dg_grant_ex, fire_bast_records, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, mxfs_pal_time_ms, pending_signal_resource, promote_waiters, resource_equal, resource_hash, send_grant
    called_by: dlm_convert_tcp_wrapper
  fn mxfs_dlm_purge_node(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node) -> int
    calls: fail_all_pending, lock_free, mxfs_dlm_lock, mxfs_pal_log, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, mxfs_pal_time_ms, pending_signal_resource, pending_wait, resource_equal
    called_by: mxfs_v5_dlm_recovery_complete, v5_clean_depart_cb, v5_handle_node_death, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_tcp_declare_dead
  fn mxfs_dlm_purge_stale_for_resource(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: collect_post_promotion_basts, dg_grant_ex, fire_bast_records, lock_free, mode_name, mxfs_pal_log, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, pending_signal_resource, promote_waiters, resource_equal, resource_hash, send_grant
  fn mxfs_dlm_withdraw_release_all(struct mxfs_dlm_ctx *ctx) -> void
    calls: mxfs_dlm_unlock, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock
  fn mxfs_dlm_release_all(struct mxfs_dlm_ctx *ctx) -> void
    calls: lock_free, mxfs_pal_log, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn static node_id_cmp(const void *a, const void *b) -> int
  fn mxfs_dlm_resource_master(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> mxfs_node_id_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
    called_by: dlm_lock_impl, mxfs_dlm_is_resource_master, mxfs_dlm_send_unconditional_release, mxfs_dlm_unlock_gen
  fn mxfs_dlm_is_resource_master(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> bool
    calls: mxfs_dlm_resource_master
    called_by: mxfs_v5_dlm_inode_master_self
  fn mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx, const mxfs_node_id_t *nodes, int count) -> int
    calls: fail_all_pending, mxfs_dlm_advance_epoch, mxfs_dlm_lock, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, mxfs_pal_time_ms, pending_wait
    called_by: membership_stab_worker_fn, mxfs_dlm_is_single_node, queue_membership_update, v5_refresh_active_nodes
  fn mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx) -> bool
    calls: dlm_membership_settling, mxfs_dlm_update_active_nodes
    called_by: mxfs_v5_dlm_is_single_node, mxfs_v5_dlm_set_peer_joined_notify, v5_discovery_peer_cb, v5_peer_connect_cb_tcp
  fn mxfs_dlm_held_mode_nb(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t *out_mode) -> int
    calls: mxfs_pal_rwlock_tryrdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_v5_dlm_inode_held_nb
  fn mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
    calls: mxfs_pal_may_sleep, mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
  fn mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    calls: mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_v5_dlm_inode_grant_gen
  fn mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
    calls: mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_v5_dlm_inode_granted_mode
  fn mxfs_dlm_grant_was_handoff(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *gen_out) -> bool
    calls: mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_v5_dlm_inode_grant_handoff
  fn mxfs_dlm_grant_dir_epoch(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    calls: atomic_inc_return, mxfs_pal_rwlock_rdlock, mxfs_pal_rwlock_unlock, resource_equal, resource_hash
    called_by: mxfs_v5_dlm_inode_dir_epoch
  fn mxfs_dlm_advance_epoch(struct mxfs_dlm_ctx *ctx) -> mxfs_epoch_t
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_update_active_nodes
  fn mxfs_dlm_get_epoch(struct mxfs_dlm_ctx *ctx) -> mxfs_epoch_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn static dg_grant_ex(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *res, mxfs_node_id_t owner, uint32_t gen, uint32_t *epoch_out) -> bool
    calls: atomic_inc_return, mode_name, resource_equal, resource_hash, resource_hash_raw
    called_by: dlm_lock_impl, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen
  fn static dg_release(const struct mxfs_resource_id *res, mxfs_node_id_t owner) -> void
    calls: resource_equal
    called_by: mxfs_dlm_process_remote_release, mxfs_dlm_unlock_gen
  fn mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, mxfs_epoch_t request_epoch) -> int
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  fn mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, int status, mxfs_epoch_t grant_epoch, uint32_t grant_gen, uint8_t handoff, uint32_t dir_epoch) -> int
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  fn mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender, const struct mxfs_resource_id *resource, uint32_t grant_gen) -> int
    calls: collect_post_promotion_basts, dg_grant_ex, dg_release, fire_bast_records, lock_free, mode_name, mxfs_pal_log, mxfs_pal_rwlock_unlock, mxfs_pal_rwlock_wrlock, pending_signal_resource, promote_waiters, resource_equal, resource_hash, send_grant, state_name
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  struct mxfs_lkt_ev { seq, ts_ms, ino, act, owner, mode, rtype }
  struct mxfs_bast_record { owner, requested_mode }
  struct dg_shadow_ent { res, owner, last_owner, gen, epoch, active, used, last_grant_seq, grant_count }

[dlm/dlm.h]
  fn mxfs_dlm_create(mxfs_node_id_t local_node) -> struct mxfs_dlm_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_destroy(struct mxfs_dlm_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_lock(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode) -> int
    called_by: dlm_lock_tcp_wrapper, mxfs_dlm_purge_node, mxfs_dlm_update_active_nodes, mxfs_unmount, mxfs_v5_dlm_ag_lock, mxfs_v5_dlm_ag_lock_nb, mxfs_v5_dlm_iclus_lock, mxfs_v5_dlm_inode_lock, mxfs_v5_dlm_inode_lock_try
  fn mxfs_dlm_lock_retries(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, int max_retries) -> int
    called_by: mxfs_dlm_lock, mxfs_v5_dlm_inode_lock_retries
  fn mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: dlm_unlock_tcp_wrapper, mxfs_dlm_withdraw_release_all, mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: mxfs_dlm_release_orphan_if_unheld, mxfs_v5_dlm_inode_release_unconditional
  fn mxfs_dlm_release_orphan_if_unheld(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: mxfs_dlm_unlock_gen, mxfs_v5_dlm_ag_orphan_nak
  fn mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t expected_gen) -> int
    called_by: mxfs_dlm_unlock, mxfs_v5_dlm_iclus_unlock_gen, mxfs_v5_dlm_inode_unlock_free, mxfs_v5_dlm_inode_unlock_open
  fn mxfs_dlm_lock_convert(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t new_mode) -> int
    called_by: dlm_convert_tcp_wrapper
  fn mxfs_dlm_release_all(struct mxfs_dlm_ctx *ctx) -> void
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_withdraw_release_all(struct mxfs_dlm_ctx *ctx) -> void
  fn mxfs_dlm_purge_node(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node) -> int
    called_by: mxfs_v5_dlm_recovery_complete, v5_clean_depart_cb, v5_handle_node_death, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_tcp_declare_dead
  fn mxfs_dlm_purge_stale_for_resource(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> int
  fn mxfs_dlm_resource_master(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> mxfs_node_id_t
    called_by: dlm_lock_impl, mxfs_dlm_is_resource_master, mxfs_dlm_send_unconditional_release, mxfs_dlm_unlock_gen
  fn mxfs_dlm_is_resource_master(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> bool
    called_by: mxfs_v5_dlm_inode_master_self
  fn mxfs_dlm_get_view_sig(struct mxfs_dlm_ctx *ctx, uint32_t *count) -> uint64_t
    called_by: v5_view_sig_provider
  fn mxfs_dlm_report_peer_view(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node, uint32_t count, uint64_t hash) -> void
    called_by: v5_view_report_cb
  fn mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx, const mxfs_node_id_t *nodes, int count) -> int
    called_by: membership_stab_worker_fn, mxfs_dlm_is_single_node, queue_membership_update, v5_refresh_active_nodes
  fn mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx) -> bool
    called_by: mxfs_v5_dlm_is_single_node, mxfs_v5_dlm_set_peer_joined_notify, v5_discovery_peer_cb, v5_peer_connect_cb_tcp
  fn mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
  fn mxfs_dlm_held_mode_nb(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t *out_mode) -> int
    called_by: mxfs_v5_dlm_inode_held_nb
  fn mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
    called_by: mxfs_v5_dlm_inode_granted_mode
  fn mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    called_by: mxfs_v5_dlm_inode_grant_gen
  fn mxfs_dlm_grant_was_handoff(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *gen_out) -> bool
    called_by: mxfs_v5_dlm_inode_grant_handoff
  fn mxfs_dlm_grant_dir_epoch(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    called_by: mxfs_v5_dlm_inode_dir_epoch
  fn mxfs_dlm_advance_epoch(struct mxfs_dlm_ctx *ctx) -> mxfs_epoch_t
    called_by: mxfs_dlm_update_active_nodes
  fn mxfs_dlm_get_epoch(struct mxfs_dlm_ctx *ctx) -> mxfs_epoch_t
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, mxfs_epoch_t request_epoch) -> int
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  fn mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, int status, mxfs_epoch_t grant_epoch, uint32_t grant_gen, uint8_t handoff, uint32_t dir_epoch) -> int
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  fn mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender, const struct mxfs_resource_id *resource, uint32_t grant_gen) -> int
    called_by: peer_msg_cb, v5_peer_msg_cb_tcp
  fn mxfs_dlm_modes_compatible(uint8_t held, uint8_t requested) -> int
  struct mxfs_lock { resource, owner, mode, state, flags, queued_at, granted_at, grant_gen, handoff, dir_epoch }
  struct mxfs_dlm_pending { next, resource, lock, cond, done, granted_mode, status, request_epoch }
  typedef_fn mxfs_dlm_grant_cb
  typedef_fn mxfs_dlm_bast_cb
  typedef_fn mxfs_dlm_send_cb
  typedef_fn mxfs_dlm_membership_cb
  struct mxfs_dlm_ctx { bucket_count, lock_count, table_rwlock, local_node, shutting_down, grant_gen_next, current_epoch, epoch_lock, nodes, count }
  typedef_fn mxfs_dlm_lock_fn
  typedef_fn mxfs_dlm_unlock_fn
  typedef_fn mxfs_dlm_convert_fn

[dlm/dlm_caw.c]
  fn static caw_inject_take(int *knob) -> bool
    calls: caw_slot, mxfs_pal_log
    called_by: caw_grant_epoch_update, caw_owed_dispatch, caw_owed_worker_fn, caw_release_all_body
  fn static caw_watch_armed(uint32_t slot_index) -> bool
    calls: caw_watch_note, mxfs_pal_bdev_compare_and_write, mxfs_pal_time_ms, slot_offset
    called_by: caw_slot
  fn static caw_watch_span_armed(uint32_t start_idx, uint32_t nslots) -> bool
  fn static caw_watch_note(bool is_caw, uint64_t ms, int rc) -> void
    called_by: caw_slot, caw_watch_armed
  fn static caw_watch_span_note(void) -> void
  fn static caw_watch_note(bool is_caw, uint64_t ms, int rc) -> void
    called_by: caw_slot, caw_watch_armed
  fn static caw_failstop_grace_ms(void) -> uint32_t
    called_by: caw_join_bounded, mxfs_dlm_caw_stop
  fn static mode_name(uint8_t mode) -> const char
    called_by: dg_grant_ex, dlm_lock_impl, do_scsi_read_fua, fire_bast_records, main, mxfs_dlm_audit_double_grant, mxfs_dlm_lock_retries, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen, promote_waiters
  fn static holders_for_mode(struct mxfs_caw_lock_slot *slot, uint8_t mode) -> uint64_t
    called_by: caw_convert_body, compatible_excluding_self
  fn static compatible_excluding_self(const struct mxfs_caw_lock_slot *slot, uint8_t mode, uint64_t node_bit) -> bool
    calls: caw_exwin_log, caw_grant_epoch_update, caw_grant_meta_store, caw_grant_result_fill, caw_grant_seq_prebump, caw_slot, holders_for_mode, mxfs_pal_time_ms, recompute_granted_mode
    called_by: caw_convert_body
  fn static node_held_mode(const struct mxfs_caw_lock_slot *slot, uint64_t node_bit) -> uint8_t
    calls: lreq_release_all, untrack_held
    called_by: bast_poll_fn, caw_convert_body, caw_grant_epoch_update, mxfs_dlm_caw_granted_mode, mxfs_dlm_caw_held
  fn static slot_has_holders(const struct mxfs_caw_lock_slot *slot) -> bool
    calls: mxfs_pal_log
    called_by: caw_open_clear_body, caw_purge_dead_nodes_body, caw_release_all_body, caw_revoke_consume
  fn static caw_revoke_consume(struct mxfs_caw_lock_slot *new_slot, const struct mxfs_caw_lock_slot *ref) -> void
    calls: slot_has_holders
  fn static recompute_waiter_mode(const struct mxfs_caw_lock_slot *slot) -> uint8_t
    called_by: caw_convert_body, caw_release_all_body, caw_strip_node_state, caw_unlk_delta_classify
  fn static caw_unlk_delta_is_registration(const struct mxfs_caw_lock_slot *prev, const struct mxfs_caw_lock_slot *now, struct mxfs_caw_lock_slot *scratch, uint64_t self_bit) -> bool
    calls: caw_unlk_delta_classify
  fn static caw_unlk_delta_classify(const struct mxfs_caw_lock_slot *prev, const struct mxfs_caw_lock_slot *now, struct mxfs_caw_lock_slot *scratch, uint64_t self_bit) -> int
    calls: recompute_waiter_mode
    called_by: caw_unlk_delta_is_registration
  fn static caw_grant_streak_note(struct mxfs_caw_lock_slot *slot, uint8_t mode) -> void
  fn static slot_offset(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index) -> uint64_t
    called_by: caw_purge_dead_nodes_body, caw_repair_slot, caw_slot, caw_watch_armed, mxfs_dlm_caw_footprint_scan, mxfs_journal_replay, mxfs_journal_slot_open, scan_disk_for_node_slot
  fn static slot_appears_corrupt(const struct mxfs_caw_lock_slot *s) -> bool
    calls: mxfs_pal_free, read_slot
  fn static caw_repair_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index, const struct mxfs_caw_lock_slot *corrupt, struct mxfs_caw_lock_slot *repaired_out) -> int
    calls: mxfs_pal_bdev_compare_and_write, mxfs_pal_log, mxfs_pal_time_ms, recompute_granted_mode, slot_offset
  fn static read_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index, struct mxfs_caw_lock_slot *out) -> int
    called_by: bast_poll_fn, caw_convert_body, caw_count_resource_slots, caw_force_release_self_body, caw_open_set_body, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, is_tracked_held, mxfs_dlm_caw_footprint_scan, slot_appears_corrupt, slot_hint_get
  fn static read_slot_span(struct mxfs_dlm_caw_ctx *ctx, uint32_t start_idx, uint32_t nslots, struct mxfs_caw_lock_slot *buf) -> int
    calls: mxfs_pal_free
  fn static caw_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index, const struct mxfs_caw_lock_slot *compare, const struct mxfs_caw_lock_slot *write) -> int
    calls: caw_watch_armed, caw_watch_note, mxfs_pal_bdev_compare_and_write, mxfs_pal_bdev_read_prio, mxfs_pal_log, mxfs_pal_sleep_ms, mxfs_pal_time_ms, slot_offset
    called_by: caw_convert_body, caw_force_release_self_body, caw_inject_take, caw_open_clear_body, caw_open_set_body, caw_purge_dead_nodes_body, caw_release_all_body, compatible_excluding_self, mxfs_dlm_caw_set_dir_block0
  fn static caw_may_have_written(int rc) -> bool
    calls: lreq_release_all, mxfs_pal_log, untrack_held
    called_by: caw_force_release_self_body
  fn static slot_hint_store(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t slot_idx) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
    called_by: caw_open_set_body
  fn static slot_hint_get(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *slot_idx_out) -> bool
    calls: mxfs_pal_free, read_slot
    called_by: mxfs_dlm_caw_dump_slot
  fn static caw_next_grant_epoch(uint64_t prev) -> uint64_t
    called_by: caw_grant_epoch_update
  fn static caw_grant_epoch_update(struct mxfs_caw_lock_slot *s, const struct mxfs_caw_lock_slot *cur, uint8_t grantee_slot, uint8_t mode) -> bool
    calls: caw_inject_take, caw_next_grant_epoch, mxfs_pal_log, node_held_mode
    called_by: caw_convert_body, compatible_excluding_self
  fn static caw_grant_result_fill(struct mxfs_grant_result *gres, const struct mxfs_resource_id *resource, const struct mxfs_caw_lock_slot *s, uint8_t held, bool reaffirm) -> void
    called_by: caw_convert_body, compatible_excluding_self
  fn static caw_tombstone_slot(struct mxfs_caw_lock_slot *s) -> void
    calls: mxfs_pal_time_ms
    called_by: caw_open_clear_body, caw_purge_dead_nodes_body, caw_release_all_body
  fn static caw_claim_inherit_epoch(struct mxfs_caw_lock_slot *fresh, const struct mxfs_caw_lock_slot *prev, const struct mxfs_resource_id *resource) -> void
    called_by: caw_open_set_body
  fn static caw_mint_lineage(void) -> uint64_t
    calls: mxfs_pal_get_random_bytes
    called_by: caw_open_set_body
  fn static caw_grant_meta_store(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t dir_epoch, bool handoff, uint64_t dir_block0_fsb, uint32_t dir_block0_gen) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
    called_by: caw_convert_body, compatible_excluding_self
  fn static caw_grant_meta_get_epoch(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *epoch_out) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
  fn static caw_grant_meta_store_unless_releasing(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t dir_epoch, bool handoff, uint64_t dir_block0_fsb, uint32_t dir_block0_gen) -> bool
    calls: mxfs_pal_log, mxfs_pal_sleep_ms
  fn static caw_grant_seq_prebump(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, resource_hash_raw
    called_by: caw_convert_body, compatible_excluding_self
  fn static caw_grant_meta_seq(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint64_t
    calls: mxfs_pal_log, mxfs_pal_time_ms
    called_by: mxfs_dlm_caw_grant_seq32
  fn static caw_release_mark(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, bool on) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, resource_hash_raw
  fn static caw_grant_meta_get(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *epoch_out, bool *handoff_out) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
    called_by: mxfs_dlm_caw_grant_dir_epoch, mxfs_dlm_caw_grant_handoff
  fn mxfs_dlm_caw_grant_dir_epoch(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    calls: caw_grant_meta_get
    called_by: mxfs_v5_dlm_inode_dir_epoch
  fn mxfs_dlm_caw_grant_dir_block0(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t want_gen, uint64_t *fsb_out) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_hash_raw
    called_by: mxfs_v5_dlm_inode_dir_block0
  fn mxfs_dlm_caw_grant_handoff(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *gen_out) -> bool
    calls: caw_grant_meta_get
    called_by: mxfs_v5_dlm_inode_grant_handoff
  fn mxfs_dlm_caw_grant_seq32(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    calls: caw_grant_meta_seq
    called_by: mxfs_v5_dlm_inode_grant_gen
  fn mxfs_dlm_caw_orphan_clock_get(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, bool starve) -> uint64_t
    calls: mxfs_pal_spinlock_lock, mxfs_pal_spinlock_unlock, resource_hash_raw
    called_by: mxfs_v5_dlm_inode_orphan_clock_get
  fn mxfs_dlm_caw_orphan_clock_set(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, bool starve, uint64_t val) -> void
    calls: bucket, mxfs_pal_spinlock_lock, mxfs_pal_spinlock_unlock, resource_hash_raw
    called_by: mxfs_v5_dlm_inode_orphan_clock_set
  fn static lreq_bucket(const struct mxfs_resource_id *resource) -> uint32_t
    calls: lreq_reserve_give, mxfs_pal_free
    called_by: caw_owe_residue, lreq_find, lreq_gc, lreq_join
  fn static lreq_find(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> struct mxfs_caw_lreq
    calls: lreq_bucket
    called_by: caw_owe_residue, lreq_clr_snap, lreq_join, lreq_pub_seq_peek, lreq_release_all
  fn static lreq_owed_pending(const struct mxfs_caw_lreq *e) -> bool
    called_by: caw_owed_count_locked, caw_owed_release, lreq_finish, lreq_gc, lreq_oq_sync, lreq_owed_merge, lreq_owed_retract, mxfs_dlm_caw_destroy
  fn static lreq_oq_remove(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> void
    called_by: caw_owed_sweep, lreq_oq_rotate, lreq_oq_sync
  fn static lreq_oq_push_tail(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> void
    called_by: lreq_oq_rotate, lreq_oq_sync
  fn static lreq_oq_rotate(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> void
    calls: lreq_oq_push_tail, lreq_oq_remove
    called_by: caw_owed_sweep
  fn static lreq_oq_sync(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> void
    calls: lreq_oq_push_tail, lreq_oq_remove, lreq_owed_pending
    called_by: caw_owed_release, lreq_owed_merge, lreq_owed_retract
  fn static lreq_owed_merge(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, const struct mxfs_caw_owed_intent *in) -> void
    calls: lreq_oq_sync, lreq_owed_pending, mxfs_pal_time_ms
    called_by: caw_owe_residue
  fn static lreq_reserve_take(struct mxfs_dlm_caw_ctx *ctx) -> struct mxfs_caw_lreq
    called_by: caw_owe_residue
  fn static lreq_reserve_give(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> bool
    called_by: lreq_bucket, lreq_gc, lreq_join, lreq_reserve_fill
  fn static lreq_reserve_fill(struct mxfs_dlm_caw_ctx *ctx, uint32_t target) -> void
    calls: lreq_reserve_give, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: lreq_join
  fn static lreq_gc(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e) -> void
    calls: lreq_bucket, lreq_owed_pending, lreq_reserve_give, mxfs_pal_free
    called_by: caw_owed_release, lreq_clr_end, lreq_finish, lreq_release_all
  fn static lreq_join(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode) -> struct mxfs_caw_lreq
    calls: lreq_bucket, lreq_find, lreq_reserve_fill, lreq_reserve_give, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_convert_body
  fn static lreq_world_frozen(const struct mxfs_dlm_caw_ctx *ctx) -> bool
    called_by: lreq_owed_retract, lreq_plan
  fn static lreq_plan(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, uint8_t giveup_mode, bool self_joined, struct mxfs_caw_clear_plan *plan) -> void
    calls: lreq_world_frozen, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static lreq_owed_retract(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, uint64_t gen0, const struct mxfs_caw_clear_plan *plan, uint8_t giveup_mode, bool proven, bool terminal) -> void
    calls: lreq_oq_sync, lreq_owed_pending, lreq_world_frozen, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_owed_dispatch
  fn static lreq_clr_begin(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_caw_owed_intent *intent, uint64_t *pub_seq0, uint64_t *gen0, struct mxfs_caw_lreq **out) -> int
  fn static lreq_clr_begin_wait(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_caw_owed_intent *intent, uint64_t *pub_seq0, uint64_t *gen0, struct mxfs_caw_lreq **out, uint64_t deadline_ms) -> int
    calls: mxfs_pal_free
    called_by: caw_force_release_self_body
  fn static lreq_clr_begin_existing(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, uint64_t *gen0) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static lreq_clr_end(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, bool committed) -> void
    calls: lreq_gc, mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_force_release_self_body
  fn static lreq_clr_snap(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, struct mxfs_caw_clr_snap *s) -> void
    calls: lreq_find, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static lreq_clr_still_good(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_caw_clr_snap *s) -> bool
    calls: mxfs_pal_sleep_ms
  fn static caw_slot_clearing(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t slot_idx, const struct mxfs_caw_lock_slot *cur, struct mxfs_caw_lock_slot *new, const char *site, uint8_t owed_mode) -> int
    called_by: caw_convert_body
  fn static find_slot_skip(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out, uint32_t *empty_out, uint32_t skip_idx, uint32_t *last_read_out, uint64_t deadline) -> int
    called_by: find_slot
  fn static find_slot(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out, uint32_t *empty_out) -> int
    calls: find_slot_skip
    called_by: caw_convert_body, caw_open_clear_body, caw_open_set_body, mxfs_dlm_caw_dump_slot, mxfs_dlm_caw_granted_mode, mxfs_dlm_caw_held, mxfs_dlm_caw_open_holders, mxfs_dlm_caw_open_probe, mxfs_dlm_caw_read_generation, mxfs_dlm_caw_set_dir_block0
  fn static find_slot_deadline(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out, uint32_t *empty_out, uint64_t deadline) -> int
    called_by: caw_owed_resolve
  fn mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *out_gen) -> int
    calls: find_slot
    called_by: mxfs_v5_dlm_ag_read_generation
  fn mxfs_dlm_caw_victim_manifest_read(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_dlm_caw_set_dir_block0(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t fsb, uint32_t gen) -> void
    calls: caw_slot, find_slot
    called_by: mxfs_v5_dlm_inode_set_dir_block0
  fn static caw_count_resource_slots(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *dup_slots, int dupmax, uint64_t *holders_ex_or) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, read_slot, resource_hash_raw
    called_by: mxfs_dlm_caw_ex_count, mxfs_dlm_caw_self_held_scan
  fn static track_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index) -> bool
  fn static is_tracked_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index) -> bool
    calls: read_slot
    called_by: caw_purge_dead_nodes_body
  fn static caw_adopt_retained(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t slot_idx, const struct mxfs_caw_lock_slot *cur_slot, struct mxfs_caw_lock_slot *new_slot, uint8_t our_mode) -> int
  fn static untrack_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index) -> void
    called_by: caw_force_release_self_body, caw_may_have_written, caw_release_all_body, node_held_mode
  fn static caw_send_bast_mcast(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t requested_mode) -> void
    calls: mxfs_pal_udp_sendto
    called_by: caw_convert_body
  fn static caw_send_grant_mcast(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t wake_mask) -> void
    calls: mxfs_pal_udp_sendto
  fn static caw_nudge_prepare(struct mxfs_dlm_caw_ctx *ctx) -> uint64_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_acquire_poll_sleep
  fn static caw_nudge_ring_wants_wake(struct mxfs_dlm_caw_ctx *ctx, uint64_t from_seq, const struct mxfs_resource_id *res) -> bool
    calls: mxfs_pal_cond_timedwait, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms
    called_by: caw_nudge_check
  fn static caw_nudge_wait(struct mxfs_dlm_caw_ctx *ctx, uint64_t seen_seq, uint32_t ms, const struct mxfs_resource_id *res) -> bool
    called_by: caw_acquire_poll_sleep
  fn static caw_nudge_check(struct mxfs_dlm_caw_ctx *ctx, uint64_t from_seq, const struct mxfs_resource_id *res) -> bool
    calls: caw_nudge_ring_wants_wake, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_acquire_poll_sleep
  fn static caw_drop_own_waiter(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_idx, const struct mxfs_resource_id *resource, struct mxfs_caw_lreq *e, bool self_joined, uint8_t giveup_mode, bool collector, uint64_t deadline) -> int
    called_by: caw_convert_body, caw_owed_dispatch
  fn static caw_owed_resolve(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *slot_idx, uint64_t deadline) -> int
    calls: find_slot_deadline, mxfs_pal_alloc, mxfs_pal_free
    called_by: caw_owed_dispatch
  fn static caw_owed_dispatch(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, uint64_t deadline) -> bool
    calls: caw_drop_own_waiter, caw_inject_take, caw_owed_resolve, lreq_owed_retract, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: caw_owed_sweep
  fn static caw_owed_release(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_lreq *e, bool attempted) -> uint64_t
    calls: lreq_gc, lreq_oq_sync, lreq_owed_pending, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, stop
    called_by: caw_owed_sweep
  fn static caw_owed_count_locked(struct mxfs_dlm_caw_ctx *ctx) -> uint32_t
    calls: lreq_owed_pending
    called_by: caw_owed_count, mxfs_dlm_caw_stop
  fn static caw_owed_count(struct mxfs_dlm_caw_ctx *ctx) -> uint32_t
    calls: caw_owed_count_locked, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_owed_worker_fn
  fn static caw_owed_sweep(struct mxfs_dlm_caw_ctx *ctx, bool drain, uint64_t *seq0, uint64_t *next_due, uint64_t deadline) -> uint32_t
    calls: caw_owed_dispatch, caw_owed_release, lreq_oq_remove, lreq_oq_rotate, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: caw_owed_worker_fn
  fn static caw_owed_worker_fn(void *data) -> void
    calls: caw_inject_take, caw_owed_count, caw_owed_sweep, mxfs_pal_cond_timedwait, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, stop
  fn static lreq_finish(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, struct mxfs_caw_lreq *e, uint8_t req_mode, uint8_t held_mode) -> void
    calls: lreq_gc, lreq_owed_pending, mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, stop
    called_by: caw_convert_body
  fn static caw_owed_fail_latch(struct mxfs_dlm_caw_ctx *ctx) -> bool
    calls: mxfs_pal_time_ms
    called_by: caw_teardown_expire_locked, mxfs_dlm_caw_stop
  fn static caw_owed_fail_notify(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_teardown_escalate_work
  fn static caw_teardown_escalate_work(void *arg) -> void
    calls: caw_owed_fail_notify
  fn static caw_teardown_expire_locked(struct mxfs_dlm_caw_ctx *ctx) -> bool
    calls: caw_owed_fail_latch, mxfs_pal_time_ms
    called_by: caw_join_bounded, mxfs_dlm_caw_stop
  fn static caw_teardown_escalate_queue(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: pr_err
    called_by: caw_join_bounded, mxfs_dlm_caw_stop
  fn static caw_join_bounded(struct mxfs_dlm_caw_ctx *ctx, mxfs_thread_t **slot, const char *what, uint64_t esc_at_ms) -> void
    calls: caw_failstop_grace_ms, caw_teardown_escalate_queue, caw_teardown_expire_locked, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join_timeout, mxfs_pal_time_ms, pr_err
    called_by: caw_bastq_join_workers, mxfs_dlm_caw_start, mxfs_dlm_caw_stop
  fn static caw_op_enter(struct mxfs_dlm_caw_ctx *ctx) -> bool
    called_by: mxfs_dlm_caw_convert, mxfs_dlm_caw_flush_held_to_disk, mxfs_dlm_caw_force_release_self, mxfs_dlm_caw_open_clear, mxfs_dlm_caw_open_set, mxfs_dlm_caw_purge_dead_nodes_ex, mxfs_dlm_caw_unlock_gen, mxfs_dlm_caw_unlock_state
  fn static caw_op_leave(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_caw_convert, mxfs_dlm_caw_flush_held_to_disk, mxfs_dlm_caw_force_release_self, mxfs_dlm_caw_open_clear, mxfs_dlm_caw_open_set, mxfs_dlm_caw_purge_dead_nodes_ex, mxfs_dlm_caw_unlock_gen, mxfs_dlm_caw_unlock_state
  fn static lreq_release_all(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t pub_seq0) -> void
    calls: lreq_find, lreq_gc, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_force_release_self_body, caw_may_have_written, caw_release_all_body, node_held_mode
  fn static lreq_pub_seq_peek(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint64_t
    calls: lreq_find, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_release_all_body
  fn static caw_yield_stamp(const struct mxfs_caw_lock_slot *cur, uint64_t new_yield_to) -> uint64_t
    calls: mxfs_pal_time_real_ms
  fn static caw_pick_next_ex_waiter(uint64_t ex_waiters, uint64_t self_bit) -> uint64_t
  fn static caw_standing_ex_resv(const struct mxfs_caw_lock_slot *s) -> uint64_t
  fn static caw_last_ex_bit(const struct mxfs_caw_lock_slot *s) -> uint64_t
  fn static caw_handoff_nominee_ok(const struct mxfs_caw_lock_slot *cur, const struct mxfs_caw_lock_slot *new_slot) -> bool
  fn static caw_exwin_log(const struct mxfs_resource_id *resource, const char *path, uint32_t mode, int slotno, uint64_t waited_ms, uint64_t yt, uint64_t wex) -> void
    calls: mxfs_pal_time_real_ms
    called_by: caw_convert_body, compatible_excluding_self
  fn static caw_acquire_poll_sleep(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t start, uint32_t *poll_ms, uint32_t hopeless_ms, uint64_t pre_read_seq) -> int
    calls: caw_nudge_check, caw_nudge_prepare, caw_nudge_wait, mxfs_pal_time_ms
  fn static caw_wait_for_grant(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_idx, const struct mxfs_resource_id *resource, uint8_t mode, uint64_t reg_gen, uint64_t reg_epoch, struct mxfs_caw_lreq *lreq, struct mxfs_grant_result *gres, uint64_t deadline_ms) -> int
    called_by: caw_convert_body
  fn static mem_lock_track(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_convert_body, caw_unlock_gen_body
  fn static mem_lock_untrack(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static caw_inode_backoff(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, int retry) -> void
    calls: mxfs_pal_get_random_bytes, mxfs_pal_sleep_ms
    called_by: caw_convert_body
  fn static caw_check_exclusion(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_caw_lock_slot *slot, uint8_t mode) -> void
    calls: mxfs_pal_log
  fn static caw_verify_grant_persisted(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t slot_idx, uint8_t mode) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, read_slot
  fn static caw_lock_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, bool attested, uint64_t local_epoch, uint8_t *granted_mode, struct mxfs_grant_result *gres, uint64_t deadline_ms) -> int
  fn mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, struct mxfs_grant_result *gres) -> int
    called_by: dlm_lock_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest, mxfs_v5_dlm_iclus_lock, mxfs_v5_dlm_inode_lock, mxfs_v5_dlm_inode_lock_retries, mxfs_v5_dlm_inode_lock_try
  fn mxfs_dlm_caw_lock_deadline(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, struct mxfs_grant_result *gres, uint64_t deadline_ms) -> int
    called_by: mxfs_v5_dlm_inode_lock_retries
  fn mxfs_dlm_caw_lock_attested(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint64_t local_epoch, uint8_t *granted_mode, struct mxfs_grant_result *gres) -> int
    called_by: mxfs_v5_dlm_ag_lock, mxfs_v5_dlm_ag_lock_nb
  fn mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_caw_unlock_gen
    called_by: dlm_unlock_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest
  fn static caw_unlock_gen_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t expected_gen32, bool is_free, int open_op, enum mxfs_unlock_state *state_out) -> int
    calls: mem_lock_track
    called_by: caw_convert_body, mxfs_dlm_caw_unlock_gen, mxfs_dlm_caw_unlock_state
  fn mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t expected_gen32, bool is_free, int open_op) -> int
    calls: caw_op_enter, caw_op_leave, caw_unlock_gen_body
    called_by: mxfs_dlm_caw_unlock, mxfs_v5_dlm_iclus_unlock_gen, mxfs_v5_dlm_inode_unlock_free, mxfs_v5_dlm_inode_unlock_open
  fn mxfs_dlm_caw_unlock_state(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, enum mxfs_unlock_state *state_out) -> int
    calls: caw_op_enter, caw_op_leave, caw_unlock_gen_body
    called_by: mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: find_slot, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, node_held_mode
    called_by: mxfs_v5_dlm_ag_held, mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
    calls: find_slot, mxfs_pal_alloc, mxfs_pal_free, node_held_mode
    called_by: mxfs_v5_dlm_iclus_held_rawmode, mxfs_v5_dlm_inode_granted_mode
  fn mxfs_dlm_caw_open_holders(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *oh_out) -> int
    calls: find_slot, mxfs_pal_alloc, mxfs_pal_free
    called_by: mxfs_v5_dlm_inode_open_holders
  fn static caw_open_set_dedup(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t mine_idx, struct mxfs_caw_lock_slot *cur, struct mxfs_caw_lock_slot *new_slot) -> int
    called_by: caw_open_set_body
  fn static caw_open_set_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: caw_claim_inherit_epoch, caw_mint_lineage, caw_open_set_dedup, caw_slot, find_slot, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_sleep_ms, mxfs_pal_time_ms, read_slot, resource_hash_raw, slot_hint_store
    called_by: mxfs_dlm_caw_open_set
  fn mxfs_dlm_caw_open_set(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    calls: caw_op_enter, caw_op_leave, caw_open_set_body
    called_by: mxfs_v5_dlm_inode_open_set
  fn mxfs_dlm_caw_open_probe(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *oh_out, bool *authoritative) -> int
    calls: find_slot, mxfs_pal_alloc, mxfs_pal_free
    called_by: mxfs_v5_dlm_inode_open_probe
  fn static caw_open_clear_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    calls: caw_slot, caw_tombstone_slot, find_slot, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_time_ms, slot_has_holders
    called_by: mxfs_dlm_caw_open_clear
  fn mxfs_dlm_caw_open_clear(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    calls: caw_op_enter, caw_op_leave, caw_open_clear_body
    called_by: mxfs_v5_dlm_inode_open_clear
  fn mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    calls: find_slot, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, slot_hint_get
    called_by: mxfs_v5_dlm_inode_dump_slot
  fn mxfs_dlm_caw_ex_count(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, int *nslots_out) -> int
    calls: caw_count_resource_slots
    called_by: mxfs_v5_dlm_ag_ex_count, mxfs_v5_dlm_inode_ex_count
  fn mxfs_dlm_caw_self_held_scan(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, int *nslots_out, uint64_t *hex_or_out) -> int
    calls: caw_count_resource_slots
    called_by: mxfs_v5_dlm_inode_self_held_scan
  fn static caw_forcerel_precondition(const struct mxfs_resource_id *resource, const struct mxfs_forcerel_attest *att) -> int
    called_by: caw_force_release_self_body
  fn static caw_force_release_self_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_forcerel_attest *att) -> int
    calls: caw_forcerel_precondition, caw_may_have_written, caw_slot, lreq_clr_begin_wait, lreq_clr_end, lreq_release_all, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_time_ms, read_slot, recompute_granted_mode, resource_hash_raw, untrack_held
    called_by: mxfs_dlm_caw_force_release_self
  fn mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_forcerel_attest *att) -> int
    calls: caw_force_release_self_body, caw_op_enter, caw_op_leave
    called_by: mxfs_v5_dlm_inode_force_release_self
  fn static caw_convert_body(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t new_mode, struct mxfs_grant_result *gres) -> int
    calls: caw_drop_own_waiter, caw_exwin_log, caw_grant_epoch_update, caw_grant_meta_store, caw_grant_result_fill, caw_grant_seq_prebump, caw_inode_backoff, caw_send_bast_mcast, caw_slot, caw_slot_clearing, caw_unlock_gen_body, caw_wait_for_grant, compatible_excluding_self, find_slot, holders_for_mode
    called_by: mxfs_dlm_caw_convert
  fn mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t new_mode, struct mxfs_grant_result *gres) -> int
    calls: caw_convert_body, caw_op_enter, caw_op_leave
    called_by: dlm_convert_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest
  fn static caw_owe_residue(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t slot_hint) -> bool
    calls: lreq_bucket, lreq_find, lreq_owed_merge, lreq_reserve_take, mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: caw_release_all_body
  fn mxfs_dlm_caw_pin_resource(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *res) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, pr_err
    called_by: mxfs_v5_dlm_iclus_pin, mxfs_v5_dlm_inode_pin
  fn static caw_res_pinned(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *res) -> bool
    called_by: caw_release_all_body
  fn static caw_release_all_body(struct mxfs_dlm_caw_ctx *ctx, uint32_t *owed, uint32_t *lost) -> void
    calls: caw_inject_take, caw_owe_residue, caw_res_pinned, caw_slot, caw_tombstone_slot, lreq_pub_seq_peek, lreq_release_all, mxfs_pal_alloc, mxfs_pal_cond_resched, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, pr_err
    called_by: mxfs_dlm_caw_release_all, mxfs_dlm_caw_stop
  fn mxfs_dlm_caw_release_all(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: caw_release_all_body
    called_by: mxfs_unmount
  fn mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx, uint8_t dead_slot) -> int
    calls: mxfs_dlm_caw_purge_dead_nodes, mxfs_pal_log
    called_by: mxfs_v5_dlm_recovery_complete
  fn static caw_strip_node_state(struct mxfs_caw_lock_slot *ns, uint64_t mask, bool keep_ex) -> bool
    calls: mxfs_pal_time_ms, recompute_granted_mode, recompute_waiter_mode
    called_by: caw_purge_dead_nodes_body
  fn static caw_victim_state_mask(const struct mxfs_caw_lock_slot *s, uint64_t mask) -> uint64_t
  fn static caw_victim_footprint(const struct mxfs_caw_lock_slot *s, uint64_t mask) -> uint32_t
  fn static caw_resource_same(const struct mxfs_resource_id *a, const struct mxfs_resource_id *b) -> bool
    calls: mxfs_pal_log
  fn static caw_purge_candidate(const struct mxfs_caw_lock_slot *s, uint64_t dead_mask, bool keep_ex) -> bool
    called_by: caw_purge_dead_nodes_body, mxfs_dlm_caw_footprint_scan
  fn mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx, uint64_t dead_mask) -> int
    calls: mxfs_dlm_caw_purge_dead_nodes_ex
    called_by: mxfs_dlm_caw_purge_node, mxfs_mount
  fn mxfs_dlm_caw_set_adopt_window(struct mxfs_dlm_caw_ctx *ctx, bool on) -> void
    called_by: mxfs_v5_dlm_init, mxfs_v5_dlm_settle_own_slot
  fn mxfs_dlm_caw_retained_count(struct mxfs_dlm_caw_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_init
  fn static caw_purge_dead_nodes_body(struct mxfs_dlm_caw_ctx *ctx, uint64_t dead_mask, uint32_t flags) -> int
    calls: caw_purge_candidate, caw_slot, caw_strip_node_state, caw_tombstone_slot, is_tracked_held, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_cond_resched, mxfs_pal_free, mxfs_pal_log, read_slot, slot_has_holders, slot_offset
    called_by: mxfs_dlm_caw_purge_dead_nodes_ex
  fn mxfs_dlm_caw_purge_dead_nodes_ex(struct mxfs_dlm_caw_ctx *ctx, uint64_t dead_mask, uint32_t flags) -> int
    calls: caw_op_enter, caw_op_leave, caw_purge_dead_nodes_body
    called_by: mxfs_dlm_caw_purge_dead_nodes, mxfs_v5_dlm_init, mxfs_v5_dlm_settle_own_slot
  fn static caw_scrub_classify(void *arg, const struct mxfs_resource_id *res) -> int
  fn static caw_closure_scrub_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_idx, const struct mxfs_resource_id *res, uint64_t cand_mask, const char *site, uint64_t el_ms) -> int
  fn mxfs_dlm_caw_footprint_scan(struct mxfs_dlm_caw_ctx *ctx, uint64_t node_mask, int *out_ex) -> int
    calls: caw_purge_candidate, mxfs_pal_alloc, mxfs_pal_bdev_read_prio, mxfs_pal_cond_resched, mxfs_pal_free, mxfs_pal_log, read_slot, slot_offset
    called_by: mxfs_v5_dlm_mount_residue_blocking
  fn static caw_bast_mode_join(uint8_t a, uint8_t b) -> uint8_t
  fn static caw_bastq_free(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: caw_bast_submit, caw_bastq_init, caw_create_unwind, mxfs_dlm_caw_destroy, mxfs_dlm_caw_start
  fn static caw_bastq_init(struct mxfs_dlm_caw_ctx *ctx) -> int
    calls: caw_bastq_free, mxfs_pal_alloc, mxfs_pal_cond_create, mxfs_pal_log, mxfs_pal_mutex_create
  fn static caw_bastq_enqueue_locked(struct mxfs_dlm_caw_ctx *ctx, struct mxfs_caw_bq_ent *e) -> void
    called_by: caw_bast_disp_fn
  fn static caw_bastq_unhash_locked(struct mxfs_dlm_caw_ctx *ctx, uint32_t bucket, struct mxfs_caw_bq_ent *e) -> void
    called_by: caw_bast_disp_fn
  fn static caw_bast_submit(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t requested_mode) -> void
    calls: caw_bastq_free, mxfs_pal_log
    called_by: bast_poll_fn, bast_recv_fn, mxfs_dlm_caw_start
  fn static caw_bast_disp_fn(void *data) -> void
    calls: caw_bastq_enqueue_locked, caw_bastq_unhash_locked, mxfs_pal_cond_signal, mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, resource_hash_raw
  fn static caw_bastq_join_workers(struct mxfs_dlm_caw_ctx *ctx, uint64_t esc_at_ms) -> void
    calls: caw_join_bounded, mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_caw_start, mxfs_dlm_caw_stop
  fn static caw_bastq_report(struct mxfs_dlm_caw_ctx *ctx, const char *when) -> void
    calls: pr_info
    called_by: bast_poll_fn, mxfs_dlm_caw_stop
  fn static bast_poll_fn(void *data) -> void
    calls: caw_bast_submit, caw_bastq_report, mxfs_pal_alloc, mxfs_pal_cond_timedwait, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, node_held_mode, read_slot
  fn static bast_recv_fn(void *data) -> void
    calls: caw_bast_submit, mxfs_pal_cond_broadcast, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_udp_recvfrom, read
  fn static caw_create_unwind(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: caw_bastq_free, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_destroy, mxfs_pal_spinlock_destroy
  fn mxfs_dlm_caw_create(mxfs_bdev_t *dev, uint64_t disklock_offset, mxfs_node_id_t local_node, uint8_t node_slot, const uint8_t *volume_uuid, int max_held) -> struct mxfs_dlm_caw_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn static caw_set_lc(struct mxfs_dlm_caw_ctx *ctx, enum mxfs_caw_lifecycle lc) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_caw_start
  fn mxfs_dlm_caw_start(struct mxfs_dlm_caw_ctx *ctx) -> int
    calls: caw_bast_submit, caw_bastq_free, caw_bastq_join_workers, caw_join_bounded, caw_set_lc, mxfs_pal_cond_signal, mxfs_pal_log, mxfs_pal_time_ms, mxfs_pal_udp_close, mxfs_pal_udp_join_multicast, mxfs_pal_udp_open, mxfs_pal_udp_set_recv_timeout
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_caw_set_release_on_stop(struct mxfs_dlm_caw_ctx *ctx, bool on) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_departed_clean(struct mxfs_dlm_caw_ctx *ctx) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_caw_stop, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_set_membership(struct mxfs_dlm_caw_ctx *ctx, uint64_t view, uint32_t members) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: v5_membership_beacon_caw
  fn mxfs_dlm_caw_unsafe_to_free(struct mxfs_dlm_caw_ctx *ctx) -> bool
    calls: pr_err
    called_by: mxfs_dlm_caw_destroy
  fn mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: caw_bastq_join_workers, caw_bastq_report, caw_failstop_grace_ms, caw_join_bounded, caw_owed_count_locked, caw_owed_fail_latch, caw_release_all_body, caw_teardown_escalate_queue, caw_teardown_expire_locked, mxfs_dlm_caw_departed_clean, mxfs_pal_cond_broadcast, mxfs_pal_cond_signal, mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock
    called_by: mxfs_dlm_caw_destroy, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_destroy(struct mxfs_dlm_caw_ctx *ctx) -> void
    calls: caw_bastq_free, lreq_owed_pending, mxfs_dlm_caw_stop, mxfs_dlm_caw_unsafe_to_free, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_spinlock_destroy, mxfs_pal_udp_close, pr_err, stop
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn static caw_flush_held_body(struct mxfs_dlm_caw_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_dlm_caw_flush_held_to_disk
  fn mxfs_dlm_caw_flush_held_to_disk(struct mxfs_dlm_caw_ctx *ctx) -> int
    calls: caw_flush_held_body, caw_op_enter, caw_op_leave
    called_by: mxfs_dlm_caw_set_single_node
  fn mxfs_dlm_caw_set_single_node(struct mxfs_dlm_caw_ctx *ctx, bool single) -> void
    calls: mxfs_dlm_caw_flush_held_to_disk, mxfs_pal_log
    called_by: discovery_peer_cb, mxfs_mount, mxfs_v5_dlm_init, v5_discovery_peer_cb
  fn mxfs_dlm_caw_set_bast_cb(struct mxfs_dlm_caw_ctx *ctx, mxfs_dlm_bast_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_caw_set_closure_cand_mask(struct mxfs_dlm_caw_ctx *ctx, uint64_t mask) -> void
    called_by: mxfs_v5_dlm_shutdown_defer_release, v5_closure_note_terminal
  struct mxfs_caw_lreq { next, resource, attempts, writers, tenure, pin, owed_holder_mask, owed_waiters, owed_waiters_ex, owed_busy }
  struct mxfs_caw_clr_snap { seq, quiet, armed }
  struct mxfs_caw_clear_plan { waiters, waiters_ex, holder, holder_moot }
  struct mxfs_caw_owed_intent { holder_mask, waiters, waiters_ex, slot_hint }
  struct caw_closure_obs { vfoot, hint_vanished, hint_bit_gone, hint_res_moved, class_flipped, cas_miscompare }
  struct caw_scrub_carg { ctx, data, bit }

[dlm/dlm_caw.h]
  fn mxfs_dlm_caw_create(mxfs_bdev_t *dev, uint64_t disklock_offset, mxfs_node_id_t local_node, uint8_t node_slot, const uint8_t *volume_uuid, int max_held) -> struct mxfs_dlm_caw_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_caw_destroy(struct mxfs_dlm_caw_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_start(struct mxfs_dlm_caw_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx) -> void
    called_by: mxfs_dlm_caw_destroy, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_set_release_on_stop(struct mxfs_dlm_caw_ctx *ctx, bool on) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_departed_clean(struct mxfs_dlm_caw_ctx *ctx) -> bool
    called_by: mxfs_dlm_caw_stop, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_dlm_caw_unsafe_to_free(struct mxfs_dlm_caw_ctx *ctx) -> bool
    called_by: mxfs_dlm_caw_destroy
  fn mxfs_dlm_caw_set_membership(struct mxfs_dlm_caw_ctx *ctx, uint64_t view, uint32_t members) -> void
    called_by: v5_membership_beacon_caw
  fn mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, struct mxfs_grant_result *gres) -> int
    called_by: dlm_lock_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest, mxfs_v5_dlm_iclus_lock, mxfs_v5_dlm_inode_lock, mxfs_v5_dlm_inode_lock_retries, mxfs_v5_dlm_inode_lock_try
  fn mxfs_dlm_caw_lock_deadline(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode, struct mxfs_grant_result *gres, uint64_t deadline_ms) -> int
    called_by: mxfs_v5_dlm_inode_lock_retries
  fn mxfs_dlm_caw_lock_attested(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint64_t local_epoch, uint8_t *granted_mode, struct mxfs_grant_result *gres) -> int
    called_by: mxfs_v5_dlm_ag_lock, mxfs_v5_dlm_ag_lock_nb
  fn mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t expected_gen32, bool is_free, int open_op) -> int
    called_by: mxfs_dlm_caw_unlock, mxfs_v5_dlm_iclus_unlock_gen, mxfs_v5_dlm_inode_unlock_free, mxfs_v5_dlm_inode_unlock_open
  fn mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: dlm_unlock_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest
  fn mxfs_dlm_caw_unlock_state(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, enum mxfs_unlock_state *state_out) -> int
    called_by: mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    called_by: mxfs_v5_dlm_inode_dump_slot
  fn mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: mxfs_v5_dlm_ag_held, mxfs_v5_dlm_ag_unlock
  fn mxfs_dlm_caw_open_holders(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *oh_out) -> int
    called_by: mxfs_v5_dlm_inode_open_holders
  fn mxfs_dlm_caw_open_clear(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> void
    called_by: mxfs_v5_dlm_inode_open_clear
  fn mxfs_dlm_caw_open_set(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> int
    called_by: mxfs_v5_dlm_inode_open_set
  fn mxfs_dlm_caw_open_probe(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *oh_out, bool *authoritative) -> int
    called_by: mxfs_v5_dlm_inode_open_probe
  fn mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint8_t
    called_by: mxfs_v5_dlm_iclus_held_rawmode, mxfs_v5_dlm_inode_granted_mode
  fn mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t *out_gen) -> int
    called_by: mxfs_v5_dlm_ag_read_generation
  fn mxfs_dlm_caw_victim_manifest_read(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_dlm_caw_ex_count(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, int *nslots_out) -> int
    called_by: mxfs_v5_dlm_ag_ex_count, mxfs_v5_dlm_inode_ex_count
  fn mxfs_dlm_caw_self_held_scan(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, int *nslots_out, uint64_t *hex_or_out) -> int
    called_by: mxfs_v5_dlm_inode_self_held_scan
  fn mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, const struct mxfs_forcerel_attest *att) -> int
    called_by: mxfs_v5_dlm_inode_force_release_self
  fn mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint8_t new_mode, struct mxfs_grant_result *gres) -> int
    called_by: dlm_convert_caw_wrapper, mxfs_v5_dlm_caw_pw_selftest
  fn mxfs_dlm_caw_grant_dir_epoch(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    called_by: mxfs_v5_dlm_inode_dir_epoch
  fn mxfs_dlm_caw_grant_handoff(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t *gen_out) -> bool
    called_by: mxfs_v5_dlm_inode_grant_handoff
  fn mxfs_dlm_caw_grant_dir_block0(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint32_t want_gen, uint64_t *fsb_out) -> bool
    called_by: mxfs_v5_dlm_inode_dir_block0
  fn mxfs_dlm_caw_set_dir_block0(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, uint64_t fsb, uint32_t gen) -> void
    called_by: mxfs_v5_dlm_inode_set_dir_block0
  fn mxfs_dlm_caw_grant_seq32(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource) -> uint32_t
    called_by: mxfs_v5_dlm_inode_grant_gen
  fn mxfs_dlm_caw_orphan_clock_get(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, bool starve) -> uint64_t
    called_by: mxfs_v5_dlm_inode_orphan_clock_get
  fn mxfs_dlm_caw_orphan_clock_set(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *resource, bool starve, uint64_t val) -> void
    called_by: mxfs_v5_dlm_inode_orphan_clock_set
  fn mxfs_dlm_caw_release_all(struct mxfs_dlm_caw_ctx *ctx) -> void
    called_by: mxfs_unmount
  fn mxfs_dlm_caw_pin_resource(struct mxfs_dlm_caw_ctx *ctx, const struct mxfs_resource_id *res) -> int
    called_by: mxfs_v5_dlm_iclus_pin, mxfs_v5_dlm_inode_pin
  fn mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx, uint8_t dead_slot) -> int
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx, uint64_t dead_mask) -> int
    called_by: mxfs_dlm_caw_purge_node, mxfs_mount
  fn mxfs_dlm_caw_purge_dead_nodes_ex(struct mxfs_dlm_caw_ctx *ctx, uint64_t dead_mask, uint32_t flags) -> int
    called_by: mxfs_dlm_caw_purge_dead_nodes, mxfs_v5_dlm_init, mxfs_v5_dlm_settle_own_slot
  fn mxfs_dlm_caw_footprint_scan(struct mxfs_dlm_caw_ctx *ctx, uint64_t node_mask, int *out_ex) -> int
    called_by: mxfs_v5_dlm_mount_residue_blocking
  fn mxfs_dlm_caw_set_adopt_window(struct mxfs_dlm_caw_ctx *ctx, bool on) -> void
    called_by: mxfs_v5_dlm_init, mxfs_v5_dlm_settle_own_slot
  fn mxfs_dlm_caw_retained_count(struct mxfs_dlm_caw_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_dlm_caw_set_single_node(struct mxfs_dlm_caw_ctx *ctx, bool single) -> void
    called_by: discovery_peer_cb, mxfs_mount, mxfs_v5_dlm_init, v5_discovery_peer_cb
  fn mxfs_dlm_caw_flush_held_to_disk(struct mxfs_dlm_caw_ctx *ctx) -> int
    called_by: mxfs_dlm_caw_set_single_node
  fn mxfs_dlm_caw_set_bast_cb(struct mxfs_dlm_caw_ctx *ctx, mxfs_dlm_bast_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_dlm_caw_set_closure_cand_mask(struct mxfs_dlm_caw_ctx *ctx, uint64_t mask) -> void
    called_by: mxfs_v5_dlm_shutdown_defer_release, v5_closure_note_terminal
  struct mxfs_caw_lock_slot { magic, generation, resource, holders_ex, holders_pw, holders_pr, holders_cw, holders_cr, waiters, granted_mode }
  struct mxfs_caw_bast_notify { magic, version, pad, resource, requester, requested_mode, pad2, volume_uuid, wake_mask }
  struct mxfs_caw_nudge_rec { seq, wake_mask, resource, version }
  enum mxfs_caw_bq_state { MXFS_CAW_BQ_FREE, MXFS_CAW_BQ_QUEUED, MXFS_CAW_BQ_RUNNING }
  struct mxfs_caw_bq_ent { resource, hnext, qnext, enq_ms, merges, state, queued_mode, rearm, rearm_mode }
  enum mxfs_caw_lifecycle { MXFS_CAW_LC_NEW, created, no, threads, no, admitted, ops, MXFS_CAW_LC_STARTING, inside, mxfs_dlm_caw_start }
  struct mxfs_dlm_caw_ctx { dev, base_offset, lock_region_offset, local_node, node_slot, node_bit, slots, count, lock, max_held }
  struct mxfs_caw_mem_lock { resource, mode }
  struct mxfs_caw_slot_hint { resource, slot_idx, valid }
  struct mxfs_caw_grant_meta { resource, dir_epoch, handoff, valid, dir_block0_fsb, dir_block0_gen, releasing, grant_seq }
  struct mxfs_caw_orphan_clock { resource, valid, orphan_since_ns, bast_starve_since_ns }

[dlm/dlm_shared.c]
  fn resource_hash_raw(const struct mxfs_resource_id *res) -> uint32_t
    called_by: caw_bast_disp_fn, caw_count_resource_slots, caw_force_release_self_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_open_set_body, caw_release_mark, dg_grant_ex, held_bucket, mxfs_dlm_caw_grant_dir_block0, mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set, mxfs_dlm_resource_master
  fn resource_equal(const struct mxfs_resource_id *a, const struct mxfs_resource_id *b) -> bool
    called_by: collect_post_promotion_basts, dg_grant_ex, dg_release, dlm_lock_impl, find_conflicting_waiter, find_lock_slot, held_insert, held_remove, mxfs_dlm_audit_double_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb
  fn holders_for_mode_const(const struct mxfs_caw_lock_slot *slot, uint8_t mode) -> uint64_t
    called_by: is_compatible, net2_lock_apply_entry
  fn is_compatible(const struct mxfs_caw_lock_slot *slot, uint8_t mode) -> bool
    calls: holders_for_mode_const
  fn recompute_granted_mode(const struct mxfs_caw_lock_slot *slot) -> uint8_t
    called_by: caw_convert_body, caw_force_release_self_body, caw_release_all_body, caw_repair_slot, caw_strip_node_state, compatible_excluding_self
  fn caw_slot_holders_popcount_ok(const struct mxfs_caw_lock_slot *s) -> bool

[dlm/dlm_shared.h]
  fn hweight64(x) -> return
  fn resource_hash_raw(const struct mxfs_resource_id *res) -> uint32_t
    called_by: caw_bast_disp_fn, caw_count_resource_slots, caw_force_release_self_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_open_set_body, caw_release_mark, dg_grant_ex, held_bucket, mxfs_dlm_caw_grant_dir_block0, mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set, mxfs_dlm_resource_master
  fn resource_equal(const struct mxfs_resource_id *a, const struct mxfs_resource_id *b) -> bool
    called_by: collect_post_promotion_basts, dg_grant_ex, dg_release, dlm_lock_impl, find_conflicting_waiter, find_lock_slot, held_insert, held_remove, mxfs_dlm_audit_double_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb
  fn holders_for_mode_const(const struct mxfs_caw_lock_slot *slot, uint8_t mode) -> uint64_t
    called_by: is_compatible, net2_lock_apply_entry
  fn is_compatible(const struct mxfs_caw_lock_slot *slot, uint8_t mode) -> bool
  fn recompute_granted_mode(const struct mxfs_caw_lock_slot *slot) -> uint8_t
    called_by: caw_convert_body, caw_force_release_self_body, caw_release_all_body, caw_repair_slot, caw_strip_node_state, compatible_excluding_self
  fn caw_slot_holders_popcount_ok(const struct mxfs_caw_lock_slot *s) -> bool

[dlm/journal.c]
  fn static round_up_sector(uint32_t bytes) -> uint32_t
    called_by: compute_entry_size
  fn static slot_offset(struct mxfs_journal_ctx *ctx, int slot) -> uint64_t
    called_by: caw_purge_dead_nodes_body, caw_repair_slot, caw_slot, caw_watch_armed, mxfs_dlm_caw_footprint_scan, mxfs_journal_replay, mxfs_journal_slot_open, scan_disk_for_node_slot
  fn static sector_crc(const void *buf, size_t crc_offset) -> uint32_t
    calls: mxfs_pal_crc32c
    called_by: flush_slot_header, mxfs_journal_format, mxfs_journal_open, mxfs_journal_replay, mxfs_journal_slot_mark_clean, mxfs_journal_slot_mark_dirty, mxfs_journal_slot_open
  fn static read_sector(mxfs_bdev_t *dev, uint64_t offset, void *buf) -> int
    calls: mxfs_pal_bdev_read
    called_by: closure_read_gate_sector, find_lock_slot, mxfs_disklock_purge_node, mxfs_disklock_read_all, mxfs_disklock_write_grant, mxfs_journal_open, mxfs_journal_replay, mxfs_journal_slot_mark_clean, mxfs_journal_slot_mark_dirty, mxfs_journal_slot_open, read_entry_at, scan_disk_for_node_slot, validate_lockstate
  fn static write_sector(mxfs_bdev_t *dev, uint64_t offset, const void *buf) -> int
    calls: mxfs_pal_bdev_write
    called_by: flush_slot_header, mxfs_disklock_clear_grant, mxfs_disklock_write_grant, mxfs_journal_format, mxfs_journal_replay, mxfs_journal_slot_mark_clean, mxfs_journal_slot_mark_dirty, purge_cas_zero
  fn static entry_sector_offset(struct mxfs_journal_ctx *ctx, uint32_t rel_sector) -> uint64_t
    called_by: mxfs_journal_txn_commit, read_entry_at
  fn static advance_sector(struct mxfs_journal_ctx *ctx, uint32_t pos, uint32_t count) -> uint32_t
    called_by: mxfs_journal_replay, mxfs_journal_txn_commit, read_entry_at
  fn static free_sectors(struct mxfs_journal_ctx *ctx) -> uint32_t
    called_by: mxfs_journal_txn_commit, write_entry
  fn static checkpoint_locked(struct mxfs_journal_ctx *ctx) -> int
    calls: flush_slot_header, mxfs_pal_bdev_flush, mxfs_pal_log
    called_by: mxfs_journal_txn_commit, write_entry
  fn static total_data_sectors(struct mxfs_journal_ctx *ctx) -> uint32_t
    called_by: mxfs_journal_txn_commit
  fn static write_entry(struct mxfs_journal_ctx *ctx, void *entry_buf, uint32_t total_len) -> int
    calls: checkpoint_locked, free_sectors
    called_by: mxfs_journal_txn_commit, write_simple_entry
  fn static flush_slot_header(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_pal_log, sector_crc, write_sector
    called_by: checkpoint_locked, mxfs_journal_checkpoint, mxfs_journal_flush
  fn static write_simple_entry(struct mxfs_journal_ctx *ctx, uint32_t type, uint64_t txn_id) -> int
    calls: write_entry
    called_by: mxfs_journal_checkpoint, mxfs_journal_txn_commit, mxfs_journal_write_unmount
  fn static free_txn_entries(struct mxfs_txn *txn) -> void
    calls: mxfs_pal_free
    called_by: mxfs_journal_txn_abort, mxfs_journal_txn_commit
  fn mxfs_journal_create(mxfs_node_id_t local_node) -> struct mxfs_journal_ctx
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_create
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_destroy(struct mxfs_journal_ctx *ctx) -> void
    calls: mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_journal_claim_slot(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_release_slot(struct mxfs_journal_ctx *ctx) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn static scan_disk_for_node_slot(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, read_sector, slot_offset
    called_by: mxfs_journal_find_slot_by_node, mxfs_journal_mark_needs_recovery
  fn mxfs_journal_mark_needs_recovery(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, scan_disk_for_node_slot
    called_by: disklock_expire_cb, lease_expire_cb, peer_disconnect_cb
  fn mxfs_journal_begin_recovery(struct mxfs_journal_ctx *ctx, int slot) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: recover_dead_node_journal
  fn mxfs_journal_finish_recovery(struct mxfs_journal_ctx *ctx, int slot) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: recover_dead_node_journal
  fn mxfs_journal_get_state(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> enum mxfs_journal_state
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_journal_slot_count(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_journal_find_slot_by_node(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, scan_disk_for_node_slot
    called_by: recover_dead_node_journal
  fn mxfs_journal_format(mxfs_bdev_t *dev, uint64_t offset, uint32_t slot_count, const uint8_t *uuid) -> int
    calls: mxfs_pal_alloc, mxfs_pal_bdev_flush, mxfs_pal_free, mxfs_pal_log, sector_crc, write_sector
    called_by: mxfs_mount
  fn mxfs_journal_open(struct mxfs_journal_ctx *ctx, mxfs_bdev_t *dev, uint64_t offset) -> int
    calls: mxfs_pal_alloc, mxfs_pal_log, read_sector, sector_crc
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_slot_open(struct mxfs_journal_ctx *ctx, int slot) -> int
    calls: mxfs_pal_log, read_sector, sector_crc, slot_offset
    called_by: mxfs_mount
  fn mxfs_journal_slot_mark_dirty(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_pal_log, read_sector, sector_crc, write_sector
    called_by: mxfs_mount
  fn mxfs_journal_slot_mark_clean(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_pal_log, read_sector, sector_crc, write_sector
    called_by: mxfs_journal_write_unmount, mxfs_unmount
  fn mxfs_journal_txn_begin(struct mxfs_journal_ctx *ctx) -> struct mxfs_txn
    calls: mxfs_pal_alloc, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_journal_txn_log_write(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn, uint64_t disk_offset, const void *data, uint32_t len) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log
  fn mxfs_journal_txn_log_revoke(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn, uint64_t disk_offset, uint32_t len) -> int
    calls: mxfs_pal_alloc, mxfs_pal_log
  fn static compute_entry_size(struct mxfs_txn_entry *e) -> uint32_t
    calls: round_up_sector
    called_by: mxfs_journal_txn_commit
  fn static serialize_entry(struct mxfs_journal_ctx *ctx, struct mxfs_txn_entry *e, uint64_t txn_id, uint8_t *buf, uint32_t entry_size) -> uint32_t
    calls: mxfs_pal_crc32c
    called_by: mxfs_journal_txn_commit
  fn mxfs_journal_txn_commit(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn) -> int
    calls: advance_sector, checkpoint_locked, compute_entry_size, entry_sector_offset, free_sectors, free_txn_entries, mxfs_pal_alloc, mxfs_pal_bdev_write, mxfs_pal_crc32c, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, serialize_entry, total_data_sectors
  fn mxfs_journal_txn_abort(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn) -> void
    calls: free_txn_entries, mxfs_pal_free, mxfs_pal_log
  fn static is_revoked(struct revoke_entry *revoke_list, uint64_t disk_offset) -> bool
    calls: mxfs_pal_bdev_write, mxfs_pal_free, mxfs_pal_log
    called_by: mxfs_journal_replay
  fn static free_revoke_list(struct revoke_entry *list) -> void
    calls: mxfs_pal_free
    called_by: mxfs_journal_replay
  fn static is_committed(struct committed_txn *list, uint64_t txn_id) -> bool
    called_by: mxfs_journal_replay
  fn static free_committed_list(struct committed_txn *list) -> void
    calls: mxfs_pal_free
    called_by: mxfs_journal_replay
  fn static read_entry_at(struct mxfs_journal_ctx *ctx, uint32_t sector_pos, struct mxfs_journal_entry_hdr *out_hdr, void **out_buf) -> int
    calls: advance_sector, entry_sector_offset, mxfs_pal_alloc, mxfs_pal_crc32c, mxfs_pal_free, mxfs_pal_log, read_sector
    called_by: mxfs_journal_replay
  fn mxfs_journal_replay(struct mxfs_journal_ctx *ctx, int slot) -> int
    calls: advance_sector, free_committed_list, free_revoke_list, is_committed, is_revoked, mxfs_pal_alloc, mxfs_pal_bdev_flush, mxfs_pal_bdev_write, mxfs_pal_free, mxfs_pal_log, read_entry_at, read_sector, sector_crc, slot_offset, write_sector
    called_by: mxfs_mount, recover_dead_node_journal
  fn mxfs_journal_flush(struct mxfs_journal_ctx *ctx) -> int
    calls: flush_slot_header, mxfs_pal_bdev_flush, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_fsync, mxfs_sync_fs
  fn mxfs_journal_checkpoint(struct mxfs_journal_ctx *ctx) -> int
    calls: flush_slot_header, mxfs_pal_bdev_flush, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, write_simple_entry
  fn mxfs_journal_write_unmount(struct mxfs_journal_ctx *ctx) -> int
    calls: mxfs_journal_slot_mark_clean, mxfs_pal_bdev_flush, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, write_simple_entry
    called_by: mxfs_unmount
  struct revoke_entry { disk_offset, len, next }
  struct committed_txn { txn_id, next }

[dlm/journal.h]
  fn mxfs_journal_create(mxfs_node_id_t local_node) -> struct mxfs_journal_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_destroy(struct mxfs_journal_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_journal_claim_slot(struct mxfs_journal_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_release_slot(struct mxfs_journal_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_journal_mark_needs_recovery(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: disklock_expire_cb, lease_expire_cb, peer_disconnect_cb
  fn mxfs_journal_begin_recovery(struct mxfs_journal_ctx *ctx, int slot) -> int
    called_by: recover_dead_node_journal
  fn mxfs_journal_finish_recovery(struct mxfs_journal_ctx *ctx, int slot) -> int
    called_by: recover_dead_node_journal
  fn mxfs_journal_get_state(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> enum mxfs_journal_state
  fn mxfs_journal_slot_count(struct mxfs_journal_ctx *ctx) -> int
  fn mxfs_journal_find_slot_by_node(struct mxfs_journal_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: recover_dead_node_journal
  fn mxfs_journal_format(mxfs_bdev_t *dev, uint64_t offset, uint32_t slot_count, const uint8_t *uuid) -> int
    called_by: mxfs_mount
  fn mxfs_journal_open(struct mxfs_journal_ctx *ctx, mxfs_bdev_t *dev, uint64_t offset) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_journal_slot_open(struct mxfs_journal_ctx *ctx, int slot) -> int
    called_by: mxfs_mount
  fn mxfs_journal_slot_mark_dirty(struct mxfs_journal_ctx *ctx) -> int
    called_by: mxfs_mount
  fn mxfs_journal_slot_mark_clean(struct mxfs_journal_ctx *ctx) -> int
    called_by: mxfs_journal_write_unmount, mxfs_unmount
  fn mxfs_journal_txn_begin(struct mxfs_journal_ctx *ctx) -> struct mxfs_txn
  fn mxfs_journal_txn_log_write(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn, uint64_t disk_offset, const void *data, uint32_t len) -> int
  fn mxfs_journal_txn_log_revoke(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn, uint64_t disk_offset, uint32_t len) -> int
  fn mxfs_journal_txn_commit(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn) -> int
  fn mxfs_journal_txn_abort(struct mxfs_journal_ctx *ctx, struct mxfs_txn *txn) -> void
  fn mxfs_journal_replay(struct mxfs_journal_ctx *ctx, int slot) -> int
    called_by: mxfs_mount, recover_dead_node_journal
  fn mxfs_journal_flush(struct mxfs_journal_ctx *ctx) -> int
    called_by: mxfs_fsync, mxfs_sync_fs
  fn mxfs_journal_checkpoint(struct mxfs_journal_ctx *ctx) -> int
  fn mxfs_journal_write_unmount(struct mxfs_journal_ctx *ctx) -> int
    called_by: mxfs_unmount
  struct mxfs_journal_super { magic, version, slot_count, slot_size_sectors, sector_size, crc, fs_uuid, reserved }
  struct mxfs_journal_slot_hdr { magic, flags, owner, head_sector, tail_sector, crc, seq_head, seq_tail, reserved }
  struct mxfs_journal_entry_hdr { magic, type, seq, txn_id, total_len, payload_len, crc, pad }
  struct mxfs_journal_metadata_payload { disk_offset, data_len, pad }
  struct mxfs_journal_revoke_payload { disk_offset, len, pad }
  enum mxfs_journal_state { MXFS_JSLOT_FREE, MXFS_JSLOT_CLAIMED, MXFS_JSLOT_ACTIVE, MXFS_JSLOT_NEEDS_RECOVERY, MXFS_JSLOT_RECOVERING, MXFS_JSLOT_RECOVERED }
  struct mxfs_journal_slot { node_id, state, claimed_at }
  struct mxfs_txn_entry { type, data_len, disk_offset, data, next }
  struct mxfs_txn { txn_id, entries, tail, count }
  struct mxfs_journal_ctx { slots, local_slot, local_node, lock, dev, xfs_dev, journal_offset, super_disk, slot_base, slot_size_sectors }

[dlm/lease.c]
  fn static lease_find(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> struct mxfs_node_lease
    called_by: mxfs_lease_has_node, mxfs_lease_is_valid, mxfs_lease_process_renewal, mxfs_lease_register_node, mxfs_lease_renew_fn
  fn static mxfs_lease_renew_fn(void *arg) -> void
    calls: lease_find, mxfs_lease_stop, mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, mxfs_pal_udp_sendto
  fn static mxfs_lease_udp_recv_fn(void *arg) -> void
    calls: mxfs_le16_to_cpu, mxfs_le32_to_cpu, mxfs_le64_to_cpu, mxfs_lease_process_renewal, mxfs_pal_log, mxfs_pal_udp_recvfrom, signature
  fn static mxfs_lease_monitor_fn(void *arg) -> void
    calls: mxfs_lease_stop, mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
  fn mxfs_lease_create(mxfs_node_id_t local_node, const uint8_t *volume_uuid, const char *mcast_addr, uint16_t lease_port, bool use_broadcast) -> struct mxfs_lease_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_lease_destroy(struct mxfs_lease_ctx *ctx) -> void
    calls: mxfs_lease_stop, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_udp_close
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_lease_start(struct mxfs_lease_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_thread_join
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_lease_stop(struct mxfs_lease_ctx *ctx) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join, mxfs_pal_udp_shutdown
    called_by: mxfs_lease_destroy, mxfs_lease_monitor_fn, mxfs_lease_renew_fn, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_lease_register_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: lease_find, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: discovery_peer_cb, peer_connect_cb, v5_discovery_peer_cb, v5_peer_connect_cb_tcp
  fn mxfs_lease_unregister_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_v5_dlm_recovery_complete, purge_node_dlm, remove_node, v5_clean_depart_cb, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_tcp_declare_dead
  fn mxfs_lease_process_renewal(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id, mxfs_epoch_t epoch) -> int
    calls: lease_find, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: mxfs_lease_udp_recv_fn
  fn mxfs_lease_has_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> bool
    calls: lease_find, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: discovery_peer_cb, v5_discovery_peer_cb, v5_peer_connect_cb_tcp, v5_peer_disconnect_cb_tcp
  fn mxfs_lease_is_valid(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> bool
    calls: lease_find, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
  fn mxfs_lease_get_active_nodes(struct mxfs_lease_ctx *ctx, mxfs_node_id_t *out, int max_count) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: membership_stab_worker_fn, mxfs_v5_dlm_init, queue_membership_update, v5_membership_beacon_caw, v5_refresh_active_nodes, v5_tcp_death_worker_fn
  fn mxfs_lease_set_expire_cb(struct mxfs_lease_ctx *ctx, mxfs_lease_expire_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init

[dlm/lease.h]
  fn mxfs_lease_create(mxfs_node_id_t local_node, const uint8_t *volume_uuid, const char *mcast_addr, uint16_t lease_port, bool use_broadcast) -> struct mxfs_lease_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_lease_destroy(struct mxfs_lease_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_lease_start(struct mxfs_lease_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_lease_stop(struct mxfs_lease_ctx *ctx) -> void
    called_by: mxfs_lease_destroy, mxfs_lease_monitor_fn, mxfs_lease_renew_fn, mxfs_mount, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_lease_register_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: discovery_peer_cb, peer_connect_cb, v5_discovery_peer_cb, v5_peer_connect_cb_tcp
  fn mxfs_lease_unregister_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: mxfs_v5_dlm_recovery_complete, purge_node_dlm, remove_node, v5_clean_depart_cb, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_tcp_declare_dead
  fn mxfs_lease_process_renewal(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id, mxfs_epoch_t epoch) -> int
    called_by: mxfs_lease_udp_recv_fn
  fn mxfs_lease_is_valid(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> bool
  fn mxfs_lease_has_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id) -> bool
    called_by: discovery_peer_cb, v5_discovery_peer_cb, v5_peer_connect_cb_tcp, v5_peer_disconnect_cb_tcp
  fn mxfs_lease_get_active_nodes(struct mxfs_lease_ctx *ctx, mxfs_node_id_t *out, int max_count) -> int
    called_by: membership_stab_worker_fn, mxfs_v5_dlm_init, queue_membership_update, v5_membership_beacon_caw, v5_refresh_active_nodes, v5_tcp_death_worker_fn
  fn mxfs_lease_set_expire_cb(struct mxfs_lease_ctx *ctx, mxfs_lease_expire_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  struct mxfs_lease_udp_msg { magic, version, pad, node_id, volume_uuid, lease_duration_ms, view_count, pad2, view_hash }
  struct mxfs_node_lease { node_id, epoch, granted_at, duration_ms, last_renewal, state, missed_renewals }
  typedef_fn mxfs_lease_expire_cb
  struct mxfs_lease_ctx { nodes, node_count, default_duration_ms, renew_interval_ms, timeout_ms, local_node, renew_thread, monitor_thread, lock, running }

[dlm/mount.c]
  fn static mount_put_be32(void *p, uint32_t v) -> void
    called_by: build_symlink_hdr_v5
  fn static mount_put_be64(void *p, uint64_t v) -> void
    called_by: build_symlink_hdr_v5, flush_superblock_counters
  fn static mount_put_le32(void *p, uint32_t v) -> void
    called_by: build_symlink_hdr_v5, flush_superblock_counters
  fn static mount_get_be32(const void *p) -> uint32_t
    called_by: readlink_remote
  fn static mxfs_generate_random_uuid(uint8_t *uuid, mxfs_node_id_t *node_id) -> void
    calls: mxfs_pal_get_random_bytes, mxfs_pal_log
    called_by: load_node_uuid
  fn static load_node_uuid(const char *path, uint8_t *uuid, mxfs_node_id_t *node_id) -> int
    calls: mxfs_generate_random_uuid, mxfs_pal_log, mxfs_pal_read_file
    called_by: mxfs_mount
  fn static queue_membership_update(struct mxfs_mount *mnt) -> void
    calls: mxfs_dlm_update_active_nodes, mxfs_lease_get_active_nodes, mxfs_pal_cond_signal, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: discovery_peer_cb, disklock_expire_cb, peer_connect_cb
  fn static membership_stab_worker_fn(void *arg) -> void
    calls: mxfs_dlm_update_active_nodes, mxfs_lease_get_active_nodes, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms
  fn static purge_node_dlm(struct mxfs_mount *mnt, mxfs_node_id_t node_id) -> void
    calls: mxfs_disklock_unmonitor_node, mxfs_lease_unregister_node
    called_by: disklock_expire_cb, peer_disconnect_cb, remove_node
  fn static remove_node(struct mxfs_mount *mnt, mxfs_node_id_t node_id) -> void
    calls: mxfs_disklock_unmonitor_node, mxfs_lease_unregister_node, purge_node_dlm
    called_by: lease_expire_cb, peer_disconnect_cb, peer_msg_cb
  fn static dlm_send_cb(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target, const void *msg, size_t len) -> int
    calls: mxfs_peer_send
  fn static peer_msg_cb(void *data, mxfs_node_id_t sender, void *msg, size_t len) -> void
    calls: mxfs_dlm_process_remote_grant, mxfs_dlm_process_remote_release, mxfs_dlm_process_remote_request, mxfs_pal_log, queue_bast_to_worker, remove_node
  fn static check_tcp_scale_warning(struct mxfs_mount *mnt) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: discovery_peer_cb, peer_connect_cb
  fn static peer_connect_cb(void *data, mxfs_node_id_t node_id) -> void
    calls: check_tcp_scale_warning, mxfs_disklock_monitor_node, mxfs_lease_register_node, mxfs_pal_log, queue_membership_update
  fn static recover_dead_node_journal(struct mxfs_mount *mnt, mxfs_node_id_t dead_node) -> void
    calls: mxfs_journal_begin_recovery, mxfs_journal_find_slot_by_node, mxfs_journal_finish_recovery, mxfs_journal_replay, mxfs_pal_log
    called_by: disklock_expire_cb, journal_recovery_thread_fn, lease_expire_cb
  fn static journal_recovery_thread_fn(void *arg) -> void
    calls: mxfs_pal_free, mxfs_pal_log, recover_dead_node_journal
  fn static peer_disconnect_cb(void *data, mxfs_node_id_t node_id) -> void
    calls: lease_expire_cb, mxfs_disklock_purge_node, mxfs_journal_mark_needs_recovery, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join, mxfs_pal_time_ms, mxfs_scsipr_preempt, purge_node_dlm, remove_node
  fn static discovery_peer_cb(void *data, const struct mxfs_discovery_announce *ann) -> void
    calls: check_tcp_scale_warning, mxfs_disklock_monitor_node, mxfs_dlm_caw_set_single_node, mxfs_lease_has_node, mxfs_lease_register_node, mxfs_pal_log, mxfs_peer_add, mxfs_peer_connect, mxfs_peer_connect_force, mxfs_peer_is_connected, queue_membership_update
  fn static disklock_expire_cb(void *data, mxfs_node_id_t dead_node, int dead_slot, mxfs_epoch_t dead_epoch) -> void
    calls: mxfs_disklock_purge_node, mxfs_journal_mark_needs_recovery, mxfs_pal_log, mxfs_pal_time_ms, mxfs_scsipr_preempt, purge_node_dlm, queue_membership_update, recover_dead_node_journal
  fn static lease_expire_cb(void *data, mxfs_node_id_t dead_node) -> void
    calls: mxfs_disklock_purge_node, mxfs_journal_mark_needs_recovery, mxfs_pal_log, mxfs_pal_time_ms, mxfs_scsipr_preempt, recover_dead_node_journal, remove_node
    called_by: peer_disconnect_cb
  fn static queue_bast_to_worker(struct mxfs_mount *mnt, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t requested_mode) -> int
    calls: mxfs_pal_log
    called_by: dlm_bast_cb, dlm_bast_cb_caw, peer_msg_cb
  fn static bast_worker_fn(void *arg) -> void
    calls: mxfs_pal_cond_wait, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
  fn static dlm_bast_cb(struct mxfs_dlm_ctx *ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t requested_mode) -> void
    calls: mxfs_pal_log, mxfs_pal_sleep_ms, mxfs_peer_send, queue_bast_to_worker
  fn static dlm_bast_cb_caw(struct mxfs_dlm_ctx *fake_ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t requested_mode) -> void
    calls: mxfs_pal_log, queue_bast_to_worker
  fn static dlm_lock_tcp_wrapper(void *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode) -> int
    calls: mxfs_dlm_lock
  fn static dlm_unlock_tcp_wrapper(void *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_unlock
  fn static dlm_convert_tcp_wrapper(void *ctx, const struct mxfs_resource_id *resource, uint8_t new_mode) -> int
    calls: mxfs_dlm_lock_convert
  fn static dlm_lock_caw_wrapper(void *ctx, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t flags, uint8_t *granted_mode) -> int
    calls: mxfs_dlm_caw_lock
  fn static dlm_unlock_caw_wrapper(void *ctx, const struct mxfs_resource_id *resource) -> int
    calls: mxfs_dlm_caw_unlock
  fn static dlm_convert_caw_wrapper(void *ctx, const struct mxfs_resource_id *resource, uint8_t new_mode) -> int
    calls: mxfs_dlm_caw_convert
  fn static cache_flush_worker_fn(void *arg) -> void
    calls: mxfs_pal_cond_timedwait, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static dlm_membership_cb(struct mxfs_dlm_ctx *ctx) -> void
    calls: mxfs_pal_cond_signal, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_mount(const struct mxfs_mount_opts *opts, struct mxfs_mount **mnt_out) -> int
    calls: load_node_uuid, mxfs_discovery_create, mxfs_discovery_destroy, mxfs_discovery_set_peer_cb, mxfs_discovery_set_transport, mxfs_discovery_start, mxfs_discovery_start_recv_only, mxfs_discovery_stop, mxfs_disklock_claim_slot, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_disklock_set_expire_cb, mxfs_disklock_start_heartbeat, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_create
  fn mxfs_unmount(struct mxfs_mount *mnt) -> void
    calls: first, mxfs_discovery_destroy, mxfs_discovery_stop, mxfs_disklock_destroy, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_destroy, mxfs_dlm_caw_release_all, mxfs_dlm_caw_set_release_on_stop, mxfs_dlm_caw_stop, mxfs_dlm_destroy, mxfs_dlm_get_epoch, mxfs_dlm_lock, mxfs_dlm_release_all, mxfs_journal_destroy, mxfs_journal_release_slot
  fn mxfs_lookup(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint64_t *ino_out) -> int
  fn mxfs_stat(struct mxfs_mount *mnt, uint64_t ino, struct mxfs_stat *st) -> int
  fn static mxfs_has_peers(struct mxfs_mount *mnt) -> bool
    calls: mxfs_write_direct
    called_by: mxfs_read, mxfs_read_pinned, mxfs_write, mxfs_write_pinned
  fn static mxfs_read_direct(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, uint8_t *dst, uint64_t offset, uint32_t len) -> int64_t
    called_by: mxfs_read, mxfs_read_pinned
  fn static mxfs_write_direct(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, const uint8_t *src, uint64_t offset, uint32_t len) -> int64_t
    calls: mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_bdev_write, mxfs_pal_bdev_write_async, mxfs_pal_free, mxfs_pal_log
    called_by: mxfs_fsync, mxfs_has_peers, mxfs_write, mxfs_write_pinned
  fn mxfs_read(struct mxfs_mount *mnt, uint64_t ino, void *buf, uint64_t offset, uint32_t len) -> int64_t
    calls: mxfs_has_peers, mxfs_read_direct
  fn static mxfs_read_pinned(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, uint8_t *dst, uint64_t offset, uint32_t len) -> int64_t
    calls: mxfs_has_peers, mxfs_read_direct
  fn mxfs_read_bulk(struct mxfs_mount *mnt, uint64_t ino, uint64_t offset, uint64_t total_len, uint32_t chunk_size, mxfs_read_chunk_fn cb, void *ctx, uint64_t *size_out) -> int64_t
  fn mxfs_write(struct mxfs_mount *mnt, uint64_t ino, const void *buf, uint64_t offset, uint32_t len) -> int64_t
    calls: extents, mxfs_has_peers, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_time_real_sec, mxfs_write_direct
  fn static mxfs_write_pinned(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, const void *buf, uint64_t offset, uint32_t len) -> int64_t
    calls: mxfs_has_peers, mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_write_direct
  fn mxfs_write_bulk(struct mxfs_mount *mnt, uint64_t ino, uint64_t offset, uint64_t total_len, uint32_t chunk_size, mxfs_write_chunk_fn write_fn, void *ctx, uint64_t *size_out) -> int64_t
  fn mxfs_truncate(struct mxfs_mount *mnt, uint64_t ino, uint64_t size) -> int
  fn mxfs_trim_eof_blocks(struct mxfs_mount *mnt, uint64_t ino) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log
  fn mxfs_fsync(struct mxfs_mount *mnt, uint64_t ino) -> int
    calls: mxfs_journal_flush, mxfs_pal_bdev_flush, mxfs_write_direct
  fn static fallocate_prealloc(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, uint64_t offset, uint64_t len, bool keep_size) -> int
    calls: mxfs_pal_log, mxfs_pal_time_real_sec
    called_by: mxfs_fallocate
  fn static fallocate_punch_hole(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, uint64_t offset, uint64_t len) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_time_real_sec
    called_by: mxfs_fallocate
  fn static fallocate_zero_range(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, uint64_t offset, uint64_t len, bool keep_size) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_time_real_sec
    called_by: mxfs_fallocate
  fn mxfs_fallocate(struct mxfs_mount *mnt, uint64_t ino, int mode, uint64_t offset, uint64_t len) -> int
    calls: fallocate_prealloc, fallocate_punch_hole, fallocate_zero_range
  fn static flush_superblock_counters(struct mxfs_mount *mnt) -> int
    calls: mount_put_be64, mount_put_le32, mxfs_pal_alloc, mxfs_pal_crc32c, mxfs_pal_free, mxfs_pal_log
    called_by: mxfs_sync_fs
  fn mxfs_sync_fs(struct mxfs_mount *mnt) -> int
    calls: flush_superblock_counters, mxfs_journal_flush, mxfs_pal_bdev_flush, mxfs_pal_log, mxfs_pal_time_ms
  fn mxfs_readdir(struct mxfs_mount *mnt, uint64_t dir_ino, mxfs_readdir_fn cb, void *ctx) -> int
  fn mxfs_create(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn mxfs_mknod(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint32_t rdev, uint64_t *ino_out) -> int
  fn mxfs_mkdir(struct mxfs_mount *mnt, uint64_t parent_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn static rmdir_count_cb(void *ctx, const char *name, uint8_t namelen, uint64_t ino, uint8_t ftype) -> int
  fn mxfs_rmdir(struct mxfs_mount *mnt, uint64_t parent_ino, const char *name, uint8_t namelen) -> int
  fn mxfs_unlink(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen) -> int
  fn static mxfs_mode_to_ftype(uint16_t mode) -> uint8_t
    called_by: mxfs_rename
  fn mxfs_rename(struct mxfs_mount *mnt, uint64_t old_dir_ino, const char *old_name, uint8_t old_namelen, uint64_t new_dir_ino, const char *new_name, uint8_t new_namelen, unsigned int flags) -> int
    calls: mxfs_mode_to_ftype
  fn mxfs_link(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint64_t target_ino) -> int
  fn static build_symlink_hdr_v5(uint8_t *blkbuf, uint32_t blocksize, uint32_t offset, uint32_t nbytes, const uint8_t *uuid, uint64_t owner, uint64_t disk_blkno_sectors) -> void
    calls: mount_put_be32, mount_put_be64, mount_put_le32, mxfs_pal_crc32c
  fn static symlink_write_remote_blocks(struct mxfs_mount *mnt, uint64_t ino, const char *target, int target_len, struct mxfs_extent_map *emap) -> int
  fn mxfs_symlink(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, const char *target, uint16_t target_len, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn static readlink_remote(struct mxfs_mount *mnt, struct mxfs_cached_inode *ci, char *buf, uint32_t buflen) -> int
    calls: mount_get_be32, mxfs_pal_alloc, mxfs_pal_bdev_read, mxfs_pal_free, mxfs_pal_log
    called_by: mxfs_readlink
  fn mxfs_readlink(struct mxfs_mount *mnt, uint64_t ino, char *buf, uint32_t buflen) -> int
    calls: mxfs_pal_log, readlink_remote
  fn mxfs_chmod(struct mxfs_mount *mnt, uint64_t ino, uint16_t mode) -> int
    calls: mxfs_pal_time_real_sec
  fn mxfs_chown(struct mxfs_mount *mnt, uint64_t ino, uint32_t uid, uint32_t gid) -> int
    calls: mxfs_pal_time_real_sec
  fn mxfs_utimes(struct mxfs_mount *mnt, uint64_t ino, uint32_t atime_sec, uint32_t atime_nsec, uint32_t mtime_sec, uint32_t mtime_nsec) -> int
    calls: mxfs_pal_time_real_sec
  fn mxfs_root_ino(struct mxfs_mount *mnt) -> uint64_t
  fn mxfs_statfs(struct mxfs_mount *mnt, uint32_t *blocksize, uint64_t *total_blocks, uint64_t *free_blocks, uint64_t *total_inodes, uint64_t *free_inodes) -> int
  fn mxfs_get_dlm_transport(struct mxfs_mount *mnt) -> enum mxfs_dlm_transport
  fn mxfs_inode_lock_shared(struct mxfs_mount *mnt, uint64_t ino, uint64_t *size_out) -> int
  fn mxfs_inode_lock_exclusive(struct mxfs_mount *mnt, uint64_t ino, uint64_t *size_out) -> int
  fn mxfs_inode_unlock(struct mxfs_mount *mnt, uint64_t ino) -> void
  fn mxfs_inode_lock_downgrade(struct mxfs_mount *mnt, uint64_t ino) -> int
  fn mxfs_get_block_map(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, uint64_t *phys_block_out, uint32_t *flags_out) -> int
  fn mxfs_get_block_map_range(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, struct mxfs_extent_range *range) -> int
  fn mxfs_convert_unwritten(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block) -> int
  fn mxfs_update_inode_size(struct mxfs_mount *mnt, uint64_t ino, uint64_t new_size) -> int
    calls: mxfs_pal_log
  fn mxfs_alloc_file_block(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, uint64_t *phys_block_out) -> int
    calls: mxfs_pal_log
  fn mxfs_seek_data(struct mxfs_mount *mnt, uint64_t ino, int64_t offset) -> int64_t
    calls: extents
  fn mxfs_seek_hole(struct mxfs_mount *mnt, uint64_t ino, int64_t offset) -> int64_t
  struct bast_work_item { resource, owner, requested_mode, next }
  struct journal_recovery_work { mnt, dead_node }

[dlm/mount.h]
  struct mxfs_mount { dev, xfs_dev, dev_path, sb, node_id, node_uuid, volume_id, node_slot, dlm_transport, dlm_caw }

[dlm/mxfs.h]
  fn mxfs_mount(const struct mxfs_mount_opts *opts, struct mxfs_mount **mnt_out) -> int
  fn mxfs_unmount(struct mxfs_mount *mnt) -> void
  fn mxfs_get_dlm_transport(struct mxfs_mount *mnt) -> enum mxfs_dlm_transport
  fn mxfs_lookup(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint64_t *ino_out) -> int
  fn mxfs_stat(struct mxfs_mount *mnt, uint64_t ino, struct mxfs_stat *st) -> int
  fn mxfs_read(struct mxfs_mount *mnt, uint64_t ino, void *buf, uint64_t offset, uint32_t len) -> int64_t
  fn mxfs_read_bulk(struct mxfs_mount *mnt, uint64_t ino, uint64_t offset, uint64_t total_len, uint32_t chunk_size, mxfs_read_chunk_fn cb, void *ctx, uint64_t *size_out) -> int64_t
  fn mxfs_write(struct mxfs_mount *mnt, uint64_t ino, const void *buf, uint64_t offset, uint32_t len) -> int64_t
  fn mxfs_write_bulk(struct mxfs_mount *mnt, uint64_t ino, uint64_t offset, uint64_t total_len, uint32_t chunk_size, mxfs_write_chunk_fn write_fn, void *ctx, uint64_t *size_out) -> int64_t
  fn mxfs_truncate(struct mxfs_mount *mnt, uint64_t ino, uint64_t size) -> int
  fn mxfs_trim_eof_blocks(struct mxfs_mount *mnt, uint64_t ino) -> int
  fn mxfs_fsync(struct mxfs_mount *mnt, uint64_t ino) -> int
  fn mxfs_fallocate(struct mxfs_mount *mnt, uint64_t ino, int mode, uint64_t offset, uint64_t len) -> int
  fn mxfs_sync_fs(struct mxfs_mount *mnt) -> int
  fn mxfs_readdir(struct mxfs_mount *mnt, uint64_t dir_ino, mxfs_readdir_fn cb, void *ctx) -> int
  fn mxfs_create(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn mxfs_mkdir(struct mxfs_mount *mnt, uint64_t parent_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn mxfs_rmdir(struct mxfs_mount *mnt, uint64_t parent_ino, const char *name, uint8_t namelen) -> int
  fn mxfs_unlink(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen) -> int
  fn mxfs_rename(struct mxfs_mount *mnt, uint64_t old_dir_ino, const char *old_name, uint8_t old_namelen, uint64_t new_dir_ino, const char *new_name, uint8_t new_namelen, unsigned int flags) -> int
  fn mxfs_link(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint64_t target_ino) -> int
  fn mxfs_mknod(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, uint16_t mode, uint32_t uid, uint32_t gid, uint32_t rdev, uint64_t *ino_out) -> int
  fn mxfs_symlink(struct mxfs_mount *mnt, uint64_t dir_ino, const char *name, uint8_t namelen, const char *target, uint16_t target_len, uint32_t uid, uint32_t gid, uint64_t *ino_out) -> int
  fn mxfs_readlink(struct mxfs_mount *mnt, uint64_t ino, char *buf, uint32_t buflen) -> int
  fn mxfs_chmod(struct mxfs_mount *mnt, uint64_t ino, uint16_t mode) -> int
  fn mxfs_chown(struct mxfs_mount *mnt, uint64_t ino, uint32_t uid, uint32_t gid) -> int
  fn mxfs_utimes(struct mxfs_mount *mnt, uint64_t ino, uint32_t atime_sec, uint32_t atime_nsec, uint32_t mtime_sec, uint32_t mtime_nsec) -> int
  fn mxfs_root_ino(struct mxfs_mount *mnt) -> uint64_t
  fn mxfs_statfs(struct mxfs_mount *mnt, uint32_t *blocksize, uint64_t *total_blocks, uint64_t *free_blocks, uint64_t *total_inodes, uint64_t *free_inodes) -> int
  fn mxfs_get_block_map(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, uint64_t *phys_block_out, uint32_t *flags_out) -> int
  fn mxfs_get_block_map_range(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, struct mxfs_extent_range *range) -> int
  fn mxfs_inode_lock_shared(struct mxfs_mount *mnt, uint64_t ino, uint64_t *size_out) -> int
  fn mxfs_inode_lock_exclusive(struct mxfs_mount *mnt, uint64_t ino, uint64_t *size_out) -> int
  fn mxfs_inode_unlock(struct mxfs_mount *mnt, uint64_t ino) -> void
  fn mxfs_inode_lock_downgrade(struct mxfs_mount *mnt, uint64_t ino) -> int
  fn mxfs_update_inode_size(struct mxfs_mount *mnt, uint64_t ino, uint64_t new_size) -> int
  fn mxfs_alloc_file_block(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block, uint64_t *phys_block_out) -> int
  fn mxfs_convert_unwritten(struct mxfs_mount *mnt, uint64_t ino, uint64_t logical_block) -> int
  fn mxfs_seek_data(struct mxfs_mount *mnt, uint64_t ino, int64_t offset) -> int64_t
  fn mxfs_seek_hole(struct mxfs_mount *mnt, uint64_t ino, int64_t offset) -> int64_t
  fn mxfs_getxattr(struct mxfs_mount *mnt, uint64_t ino, const char *name, void *value, int size) -> int
  fn mxfs_setxattr(struct mxfs_mount *mnt, uint64_t ino, const char *name, const void *value, int size, int flags) -> int
  fn mxfs_listxattr(struct mxfs_mount *mnt, uint64_t ino, char *list, int size) -> int
  fn mxfs_removexattr(struct mxfs_mount *mnt, uint64_t ino, const char *name) -> int
  struct mxfs_stat { ino, mode, nlink, uid, gid, size, atime_sec, atime_nsec, mtime_sec, mtime_nsec }
  typedef_fn mxfs_readdir_fn
  enum mxfs_dlm_transport { MXFS_DLM_TRANSPORT_CAW, compare, and, write, disk, based, MXFS_DLM_TRANSPORT_TCP, TCP, network, based }
  struct mxfs_mount_opts { device, node_uuid_path, dlm_port, discovery_port, multicast_addr, use_broadcast, max_block_cache, max_inode_cache, max_dir_cache, max_dlm_lock_caw }
  typedef_fn mxfs_read_chunk_fn
  typedef_fn mxfs_write_chunk_fn

[dlm/net2.c]
  fn net2_stat_bump(struct mxfs_net2_ctx *ctx, uint64_t *field) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_accept_fn, net2_link_conn_fn, net2_link_enqueue_ref, net2_link_recv_fn, net2_midcomms_rto_scan, sess_create
  fn net2_pri_for_type(uint16_t inner_type) -> enum net2_priority
    called_by: vc_send_inc
  fn net2_deliver(struct mxfs_net2_ctx *ctx, struct net2_session *sess, const void *payload, uint32_t len) -> void
    called_by: net2_midcomms_rx
  fn static net2_session_drained(struct mxfs_net2_ctx *ctx, uint16_t slot) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_rt_fn
  fn static net2_rt_fn(void *arg) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_link_connect, net2_link_down, net2_link_reap, net2_midcomms_gc, net2_midcomms_rto_scan, net2_session_drained
  fn static net2_tunables_clamp(struct mxfs_net2_tunables *t) -> void
    called_by: mxfs_net2_create
  fn mxfs_net2_create(const struct mxfs_net2_cfg *cfg, struct mxfs_net2_ctx **ctx_out) -> int
    calls: mxfs_net2_fault_init, mxfs_pal_alloc, mxfs_pal_cond_create, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy, net2_provider_get, net2_tunables_clamp
    called_by: net2_selftest_fn, vc_node_start
  fn mxfs_net2_start(struct mxfs_net2_ctx *ctx) -> int
    calls: mxfs_pal_log, net2_link_listen_start, net2_link_shutdown_all
    called_by: net2_selftest_fn, vc_node_start
  fn mxfs_net2_stop(struct mxfs_net2_ctx *ctx) -> void
    calls: mxfs_pal_log, mxfs_pal_thread_join, net2_link_shutdown_all, net2_midcomms_shutdown
    called_by: mxfs_net2_destroy, net2_selftest_fn
  fn mxfs_net2_destroy(struct mxfs_net2_ctx *ctx) -> void
    calls: mxfs_net2_stop, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: net2_selftest_fn, vc_node_kill, vc_node_start
  fn mxfs_net2_register_recv_cb(struct mxfs_net2_ctx *ctx, mxfs_net2_recv_cb cb, void *data) -> void
    called_by: mep_node_down, mep_node_up, net2_lockspace_create, net2_lockspace_destroy, net2_selftest_fn, vc_node_start
  fn mxfs_net2_set_ambiguous_cb(struct mxfs_net2_ctx *ctx, mxfs_net2_ambiguous_cb cb, void *data) -> void
    called_by: vc_node_start
  fn mxfs_net2_set_peer_addr(struct mxfs_net2_ctx *ctx, uint16_t slot, const char *host, uint16_t port) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_selftest_fn, shenv_heal, shenv_partition, vc_node_start
  fn mxfs_net2_update_view(struct mxfs_net2_ctx *ctx, uint64_t member_mask, uint64_t membership_epoch) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_lockspace_epoch_commit, net2_selftest_fn, vc_view_node
  fn mxfs_net2_send(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_id *dst, enum net2_priority pri, bool reliable, uint32_t msg_id, const void *buf, uint32_t len) -> int
    calls: net2_midcomms_send
    called_by: mepoch_send, net2_selftest_fn, net2_selftest_recv_cb, net2_shard_send, vc_send_inc
  fn mxfs_net2_get_stats(struct mxfs_net2_ctx *ctx, struct mxfs_net2_stats *out) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: get_mount, vc_assert_invariants, vc_dump_stats
  fn mxfs_net2_get_session_stats(struct mxfs_net2_ctx *ctx, uint16_t slot, struct mxfs_net2_session_stats *out) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: get_sess, net2_selftest_fn, scen_sh_reconfig, vc_assert_invariants, vc_dump_stats, vc_quiesce
  fn mxfs_net2_fault_rule_set(struct mxfs_net2_ctx *ctx, int idx, const struct mxfs_net2_fault_rule *rule) -> int
    calls: mxfs_net2_fault_set, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mep_drop_all_rx, rule_set
  fn mxfs_net2_fault_reset(struct mxfs_net2_ctx *ctx, uint64_t seed) -> void
    calls: mxfs_net2_fault_init, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release
  fn mxfs_net2_link_reset(struct mxfs_net2_ctx *ctx, uint16_t slot) -> int
    calls: net2_link_down
    called_by: scen_mc_reset_framing, shenv_partition
  fn static net2_selftest_pack(uint8_t buf[12], uint32_t kind, uint32_t seq) -> void
    called_by: net2_selftest_fn, net2_selftest_recv_cb
  fn static net2_selftest_unpack(const void *payload, uint32_t len, uint32_t *kind, uint32_t *seq) -> int
    calls: mxfs_pal_log
    called_by: net2_selftest_recv_cb
  fn static net2_selftest_recv_cb(void *data, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    calls: mxfs_net2_send, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_selftest_pack, net2_selftest_unpack
  fn static net2_selftest_fn(void *arg) -> void
    calls: mxfs_net2_create, mxfs_net2_destroy, mxfs_net2_get_session_stats, mxfs_net2_register_recv_cb, mxfs_net2_send, mxfs_net2_set_peer_addr, mxfs_net2_start, mxfs_net2_stop, mxfs_net2_update_view, mxfs_pal_get_random_bytes, mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_net2_selftest_maybe_start(void) -> void
    calls: mxfs_pal_log
  fn mxfs_net2_selftest_stop(void) -> void
    calls: mxfs_pal_thread_join
  struct net2_selftest_st { ctx, lock, pings_rcvd, pongs_rcvd, send_fail }

[dlm/net2.h]
  fn mxfs_net2_create(const struct mxfs_net2_cfg *cfg, struct mxfs_net2_ctx **ctx_out) -> int
    called_by: net2_selftest_fn, vc_node_start
  fn mxfs_net2_start(struct mxfs_net2_ctx *ctx) -> int
    called_by: net2_selftest_fn, vc_node_start
  fn mxfs_net2_stop(struct mxfs_net2_ctx *ctx) -> void
    called_by: mxfs_net2_destroy, net2_selftest_fn
  fn mxfs_net2_destroy(struct mxfs_net2_ctx *ctx) -> void
    called_by: net2_selftest_fn, vc_node_kill, vc_node_start
  fn mxfs_net2_register_recv_cb(struct mxfs_net2_ctx *ctx, mxfs_net2_recv_cb cb, void *data) -> void
    called_by: mep_node_down, mep_node_up, net2_lockspace_create, net2_lockspace_destroy, net2_selftest_fn, vc_node_start
  fn mxfs_net2_send(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_id *dst, enum net2_priority pri, bool reliable, uint32_t msg_id, const void *buf, uint32_t len) -> int
    called_by: mepoch_send, net2_selftest_fn, net2_selftest_recv_cb, net2_shard_send, vc_send_inc
  fn mxfs_net2_update_view(struct mxfs_net2_ctx *ctx, uint64_t member_mask, uint64_t membership_epoch) -> void
    called_by: net2_lockspace_epoch_commit, net2_selftest_fn, vc_view_node
  fn net2_pri_for_type(uint16_t inner_type) -> enum net2_priority
    called_by: vc_send_inc
  fn mxfs_net2_set_peer_addr(struct mxfs_net2_ctx *ctx, uint16_t slot, const char *host, uint16_t port) -> int
    called_by: net2_selftest_fn, shenv_heal, shenv_partition, vc_node_start
  fn mxfs_net2_set_ambiguous_cb(struct mxfs_net2_ctx *ctx, mxfs_net2_ambiguous_cb cb, void *data) -> void
    called_by: vc_node_start
  fn mxfs_net2_get_stats(struct mxfs_net2_ctx *ctx, struct mxfs_net2_stats *out) -> void
    called_by: get_mount, vc_assert_invariants, vc_dump_stats
  fn mxfs_net2_get_session_stats(struct mxfs_net2_ctx *ctx, uint16_t slot, struct mxfs_net2_session_stats *out) -> int
    called_by: get_sess, net2_selftest_fn, scen_sh_reconfig, vc_assert_invariants, vc_dump_stats, vc_quiesce
  fn mxfs_net2_fault_rule_set(struct mxfs_net2_ctx *ctx, int idx, const struct mxfs_net2_fault_rule *rule) -> int
    called_by: mep_drop_all_rx, rule_set
  fn mxfs_net2_fault_reset(struct mxfs_net2_ctx *ctx, uint64_t seed) -> void
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release
  fn mxfs_net2_link_reset(struct mxfs_net2_ctx *ctx, uint16_t slot) -> int
    called_by: scen_mc_reset_framing, shenv_partition
  fn mxfs_net2_selftest_maybe_start(void) -> void
  fn mxfs_net2_selftest_stop(void) -> void
  struct mxfs_net2_id { membership_epoch, cluster_uuid_hash, incarnation, slot }
  enum net2_priority { NET2_PRI_FENCE, fencing, MEPOCH, control, NET2_PRI_RELEASE, RELEASE, RELEASE_ACK, their, retx, NET2_PRI_REVOKE }
  enum mxfs_net2_freeze_scope { MXFS_NET2_FZ_NONE, MXFS_NET2_FZ_RESOURCE, MXFS_NET2_FZ_SHARD, MXFS_NET2_FZ_FS }
  enum mxfs_net2_freeze_reason { MXFS_NET2_FZR_SUSPECT, MXFS_NET2_FZR_ELECTION, MXFS_NET2_FZR_XFER, MXFS_NET2_FZR_QUORUM_LOSS, MXFS_NET2_FZR_NOFENCE, MXFS_NET2_FZR_COMM_AMBIGUOUS, MXFS_NET2_FZR_RECOVERY, MXFS_NET2_FZR_COUNT }
  struct mxfs_net2_tunables { rto_initial_ms, rto_max_ms, rt_tick_ms, delayed_ack_ms, delayed_ack_frames, ambiguity_ms, suspect_grace_ms, mepoch_lease_ms, tx_win, rx_win }
  enum mxfs_net2_topology { MXFS_NET2_TOPO_AUTO, mesh, until, the, overlay, gate, 11, step, 8, is }
  struct mxfs_net2_cfg { node_id, uuid, uuid_hash, volume_id, fs_gen, self_slot, self_incarnation, boot_nonce, base_port, membership_port }
  typedef_fn mxfs_net2_recv_cb
  typedef_fn mxfs_net2_ambiguous_cb

[dlm/net2_ctx.h]
  fn net2_deliver(struct mxfs_net2_ctx *ctx, struct net2_session *sess, const void *payload, uint32_t len) -> void
    called_by: net2_midcomms_rx
  fn net2_stat_bump(struct mxfs_net2_ctx *ctx, uint64_t *field) -> void
    called_by: net2_link_accept_fn, net2_link_conn_fn, net2_link_enqueue_ref, net2_link_recv_fn, net2_midcomms_rto_scan, sess_create
  enum net2_sess_state { NET2_SESS_EMBRYONIC, tx, buffered, peer, nonce, unknown, yet, NET2_SESS_ESTABLISHED, handshake, bound }
  struct net2_txent { occupied, enqueued, pri, frame_class, inner_type, msg_id, seq, epoch, payload, len }
  struct net2_dir_tx { next_seq, unacked_base, ring }
  struct net2_dir_rx { cum_ack, rcvd_mask, dedup, dedup_pos, acks_owed, ack_pending, ack_deadline_ms }
  struct net2_session { gc_next, peer_slot, peer_inc, peer_nonce, peer_features, refs, state, superseded_at_ms, msg_id_next, comm_ambiguous }
  enum net2_link_state { NET2_LINK_DOWN, NET2_LINK_CONNECTING, NET2_LINK_ACTIVE }
  struct net2_eqent { next, sess, seq, retx, frame, frame_len, inner_type, frame_class, pri, enq_ms }
  struct net2_linkq { depth, deficit, fresh_burst }
  struct net2_link { peer_slot, host, port, addr_known, desired, state, sock, sess, recv_thread, egress_thread }
  struct net2_provider { name }
  struct mxfs_net2_ctx { cfg, tun, running, membership_epoch, member_mask, listen_sock, accept_thread, pending_sock, links, sessions }

[dlm/net2_epoch.c]
  fn static n2edbg(void) -> int
  fn mxfs_mepoch_rec_seal(struct mxfs_mepoch_rec *r) -> void
    calls: mxfs_pal_crc32c
    called_by: net2_membership_inc_bump, scen_mep_membership
  fn mxfs_mepoch_rec_valid(const struct mxfs_mepoch_rec *r) -> bool
    calls: mxfs_pal_crc32c
    called_by: mep_disk, net2_membership_inc_bump, net2_mepoch_bootstrap, net2_mepoch_tick
  fn static mepoch_voters(uint64_t member_mask, uint16_t *out /* [5] */) -> int
    called_by: mepoch_round_check, mepoch_round_start, mepoch_validate, net2_mepoch_propose, net2_mepoch_rx, net2_mepoch_tick
  fn static mepoch_majority(int nvoters) -> int
    called_by: mepoch_round_check
  fn static slot_alive(struct net2_mepoch *mp, uint16_t slot, uint64_t now) -> bool
  fn static mepoch_proposer(struct net2_mepoch *mp, uint64_t now) -> uint16_t
    calls: mxfs_pal_mutex_unlock
    called_by: net2_mepoch_propose, net2_mepoch_tick
  fn static mepoch_write_own(struct net2_mepoch *mp, const struct mxfs_mepoch_rec *r) -> int
    called_by: mepoch_adopt_committed, mepoch_stage
  fn static mepoch_send(struct net2_mepoch *mp, uint16_t slot, struct mxfs_n2msg *m) -> void
    calls: mxfs_net2_send
    called_by: mepoch_round_commit, mepoch_round_start, net2_mepoch_rx, net2_mepoch_tick
  fn static mepoch_fill_from_cand(struct net2_mepoch *mp, struct mxfs_n2msg *m, uint16_t type) -> void
    called_by: mepoch_round_commit, mepoch_round_start, net2_mepoch_tick
  fn static mepoch_adopt_committed(struct net2_mepoch *mp, const struct mxfs_mepoch_rec *r, const uint32_t *incs, uint64_t now, struct commit_fire *cf) -> void
    calls: mepoch_write_own
    called_by: mepoch_round_commit, net2_mepoch_bootstrap, net2_mepoch_rx, net2_mepoch_tick
  fn static mepoch_fire(struct net2_mepoch *mp, struct commit_fire *cf) -> void
    called_by: net2_mepoch_bootstrap, net2_mepoch_propose, net2_mepoch_rx, net2_mepoch_tick
  fn static mepoch_validate(struct net2_mepoch *mp, const struct mxfs_n2msg *m) -> uint8_t
    calls: mepoch_voters
    called_by: mepoch_round_start, net2_mepoch_rx
  fn static mepoch_stage(struct net2_mepoch *mp, const struct mxfs_n2msg *m) -> void
    calls: mepoch_write_own
    called_by: mepoch_round_start, net2_mepoch_rx
  fn static mepoch_round_commit(struct net2_mepoch *mp, uint64_t now, struct commit_fire *cf) -> void
    calls: mepoch_adopt_committed, mepoch_fill_from_cand, mepoch_send
    called_by: mepoch_round_check
  fn static mepoch_round_check(struct net2_mepoch *mp, uint64_t now, struct commit_fire *cf) -> void
    calls: mepoch_majority, mepoch_round_commit, mepoch_voters
    called_by: mepoch_round_start, net2_mepoch_rx
  fn static mepoch_round_start(struct net2_mepoch *mp, uint64_t now, struct commit_fire *cf) -> void
    calls: mepoch_fill_from_cand, mepoch_round_check, mepoch_send, mepoch_stage, mepoch_validate, mepoch_voters
    called_by: net2_mepoch_propose, net2_mepoch_tick
  fn net2_mepoch_create(const struct net2_mepoch_cfg *cfg, struct net2_mepoch **out) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_create
    called_by: mep_node_up
  fn net2_mepoch_destroy(struct net2_mepoch *mp) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: mep_node_down
  fn net2_mepoch_bootstrap(struct net2_mepoch *mp) -> int
    calls: mepoch_adopt_committed, mepoch_fire, mxfs_mepoch_rec_valid, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: mep_form, mep_wait_epoch, scen_mep_bootstrap, scen_mep_restart_all
  fn net2_mepoch_propose(struct net2_mepoch *mp, uint64_t member_mask, uint64_t fenced_mask, uint64_t fence_ok_mask, const uint32_t *incs) -> int
    calls: mepoch_fire, mepoch_proposer, mepoch_round_start, mepoch_voters, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: mep_form, mep_wait_epoch, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_stall
  fn net2_mepoch_rx(struct net2_mepoch *mp, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    calls: mepoch_adopt_committed, mepoch_fire, mepoch_round_check, mepoch_send, mepoch_stage, mepoch_validate, mepoch_voters, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: mep_recv_cb
  fn net2_mepoch_suspect(struct net2_mepoch *mp, uint16_t slot, bool suspected) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: scen_mep_prepared_adoption, scen_mep_stall
  fn net2_mepoch_tick(struct net2_mepoch *mp, uint64_t now_ms) -> void
    calls: mepoch_adopt_committed, mepoch_fill_from_cand, mepoch_fire, mepoch_proposer, mepoch_round_start, mepoch_send, mepoch_voters, mxfs_mepoch_rec_valid, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mep_pump
  fn net2_mepoch_committed(struct net2_mepoch *mp, struct mxfs_mepoch_rec *out, uint32_t *incs_out) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn net2_mepoch_round_status(struct net2_mepoch *mp, bool *active, uint8_t *last_reason) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_no_fence_proof, scen_mep_stall
  struct net2_mepoch { cfg, lock, have_committed, committed, member_incs, have_prepared, prepared, prep_incs, round_active, cand }
  struct commit_fire { fire, rec, incs, fence_fire, fence_epoch }

[dlm/net2_epoch.h]
  fn net2_mepoch_create(const struct net2_mepoch_cfg *cfg, struct net2_mepoch **out) -> int
    called_by: mep_node_up
  fn net2_mepoch_destroy(struct net2_mepoch *mp) -> void
    called_by: mep_node_down
  fn net2_mepoch_bootstrap(struct net2_mepoch *mp) -> int
    called_by: mep_form, mep_wait_epoch, scen_mep_bootstrap, scen_mep_restart_all
  fn net2_mepoch_propose(struct net2_mepoch *mp, uint64_t member_mask, uint64_t fenced_mask, uint64_t fence_ok_mask, const uint32_t *incs) -> int
    called_by: mep_form, mep_wait_epoch, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_stall
  fn net2_mepoch_rx(struct net2_mepoch *mp, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    called_by: mep_recv_cb
  fn net2_mepoch_suspect(struct net2_mepoch *mp, uint16_t slot, bool suspected) -> void
    called_by: scen_mep_prepared_adoption, scen_mep_stall
  fn net2_mepoch_tick(struct net2_mepoch *mp, uint64_t now_ms) -> void
    called_by: mep_pump
  fn net2_mepoch_committed(struct net2_mepoch *mp, struct mxfs_mepoch_rec *out, uint32_t *incs_out /* MXFS_MAX_NODES or NULL */) -> bool
  fn net2_mepoch_round_status(struct net2_mepoch *mp, bool *active, uint8_t *last_reason) -> void
    called_by: scen_mep_no_fence_proof, scen_mep_stall
  fn mxfs_mepoch_rec_seal(struct mxfs_mepoch_rec *r) -> void
    called_by: net2_membership_inc_bump, scen_mep_membership
  fn mxfs_mepoch_rec_valid(const struct mxfs_mepoch_rec *r) -> bool
    called_by: mep_disk, net2_membership_inc_bump, net2_mepoch_bootstrap, net2_mepoch_tick
  struct net2_mepoch_storage { data }
  enum net2_mepoch_reason { N2ME_OK, N2ME_NOT_MONOTONIC, cand, epoch, committed, 1, N2ME_FENCED_SHRANK, fenced, does, not }
  struct net2_mepoch_cfg { self_slot, self_inc, lease_ms, probe_interval_ms, round_retry_ms, st, net, cb_data }

[dlm/net2_fault.c]
  fn mxfs_net2_fault_prng_next(uint64_t *state) -> uint64_t
    called_by: canonical_fault_prng, mxfs_net2_fault_eval, scen_wire_fuzz
  fn mxfs_net2_fault_init(struct mxfs_net2_fault_state *st, uint64_t seed) -> void
    called_by: canonical_fault_seq, mxfs_net2_create, mxfs_net2_fault_reset, scen_fault_engine
  fn mxfs_net2_fault_set(struct mxfs_net2_fault_state *st, int idx, const struct mxfs_net2_fault_rule *rule) -> int
    called_by: canonical_fault_seq, mxfs_net2_fault_rule_set, scen_fault_engine
  fn mxfs_net2_fault_clear(struct mxfs_net2_fault_state *st) -> void
  fn mxfs_net2_fault_eval(struct mxfs_net2_fault_state *st, enum mxfs_net2_fault_dir dir, uint8_t frame_class, uint16_t inner_type, struct mxfs_net2_fault_hit *hit) -> int
    calls: mxfs_net2_fault_prng_next
    called_by: canonical_fault_seq, scen_fault_engine
  fn static parse_u32(const char **s, uint32_t *out, uint32_t wildcard) -> int
    called_by: mxfs_net2_fault_parse_rule
  fn static match_word(const char **s, const char *w) -> int
    called_by: mxfs_net2_fault_parse_rule
  fn static expect_colon(const char **s) -> int
    called_by: mxfs_net2_fault_parse_rule
  fn mxfs_net2_fault_parse_rule(const char *str, struct mxfs_net2_fault_rule *rule) -> int
    calls: expect_colon, match_word, parse_u32
    called_by: canonical_fault_seq, rule_set, scen_fault_engine

[dlm/net2_fault.h]
  fn mxfs_net2_fault_init(struct mxfs_net2_fault_state *st, uint64_t seed) -> void
    called_by: canonical_fault_seq, mxfs_net2_create, mxfs_net2_fault_reset, scen_fault_engine
  fn mxfs_net2_fault_set(struct mxfs_net2_fault_state *st, int idx, const struct mxfs_net2_fault_rule *rule) -> int
    called_by: canonical_fault_seq, mxfs_net2_fault_rule_set, scen_fault_engine
  fn mxfs_net2_fault_clear(struct mxfs_net2_fault_state *st) -> void
  fn mxfs_net2_fault_eval(struct mxfs_net2_fault_state *st, enum mxfs_net2_fault_dir dir, uint8_t frame_class, uint16_t inner_type, struct mxfs_net2_fault_hit *hit) -> int
    called_by: canonical_fault_seq, scen_fault_engine
  fn mxfs_net2_fault_parse_rule(const char *str, struct mxfs_net2_fault_rule *rule) -> int
    called_by: canonical_fault_seq, rule_set, scen_fault_engine
  fn mxfs_net2_fault_prng_next(uint64_t *state) -> uint64_t
    called_by: canonical_fault_prng, mxfs_net2_fault_eval, scen_wire_fuzz
  enum mxfs_net2_fault_action { MXFS_NET2_FAULT_NONE, MXFS_NET2_FAULT_DROP, MXFS_NET2_FAULT_DUP, MXFS_NET2_FAULT_DELAY, MXFS_NET2_FAULT_REORDER, MXFS_NET2_FAULT_TRUNC, MXFS_NET2_FAULT_CORRUPT, MXFS_NET2_FAULT_ACTION_COUNT }
  enum mxfs_net2_fault_dir { MXFS_NET2_FAULT_SEND, MXFS_NET2_FAULT_RECV, MXFS_NET2_FAULT_ANY_DIR }
  struct mxfs_net2_fault_rule { active, action, dir, frame_class, inner_type, prob_ppm, count, delay_ms }
  struct mxfs_net2_fault_state { rules, prng, evals, injected }
  struct mxfs_net2_fault_hit { action, delay_ms }

[dlm/net2_link.c]
  fn static net2_count_malformed(struct mxfs_net2_ctx *ctx, enum mxfs_net2_hdr_err err) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_read_frame
  fn static net2_inner_type(uint8_t frame_class, const uint8_t *payload, uint32_t len) -> uint16_t
    called_by: net2_link_recv_fn
  fn static net2_fault_check(struct mxfs_net2_ctx *ctx, enum mxfs_net2_fault_dir dir, uint8_t frame_class, uint16_t inner_type, struct mxfs_net2_fault_hit *hit) -> int
    calls: mxfs_pal_tcp_close
    called_by: net2_link_accept_fn, net2_link_conn_fn, net2_link_egress_fn, net2_link_recv_fn
  fn static net2_build_hello(struct mxfs_net2_ctx *ctx, uint8_t frame_class, uint16_t dst_slot, uint32_t dst_inc, uint8_t *frame) -> uint32_t
    called_by: net2_link_accept_fn, net2_link_conn_fn
  fn static net2_parse_hello(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_hdr *hdr, const uint8_t *payload, uint32_t len, struct net2_hello *out) -> int
    called_by: net2_link_accept_fn, net2_link_conn_fn
  fn static net2_read_frame(struct mxfs_net2_ctx *ctx, mxfs_sock_t *sock, struct mxfs_net2_hdr *hdr_out, uint8_t *payload, uint32_t payload_cap) -> int
    calls: mxfs_pal_tcp_recv, net2_count_malformed
    called_by: net2_link_accept_fn, net2_link_conn_fn, net2_link_recv_fn
  fn static net2_linkq_push(struct net2_linkq *q, struct net2_eqent *ent, bool retx) -> void
    called_by: net2_link_egress_fn, net2_link_enqueue_frame, net2_link_enqueue_ref
  fn static net2_linkq_pop_list(struct net2_linkq *q, bool retx) -> struct net2_eqent
    called_by: net2_link_flush_locked, net2_linkq_pick
  fn static net2_linkq_pick(struct net2_linkq *q, uint64_t now_ms) -> struct net2_eqent
    calls: net2_linkq_pop_list
    called_by: net2_link_egress_fn
  fn static net2_eqent_free(struct mxfs_net2_ctx *ctx, struct net2_eqent *ent, bool clear_enqueued) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_sess_unref
    called_by: net2_link_egress_fn, net2_link_flush_locked
  fn static net2_link_flush_locked(struct mxfs_net2_ctx *ctx, struct net2_link *link) -> void
    calls: net2_eqent_free, net2_linkq_pop_list
    called_by: net2_link_down, net2_link_shutdown_all
  fn net2_link_down(struct mxfs_net2_ctx *ctx, struct net2_link *link) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_shutdown, net2_link_flush_locked, net2_midcomms_link_reset, net2_sess_unref
    called_by: mxfs_net2_link_reset, net2_link_accept_fn, net2_link_egress_fn, net2_link_recv_fn, net2_rt_fn
  fn net2_link_reap(struct mxfs_net2_ctx *ctx, struct net2_link *link) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_close, mxfs_pal_thread_join
    called_by: net2_link_accept_fn, net2_link_connect, net2_link_shutdown_all, net2_rt_fn
  fn static net2_link_recv_fn(void *arg) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, net2_fault_check, net2_inner_type, net2_link_down, net2_midcomms_rx, net2_read_frame, net2_sess_unref, net2_stat_bump
  fn static net2_linkq_earliest_blocked(struct net2_link *link) -> uint64_t
    called_by: net2_link_egress_fn
  fn static net2_link_send_bytes(struct net2_link *link, mxfs_sock_t *sock, const uint8_t *frame, uint32_t len) -> int
    calls: mxfs_pal_tcp_send
    called_by: net2_link_egress_fn
  fn static net2_link_egress_fn(void *arg) -> void
    calls: mxfs_pal_alloc, mxfs_pal_cond_timedwait, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_eqent_free, net2_fault_check, net2_link_down, net2_link_send_bytes, net2_linkq_earliest_blocked, net2_linkq_pick, net2_linkq_push, net2_midcomms_ack_deadline
  fn static net2_link_install(struct mxfs_net2_ctx *ctx, struct net2_link *link, mxfs_sock_t *sock, const struct net2_hello *hello) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_close, mxfs_pal_tcp_shutdown, net2_link_kick, net2_midcomms_bind, net2_midcomms_resume_flush, net2_sess_ref, net2_sess_unref
    called_by: net2_link_accept_fn, net2_link_conn_fn
  fn static net2_link_accept_fn(void *arg) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_tcp_accept, mxfs_pal_tcp_close, mxfs_pal_tcp_getpeername, mxfs_pal_tcp_send, mxfs_pal_tcp_set_opts, net2_build_hello, net2_fault_check, net2_link_down, net2_link_install, net2_link_reap, net2_parse_hello
  fn static net2_link_conn_fn(void *arg) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_close, mxfs_pal_tcp_connect, mxfs_pal_tcp_send, mxfs_pal_tcp_set_opts, net2_build_hello, net2_fault_check, net2_link_install, net2_parse_hello, net2_read_frame, net2_stat_bump
  fn net2_link_connect(struct mxfs_net2_ctx *ctx, uint16_t slot) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_shutdown, mxfs_pal_time_ms, net2_link_reap
    called_by: net2_rt_fn
  fn net2_link_class_full(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, uint8_t pri) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_midcomms_send
  fn net2_link_enqueue_ref(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, struct net2_session *sess, uint64_t seq, uint8_t pri, bool retx, uint16_t inner_type) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_linkq_push, net2_sess_ref, net2_stat_bump
    called_by: net2_midcomms_resume_flush, net2_midcomms_rto_scan, net2_midcomms_send
  fn net2_link_enqueue_frame(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, uint8_t *frame, uint32_t frame_len, uint8_t frame_class, uint8_t pri, uint16_t inner_type) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_linkq_push
    called_by: net2_midcomms_send
  fn net2_link_kick(struct mxfs_net2_ctx *ctx, uint16_t dst_slot) -> void
    calls: mxfs_pal_cond_signal, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_install, net2_midcomms_resume_flush, net2_midcomms_rto_scan, net2_midcomms_rx, net2_midcomms_send
  fn net2_link_listen_start(struct mxfs_net2_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_tcp_close, mxfs_pal_tcp_listen
    called_by: mxfs_net2_start
  fn net2_link_shutdown_all(struct mxfs_net2_ctx *ctx) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_close, mxfs_pal_tcp_shutdown, mxfs_pal_thread_join, net2_link_flush_locked, net2_link_reap, net2_sess_unref
    called_by: mxfs_net2_start, mxfs_net2_stop
  struct net2_thread_arg { ctx, link, sess }
  struct net2_hello { slot, inc, nonce, features, wire_ver }
  struct net2_conn_arg { ctx, link }

[dlm/net2_link.h]
  fn net2_link_listen_start(struct mxfs_net2_ctx *ctx) -> int
    called_by: mxfs_net2_start
  fn net2_link_connect(struct mxfs_net2_ctx *ctx, uint16_t slot) -> void
    called_by: net2_rt_fn
  fn net2_link_down(struct mxfs_net2_ctx *ctx, struct net2_link *link) -> void
    called_by: mxfs_net2_link_reset, net2_link_accept_fn, net2_link_egress_fn, net2_link_recv_fn, net2_rt_fn
  fn net2_link_reap(struct mxfs_net2_ctx *ctx, struct net2_link *link) -> void
    called_by: net2_link_accept_fn, net2_link_connect, net2_link_shutdown_all, net2_rt_fn
  fn net2_link_class_full(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, uint8_t pri) -> bool
    called_by: net2_midcomms_send
  fn net2_link_enqueue_ref(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, struct net2_session *sess, uint64_t seq, uint8_t pri, bool retx, uint16_t inner_type) -> int
    called_by: net2_midcomms_resume_flush, net2_midcomms_rto_scan, net2_midcomms_send
  fn net2_link_enqueue_frame(struct mxfs_net2_ctx *ctx, uint16_t dst_slot, uint8_t *frame, uint32_t frame_len, uint8_t frame_class, uint8_t pri, uint16_t inner_type) -> int
    called_by: net2_midcomms_send
  fn net2_link_kick(struct mxfs_net2_ctx *ctx, uint16_t dst_slot) -> void
    called_by: net2_link_install, net2_midcomms_resume_flush, net2_midcomms_rto_scan, net2_midcomms_rx, net2_midcomms_send
  fn net2_link_shutdown_all(struct mxfs_net2_ctx *ctx) -> void
    called_by: mxfs_net2_start, mxfs_net2_stop

[dlm/net2_lock.c]
  fn static n2dbg(void) -> int
  fn net2_rec_get(struct net2_shard *sh, const struct mxfs_resource_id *res, bool create) -> struct n2_lock_rec
    calls: mxfs_pal_alloc, resource_equal, resource_hash_raw
    called_by: net2_lock_apply_entry, net2_lock_emit_result, net2_lock_leader_validate, net2_lock_post_release_grants, shard_install_held_report, snap_install_rec
  fn static rec_slot_view(const struct n2_lock_rec *rec, uint64_t exclude_bit, struct mxfs_caw_lock_slot *v) -> void
    called_by: net2_lock_apply_entry
  fn static rec_compatible(const struct n2_lock_rec *rec, uint8_t mode, uint16_t requester) -> bool
    called_by: grant_waiters, net2_lock_leader_validate
  fn static rec_clear_holder(struct n2_lock_rec *rec, uint64_t bit) -> void
    called_by: net2_lock_apply_entry
  fn static rec_set_holder(struct n2_lock_rec *rec, uint8_t mode, uint64_t bit) -> void
    called_by: net2_lock_apply_entry
  fn static rec_all_holders(const struct n2_lock_rec *rec) -> uint64_t
    calls: net2_ls_stat_bump, send_result
    called_by: net2_lock_leader_validate
  fn static opcache_client(struct net2_shard *sh, uint16_t slot, uint32_t inc, bool create) -> struct n2_opcache_client
    called_by: opcache_find, opcache_store
  fn static opcache_find(struct net2_shard *sh, uint16_t slot, uint32_t inc, uint64_t request_id) -> struct n2_opcache_ent
    calls: opcache_client
    called_by: net2_lock_leader_validate
  fn static opcache_store(struct net2_shard *sh, uint16_t slot, uint32_t inc, uint64_t request_id, uint8_t status, uint8_t mode, uint64_t gen) -> void
    calls: opcache_client
    called_by: net2_lock_apply_entry
  fn static waitq_has(const struct n2_lock_rec *rec, uint16_t slot, uint32_t inc, uint64_t request_id) -> bool
    called_by: grant_waiters, net2_lock_leader_validate, waitq_push
  fn static waitq_push(struct net2_shard *sh, struct n2_lock_rec *rec, uint16_t slot, uint32_t inc, uint64_t request_id, uint8_t mode, uint64_t enq_seq) -> void
    calls: mxfs_pal_alloc, waitq_has
    called_by: net2_lock_apply_entry
  fn static waitq_remove(struct n2_lock_rec *rec, uint16_t slot, uint32_t inc, uint64_t request_id) -> void
    calls: mxfs_pal_free
    called_by: net2_lock_apply_entry
  fn net2_lock_apply_entry(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *e) -> void
    calls: holders_for_mode_const, net2_ls_stat_max, net2_rec_get, opcache_store, rec_clear_holder, rec_set_holder, rec_slot_view, waitq_push, waitq_remove
    called_by: shard_advance_commit, shard_rx_append
  fn static send_result(struct net2_lockspace *ls, struct net2_shard *sh, uint16_t type, uint16_t flags, const struct n2_log_ent *e, uint8_t status) -> void
    calls: net2_shard_send
    called_by: net2_lock_emit_result, net2_lock_leader_validate, rec_all_holders
  fn net2_lock_emit_result(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *e) -> void
    calls: net2_ls_hook, net2_ls_stat_bump, net2_rec_get, net2_shard_i_am_leader, net2_shard_send, send_result
    called_by: shard_advance_commit
  fn static pick_next_waiter(struct n2_lock_rec *rec) -> struct n2_waiter
    called_by: grant_waiters
  fn static grant_waiters(struct net2_lockspace *ls, struct net2_shard *sh, struct n2_lock_rec *rec) -> void
    calls: net2_shard_append, pick_next_waiter, rec_compatible, waitq_has
    called_by: net2_lock_post_release_grants
  fn net2_lock_post_release_grants(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_resource_id *res) -> void
    calls: grant_waiters, net2_rec_get, net2_shard_i_am_leader
    called_by: shard_advance_commit
  fn static deny(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, uint8_t reason, uint16_t hint) -> void
    calls: net2_ls_stat_bump, net2_shard_send
    called_by: dlm_lock_impl, net2_lock_leader_validate
  fn net2_lock_leader_validate(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, const struct mxfs_net2_id *src) -> void
    calls: deny, net2_ls_hook, net2_ls_stat_bump, net2_rec_get, net2_shard_append, net2_shard_i_am_leader, net2_shard_prove_term, opcache_find, rec_all_holders, rec_compatible, send_result, waitq_has
  fn static creq_find(struct net2_lockspace *ls, uint64_t request_id) -> struct n2_creq
    called_by: creq_wait, net2_lock_client_rx, net2_lock_client_tick
  fn static held_bucket(const struct mxfs_resource_id *res) -> uint32_t
    calls: resource_hash_raw
    called_by: held_insert, held_remove, net2_lock_client_rx, net2_lock_held_mode
  fn static held_insert(struct net2_lockspace *ls, const struct mxfs_resource_id *res, uint8_t mode, uint64_t gen) -> void
    calls: held_bucket, mxfs_pal_alloc, resource_equal
    called_by: net2_lock_client_rx
  fn static held_remove(struct net2_lockspace *ls, const struct mxfs_resource_id *res) -> void
    calls: held_bucket, mxfs_pal_free, resource_equal
    called_by: net2_lock_client_rx
  fn net2_lock_held_mode(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint64_t *gen_out) -> uint8_t
    calls: held_bucket, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, resource_equal
    called_by: assert_no_overlap
  fn static creq_pick_target(struct net2_lockspace *ls, const struct mxfs_resource_id *res, uint32_t retries) -> uint16_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_shard_get, net2_shard_id_for
    called_by: net2_lock_acquire, net2_lock_client_tick, net2_lock_release
  fn static creq_send(struct net2_lockspace *ls, struct n2_creq *cr) -> void
    calls: net2_shard_id_for, net2_shard_send
    called_by: net2_lock_acquire, net2_lock_client_tick, net2_lock_release
  fn net2_lock_client_rx(struct net2_lockspace *ls, const struct mxfs_net2_id *src, const struct mxfs_n2msg *m) -> void
    calls: creq_alloc, creq_find, held_bucket, held_insert, held_remove, mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_ls_stat_bump, resource_equal
    called_by: ls_recv_cb, net2_shard_send
  fn net2_lock_client_tick(struct net2_lockspace *ls, uint64_t now_ms) -> void
    calls: creq_find, creq_pick_target, creq_send, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_ls_stat_bump
    called_by: ls_rt_fn
  fn static creq_alloc(struct net2_lockspace *ls, struct n2_creq **out) -> int
    called_by: net2_lock_acquire, net2_lock_client_rx, net2_lock_release
  fn static creq_wait(struct net2_lockspace *ls, uint64_t request_id, uint32_t deadline_ms, struct n2_creq *result) -> int
    calls: creq_find, mxfs_pal_cond_timedwait, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: net2_lock_acquire, net2_lock_release
  fn net2_lock_acquire(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t deadline_ms, uint64_t *gen_out, uint64_t *dir_epoch_out) -> int
    calls: creq_alloc, creq_pick_target, creq_send, creq_wait, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: killpoint_run, op_acquire_fn, scen_sh_basic, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote, shenv_start
  fn net2_lock_release(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint64_t gen, uint32_t deadline_ms) -> int
    calls: creq_alloc, creq_pick_target, creq_send, creq_wait, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: killpoint_run, op_release_fn, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote, shenv_start

[dlm/net2_lock.h]
  fn net2_lock_acquire(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint8_t mode, uint32_t deadline_ms, uint64_t *gen_out, uint64_t *dir_epoch_out) -> int
    called_by: killpoint_run, op_acquire_fn, scen_sh_basic, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote, shenv_start
  fn net2_lock_release(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint64_t gen, uint32_t deadline_ms) -> int
    called_by: killpoint_run, op_release_fn, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote, shenv_start
  fn net2_lock_held_mode(struct net2_lockspace *ls, const struct mxfs_resource_id *resource, uint64_t *gen_out) -> uint8_t
    called_by: assert_no_overlap

[dlm/net2_membership.c]
  fn static n2mbdbg(void) -> int
  fn static mb_set_state(struct net2_membership *mb, uint16_t slot, enum net2_member_state to, struct mb_fires *fires) -> void
    called_by: net2_membership_fence_done, net2_membership_observe, net2_membership_tick, net2_membership_track, net2_membership_untrack
  fn static mb_fire(struct net2_membership *mb, struct mb_fires *fires) -> void
    called_by: net2_membership_fence_done, net2_membership_observe, net2_membership_tick, net2_membership_track, net2_membership_untrack
  fn net2_membership_create(const struct net2_membership_cfg *cfg, struct net2_membership **out) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_create
    called_by: scen_mep_membership
  fn net2_membership_destroy(struct net2_membership *mb) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: scen_mep_membership
  fn net2_membership_track(struct net2_membership *mb, uint16_t slot, uint32_t inc, uint64_t nonce) -> void
    calls: mb_fire, mb_set_state, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms
    called_by: scen_mep_membership
  fn net2_membership_untrack(struct net2_membership *mb, uint16_t slot) -> void
    calls: mb_fire, mb_set_state, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn net2_membership_observe(struct net2_membership *mb, uint16_t slot, enum net2_observer obs, uint32_t inc, uint64_t nonce, uint64_t now_ms) -> void
    calls: mb_fire, mb_set_state, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_membership
  fn net2_membership_tick(struct net2_membership *mb, uint64_t now_ms) -> void
    calls: mb_fire, mb_set_state, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_membership
  fn net2_membership_fence_done(struct net2_membership *mb, uint16_t slot, uint32_t inc) -> void
    calls: mb_fire, mb_set_state, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_membership
  fn net2_membership_state(struct net2_membership *mb, uint16_t slot) -> enum net2_member_state
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_membership
  fn net2_membership_inc_bump(const struct net2_mepoch_storage *st, uint16_t self_slot, uint32_t *inc_out) -> int
    calls: mxfs_mepoch_rec_seal, mxfs_mepoch_rec_valid
    called_by: scen_mep_membership
  fn net2_membership_boot_nonce(void) -> uint64_t
    calls: mxfs_pal_get_random_bytes
    called_by: scen_mep_membership
  struct member_slot { state, inc, nonce, last_seen_ms, suspect_since_ms }
  struct net2_membership { cfg, lock, slots }
  struct mb_fires { n, slot }

[dlm/net2_membership.h]
  fn net2_membership_create(const struct net2_membership_cfg *cfg, struct net2_membership **out) -> int
    called_by: scen_mep_membership
  fn net2_membership_destroy(struct net2_membership *mb) -> void
    called_by: scen_mep_membership
  fn net2_membership_track(struct net2_membership *mb, uint16_t slot, uint32_t inc, uint64_t nonce) -> void
    called_by: scen_mep_membership
  fn net2_membership_untrack(struct net2_membership *mb, uint16_t slot) -> void
  fn net2_membership_observe(struct net2_membership *mb, uint16_t slot, enum net2_observer obs, uint32_t inc, uint64_t nonce, uint64_t now_ms) -> void
    called_by: scen_mep_membership
  fn net2_membership_tick(struct net2_membership *mb, uint64_t now_ms) -> void
    called_by: scen_mep_membership
  fn net2_membership_fence_done(struct net2_membership *mb, uint16_t slot, uint32_t inc) -> void
    called_by: scen_mep_membership
  fn net2_membership_state(struct net2_membership *mb, uint16_t slot) -> enum net2_member_state
    called_by: scen_mep_membership
  fn net2_membership_inc_bump(const struct net2_mepoch_storage *st, uint16_t self_slot, uint32_t *inc_out) -> int
    called_by: scen_mep_membership
  fn net2_membership_boot_nonce(void) -> uint64_t
    called_by: scen_mep_membership
  enum net2_member_state { N2MB_UNTRACKED, N2MB_ACTIVE, N2MB_SUSPECT, N2MB_FENCING, N2MB_DEAD }
  enum net2_observer { N2OBS_LEASE, lease, multicast, beacon, seen, N2OBS_PROBE, NET2, unicast, probe, link }
  struct net2_membership_cfg { self_slot, miss_ms, grace_ms, cb_data }

[dlm/net2_midcomms.c]
  fn net2_sess_ref(struct net2_session *sess) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_enqueue_ref, net2_link_install, net2_midcomms_rto_scan, net2_midcomms_send
  fn net2_sess_unref(struct net2_session *sess) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_eqent_free, net2_link_down, net2_link_egress_fn, net2_link_install, net2_link_recv_fn, net2_link_shutdown_all, net2_midcomms_rto_scan, net2_midcomms_send
  fn static sess_create(struct mxfs_net2_ctx *ctx, uint16_t slot, uint32_t inc, uint64_t nonce, enum net2_sess_state state) -> struct net2_session
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_create, mxfs_pal_time_ms, net2_stat_bump
    called_by: net2_midcomms_bind, net2_midcomms_send
  fn static sess_destroy(struct net2_session *sess) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_destroy
    called_by: net2_midcomms_gc, net2_midcomms_shutdown
  fn static txent_lookup(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint64_t seq) -> struct net2_txent
    called_by: ack_process, net2_midcomms_pack_entry, net2_midcomms_resume_flush, net2_midcomms_rto_scan, net2_midcomms_send
  fn static txent_retire(struct net2_session *sess, struct net2_txent *e, bool acked) -> void
    calls: mxfs_pal_free
    called_by: ack_process, tx_abort_all
  fn static tx_abort_all(struct net2_session *sess) -> void
    calls: txent_retire
    called_by: net2_midcomms_rx, net2_midcomms_shutdown, sess_supersede
  fn static ack_process(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint64_t ack, uint32_t sack, uint64_t now_ms) -> bool
    calls: mxfs_pal_log, txent_lookup, txent_retire
    called_by: net2_midcomms_rx
  fn static sess_fold_retired(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_session_stats *st) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: sess_supersede
  fn static sess_supersede(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint64_t now_ms) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, sess_fold_retired, tx_abort_all
    called_by: net2_midcomms_bind, net2_midcomms_send
  fn net2_midcomms_bind(struct mxfs_net2_ctx *ctx, uint16_t slot, uint32_t inc, uint64_t nonce, uint32_t features) -> struct net2_session
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, sess_create, sess_supersede, stop
    called_by: net2_link_install
  fn net2_midcomms_send(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_id *dst, enum net2_priority pri, bool reliable, uint32_t msg_id, const void *buf, uint32_t len) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_link_class_full, net2_link_enqueue_frame, net2_link_enqueue_ref, net2_link_kick, net2_sess_ref, net2_sess_unref, sess_create, sess_supersede, txent_lookup
    called_by: mxfs_net2_send
  fn net2_midcomms_resume_flush(struct mxfs_net2_ctx *ctx, struct net2_session *sess) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_link_enqueue_ref, net2_link_kick, txent_lookup
    called_by: net2_link_install
  fn static rx_dedup_seen(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint32_t msg_id) -> bool
    called_by: net2_midcomms_rx
  fn net2_midcomms_rx(struct mxfs_net2_ctx *ctx, struct net2_session *sess, const struct mxfs_net2_hdr *hdr, const uint8_t *payload, uint32_t len) -> void
    calls: ack_process, first, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_deliver, net2_link_kick, rx_dedup_seen, tx_abort_all
    called_by: net2_link_recv_fn
  fn net2_midcomms_pack_entry(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint64_t seq, bool retx, uint8_t *frame_out, uint16_t *inner_type) -> uint32_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, txent_lookup
    called_by: net2_link_egress_fn
  fn net2_midcomms_ack_deadline(struct net2_session *sess, uint64_t *deadline_ms) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_egress_fn
  fn net2_midcomms_make_ack(struct mxfs_net2_ctx *ctx, struct net2_session *sess, bool force, uint64_t now_ms, uint8_t *frame_out) -> uint32_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_egress_fn
  fn net2_midcomms_rto_scan(struct mxfs_net2_ctx *ctx, uint64_t now_ms) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_link_enqueue_ref, net2_link_kick, net2_sess_ref, net2_sess_unref, net2_stat_bump, txent_lookup
    called_by: net2_rt_fn
  fn net2_midcomms_link_reset(struct mxfs_net2_ctx *ctx, struct net2_session *sess) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_link_down
  fn net2_midcomms_gc(struct mxfs_net2_ctx *ctx, uint64_t now_ms) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, sess_destroy
    called_by: net2_rt_fn
  fn net2_midcomms_shutdown(struct mxfs_net2_ctx *ctx) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, sess_destroy, tx_abort_all
    called_by: mxfs_net2_stop

[dlm/net2_midcomms.h]
  fn net2_sess_ref(struct net2_session *sess) -> void
    called_by: net2_link_enqueue_ref, net2_link_install, net2_midcomms_rto_scan, net2_midcomms_send
  fn net2_sess_unref(struct net2_session *sess) -> void
    called_by: net2_eqent_free, net2_link_down, net2_link_egress_fn, net2_link_install, net2_link_recv_fn, net2_link_shutdown_all, net2_midcomms_rto_scan, net2_midcomms_send
  fn net2_midcomms_send(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_id *dst, enum net2_priority pri, bool reliable, uint32_t msg_id, const void *buf, uint32_t len) -> int
    called_by: mxfs_net2_send
  fn net2_midcomms_bind(struct mxfs_net2_ctx *ctx, uint16_t slot, uint32_t inc, uint64_t nonce, uint32_t features) -> struct net2_session
    called_by: net2_link_install
  fn net2_midcomms_resume_flush(struct mxfs_net2_ctx *ctx, struct net2_session *sess) -> void
    called_by: net2_link_install
  fn net2_midcomms_rx(struct mxfs_net2_ctx *ctx, struct net2_session *sess, const struct mxfs_net2_hdr *hdr, const uint8_t *payload, uint32_t len) -> void
    called_by: net2_link_recv_fn
  fn net2_midcomms_rto_scan(struct mxfs_net2_ctx *ctx, uint64_t now_ms) -> void
    called_by: net2_rt_fn
  fn net2_midcomms_gc(struct mxfs_net2_ctx *ctx, uint64_t now_ms) -> void
    called_by: net2_rt_fn
  fn net2_midcomms_link_reset(struct mxfs_net2_ctx *ctx, struct net2_session *sess) -> void
    called_by: net2_link_down
  fn net2_midcomms_shutdown(struct mxfs_net2_ctx *ctx) -> void
    called_by: mxfs_net2_stop
  fn net2_midcomms_ack_deadline(struct net2_session *sess, uint64_t *deadline_ms) -> bool
    called_by: net2_link_egress_fn
  fn net2_midcomms_make_ack(struct mxfs_net2_ctx *ctx, struct net2_session *sess, bool force, uint64_t now_ms, uint8_t *frame_out) -> uint32_t
    called_by: net2_link_egress_fn
  fn net2_midcomms_pack_entry(struct mxfs_net2_ctx *ctx, struct net2_session *sess, uint64_t seq, bool retx, uint8_t *frame_out, uint16_t *inner_type) -> uint32_t
    called_by: net2_link_egress_fn

[dlm/net2_msg.h]
  enum mxfs_n2msg_type { N2_ACQUIRE, client, leader, acquire, convert, N2_GRANT, leader, client, committed, grant }
  enum mxfs_n2msg_deny { N2D_NOT_LEADER, leader_hint, carries, the, known, leader, N2D_STALE_TERM, N2D_STALE_EPOCH, N2D_RETRY, electing }
  enum mxfs_n2log_op { N2L_TERM, election, reconfig, barrier, N2L_GRANT, make, requester, a, holder, gen }
  struct mxfs_n2msg { type, flags, membership_epoch, shard_term, shard_id, req_slot, req_inc, request_id, resource, mode }
  enum mxfs_n2snap_kind { N2SR_HOLDERS, N2SR_WAITER, N2SR_OPCACHE, N2SR_RECMETA, N2SR_HELD }
  struct mxfs_n2snap_rec { resource, kind, mode, slot, inc, gen_or_enqseq, request_id, aux }
  struct mxfs_n2log_rec { resource, seq, term, op, mode, slot, inc, request_id, grant_gen, dir_epoch }

[dlm/net2_overlay.c]
  fn static net2_mesh_route(struct mxfs_net2_ctx *ctx, uint16_t dst_slot) -> struct net2_link
  fn static net2_mesh_route_alt(struct mxfs_net2_ctx *ctx, uint16_t dst_slot) -> struct net2_link
  fn static net2_mesh_view_update(struct mxfs_net2_ctx *ctx) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn net2_provider_get(uint8_t topology) -> const struct net2_provider
    calls: mxfs_pal_log
    called_by: mxfs_net2_create

[dlm/net2_overlay.h]
  fn net2_provider_get(uint8_t topology) -> const struct net2_provider
    called_by: mxfs_net2_create

[dlm/net2_shard.c]
  fn static n2dbg(void) -> int
  fn net2_ls_stat_bump(struct net2_lockspace *ls, uint64_t *field) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: deny, net2_lock_client_rx, net2_lock_client_tick, net2_lock_emit_result, net2_lock_leader_validate, net2_shard_i_am_leader, net2_shard_replica_index, rec_all_holders, shard_advance_commit, shard_install_held_report, shard_reconfigure, shard_rx_append, shard_rx_append_ack, shard_rx_vote, shard_send_append
  fn net2_ls_stat_max(struct net2_lockspace *ls, uint64_t *field, uint64_t v) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: net2_lock_apply_entry, shard_advance_commit, shard_rx_append
  fn net2_ls_hook(struct net2_lockspace *ls, enum n2_hook_point p, uint32_t shard_id, uint16_t detail) -> bool
    calls: mxfs_pal_free
    called_by: net2_lock_emit_result, net2_lock_leader_validate, shard_advance_commit, shard_reconfigure, shard_send_snapshot
  fn static ls_prng(struct net2_lockspace *ls) -> uint64_t
    called_by: shard_arm_election, shard_solicit_votes
  fn static fnv1a64(uint64_t h, const void *data, size_t len) -> uint64_t
    called_by: hrw_top, net2_shard_id_for
  fn net2_shard_id_for(const struct net2_lockspace *ls, const struct mxfs_resource_id *res) -> uint32_t
    calls: fnv1a64
    called_by: assert_single_leader, creq_pick_target, creq_send, probe_monotone, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_leader_slot, shard_start_recovery
  fn static hrw_cmp(const void *a, const void *b) -> int
  fn static hrw_top(uint64_t epoch, uint32_t shard_id, uint64_t member_mask, const uint32_t *member_incs, struct n2_replica *out) -> int
    calls: fnv1a64
    called_by: net2_shard_derive_config
  fn static quorum_of(uint8_t nreplicas) -> uint8_t
    called_by: shard_advance_commit, shard_rx_vote, shard_solicit_votes
  fn net2_shard_derive_config(struct net2_lockspace *ls, struct net2_shard *sh, uint64_t epoch) -> void
    calls: hrw_top
    called_by: net2_shard_get, shard_reconfigure
  fn net2_shard_replica_index(const struct net2_shard *sh, uint16_t slot) -> int
    calls: net2_ls_stat_bump
    called_by: assert_single_leader, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_arm_election, shard_reconfigure, shard_rx_append_ack, shard_rx_vote
  fn net2_shard_i_am_leader(const struct net2_lockspace *ls, const struct net2_shard *sh) -> bool
    calls: log_slot, mxfs_pal_time_ms, net2_ls_stat_bump, net2_shard_append, net2_shard_send, shard_advance_commit, shard_send_append, shard_send_snapshot
    called_by: net2_lock_emit_result, net2_lock_leader_validate, net2_lock_post_release_grants, shard_rx_append_ack
  fn net2_shard_get(struct net2_lockspace *ls, uint32_t shard_id, bool create) -> struct net2_shard
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, net2_shard_derive_config, net2_shard_send
    called_by: creq_pick_target, scen_sh_recovery, scen_sh_two_loss, shard_leader_slot
  fn net2_shard_send(struct net2_lockspace *ls, uint16_t dst_slot, struct mxfs_n2msg *m, const uint8_t *recs, uint32_t recs_len) -> void
    calls: mxfs_net2_send, net2_lock_client_rx, net2_shard_dispatch
    called_by: creq_send, deny, net2_lock_emit_result, net2_shard_get, net2_shard_i_am_leader, send_result, shard_reconfigure, shard_rx_append, shard_rx_append_ack, shard_rx_vote, shard_send_append, shard_send_snapshot, shard_solicit_votes, shard_start_recovery, shard_xfer_finalize
  fn static log_slot(struct net2_shard *sh, uint64_t seq) -> struct n2_log_ent
    called_by: net2_shard_i_am_leader, net2_shard_prove_term, shard_advance_commit, shard_rx_append, shard_rx_append_ack, shard_send_snapshot
  fn static shard_send_append(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *e, uint16_t dst) -> void
    calls: net2_ls_stat_bump, net2_shard_send
    called_by: net2_shard_i_am_leader, shard_rx_append_ack
  fn static shard_advance_commit(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: log_slot, net2_lock_apply_entry, net2_lock_emit_result, net2_lock_post_release_grants, net2_ls_hook, net2_ls_stat_bump, net2_ls_stat_max, quorum_of
    called_by: net2_shard_i_am_leader, shard_rx_append_ack
  fn net2_shard_append(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *tmpl) -> int
    called_by: grant_waiters, net2_lock_leader_validate, net2_shard_i_am_leader, net2_shard_prove_term, shard_become_leader, shard_reconfigure, shard_recovery_maybe_finish, shard_rx_append_ack, shard_xfer_finalize
  fn static snap_put(struct snap_build *b, const struct mxfs_n2snap_rec *r) -> void
    called_by: snap_serialize
  fn static snap_serialize(struct net2_shard *sh, struct snap_build *b) -> int
    calls: snap_put
    called_by: shard_send_snapshot
  fn static shard_send_snapshot(struct net2_lockspace *ls, struct net2_shard *sh, uint16_t dst) -> void
    calls: log_slot, mxfs_pal_alloc, mxfs_pal_free, net2_ls_hook, net2_ls_stat_bump, net2_shard_send, snap_serialize
    called_by: net2_shard_i_am_leader, shard_rx_append_ack, shard_rx_snapshot_req
  fn static snap_install_rec(struct net2_shard *sh, const struct mxfs_n2snap_rec *r) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free, net2_rec_get
  fn static shard_arm_election(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: ls_prng, mxfs_pal_time_ms, net2_shard_replica_index
    called_by: net2_lockspace_suspect
  fn net2_shard_prove_term(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: log_slot, net2_shard_append
    called_by: net2_lock_leader_validate
  fn static shard_become_leader(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: net2_shard_append
    called_by: shard_rx_vote, shard_solicit_votes
  fn static shard_solicit_votes(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: ls_prng, mxfs_pal_time_ms, net2_ls_stat_bump, net2_shard_send, quorum_of, shard_become_leader
    called_by: ls_rt_fn
  fn static shard_rx_append(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, uint16_t src_slot) -> void
    calls: log_slot, net2_lock_apply_entry, net2_ls_stat_bump, net2_ls_stat_max, net2_shard_send
  fn static shard_rx_append_ack(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, uint16_t src_slot) -> void
    calls: log_slot, mxfs_pal_time_ms, net2_ls_stat_bump, net2_shard_append, net2_shard_i_am_leader, net2_shard_replica_index, net2_shard_send, shard_advance_commit, shard_send_append, shard_send_snapshot
  fn static shard_rx_vote(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, uint16_t src_slot) -> void
    calls: net2_ls_stat_bump, net2_shard_replica_index, net2_shard_send, quorum_of, shard_become_leader
  fn static shard_rx_snapshot_req(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, uint16_t src_slot) -> void
    calls: shard_send_snapshot
  fn static shard_xfer_finalize(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: net2_ls_stat_bump, net2_shard_append, net2_shard_send, shard_start_recovery
    called_by: shard_xfer_tick
  fn static shard_rx_snapshot_chunk(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, const uint8_t *payload, uint32_t len, uint32_t recs_off) -> void
  fn net2_shard_dispatch(struct net2_lockspace *ls, const struct mxfs_net2_id *src, const struct mxfs_n2msg *m, const uint8_t *payload, uint32_t len, uint32_t recs_off) -> void
    called_by: ls_recv_cb, net2_shard_send
  fn static shard_start_recovery(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_ls_stat_bump, net2_shard_id_for, net2_shard_send, shard_install_held_report
    called_by: shard_reconfigure, shard_xfer_finalize, shard_xfer_tick
  fn static shard_recovery_maybe_finish(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    calls: net2_shard_append
  fn static shard_install_held_report(struct net2_lockspace *ls, struct net2_shard *sh, uint16_t slot, const struct mxfs_n2snap_rec *r) -> void
    calls: net2_ls_stat_bump, net2_rec_get
    called_by: shard_start_recovery
  fn static shard_rx_recovery_report(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, const uint8_t *payload, uint32_t len, uint32_t recs_off, uint16_t src_slot) -> void
  fn static shard_reconfigure(struct net2_lockspace *ls, struct net2_shard *sh, uint64_t new_epoch) -> void
    calls: mxfs_pal_time_ms, net2_ls_hook, net2_ls_stat_bump, net2_shard_append, net2_shard_derive_config, net2_shard_replica_index, net2_shard_send, shard_start_recovery
    called_by: net2_lockspace_epoch_commit
  fn net2_lockspace_epoch_commit(struct net2_lockspace *ls, uint64_t epoch, uint64_t member_mask, const uint32_t *member_incs) -> void
    calls: mxfs_net2_update_view, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, shard_reconfigure
    called_by: shenv_epoch_bump
  fn net2_lockspace_suspect(struct net2_lockspace *ls, uint16_t slot) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, shard_arm_election
    called_by: shenv_suspect
  fn static ls_recv_cb(void *data, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    calls: net2_lock_client_rx, net2_shard_dispatch
  fn static shard_xfer_tick(struct net2_lockspace *ls, struct net2_shard *sh, uint64_t now) -> void
    calls: net2_shard_send, shard_start_recovery, shard_xfer_finalize
    called_by: ls_rt_fn
  fn static ls_rt_fn(void *arg) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_lock_client_tick, shard_solicit_votes, shard_xfer_tick
  fn net2_lockspace_create(struct mxfs_net2_ctx *net, const struct net2_lockspace_cfg *cfg, struct net2_lockspace **out) -> int
    calls: mxfs_net2_register_recv_cb, mxfs_pal_alloc, mxfs_pal_cond_create, mxfs_pal_mutex_create, net2_lockspace_destroy
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_start(struct net2_lockspace *ls) -> int
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_stop(struct net2_lockspace *ls) -> void
    calls: mxfs_pal_cond_broadcast, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_thread_join
    called_by: net2_lockspace_destroy
  fn net2_shard_free_recs(struct net2_shard *sh) -> void
    calls: mxfs_pal_free
    called_by: net2_lockspace_destroy
  fn net2_lockspace_destroy(struct net2_lockspace *ls) -> void
    calls: mxfs_net2_register_recv_cb, mxfs_pal_cond_destroy, mxfs_pal_free, mxfs_pal_mutex_destroy, net2_lockspace_stop, net2_shard_free_recs
    called_by: net2_lockspace_create, scen_sh_reconfig, scen_sh_xfer_no_vote, shenv_kill, shenv_stop
  fn net2_lockspace_set_bast_cb(struct net2_lockspace *ls, net2_bast_cb cb, void *data) -> void
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_set_hook(struct net2_lockspace *ls, net2_test_hook hook, void *data) -> void
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints
  fn net2_lockspace_poison(struct net2_lockspace *ls) -> void
    called_by: shenv_kill
  fn net2_lockspace_get_stats(struct net2_lockspace *ls, struct net2_lockspace_stats *out) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn net2_lockspace_shard_probe(struct net2_lockspace *ls, uint32_t shard_id, struct net2_shard *snap_out) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: assert_single_leader, probe_monotone, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_leader_slot
  struct hrw_ent { score }
  struct snap_build { recs }

[dlm/net2_shard.h]
  fn net2_lockspace_create(struct mxfs_net2_ctx *net, const struct net2_lockspace_cfg *cfg, struct net2_lockspace **out) -> int
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_start(struct net2_lockspace *ls) -> int
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_stop(struct net2_lockspace *ls) -> void
    called_by: net2_lockspace_destroy
  fn net2_lockspace_destroy(struct net2_lockspace *ls) -> void
    called_by: net2_lockspace_create, scen_sh_reconfig, scen_sh_xfer_no_vote, shenv_kill, shenv_stop
  fn net2_lockspace_epoch_commit(struct net2_lockspace *ls, uint64_t epoch, uint64_t member_mask, const uint32_t *member_incs) -> void
    called_by: shenv_epoch_bump
  fn net2_lockspace_suspect(struct net2_lockspace *ls, uint16_t slot) -> void
    called_by: shenv_suspect
  fn net2_lockspace_set_bast_cb(struct net2_lockspace *ls, net2_bast_cb cb, void *data) -> void
    called_by: scen_sh_reconfig, scen_sh_xfer_no_vote
  fn net2_lockspace_set_hook(struct net2_lockspace *ls, net2_test_hook hook, void *data) -> void
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints
  fn net2_lockspace_poison(struct net2_lockspace *ls) -> void
    called_by: shenv_kill
  fn net2_lockspace_get_stats(struct net2_lockspace *ls, struct net2_lockspace_stats *out) -> void
  fn net2_lockspace_shard_probe(struct net2_lockspace *ls, uint32_t shard_id, struct net2_shard *snap_out) -> int
    called_by: assert_single_leader, probe_monotone, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_leader_slot
  fn net2_shard_id_for(const struct net2_lockspace *ls, const struct mxfs_resource_id *res) -> uint32_t
    called_by: assert_single_leader, creq_pick_target, creq_send, probe_monotone, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_leader_slot, shard_start_recovery
  fn net2_shard_get(struct net2_lockspace *ls, uint32_t shard_id, bool create) -> struct net2_shard
    called_by: creq_pick_target, scen_sh_recovery, scen_sh_two_loss, shard_leader_slot
  fn net2_shard_derive_config(struct net2_lockspace *ls, struct net2_shard *sh, uint64_t epoch) -> void
    called_by: net2_shard_get, shard_reconfigure
  fn net2_shard_append(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *ent_template) -> int
    called_by: grant_waiters, net2_lock_leader_validate, net2_shard_i_am_leader, net2_shard_prove_term, shard_become_leader, shard_reconfigure, shard_recovery_maybe_finish, shard_rx_append_ack, shard_xfer_finalize
  fn net2_shard_dispatch(struct net2_lockspace *ls, const struct mxfs_net2_id *src, const struct mxfs_n2msg *m, const uint8_t *payload, uint32_t len, uint32_t recs_off) -> void
    called_by: ls_recv_cb, net2_shard_send
  fn net2_shard_i_am_leader(const struct net2_lockspace *ls, const struct net2_shard *sh) -> bool
    called_by: net2_lock_emit_result, net2_lock_leader_validate, net2_lock_post_release_grants, shard_rx_append_ack
  fn net2_shard_prove_term(struct net2_lockspace *ls, struct net2_shard *sh) -> void
    called_by: net2_lock_leader_validate
  fn net2_shard_replica_index(const struct net2_shard *sh, uint16_t slot) -> int
    called_by: assert_single_leader, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote, shard_arm_election, shard_reconfigure, shard_rx_append_ack, shard_rx_vote
  fn net2_shard_send(struct net2_lockspace *ls, uint16_t dst_slot, struct mxfs_n2msg *m, const uint8_t *recs, uint32_t recs_len) -> void
    called_by: creq_send, deny, net2_lock_emit_result, net2_shard_get, net2_shard_i_am_leader, send_result, shard_reconfigure, shard_rx_append, shard_rx_append_ack, shard_rx_vote, shard_send_append, shard_send_snapshot, shard_solicit_votes, shard_start_recovery, shard_xfer_finalize
  fn net2_ls_stat_bump(struct net2_lockspace *ls, uint64_t *field) -> void
    called_by: deny, net2_lock_client_rx, net2_lock_client_tick, net2_lock_emit_result, net2_lock_leader_validate, net2_shard_i_am_leader, net2_shard_replica_index, rec_all_holders, shard_advance_commit, shard_install_held_report, shard_reconfigure, shard_rx_append, shard_rx_append_ack, shard_rx_vote, shard_send_append
  fn net2_ls_stat_max(struct net2_lockspace *ls, uint64_t *field, uint64_t v) -> void
    called_by: net2_lock_apply_entry, shard_advance_commit, shard_rx_append
  fn net2_ls_hook(struct net2_lockspace *ls, enum n2_hook_point p, uint32_t shard_id, uint16_t detail) -> bool
    called_by: net2_lock_emit_result, net2_lock_leader_validate, shard_advance_commit, shard_reconfigure, shard_send_snapshot
  fn net2_lock_apply_entry(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *e) -> void
    called_by: shard_advance_commit, shard_rx_append
  fn net2_lock_leader_validate(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_n2msg *m, const struct mxfs_net2_id *src) -> void
  fn net2_lock_emit_result(struct net2_lockspace *ls, struct net2_shard *sh, const struct n2_log_ent *e) -> void
    called_by: shard_advance_commit
  fn net2_lock_post_release_grants(struct net2_lockspace *ls, struct net2_shard *sh, const struct mxfs_resource_id *res) -> void
    called_by: shard_advance_commit
  fn net2_lock_client_rx(struct net2_lockspace *ls, const struct mxfs_net2_id *src, const struct mxfs_n2msg *m) -> void
    called_by: ls_recv_cb, net2_shard_send
  fn net2_lock_client_tick(struct net2_lockspace *ls, uint64_t now_ms) -> void
    called_by: ls_rt_fn
  fn net2_rec_get(struct net2_shard *sh, const struct mxfs_resource_id *res, bool create) -> struct n2_lock_rec
    called_by: net2_lock_apply_entry, net2_lock_emit_result, net2_lock_leader_validate, net2_lock_post_release_grants, shard_install_held_report, snap_install_rec
  fn net2_shard_free_recs(struct net2_shard *sh) -> void
    called_by: net2_lockspace_destroy
  enum n2_shard_state { SH_ACTIVE, SH_ELECTING, SH_XFER, SH_FROZEN, SH_RECOVERY }
  struct n2_waiter { slot, inc, request_id, mode, enq_seq, next }
  struct n2_lock_rec { resource, grant_gen, dir_epoch, last_ex_slot, handoff, ex_streak, pending_revoke_mask, next }
  struct n2_log_ent { used, committed, op, term, seq, resource, mode, req_slot, req_inc, request_id }
  struct n2_opcache_ent { used, request_id, status, mode, gen }
  struct n2_opcache_client { used, slot, inc, next_idx, ring }
  struct n2_replica { slot }
  struct net2_shard { shard_id, memb_epoch, term, state, leader_slot, replicas, nreplicas, commit_seq, last_seq, log }
  struct net2_lockspace_stats { shards_frozen }
  enum n2_creq_state { CR_IDLE, CR_PENDING, CR_WAITING, CR_DONE }
  struct n2_creq { used, request_id, resource, mode, state, status, target_slot, last_tx_ms, retries, is_release }
  struct n2_held { used, resource, mode, gen, next }
  typedef_fn net2_bast_cb
  enum n2_hook_point { N2H_PRE_APPEND, leader, entry, built, nothing, sent, N2H_POST_LOCAL_APPEND, leader, in, ring }
  typedef_fn net2_test_hook
  struct net2_lockspace_cfg { self_slot, self_inc, elect_base_ms, elect_rank_ms, client_retry_ms, rt_tick_ms, max_held, seed }
  struct net2_lockspace { net, self_slot, self_inc, epoch, member_mask, member_inc, shards, lock, creqs, held }

[dlm/net2_stats.h]
  struct mxfs_net2_class_stats { enqueued, first_tx, retx, queue_full, max_residency_ms }
  struct mxfs_net2_session_stats { msgs_created, first_tx, retx, acked, dup_seq_suppressed, dup_op_idempotent, out_of_window_drops, stale_incarnation_drops, stale_epoch_drops, stale_term_drops }
  struct mxfs_net2_stats { cls, retired, sessions_created, sessions_gcd, comm_ambiguous_events, malformed_frames, malformed, cross_cluster_rejects, freezes, freeze_active_ms_max }

[dlm/net2_wire.h]
  fn mxfs_le16_to_cpu(v) -> return
    called_by: mxfs_discovery_recv_fn, mxfs_lease_udp_recv_fn
  fn mxfs_le32_to_cpu(v) -> return
    called_by: mxfs_discovery_recv_fn, mxfs_lease_udp_recv_fn, mxfs_mount
  fn mxfs_le64_to_cpu(v) -> return
    called_by: mxfs_lease_udp_recv_fn
  enum mxfs_net2_frame_class { MXFS_NET2_FC_DATA, MXFS_NET2_FC_ACK, standalone, ACK, unreliable, MXFS_NET2_FC_SYN, session, establish, carries, TLV }
  struct mxfs_net2_hdr { membership_epoch, seq, ack, magic, cluster_uuid_hash, src_incarnation, dst_incarnation, sack_mask, msg_id, pad }
  enum mxfs_net2_hdr_err { MXFS_NET2_HDR_OK, MXFS_NET2_HDR_EMAGIC, MXFS_NET2_HDR_EVERSION, MXFS_NET2_HDR_ECLASS, MXFS_NET2_HDR_EPRIORITY, MXFS_NET2_HDR_ELEN, MXFS_NET2_HDR_EFLAGS, MXFS_NET2_HDR_EPAD }
  enum mxfs_net2_tlv_type { MXFS_NET2_TLV_UUID, 16, B, full, cluster, UUID, MXFS_NET2_TLV_VOLUME_ID, u32, MXFS_NET2_TLV_FS_GEN, u32 }

[dlm/peer.c]
  fn static peer_find_locked(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> struct mxfs_peer
    called_by: mxfs_peer_accept_fn, mxfs_peer_find, mxfs_peer_is_connected, mxfs_peer_recv_fn, mxfs_peer_send
  fn static peer_handle_disconnect(struct mxfs_peer_ctx *ctx, struct mxfs_peer *peer) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_shutdown
    called_by: mxfs_peer_accept_fn, mxfs_peer_recv_fn
  fn static mxfs_peer_recv_fn(void *arg) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_recv, mxfs_pal_time_ms, peer_find_locked, peer_handle_disconnect
  fn static start_recv_thread(struct mxfs_peer_ctx *ctx, struct mxfs_peer *peer) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free
    called_by: mxfs_peer_accept_fn
  fn static mxfs_peer_accept_fn(void *arg) -> void
    calls: mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_tcp_accept, mxfs_pal_tcp_close, mxfs_pal_tcp_getpeername, mxfs_pal_tcp_recv, mxfs_pal_tcp_send, mxfs_pal_tcp_set_opts, mxfs_pal_tcp_shutdown, mxfs_pal_thread_join, mxfs_pal_time_ms, peer_find_locked
  fn mxfs_peer_init(mxfs_node_id_t node_id, const uint8_t *uuid, uint16_t port, mxfs_volume_id_t volume_id) -> struct mxfs_peer_ctx
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_mutex_destroy, mxfs_pal_tcp_listen
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_start(struct mxfs_peer_ctx *ctx) -> int
    calls: mxfs_pal_log
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_shutdown(struct mxfs_peer_ctx *ctx) -> void
    calls: first, mxfs_pal_free, mxfs_pal_log, mxfs_pal_mutex_destroy, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_tcp_close, mxfs_pal_tcp_recv, mxfs_pal_tcp_shutdown, mxfs_pal_thread_join
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_peer_add(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id, const uint8_t *uuid, const char *host, uint16_t port) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_create, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn static peer_connect_impl(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id, bool skip_id_check) -> int
    called_by: mxfs_peer_connect, mxfs_peer_connect_force
  fn mxfs_peer_connect(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: peer_connect_impl
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn mxfs_peer_connect_force(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> int
    calls: peer_connect_impl
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn mxfs_peer_send(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id, const void *msg, size_t len) -> int
    calls: mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_tcp_send, mxfs_pal_tcp_shutdown, peer_find_locked
    called_by: dlm_bast_cb, dlm_send_cb, mxfs_peer_broadcast, v5_bast_cb_tcp, v5_dlm_send_cb_tcp
  fn mxfs_peer_broadcast(struct mxfs_peer_ctx *ctx, const void *msg, size_t len) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_peer_send
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_peer_find(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> struct mxfs_peer
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, peer_find_locked
  fn mxfs_peer_is_connected(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> bool
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, peer_find_locked
    called_by: discovery_peer_cb, v5_discovery_peer_cb, v5_tcp_death_worker_fn
  fn mxfs_peer_set_msg_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_msg_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_set_disconnect_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_disconnect_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_set_connect_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_connect_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  struct mxfs_recv_data { ctx, node_id }

[dlm/peer.h]
  fn mxfs_peer_init(mxfs_node_id_t node_id, const uint8_t *uuid, uint16_t port, mxfs_volume_id_t volume_id) -> struct mxfs_peer_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_start(struct mxfs_peer_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_shutdown(struct mxfs_peer_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_peer_add(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id, const uint8_t *uuid, const char *host, uint16_t port) -> int
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn mxfs_peer_connect(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn mxfs_peer_connect_force(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> int
    called_by: discovery_peer_cb, v5_discovery_peer_cb
  fn mxfs_peer_send(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id, const void *msg, size_t len) -> int
    called_by: dlm_bast_cb, dlm_send_cb, mxfs_peer_broadcast, v5_bast_cb_tcp, v5_dlm_send_cb_tcp
  fn mxfs_peer_broadcast(struct mxfs_peer_ctx *ctx, const void *msg, size_t len) -> int
    called_by: mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_peer_find(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> struct mxfs_peer
  fn mxfs_peer_is_connected(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id) -> bool
    called_by: discovery_peer_cb, v5_discovery_peer_cb, v5_tcp_death_worker_fn
  fn mxfs_peer_set_msg_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_msg_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_set_disconnect_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_disconnect_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_peer_set_connect_cb(struct mxfs_peer_ctx *ctx, mxfs_peer_connect_cb cb, void *data) -> void
    called_by: mxfs_mount, mxfs_v5_dlm_init
  enum mxfs_conn_state { MXFS_CONN_DISCONNECTED, MXFS_CONN_CONNECTING, MXFS_CONN_ACTIVE }
  struct mxfs_peer { node_id, node_uuid, host, port, sock, state, send_lock, recv_thread, last_seen }
  typedef_fn mxfs_peer_msg_cb
  typedef_fn mxfs_peer_disconnect_cb
  typedef_fn mxfs_peer_connect_cb
  struct mxfs_peer_ctx { peers, peer_count, listen_sock, accept_thread, local_node_id, local_node_uuid, local_port, local_volume_id, running, peer_lock }

[dlm/scsipr.c]
  fn mxfs_scsipr_create(mxfs_bdev_t *dev, const char *dev_name, mxfs_node_id_t node_id) -> struct mxfs_scsipr_ctx
    calls: mxfs_pal_alloc, mxfs_pal_log
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx) -> void
    calls: mxfs_pal_free, mxfs_pal_log, mxfs_scsipr_unregister
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx) -> uint64_t
    called_by: mxfs_v5_dlm_detach_pr_key
  fn mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx) -> void
    calls: mxfs_pal_free, mxfs_pal_log
    called_by: mxfs_v5_dlm_detach_pr_key
  fn mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_register
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_reserve, mxfs_scsipr_read_reservation
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_observe_reservation(struct mxfs_scsipr_ctx *ctx, struct mxfs_pal_pr_reservation *out) -> int
    calls: mxfs_pal_log, mxfs_scsipr_read_reservation
    called_by: mxfs_mount, mxfs_scsipr_validate_admission, mxfs_v5_dlm_init
  fn mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx, struct mxfs_pal_pr_reservation *out) -> int
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_exclusion_holds, mxfs_scsipr_observe_reservation, mxfs_scsipr_reserve, mxfs_scsipr_validate_admission
  fn mxfs_scsipr_check_reservation_health(struct mxfs_scsipr_ctx *ctx, bool repair, uint32_t *out_gen, int *out_count) -> int
    calls: mxfs_pal_scsi_pr_reserve, mxfs_scsipr_probe_keys, mxfs_scsipr_read_reservation
    called_by: v5_resv_health_tick
  fn mxfs_resv_health_name(int h) -> const char
    called_by: v5_resv_health_tick
  fn mxfs_fence_kind_name(enum mxfs_fence_kind k) -> const char
    called_by: v5_exclusion_recheck, v5_fence_kind_contradicts_single_node
  fn mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key, bool abort) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_preempt
    called_by: disklock_expire_cb, lease_expire_cb, peer_disconnect_cb
  fn static mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key, bool *victim_present, bool *own_present, int *count, uint32_t *generation) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_log, mxfs_scsipr_read_keys
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_exclusion_holds, mxfs_scsipr_fenced_check, mxfs_scsipr_probe, mxfs_scsipr_self_check, mxfs_scsipr_validate_admission
  fn mxfs_scsipr_validate_admission(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_report_capabilities, mxfs_scsipr_observe_reservation, mxfs_scsipr_probe_keys, mxfs_scsipr_read_reservation
    called_by: mxfs_v5_dlm_init
  fn mxfs_scsipr_exclusion_holds(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key, struct mxfs_fence_result *out) -> int
    calls: mxfs_pal_log, mxfs_scsipr_probe_keys, mxfs_scsipr_read_reservation
    called_by: v5_exclusion_recheck
  fn mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members) -> int
    calls: mxfs_pal_log, mxfs_scsipr_probe_keys
    called_by: v5_tcp_death_worker_fn
  fn mxfs_scsipr_fenced_check(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_read_full_status, mxfs_scsipr_probe_keys
    called_by: v5_resv_inspect_worker
  fn mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_scsipr_probe_keys
    called_by: mxfs_v5_dlm_init
  fn mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_unregister
    called_by: mxfs_mount, mxfs_scsipr_destroy, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    calls: mxfs_pal_log, mxfs_pal_scsi_pr_read_keys
    called_by: mxfs_scsipr_probe_keys

[dlm/scsipr.h]
  fn mxfs_fence_kind_name(enum mxfs_fence_kind k) -> const char
    called_by: v5_exclusion_recheck, v5_fence_kind_contradicts_single_node
  fn mxfs_scsipr_create(mxfs_bdev_t *dev, const char *dev_name, mxfs_node_id_t node_id) -> struct mxfs_scsipr_ctx
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx) -> uint64_t
    called_by: mxfs_v5_dlm_detach_pr_key
  fn mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx) -> void
    called_by: mxfs_v5_dlm_detach_pr_key
  fn mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_v5_dlm_init
  fn mxfs_scsipr_observe_reservation(struct mxfs_scsipr_ctx *ctx, struct mxfs_pal_pr_reservation *out) -> int
    called_by: mxfs_mount, mxfs_scsipr_validate_admission, mxfs_v5_dlm_init
  fn mxfs_scsipr_check_reservation_health(struct mxfs_scsipr_ctx *ctx, bool repair, uint32_t *out_gen, int *out_count) -> int
    called_by: v5_resv_health_tick
  fn mxfs_resv_health_name(int h) -> const char
    called_by: v5_resv_health_tick
  fn mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key, bool abort) -> int
    called_by: disklock_expire_cb, lease_expire_cb, peer_disconnect_cb
  fn mxfs_scsipr_exclusion_holds(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key, struct mxfs_fence_result *out) -> int
    called_by: v5_exclusion_recheck
  fn mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: mxfs_mount, mxfs_scsipr_destroy, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    called_by: mxfs_scsipr_probe_keys
  fn mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx, struct mxfs_pal_pr_reservation *out) -> int
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_exclusion_holds, mxfs_scsipr_observe_reservation, mxfs_scsipr_reserve, mxfs_scsipr_validate_admission
  fn mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members) -> int
    called_by: v5_tcp_death_worker_fn
  fn mxfs_scsipr_fenced_check(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: v5_resv_inspect_worker
  fn mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_scsipr_validate_admission(struct mxfs_scsipr_ctx *ctx) -> int
    called_by: mxfs_v5_dlm_init
  struct mxfs_scsipr_ctx { dev, dev_name, local_key, reserved, resv_type_seen, registered, advisory_logged }
  enum mxfs_fence_kind { nothing, was, proved, replay, is, NOT, authorised, MXFS_FENCE_KIND_NONE, not, attempted }
  enum mxfs_fence_phase { No, state, changing, command, was, submitted, Safe, to, retry, a }
  struct mxfs_fence_result { kind, victim_key, pr_generation, resv_type, rc, phase }
  enum mxfs_resv_health { MXFS_RESV_HEALTH_OK, the, expected, reservation, is, in, force, MXFS_RESV_HEALTH_ABSENT, NO, reservation }

[dlm/v5_mount.c]
  fn static uuid_to_node_id(const uint8_t *uuid) -> mxfs_node_id_t
    called_by: mxfs_v5_dlm_init
  fn static v5_dlm_send_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx, mxfs_node_id_t target, const void *msg, size_t len) -> int
    calls: mxfs_peer_send
  fn static v5_peer_msg_cb_tcp(void *data, mxfs_node_id_t sender, void *msg, size_t len) -> void
    calls: mxfs_dlm_process_remote_grant, mxfs_dlm_process_remote_release, mxfs_dlm_process_remote_request, mxfs_dlm_purge_node, mxfs_lease_unregister_node, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, v5_note_dead_node, v5_refresh_active_nodes
  fn static v5_node_is_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id) -> bool
    called_by: mxfs_v5_dlm_recovery_acquire, v5_discovery_peer_cb, v5_note_dead_node, v5_peer_connect_cb_tcp
  fn static v5_note_dead_node(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id) -> void
    calls: mxfs_pal_log, v5_node_is_dead
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete, v5_handle_node_death, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_settle_resolve, v5_tcp_declare_dead
  fn static v5_refresh_active_nodes(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_dlm_update_active_nodes, mxfs_lease_get_active_nodes
    called_by: mxfs_v5_dlm_recovery_complete, v5_clean_depart_cb, v5_discovery_peer_cb, v5_handle_node_death, v5_peer_connect_cb_tcp, v5_peer_msg_cb_tcp, v5_recovered_cb, v5_tcp_declare_dead
  fn static v5_membership_beacon_caw(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_dlm_caw_set_membership, mxfs_lease_get_active_nodes, mxfs_pal_log, read
    called_by: mxfs_v5_dlm_init, mxfs_v5_dlm_recovery_complete, v5_clean_depart_cb, v5_discovery_peer_cb, v5_handle_node_death, v5_recovered_cb
  fn static v5_bast_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t requested_mode) -> void
    calls: mxfs_pal_sleep_ms, mxfs_peer_send
  fn static v5_membership_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx) -> void
  fn static v5_pr_fence_dead_node_rc(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node) -> int
    called_by: v5_pr_fence_dead_node
  fn static v5_pr_fence_dead_node(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node) -> bool
    calls: v5_pr_fence_dead_node_rc
    called_by: v5_handle_node_death, v5_tcp_declare_dead, v5_vergate_cb
  fn mxfs_recov_blocked_reason(uint32_t reason) -> const char
  fn static v5_fence_arm_submit_cb(void *data) -> int
    calls: mxfs_disklock_recovery_fence_arm_submit
  fn static v5_pr_worker_start(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_pal_log
    called_by: mxfs_v5_dlm_init, v5_fence_retry_arm
  fn static v5_fence_retry_disarm(struct mxfs_v5_dlm *ctx, int slot) -> void
    called_by: v5_fence_retry_one
  fn static v5_fence_retry_arm(struct mxfs_v5_dlm *ctx, int slot, mxfs_node_id_t victim, mxfs_epoch_t epoch) -> void
    calls: mxfs_pal_log, mxfs_pal_time_ms, v5_pr_worker_start
    called_by: v5_fence_retry_one, v5_fence_retry_worker_fn
  fn static v5_fence_retry_one(struct mxfs_v5_dlm *ctx, int slot) -> void
    calls: mxfs_disklock_recovery_fence_retryable, mxfs_pal_log, v5_dispatch_slice_recovery, v5_fence_retry_arm, v5_fence_retry_disarm, v5_pr_fence_prove
    called_by: v5_fence_retry_worker_fn
  fn static v5_resv_health_tick(struct mxfs_v5_dlm *ctx, uint64_t now) -> bool
    calls: mxfs_disklock_lowest_live_slot, mxfs_pal_log, mxfs_resv_health_name, mxfs_scsipr_check_reservation_health
    called_by: v5_fence_retry_worker_fn
  fn static v5_fence_retry_worker_fn(void *arg) -> void
    calls: mxfs_disklock_recovery_fence_retryable, mxfs_pal_log, mxfs_pal_sleep_ms_interruptible, mxfs_pal_time_ms, v5_fence_retry_arm, v5_fence_retry_one, v5_resv_health_tick
  fn static v5_blocked_set(struct mxfs_v5_dlm *ctx, int slot, uint32_t reason, mxfs_node_id_t victim, mxfs_epoch_t victim_epoch, int rc, const struct mxfs_fence_result *fres) -> void
    calls: mxfs_pal_time_ms
    called_by: mxfs_v5_dlm_recovery_acquire, v5_exclusion_recheck, v5_single_node_fence_gate
  fn static v5_blocked_clear(struct mxfs_v5_dlm *ctx, int slot) -> void
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_blocked_iter(struct mxfs_v5_dlm *ctx, int prev, struct mxfs_recov_blocked *out) -> int
  fn static v5_single_node_fence_gate(struct mxfs_v5_dlm *ctx) -> bool
    calls: mxfs_pal_log, v5_blocked_set
  fn static v5_fence_kind_contradicts_single_node(enum mxfs_fence_kind k) -> bool
    calls: mxfs_fence_kind_name, mxfs_pal_log
  fn static v5_pr_fence_prove_locked(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node, int dead_slot, mxfs_epoch_t dead_epoch) -> int
    calls: mxfs_pal_log
  fn static v5_pr_fence_prove(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node, int dead_slot, mxfs_epoch_t dead_epoch) -> int
    called_by: mxfs_v5_dlm_recovery_acquire, v5_fence_retry_one, v5_handle_node_death, v5_settle_resolve
  fn static v5_tcp_declare_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id) -> void
    calls: mxfs_dlm_purge_node, mxfs_lease_unregister_node, v5_note_dead_node, v5_pr_fence_dead_node, v5_refresh_active_nodes
    called_by: v5_peer_disconnect_cb_tcp, v5_tcp_death_worker_fn
  fn static v5_vergate_cb(void *data, int slot, mxfs_node_id_t node_id, mxfs_epoch_t epoch, int state) -> void
    calls: mxfs_pal_log, v5_pr_fence_dead_node
  fn static v5_peer_connect_cb_tcp(void *data, mxfs_node_id_t node_id) -> void
    calls: mxfs_dlm_is_single_node, mxfs_lease_has_node, mxfs_lease_register_node, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, v5_node_is_dead, v5_refresh_active_nodes
  fn static v5_peer_disconnect_cb_tcp(void *data, mxfs_node_id_t node_id) -> void
    calls: mxfs_lease_has_node, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_time_ms, v5_tcp_declare_dead
  fn static v5_tcp_death_worker_fn(void *arg) -> void
    calls: mxfs_lease_get_active_nodes, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, mxfs_peer_is_connected, mxfs_scsipr_self_check, v5_tcp_declare_dead
  fn static v5_caw_holders_alive(void *data, uint64_t slot_mask) -> bool
    calls: mxfs_disklock_slot_live
  fn static v5_bast_cb(struct mxfs_dlm_ctx *dlm_ctx, const struct mxfs_resource_id *resource, mxfs_node_id_t owner, uint8_t requested_mode) -> void
    calls: mxfs_pal_log
  fn static v5_discovery_peer_cb(void *data, const struct mxfs_discovery_announce *ann) -> void
    calls: mxfs_dlm_caw_set_single_node, mxfs_dlm_is_single_node, mxfs_lease_has_node, mxfs_lease_register_node, mxfs_pal_log, mxfs_peer_add, mxfs_peer_connect, mxfs_peer_connect_force, mxfs_peer_is_connected, v5_membership_beacon_caw, v5_node_is_dead, v5_refresh_active_nodes
  fn static v5_self_fence_cb(void *data, int reason) -> void
    calls: mxfs_pal_log
  fn static v5_resv_conflict_withdraw(struct mxfs_v5_dlm *ctx, const char *why) -> void
    calls: mxfs_pal_log
    called_by: v5_resv_inspect_worker
  fn static v5_resv_inspect_worker(void *arg) -> void
    calls: mxfs_pal_log, mxfs_pal_sleep_ms, mxfs_scsipr_fenced_check, v5_resv_conflict_withdraw
  fn mxfs_v5_dlm_note_resv_conflict(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_pal_log
    called_by: mxfs_v5_dlm_ag_unlock, mxfs_v5_dlm_inode_unlock_open, v5_resv_conflict_cb
  fn static v5_resv_conflict_cb(void *data) -> void
    calls: mxfs_v5_dlm_note_resv_conflict
  fn static v5_view_sig_provider(void *data, uint32_t *count) -> uint64_t
    calls: mxfs_dlm_get_view_sig
  fn static v5_view_report_cb(void *data, mxfs_node_id_t node, uint32_t count, uint64_t hash) -> void
    calls: mxfs_dlm_report_peer_view
  fn static v5_dispatch_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot, mxfs_node_id_t dead_node) -> void
    calls: mxfs_disklock_lowest_live_slot, mxfs_disklock_recovery_pending_iter, mxfs_pal_log
    called_by: v5_dispatch_late_deaths, v5_fence_retry_one, v5_start_slice_recovery
  fn static v5_start_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot, mxfs_node_id_t dead_node, mxfs_epoch_t victim_epoch) -> void
    calls: mxfs_disklock_mark_recovery_pending, mxfs_disklock_recovery_is_pending, v5_dispatch_slice_recovery
    called_by: v5_handle_node_death, v5_settle_resolve
  fn static v5_defer_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot, mxfs_node_id_t dead_node, mxfs_epoch_t victim_epoch) -> void
    calls: mxfs_disklock_mark_recovery_pending, mxfs_disklock_recovery_is_pending, mxfs_pal_log, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: v5_handle_node_death
  fn static v5_handle_node_death(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node, int dead_slot, mxfs_epoch_t dead_epoch) -> void
    calls: mxfs_disklock_find_node_slot, mxfs_disklock_purge_node, mxfs_dlm_purge_node, mxfs_pal_log, mxfs_v5_dlm_recovery_complete, v5_defer_slice_recovery, v5_membership_beacon_caw, v5_note_dead_node, v5_pr_fence_dead_node, v5_pr_fence_prove, v5_refresh_active_nodes, v5_start_slice_recovery
    called_by: v5_disklock_expire_cb, v5_lease_expire_cb
  fn static v5_lease_expire_cb(void *data, mxfs_node_id_t dead_node) -> void
    calls: v5_handle_node_death
    called_by: mxfs_v5_dlm_init
  fn static v5_disklock_expire_cb(void *data, mxfs_node_id_t dead_node, int dead_slot, mxfs_epoch_t dead_epoch) -> void
    calls: v5_handle_node_death
  fn static v5_recovered_cb(void *data, int slot, mxfs_node_id_t dead_node) -> void
    calls: mxfs_dlm_purge_node, mxfs_lease_unregister_node, v5_membership_beacon_caw, v5_note_dead_node, v5_refresh_active_nodes
  fn static v5_clean_depart_cb(void *data, int slot, mxfs_node_id_t node, mxfs_epoch_t epoch) -> void
    calls: mxfs_dlm_purge_node, mxfs_lease_unregister_node, v5_membership_beacon_caw, v5_refresh_active_nodes
  fn static v5_closure_note_terminal(struct mxfs_v5_dlm *ctx, int slot, const struct mxfs_recov_outcome *oc) -> void
    calls: mxfs_dlm_caw_set_closure_cand_mask, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_v5_dlm_recovery_scan_outcomes, v5_recov_outcome_cb
  fn static v5_recov_outcome_cb(void *data, int slot, const struct mxfs_recov_outcome *oc) -> int
    calls: v5_closure_note_terminal
  fn static v5_settle_resolve(struct mxfs_v5_dlm *ctx, bool dispatch) -> uint64_t
    calls: mxfs_disklock_confirm_dead_mask, mxfs_disklock_mark_recovery_pending, mxfs_disklock_recovery_is_pending, mxfs_pal_log, mxfs_pal_sleep_ms, v5_note_dead_node, v5_pr_fence_prove, v5_start_slice_recovery
    called_by: mxfs_v5_dlm_mount_recovery_cohort, v5_settle_worker_fn
  fn static v5_settle_worker_fn(void *arg) -> void
    calls: v5_settle_resolve
  fn mxfs_v5_dlm_settle_own_slot(struct mxfs_v5_dlm *ctx) -> int
    calls: mxfs_dlm_caw_purge_dead_nodes_ex, mxfs_dlm_caw_set_adopt_window, mxfs_pal_log
  fn mxfs_v5_dlm_mount_recovery_cohort(struct mxfs_v5_dlm *ctx, uint64_t *out_slots) -> int
    calls: v5_settle_resolve
  fn mxfs_v5_dlm_mount_residue_blocking(struct mxfs_v5_dlm *ctx, uint64_t *out_residue, int *out_nslots, int *out_nex) -> int
    calls: mxfs_dlm_caw_footprint_scan
  fn static v5_take_late_deaths(struct mxfs_v5_dlm *ctx, mxfs_node_id_t *nodes) -> uint64_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: mxfs_v5_dlm_mount_take_late_deaths, v5_dispatch_late_deaths
  fn mxfs_v5_dlm_mount_take_late_deaths(struct mxfs_v5_dlm *ctx) -> uint64_t
    calls: v5_take_late_deaths
  fn mxfs_v5_dlm_mount_defer_late_deaths(struct mxfs_v5_dlm *ctx, uint64_t slots) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn mxfs_v5_dlm_mount_pending_recovery(struct mxfs_v5_dlm *ctx, uint64_t *out_mask) -> int
    calls: mxfs_disklock_get_recovery_pending_slots, mxfs_disklock_mark_recovery_pending, mxfs_disklock_pending_node, mxfs_disklock_recovery_is_pending
  fn static v5_dispatch_late_deaths(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_disklock_pending_node, mxfs_disklock_recovery_is_pending, mxfs_pal_log, v5_dispatch_slice_recovery, v5_take_late_deaths
    called_by: mxfs_v5_dlm_mount_settle
  fn mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx) -> int
    calls: mxfs_pal_log, v5_dispatch_late_deaths
    called_by: mxfs_v5_dlm_init
  fn static v5_exclusion_recheck(struct mxfs_v5_dlm *ctx, mxfs_node_id_t victim, uint32_t dead_slot, const char *site) -> int
    calls: mxfs_disklock_lowest_live_slot, mxfs_disklock_pending_epoch, mxfs_disklock_recovery_replay_authorized, mxfs_fence_kind_name, mxfs_pal_log, mxfs_scsipr_exclusion_holds, mxfs_v5_dlm_is_single_node, v5_blocked_set
    called_by: mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_recovery_acquire(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> int
    calls: mxfs_disklock_pending_epoch, mxfs_disklock_pending_node, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_read, mxfs_disklock_recovery_replay_authorized, mxfs_disklock_recovery_takeover, mxfs_pal_log, v5_blocked_set, v5_exclusion_recheck, v5_node_is_dead, v5_note_dead_node, v5_pr_fence_prove
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_recovery_release(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> void
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> int
    calls: mxfs_disklock_clear_recovery_pending, mxfs_disklock_pending_epoch, mxfs_disklock_pending_node, mxfs_disklock_purge_node, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_is_pending, mxfs_disklock_recovery_replay_authorized, mxfs_disklock_recovery_slot_status, mxfs_dlm_caw_purge_node, mxfs_dlm_purge_node, mxfs_lease_unregister_node, mxfs_pal_bdev_flush, mxfs_pal_log, mxfs_v5_dlm_recovery_acquire, mxfs_v5_dlm_recovery_release
    called_by: mxfs_v5_dlm_mount_cohort_complete, v5_handle_node_death
  fn mxfs_v5_dlm_mount_cohort_complete(struct mxfs_v5_dlm *ctx, uint64_t slots, uint64_t *out_published) -> int
    calls: mxfs_pal_log, mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_local_slot(struct mxfs_v5_dlm *ctx) -> int
    calls: mxfs_disklock_get_slot
  fn mxfs_v5_dlm_slot_unclaimed(struct mxfs_v5_dlm *ctx, int slot) -> int
    calls: mxfs_disklock_slot_unclaimed
  fn mxfs_v5_dlm_guard_slot(struct mxfs_v5_dlm *ctx, int slot) -> int
    calls: mxfs_disklock_guard_slot
  fn mxfs_v5_dlm_guard_refresh(struct mxfs_v5_dlm *ctx) -> int
    calls: mxfs_disklock_guard_refresh
  fn mxfs_v5_dlm_unguard_slot(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_disklock_unguard
  fn mxfs_v5_dlm_init(const struct mxfs_v5_dlm_opts *opts) -> struct mxfs_v5_dlm
    calls: claim, mxfs_discovery_create, mxfs_discovery_set_peer_cb, mxfs_discovery_set_transport, mxfs_discovery_start, mxfs_disklock_claim_slot, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_disklock_get_slot_node_id, mxfs_disklock_get_stale_slot_mask, mxfs_disklock_get_withdrawn_slots, mxfs_disklock_join_gate, mxfs_disklock_release_slot, mxfs_disklock_set_clean_depart_cb, mxfs_disklock_set_conflict_cb
  fn mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_discovery_stop, mxfs_disklock_withdraw, mxfs_pal_log, scan
  fn mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_v5_dlm_shutdown_defer_release
  fn mxfs_v5_dlm_shutdown_defer_release(struct mxfs_v5_dlm *ctx, struct mxfs_v5_dlm_slot_release *late) -> void
    calls: mxfs_discovery_destroy, mxfs_discovery_stop, mxfs_disklock_destroy, mxfs_disklock_release_slot, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_departed_clean, mxfs_dlm_caw_destroy, mxfs_dlm_caw_set_closure_cand_mask, mxfs_dlm_caw_set_release_on_stop, mxfs_dlm_caw_stop, mxfs_dlm_destroy, mxfs_dlm_get_epoch, mxfs_dlm_release_all, mxfs_journal_destroy, mxfs_journal_release_slot
    called_by: mxfs_v5_dlm_shutdown
  fn mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx) -> uint64_t
    calls: mxfs_scsipr_abandon, mxfs_scsipr_key
  fn mxfs_v5_dlm_slot_release_commit(struct mxfs_v5_dlm_slot_release *late, bool unmount_clean) -> void
    calls: mxfs_disklock_destroy, mxfs_disklock_release_slot, mxfs_pal_bdev_close_clone, mxfs_pal_log
  fn static make_inode_resource(struct mxfs_resource_id *res, mxfs_volume_id_t volume_id, uint64_t ino) -> void
    called_by: mxfs_v5_dlm_caw_pw_selftest, mxfs_v5_dlm_inode_dir_block0, mxfs_v5_dlm_inode_dir_epoch, mxfs_v5_dlm_inode_dump_slot, mxfs_v5_dlm_inode_ex_count, mxfs_v5_dlm_inode_force_release_self, mxfs_v5_dlm_inode_grant_gen, mxfs_v5_dlm_inode_grant_handoff, mxfs_v5_dlm_inode_granted_mode, mxfs_v5_dlm_inode_held_nb, mxfs_v5_dlm_inode_lock, mxfs_v5_dlm_inode_lock_retries, mxfs_v5_dlm_inode_lock_try, mxfs_v5_dlm_inode_master_self, mxfs_v5_dlm_inode_open_clear
  fn static make_iclus_resource(struct mxfs_resource_id *res, mxfs_volume_id_t volume_id, uint64_t base_ino) -> void
    called_by: mxfs_v5_dlm_iclus_held_rawmode, mxfs_v5_dlm_iclus_lock, mxfs_v5_dlm_iclus_pin, mxfs_v5_dlm_iclus_unlock_gen
  fn static make_ag_resource(struct mxfs_resource_id *res, mxfs_volume_id_t volume_id, uint32_t agno) -> void
    called_by: mxfs_v5_dlm_ag_ex_count, mxfs_v5_dlm_ag_held, mxfs_v5_dlm_ag_lock, mxfs_v5_dlm_ag_lock_nb, mxfs_v5_dlm_ag_orphan_nak, mxfs_v5_dlm_ag_read_generation, mxfs_v5_dlm_ag_unlock
  fn mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
    calls: make_inode_resource, mxfs_dlm_caw_lock, mxfs_dlm_lock, mxfs_pal_log, mxfs_pal_sleep_ms
    called_by: mxfs_v5_dlm_iclus_lock
  fn mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, int retries, struct mxfs_grant_result *gres) -> int
    calls: make_inode_resource, mxfs_dlm_caw_lock, mxfs_dlm_caw_lock_deadline, mxfs_dlm_lock_retries, mxfs_pal_time_ms
  fn mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    calls: mxfs_v5_dlm_inode_unlock_gen
  fn mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    calls: make_inode_resource, mxfs_dlm_caw_unlock_gen, mxfs_dlm_unlock_gen
  fn mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_send_unconditional_release
  fn mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t expected_gen) -> int
    calls: mxfs_v5_dlm_inode_unlock_open
    called_by: mxfs_v5_dlm_inode_unlock
  fn mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t expected_gen, int open_op) -> int
    calls: make_inode_resource, mxfs_dlm_caw_unlock_gen, mxfs_dlm_unlock_gen, mxfs_pal_log, mxfs_v5_dlm_note_resv_conflict
    called_by: mxfs_v5_dlm_inode_unlock_gen
  fn mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_caw_convert, mxfs_dlm_caw_lock, mxfs_dlm_caw_unlock, mxfs_pal_log
  fn mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
    calls: make_iclus_resource, mxfs_dlm_caw_lock, mxfs_dlm_lock, mxfs_pal_log, mxfs_pal_sleep_ms, mxfs_v5_dlm_inode_lock
  fn mxfs_v5_dlm_iclus_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t base_ino, uint32_t expected_gen, bool is_free) -> int
    calls: make_iclus_resource, mxfs_dlm_caw_unlock_gen, mxfs_dlm_unlock_gen
  fn mxfs_v5_dlm_iclus_pin(struct mxfs_v5_dlm *ctx, uint64_t base_ino) -> int
    calls: make_iclus_resource, mxfs_dlm_caw_pin_resource
  fn mxfs_v5_dlm_inode_pin(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_caw_pin_resource
  fn mxfs_v5_dlm_iclus_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t base_ino) -> int
    calls: make_iclus_resource, mxfs_dlm_caw_granted_mode
  fn mxfs_v5_dlm_set_iclus_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino, int *nslots_out) -> int
    calls: make_inode_resource, mxfs_dlm_caw_ex_count
  fn mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino, int *nslots_out, uint64_t *hex_or_out) -> int
    calls: make_inode_resource, mxfs_dlm_caw_self_held_scan
  fn mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino, const struct mxfs_forcerel_attest *att) -> int
    calls: make_inode_resource, mxfs_dlm_caw_force_release_self
  fn mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint32_t
    calls: make_inode_resource, mxfs_dlm_caw_grant_seq32, mxfs_dlm_grant_gen
  fn mxfs_v5_dlm_inode_orphan_clock_get(struct mxfs_v5_dlm *ctx, uint64_t ino, bool starve) -> uint64_t
    calls: make_inode_resource, mxfs_dlm_caw_orphan_clock_get
  fn mxfs_v5_dlm_inode_orphan_clock_set(struct mxfs_v5_dlm *ctx, uint64_t ino, bool starve, uint64_t val) -> void
    calls: make_inode_resource, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_v5_dlm_inode_granted_mode(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint8_t
    calls: make_inode_resource, mxfs_dlm_caw_granted_mode, mxfs_dlm_granted_mode
  fn mxfs_v5_dlm_inode_open_holders(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t *oh_out) -> int
    calls: make_inode_resource, mxfs_dlm_caw_open_holders
  fn mxfs_v5_dlm_inode_open_clear(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    calls: make_inode_resource, mxfs_dlm_caw_open_clear
    called_by: mxfs_dlm_open_last_close
  fn mxfs_v5_dlm_inode_open_set(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_caw_open_set
  fn mxfs_v5_dlm_inode_open_probe(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t *oh_out, bool *authoritative) -> int
    calls: make_inode_resource, mxfs_dlm_caw_open_probe
  fn mxfs_v5_dlm_node_bit(struct mxfs_v5_dlm *ctx) -> uint64_t
    calls: mxfs_v5_dlm_get_node_slot
  fn mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t *gen_out) -> bool
    calls: make_inode_resource, mxfs_dlm_caw_grant_handoff, mxfs_dlm_grant_was_handoff
  fn mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint32_t
    calls: make_inode_resource, mxfs_dlm_caw_grant_dir_epoch, mxfs_dlm_grant_dir_epoch
  fn mxfs_v5_dlm_inode_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t gen, uint64_t *fsb_out) -> bool
    calls: make_inode_resource, mxfs_dlm_caw_grant_dir_block0
  fn mxfs_v5_dlm_inode_set_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t fsb, uint32_t gen) -> void
    calls: make_inode_resource, mxfs_dlm_caw_set_dir_block0
  fn mxfs_v5_dlm_transport_caw(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t gen) -> void
    calls: mxfs_disklock_note_freed
  fn mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    calls: mxfs_disklock_note_freed
  fn mxfs_v5_dlm_recovery_publish_refusal(struct mxfs_v5_dlm *ctx, int dead_slot, const struct mxfs_recov_refusal_info *info, struct mxfs_recov_outcome *oc_out) -> int
    calls: mxfs_disklock_recovery_publish_refusal, mxfs_pal_log
  fn mxfs_v5_dlm_recovery_read_outcome(struct mxfs_v5_dlm *ctx, int dead_slot, struct mxfs_recov_outcome *oc_out) -> int
    calls: mxfs_disklock_recovery_read_outcome
  fn static v5_closure_classify(void *arg, const struct mxfs_resource_id *res) -> int
  fn static v5_closure_gate(void *arg) -> int
    calls: mxfs_disklock_closure_gate_revalidate
  fn static v5_closure_scrub(void *data, uint8_t blocking_slot, const struct mxfs_resource_id *res) -> int
    calls: mxfs_disklock_terminal_gate_check
  fn static v5_wait_refuse(void *data, const struct mxfs_resource_id *res) -> int
  fn mxfs_v5_dlm_recovery_backfill_legacy(struct mxfs_v5_dlm *ctx, int dead_slot, struct mxfs_recov_outcome *oc_out) -> int
    calls: mxfs_disklock_recovery_backfill_legacy
  fn mxfs_v5_dlm_recovery_scan_outcomes(struct mxfs_v5_dlm *ctx) -> void
    calls: mxfs_disklock_recovery_read_outcome, mxfs_pal_log, v5_closure_note_terminal
  fn mxfs_v5_dlm_inode_lock_try(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
    calls: make_inode_resource, mxfs_dlm_caw_lock, mxfs_dlm_lock
  fn mxfs_v5_dlm_set_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_ag_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_ag_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_fence_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_dead_node_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_dead_node_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_clean_depart_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_clean_depart_notify_fn fn, void *data) -> void
  fn static v5_owed_stuck_cb(void *data) -> void
  fn mxfs_v5_dlm_set_dlm_stuck_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_dlm_stuck_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_peer_joined_notify_fn fn, void *data) -> void
    calls: mxfs_dlm_is_single_node, mxfs_pal_log
  fn mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t local_epoch, struct mxfs_grant_result *gres) -> int
    calls: make_ag_resource, mxfs_dlm_caw_lock_attested, mxfs_dlm_lock, mxfs_pal_log
  fn mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t *out_gen) -> int
    calls: make_ag_resource, mxfs_dlm_caw_read_generation
  fn mxfs_v5_dlm_victim_ag_manifest_read(struct mxfs_v5_dlm *ctx, uint32_t agno, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_v5_dlm_victim_inode_manifest_read(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_v5_dlm_victim_recovery_read(struct mxfs_v5_dlm *ctx, uint32_t slot, uint16_t *out_stage, uint64_t *out_victim_epoch, uint32_t *out_victim_node) -> int
    calls: mxfs_disklock_recovery_read
  fn mxfs_v5_dlm_victim_untagged_authority(struct mxfs_v5_dlm *ctx, uint32_t slot, bool *out_cert_sn_excl, bool *out_victim_snlocal) -> int
    calls: mxfs_disklock_recovery_read
  fn mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t local_epoch, struct mxfs_grant_result *gres, bool demand) -> int
    calls: make_ag_resource, mxfs_dlm_caw_lock_attested, mxfs_dlm_lock
    called_by: dlm_lock_impl
  fn mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno) -> int
    calls: make_ag_resource, mxfs_dlm_release_orphan_if_unheld
  fn mxfs_v5_dlm_is_caw(struct mxfs_v5_dlm *ctx) -> int
  fn mxfs_v5_dlm_inode_held_nb(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_held_mode_nb
  fn mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno) -> int
    calls: make_ag_resource, mxfs_dlm_caw_held
  fn mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint8_t
    called_by: mxfs_v5_dlm_inode_held
  fn mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: make_inode_resource, mxfs_dlm_is_resource_master
  fn mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    calls: make_inode_resource, mxfs_dlm_caw_dump_slot
  fn mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
    calls: mxfs_v5_dlm_inode_held_rawmode
  fn mxfs_v5_dlm_is_tcp(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_ag_ex_count(struct mxfs_v5_dlm *ctx, uint32_t agno, int *nslots_out) -> int
    calls: make_ag_resource, mxfs_dlm_caw_ex_count
  fn mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx, uint32_t agno) -> enum mxfs_unlock_state
    calls: make_ag_resource, mxfs_dlm_caw_held, mxfs_dlm_caw_unlock_state, mxfs_dlm_unlock, mxfs_v5_dlm_note_resv_conflict
  fn mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx) -> bool
    calls: mxfs_dlm_is_single_node
    called_by: mxfs_dlm_open_last_close, mxfs_dlm_open_protect, mxfs_v5_dlm_is_mds, v5_exclusion_recheck
  fn mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx) -> int
    called_by: mxfs_v5_dlm_node_bit
  fn mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *ctx, uint32_t *slot, uint32_t *node, uint64_t *epoch) -> bool
    calls: mxfs_disklock_mount_identity
  fn mxfs_v5_dlm_slice_adopted(struct mxfs_v5_dlm *ctx) -> bool
    calls: mxfs_disklock_slice_adopted
  fn mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx) -> bool
    calls: mxfs_v5_dlm_is_single_node
  fn mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx) -> int
  struct mxfs_v5_dlm { node_id, node_uuid, volume_id, volume_uuid, transport, dlm_caw, dlm, peer, dlm_port, discovery_port }
  struct mxfs_md_pending { in_use, done, seq, reply }
  struct v5_fence_arm_ctx { ctx, slot, auth }
  struct v5_closure_shim { arg, volume_id }
  struct v5_closure_gate_arg { ctx, slot, victim, ag_mask }

[dlm/v5_mount.h]
  fn mxfs_v5_dlm_init(const struct mxfs_v5_dlm_opts *opts) -> struct mxfs_v5_dlm
  fn mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx) -> void
  fn mxfs_v5_dlm_shutdown_defer_release(struct mxfs_v5_dlm *ctx, struct mxfs_v5_dlm_slot_release *late) -> void
    called_by: mxfs_v5_dlm_shutdown
  fn mxfs_v5_dlm_slot_release_commit(struct mxfs_v5_dlm_slot_release *late, bool unmount_clean) -> void
  fn mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx) -> uint64_t
  fn mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx) -> void
  fn mxfs_v5_dlm_local_slot(struct mxfs_v5_dlm *ctx) -> int
  fn mxfs_v5_dlm_slot_unclaimed(struct mxfs_v5_dlm *ctx, int slot) -> int
  fn mxfs_v5_dlm_guard_slot(struct mxfs_v5_dlm *ctx, int slot) -> int
  fn mxfs_v5_dlm_guard_refresh(struct mxfs_v5_dlm *ctx) -> int
  fn mxfs_v5_dlm_unguard_slot(struct mxfs_v5_dlm *ctx) -> void
  fn mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> int
    called_by: mxfs_v5_dlm_mount_cohort_complete, v5_handle_node_death
  fn mxfs_v5_dlm_recovery_acquire(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> int
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_v5_dlm_recovery_release(struct mxfs_v5_dlm *ctx, uint32_t dead_slot) -> void
    called_by: mxfs_v5_dlm_recovery_complete
  fn mxfs_recov_blocked_reason(uint32_t reason) -> const char
  fn mxfs_v5_dlm_blocked_iter(struct mxfs_v5_dlm *ctx, int prev, struct mxfs_recov_blocked *out) -> int
  fn mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx) -> int
    called_by: mxfs_v5_dlm_init
  fn mxfs_v5_dlm_mount_residue_blocking(struct mxfs_v5_dlm *ctx, uint64_t *out_residue, int *out_nslots, int *out_nex) -> int
  fn mxfs_v5_dlm_settle_own_slot(struct mxfs_v5_dlm *ctx) -> int
  fn mxfs_v5_dlm_mount_recovery_cohort(struct mxfs_v5_dlm *ctx, uint64_t *out_slots) -> int
  fn mxfs_v5_dlm_mount_cohort_complete(struct mxfs_v5_dlm *ctx, uint64_t slots, uint64_t *out_published) -> int
  fn mxfs_v5_dlm_mount_take_late_deaths(struct mxfs_v5_dlm *ctx) -> uint64_t
  fn mxfs_v5_dlm_mount_pending_recovery(struct mxfs_v5_dlm *ctx, uint64_t *out_mask) -> int
  fn mxfs_v5_dlm_mount_defer_late_deaths(struct mxfs_v5_dlm *ctx, uint64_t slots) -> void
  fn mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
    called_by: mxfs_v5_dlm_iclus_lock
  fn mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, int retries, struct mxfs_grant_result *gres) -> int
  fn mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
  fn mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
  fn mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t expected_gen, int open_op) -> int
    called_by: mxfs_v5_dlm_inode_unlock_gen
  fn mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t expected_gen) -> int
    called_by: mxfs_v5_dlm_inode_unlock
  fn mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
  fn mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino, int *nslots_out) -> int
  fn mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino, int *nslots_out, uint64_t *hex_or_out) -> int
  fn mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino, const struct mxfs_forcerel_attest *att) -> int
  fn mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t gen) -> void
  fn mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
  fn mxfs_v5_dlm_recovery_publish_refusal(struct mxfs_v5_dlm *ctx, int dead_slot, const struct mxfs_recov_refusal_info *info, struct mxfs_recov_outcome *oc_out) -> int
  fn mxfs_v5_dlm_recovery_read_outcome(struct mxfs_v5_dlm *ctx, int dead_slot, struct mxfs_recov_outcome *oc_out) -> int
  fn mxfs_v5_dlm_recovery_backfill_legacy(struct mxfs_v5_dlm *ctx, int dead_slot, struct mxfs_recov_outcome *oc_out) -> int
  fn mxfs_v5_dlm_recovery_scan_outcomes(struct mxfs_v5_dlm *ctx) -> void
  fn mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t local_epoch, struct mxfs_grant_result *gres) -> int
  fn mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t local_epoch, struct mxfs_grant_result *gres, bool demand) -> int
    called_by: dlm_lock_impl
  fn mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx, uint32_t agno) -> enum mxfs_unlock_state
  fn mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno) -> int
  fn mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno) -> int
  fn mxfs_v5_dlm_is_caw(struct mxfs_v5_dlm *ctx) -> int
  fn mxfs_v5_dlm_inode_held_nb(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno, uint64_t *out_gen) -> int
  fn mxfs_v5_dlm_victim_ag_manifest_read(struct mxfs_v5_dlm *ctx, uint32_t agno, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_v5_dlm_victim_inode_manifest_read(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t victim_slot, bool *out_holds_ex, uint64_t *out_ex_grant_epoch, uint64_t *out_lineage) -> int
  fn mxfs_v5_dlm_victim_recovery_read(struct mxfs_v5_dlm *ctx, uint32_t slot, uint16_t *out_stage, uint64_t *out_victim_epoch, uint32_t *out_victim_node) -> int
  fn mxfs_v5_dlm_victim_untagged_authority(struct mxfs_v5_dlm *ctx, uint32_t slot, bool *out_cert_sn_excl, bool *out_victim_snlocal) -> int
  fn mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint8_t
    called_by: mxfs_v5_dlm_inode_held
  fn mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint32_t
  fn mxfs_v5_dlm_inode_orphan_clock_get(struct mxfs_v5_dlm *ctx, uint64_t ino, bool starve) -> uint64_t
  fn mxfs_v5_dlm_inode_orphan_clock_set(struct mxfs_v5_dlm *ctx, uint64_t ino, bool starve, uint64_t val) -> void
  fn mxfs_v5_dlm_inode_granted_mode(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint8_t
  fn mxfs_v5_dlm_inode_open_holders(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t *oh_out) -> int
  fn mxfs_v5_dlm_inode_open_clear(struct mxfs_v5_dlm *ctx, uint64_t ino) -> void
    called_by: mxfs_dlm_open_last_close
  fn mxfs_v5_dlm_inode_open_set(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_inode_open_probe(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t *oh_out, bool *authoritative) -> int
  fn mxfs_v5_dlm_node_bit(struct mxfs_v5_dlm *ctx) -> uint64_t
  fn mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t *gen_out) -> bool
  fn mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino) -> uint32_t
  fn mxfs_v5_dlm_inode_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino, uint32_t gen, uint64_t *fsb_out) -> bool
  fn mxfs_v5_dlm_inode_set_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino, uint64_t fsb, uint32_t gen) -> void
  fn mxfs_v5_dlm_transport_caw(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_is_tcp(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_ag_ex_count(struct mxfs_v5_dlm *ctx, uint32_t agno, int *nslots_out) -> int
  fn mxfs_v5_dlm_inode_lock_try(struct mxfs_v5_dlm *ctx, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
  fn mxfs_v5_dlm_set_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
  fn mxfs_v5_dlm_iclus_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t base_ino, uint32_t expected_gen, bool is_free) -> int
  fn mxfs_v5_dlm_iclus_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t base_ino) -> int
  fn mxfs_v5_dlm_iclus_pin(struct mxfs_v5_dlm *ctx, uint64_t base_ino) -> int
  fn mxfs_v5_dlm_inode_pin(struct mxfs_v5_dlm *ctx, uint64_t ino) -> int
  fn mxfs_v5_dlm_set_iclus_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_ag_bast_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_ag_bast_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_peer_joined_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_fence_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_note_resv_conflict(struct mxfs_v5_dlm *ctx) -> void
    called_by: mxfs_v5_dlm_ag_unlock, mxfs_v5_dlm_inode_unlock_open, v5_resv_conflict_cb
  fn mxfs_v5_dlm_set_dead_node_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_dead_node_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_clean_depart_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_clean_depart_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_dlm_stuck_notify(struct mxfs_v5_dlm *ctx, mxfs_v5_dlm_stuck_notify_fn fn, void *data) -> void
  fn mxfs_v5_dlm_set_md_request_fn(struct mxfs_v5_dlm *ctx, mxfs_v5_md_request_fn fn, void *data) -> void
  fn mxfs_v5_dlm_md_request(struct mxfs_v5_dlm *ctx, uint16_t type, const struct mxfs_md_req *req, const char *name1, const char *name2, struct mxfs_md_reply *reply) -> int
  fn mxfs_v5_dlm_mds_node_id(struct mxfs_v5_dlm *ctx) -> mxfs_node_id_t
  fn mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx) -> bool
    called_by: mxfs_dlm_open_last_close, mxfs_dlm_open_protect, mxfs_v5_dlm_is_mds, v5_exclusion_recheck
  fn mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx) -> int
    called_by: mxfs_v5_dlm_node_bit
  fn mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *ctx, uint32_t *slot, uint32_t *node, uint64_t *epoch) -> bool
  fn mxfs_v5_dlm_slice_adopted(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx) -> bool
  fn mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx) -> int
  struct mxfs_v5_dlm_opts { transport, dlm_port, discovery_port, journal_offset, disklock_offset, max_nodes, bdev, volume_uuid, max_dlm_lock_caw, lease_timeout_ms }
  struct mxfs_v5_dlm_slot_release { disklock, dev }
  struct mxfs_recov_blocked { reason, last_rc, victim_node, victim_epoch, victim_key, victim_slot, fence_kind, resv_type, fence_term, prover_node }
  typedef_fn mxfs_v5_bast_notify_fn
  typedef_fn mxfs_v5_ag_bast_notify_fn
  typedef_fn mxfs_v5_peer_joined_notify_fn
  typedef_fn mxfs_v5_fence_notify_fn
  typedef_fn mxfs_v5_dead_node_notify_fn
  typedef_fn mxfs_v5_clean_depart_notify_fn
  typedef_fn mxfs_v5_dlm_stuck_notify_fn
  typedef_fn mxfs_v5_md_request_fn

[include/mxfs/mxfs_common.h]
  struct mxfs_resource_id { volume, ino, offset, ag_number, type, pad }
  enum mxfs_error { MXFS_OK, MXFS_ERR_DEADLOCK, MXFS_ERR_LEASE_EXPIRED, MXFS_ERR_NODE_DEAD, MXFS_ERR_NO_QUORUM, MXFS_ERR_STALE_LOCK, MXFS_ERR_RECOVERY_NEEDED, MXFS_ERR_VERSION_MISMATCH, MXFS_ERR_VOLUME_UNKNOWN, MXFS_ERR_NOT_MOUNTED }
  enum mxfs_node_state { MXFS_NODE_UNKNOWN, MXFS_NODE_JOINING, MXFS_NODE_ACTIVE, MXFS_NODE_SUSPECT, missed, lease, renewal, not, yet, dead }
  enum mxfs_self_fence_reason { disklock, HB, on, disk, MXFS, super, fs_uuid, no, longer, matches }

[include/mxfs/mxfs_dlm.h]
  enum mxfs_lock_mode { MXFS_LOCK_NL, null, placeholder, no, access, MXFS_LOCK_CR, concurrent, read, MXFS_LOCK_CW, concurrent }
  enum mxfs_lock_type { MXFS_LTYPE_INODE, MXFS_LTYPE_EXTENT, MXFS_LTYPE_AG, MXFS_LTYPE_JOURNAL, MXFS_LTYPE_SUPER, superblock, lock, mount, unmount, coordination }
  enum mxfs_grant_auth_status { Never, filled, the, result, went, unused, or, a, transport, TCP }
  struct mxfs_grant_result { resource, grant_epoch, resource_lineage, generation, kind, mode, status, reaffirm }
  enum mxfs_forcerel_basis { MXFS_FORCEREL_BASIS_NONE, never, valid, refuses, Dependent, activity, on, this, resource, has }
  struct mxfs_forcerel_attest { basis, site, no_local_grant, no_dependent_users, new_users_blocked, writeback_drained }
  enum mxfs_unlock_state { MXFS_UNLOCK_UNKNOWN, outcome, unprovable, quarantine, MXFS_UNLOCK_RELEASED, bit, provably, clear, on, the }
  enum mxfs_lock_state { MXFS_LSTATE_UNLOCKED, MXFS_LSTATE_WAITING, request, sent, awaiting, grant, MXFS_LSTATE_GRANTED, MXFS_LSTATE_CONVERTING, mode, upgrade }
  enum mxfs_dlm_msg_type { MXFS_MSG_LOCK_REQ, MXFS_MSG_LOCK_GRANT, MXFS_MSG_LOCK_DENY, MXFS_MSG_LOCK_RELEASE, MXFS_MSG_LOCK_CONVERT, MXFS_MSG_LOCK_BAST, blocking, AST, request, holder }
  struct mxfs_dlm_msg_hdr { magic, version, type, length, seq, sender, target, epoch }
  struct mxfs_dlm_lock_req { hdr, resource, mode, pad, flags }
  struct mxfs_dlm_lock_resp { hdr, resource, mode, status, handoff, pad, grant_gen, dir_epoch }
  struct mxfs_dlm_lock_release { hdr, resource, grant_gen, pad }
  struct mxfs_dlm_bast { hdr, resource, requested_mode, pad }
  struct mxfs_dlm_lease_msg { hdr, lease_duration_ms, lock_count, pad }
  struct mxfs_dlm_cache_inval { hdr, resource, range_start, range_len }
  struct mxfs_md_req { hdr, parent_ino, parent_gen, newparent_ino, newparent_gen, link_ino, mode, rdev, uid, gid }
  struct mxfs_md_reply { hdr, rc, pad, child_ino, child_gen, parent_gen, newparent_gen, child_mode, child_nlink, child_size }
  struct mxfs_dlm_journal_msg { hdr, dead_node, journal_slot }
  struct mxfs_dlm_node_msg { hdr, name, port, pad, volume_id }

[include/mxfs/mxfs_netlink.h]
  enum mxfs_nl_cmd { MXFS_NL_CMD_UNSPEC, MXFS_NL_CMD_LOCK_REQ, kernel, daemon, request, distributed, lock, MXFS_NL_CMD_LOCK_GRANT, daemon, kernel }
  enum mxfs_nl_attr { MXFS_NL_ATTR_UNSPEC, MXFS_NL_ATTR_NODE_ID, u32, node, ID, MXFS_NL_ATTR_NODE_STATE, u8, mxfs_node_state, MXFS_NL_ATTR_LOCK_TYPE, u8 }
  enum mxfs_nl_mcast_groups { MXFS_NL_MCAST_LOCKS, lock, state, changes, MXFS_NL_MCAST_STATUS, node, volume, status, changes }

[include/mxfs/mxfs_super.h]
  struct mxfs_ondisk_super { magic, version, flags, crc, fs_uuid, device_size, xfs_data_size, journal_offset, journal_size, disklock_offset }

[mxfs_clayer/acquire.h]
  fn mxfs_clayer_acquire_token(struct mxfs_clayer_token *t) -> int

[mxfs_clayer/invalidate.c]
  fn mxfs_invalidate_ag(struct xfs_mount *mp, xfs_agnumber_t ag_no) -> int
    calls: xfs_buf_lock
  fn mxfs_invalidate_inode(struct xfs_inode *ip) -> int
    calls: xfs_buf_lock, xfs_log_force
  fn mxfs_pagecache_inval_inode(struct xfs_inode *ip) -> int

[mxfs_clayer/invalidate.h]
  fn mxfs_invalidate_ag(struct xfs_mount *mp, xfs_agnumber_t ag_no) -> int
  fn mxfs_invalidate_inode(struct xfs_inode *ip) -> int
  fn mxfs_pagecache_inval_inode(struct xfs_inode *ip) -> int

[mxfs_clayer/pinned_resource.h]
  fn mxfs_inode_pin(struct xfs_inode *ip) -> void
  fn mxfs_inode_unpin(struct xfs_inode *ip) -> void

[mxfs_clayer/release.h]
  fn mxfs_clayer_release_token(struct mxfs_clayer_token *t) -> int
  enum mxfs_clayer_resource_kind { MXFS_CLAYER_RES_AG, MXFS_CLAYER_RES_INODE }
  struct mxfs_clayer_token { mp, kind, ag_no, ino, epoch, cached_epoch }

[mxfs_clayer/yield_quantum.h]
  fn mxfs_yield_arm(struct xfs_inode *ip) -> void
  fn mxfs_yield_decrement(struct xfs_inode *ip) -> void

[pal/linux/kern.c]
  fn mxfs_pal_bdev_open(const char *path) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close(mxfs_bdev_t *dev) -> void
    called_by: mxfs_mount, mxfs_unmount
  fn mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev, uint64_t base_offset) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev) -> void
    calls: pr_info
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_pal_bdev_wrap(struct block_device *bdev) -> mxfs_bdev_t
    called_by: mxfs_v5_dlm_init
  fn static kaddr_to_page(void *addr) -> struct page
    calls: virt_to_page, vmalloc_to_page
    called_by: build_bio, mxfs_pal_bdev_read_plain_bdev, mxfs_pal_bdev_write_gather, mxfs_pal_bdev_write_gather_fua
  fn static build_bio(struct mxfs_bdev *dev, uint64_t offset, void *buf, uint32_t len, unsigned int op, unsigned int *batch_len) -> struct bio
    calls: kaddr_to_page
    called_by: bdev_pipelined_write, bdev_sync_io
  fn static bdev_sync_io(struct mxfs_bdev *dev, uint64_t offset, void *buf, uint32_t len, unsigned int op) -> int
    calls: build_bio
    called_by: bdev_pipelined_write, mxfs_pal_bdev_read_prio, mxfs_pal_bdev_write_fua
  fn static mxfs_bio_end_io(struct bio *bio) -> void
  fn static bdev_pipelined_read(struct mxfs_bdev *dev, uint64_t offset, void *buf, uint32_t len) -> int
    called_by: mxfs_pal_bdev_read, mxfs_pal_bdev_read_async
  fn mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: bdev_pipelined_read
    called_by: disklock_hb_fn, fs_identity_changed, hb_report_claim_exhausted, mxfs_disklock_claim_slot, mxfs_disklock_find_node_slot, mxfs_disklock_get_slot_node_id, mxfs_disklock_get_stale_slot_mask, mxfs_mount, mxfs_pal_bdev_read_async, mxfs_pal_bdev_read_prio, mxfs_write_direct, read_sector, readlink_remote
  fn static mxfs_sdev_read_lba(struct scsi_device *sdev, u64 lba, void *buf) -> int
    called_by: mxfs_sdev_resolve_by_content
  fn static mxfs_sdev_resolve_by_content(struct block_device *bdev) -> struct scsi_device
    calls: mxfs_pal_bdev_read_plain_bdev, mxfs_sdev_read_lba
    called_by: mxfs_bdev_to_sdev
  fn static mxfs_bdev_to_sdev(struct block_device *bdev) -> struct scsi_device
    calls: mxfs_sdev_resolve_by_content, pr_info
    called_by: mxfs_pal_bdev_compare_and_write, mxfs_pal_scsi_pr_preempt, mxfs_pal_scsi_pr_read_full_status, mxfs_pal_scsi_pr_report_capabilities, mxfs_pal_scsi_read_fua_bdev, mxfs_pal_scsi_write_fua_bdev
  fn mxfs_pal_sdev_cache_release(void) -> void
  fn mxfs_pal_io_budget_enter(struct mxfs_pal_io_budget *b, uint32_t ms) -> void
  fn mxfs_pal_io_budget_exit(struct mxfs_pal_io_budget *b) -> void
  fn static mxfs_pal_io_budget_remaining_ms(void) -> long
    called_by: mxfs_pal_scsi_read_fua_bdev
  fn mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev, uint64_t lba_512, void *buf, uint32_t len) -> int
    calls: atomic_inc_return, mxfs_bdev_to_sdev, mxfs_pal_bdev_read_plain_bdev, mxfs_pal_io_budget_remaining_ms, read
    called_by: mxfs_iunl_discrim, mxfs_scsi_read16_fua
  fn mxfs_pal_bdev_read_plain_bdev(struct block_device *bdev, uint64_t lba_512, void *buf, uint32_t len) -> int
    calls: kaddr_to_page
    called_by: mxfs_iunl_discrim, mxfs_pal_scsi_read_fua_bdev, mxfs_sdev_resolve_by_content
  fn static mxfs_scsi_read16_fua(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: mxfs_pal_scsi_read_fua_bdev
    called_by: mxfs_pal_bdev_read_prio
  fn mxfs_pal_scsi_write_fua_bdev(struct block_device *bdev, uint64_t lba_512, const void *buf, uint32_t len) -> int
    calls: mxfs_bdev_to_sdev
  fn mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: bdev_sync_io, mxfs_scsi_read16_fua
    called_by: caw_purge_dead_nodes_body, caw_slot, disklock_hb_fn, hb_cas_own_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_join_gate, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_retryable, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_read
  fn mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: mxfs_pal_bdev_write_gather
    called_by: is_revoked, mxfs_journal_replay, mxfs_journal_txn_commit, mxfs_pal_bdev_write_async, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather, mxfs_pal_bdev_write_gather_fua, mxfs_write_direct, write_sector
  fn mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: bdev_sync_io
    called_by: mxfs_pal_bdev_write_gather_fua, write_sector_fua
  fn static bdev_pipelined_write(struct mxfs_bdev *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: bdev_sync_io, build_bio
    called_by: mxfs_pal_bdev_write_async
  fn mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: bdev_pipelined_write
    called_by: mxfs_write_direct
  fn mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev, const uint64_t *offsets, void * const *bufs, const uint32_t *lens, int count) -> int
  fn mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: bdev_pipelined_read
  fn mxfs_pal_bdev_flush(mxfs_bdev_t *dev) -> int
    called_by: checkpoint_locked, mxfs_fsync, mxfs_journal_checkpoint, mxfs_journal_flush, mxfs_journal_format, mxfs_journal_replay, mxfs_journal_write_unmount, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather_fua, mxfs_sync_fs, mxfs_v5_dlm_recovery_complete, recov_cas_durable
  fn mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out) -> int
    called_by: mxfs_mount
  fn mxfs_pal_bdev_write_gather(mxfs_bdev_t *dev, uint64_t offset, void **bufs, int nbufs, uint32_t blocksize) -> int
    calls: kaddr_to_page, mxfs_pal_bdev_write
    called_by: mxfs_pal_bdev_write, mxfs_pal_bdev_write_gather_fua
  fn mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset, void **bufs, int nbufs, uint32_t blocksize) -> int
    calls: kaddr_to_page, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather
  fn mxfs_pal_alloc(size_t size) -> void
    calls: mxfs_pal_free
    called_by: bast_poll_fn, caw_bastq_init, caw_convert_body, caw_count_resource_slots, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole, fallocate_zero_range, flush_superblock_counters
  fn mxfs_pal_free(void *ptr) -> void
    called_by: bast_poll_fn, bast_worker_fn, caw_bastq_free, caw_convert_body, caw_count_resource_slots, caw_create_unwind, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole
  fn mxfs_pal_realloc(void *ptr, size_t new_size) -> void
    calls: mxfs_pal_alloc, mxfs_pal_free
  fn static kthread_fn_wrapper(void *data) -> int
  fn mxfs_pal_thread_join(mxfs_thread_t *t) -> void
    called_by: mxfs_discovery_start, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_lease_start, mxfs_lease_stop, mxfs_mount, mxfs_net2_selftest_stop, mxfs_net2_stop, mxfs_peer_accept_fn, mxfs_peer_shutdown, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, net2_link_reap, net2_link_shutdown_all, net2_lockspace_stop
  fn mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms) -> int
    called_by: caw_join_bounded, mxfs_disklock_stop_heartbeat
  fn mxfs_pal_thread_pid(mxfs_thread_t *t) -> int
    called_by: mxfs_disklock_start_heartbeat
  fn mxfs_pal_mutex_create(void) -> mxfs_mutex_t
    called_by: caw_bastq_init, mep_env_start, mxfs_disklock_create, mxfs_dlm_create, mxfs_journal_create, mxfs_mount, mxfs_net2_create, mxfs_peer_accept_fn, mxfs_peer_add, mxfs_peer_init, mxfs_v5_dlm_init, net2_lockspace_create, net2_membership_create, net2_mepoch_create, net2_selftest_fn
  fn mxfs_pal_mutex_destroy(mxfs_mutex_t *m) -> void
    called_by: caw_bastq_free, caw_create_unwind, mep_env_stop, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_destroy, mxfs_journal_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_peer_init, mxfs_peer_shutdown
  fn mxfs_pal_mutex_lock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_mutex_unlock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_spinlock_create(void) -> mxfs_spinlock_t
  fn mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s) -> void
    called_by: caw_create_unwind, mxfs_dlm_caw_destroy
  fn mxfs_pal_spinlock_lock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_rwlock_create(void) -> mxfs_rwlock_t
    called_by: mxfs_dlm_create
  fn mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_destroy
  fn mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_withdraw_release_all
  fn mxfs_pal_rwlock_tryrdlock(mxfs_rwlock_t *rw) -> int
    called_by: mxfs_dlm_held_mode_nb
  fn mxfs_pal_may_sleep(void) -> int
    called_by: mxfs_dlm_held_mode
  fn mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_unlock_gen, mxfs_dlm_update_active_nodes
  fn mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_unlock_gen
  fn mxfs_pal_cond_create(void) -> mxfs_cond_t
    called_by: caw_bastq_init, mxfs_disklock_create, mxfs_mount, mxfs_net2_create, net2_lockspace_create, pending_alloc
  fn mxfs_pal_cond_destroy(mxfs_cond_t *c) -> void
    called_by: caw_bastq_free, caw_create_unwind, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_unmount, net2_lockspace_destroy, pending_alloc, pending_free
  fn mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m) -> void
    called_by: bast_worker_fn
  fn mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m, uint64_t timeout_ms) -> int
    called_by: bast_poll_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_nudge_ring_wants_wake, caw_owed_worker_fn, creq_wait, disklock_hb_fn, disklock_hb_watchdog_fn, mxfs_discovery_send_fn, mxfs_dlm_caw_stop, mxfs_lease_monitor_fn, mxfs_lease_renew_fn, net2_link_egress_fn, pending_wait
  fn mxfs_pal_cond_signal(mxfs_cond_t *c) -> void
    called_by: caw_bast_disp_fn, dlm_membership_cb, mxfs_dlm_caw_start, mxfs_dlm_caw_stop, mxfs_mount, mxfs_unmount, net2_link_kick, queue_membership_update
  fn mxfs_pal_cond_broadcast(mxfs_cond_t *c) -> void
    called_by: bast_recv_fn, caw_bastq_join_workers, caw_op_leave, caw_owe_residue, lreq_clr_end, lreq_finish, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_stop, mxfs_lease_stop, net2_link_down, net2_link_shutdown_all, net2_lock_client_rx, net2_lockspace_stop
  fn static parse_ipv4(const char *host, uint16_t port, struct sockaddr_in *addr) -> int
    called_by: mxfs_pal_tcp_connect, mxfs_pal_udp_sendto
  fn mxfs_pal_tcp_connect(const char *host, uint16_t port) -> mxfs_sock_t
    calls: parse_ipv4
    called_by: net2_link_conn_fn, scen_mc_malformed_cross
  fn mxfs_pal_tcp_listen(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_peer_init, net2_link_listen_start
  fn mxfs_pal_tcp_accept(mxfs_sock_t *listener) -> mxfs_sock_t
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len) -> int
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, net2_link_accept_fn, net2_link_conn_fn, net2_link_send_bytes, scen_mc_malformed_cross
  fn mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len) -> int
    called_by: mxfs_peer_accept_fn, mxfs_peer_recv_fn, mxfs_peer_shutdown, net2_read_frame
  fn mxfs_pal_tcp_set_opts(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn, net2_link_conn_fn
  fn mxfs_pal_tcp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, mxfs_peer_shutdown, net2_link_connect, net2_link_down, net2_link_install, net2_link_shutdown_all, peer_handle_disconnect
  fn mxfs_pal_tcp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_shutdown, net2_fault_check, net2_link_accept_fn, net2_link_conn_fn, net2_link_install, net2_link_listen_start, net2_link_reap, net2_link_shutdown_all, scen_mc_malformed_cross
  fn mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len) -> int
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_udp_open(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_stop, mxfs_dlm_caw_stop, mxfs_lease_stop
  fn mxfs_pal_udp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_caw_start, mxfs_lease_destroy
  fn mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len, const char *host, uint16_t port) -> int
    calls: parse_ipv4
    called_by: caw_send_bast_mcast, caw_send_grant_mcast, mxfs_discovery_send_fn, mxfs_lease_renew_fn
  fn mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len, char *from_host, size_t host_len, uint16_t *from_port) -> int
    called_by: bast_recv_fn, mxfs_discovery_recv_fn, mxfs_lease_udp_recv_fn, mxfs_mount
  fn mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_set_broadcast(mxfs_sock_t *s) -> int
  fn mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_time_ms(void) -> uint64_t
    called_by: bast_poll_fn, bast_worker_fn, caw_acquire_poll_sleep, caw_bast_disp_fn, caw_convert_body, caw_force_release_self_body, caw_grant_meta_seq, caw_join_bounded, caw_nudge_ring_wants_wake, caw_open_clear_body, caw_open_set_body, caw_owed_dispatch, caw_owed_fail_latch, caw_owed_release, caw_owed_sweep
  fn mxfs_pal_time_real_sec(void) -> uint64_t
    called_by: fallocate_prealloc, fallocate_punch_hole, fallocate_zero_range, mxfs_chmod, mxfs_chown, mxfs_utimes, mxfs_write
  fn mxfs_pal_time_real_ms(void) -> uint64_t
    called_by: caw_exwin_log, caw_yield_stamp
  fn mxfs_pal_sleep_ms(uint32_t ms) -> void
    called_by: caw_grant_meta_store_unless_releasing, caw_grant_seq_prebump, caw_inode_backoff, caw_nudge_ring_wants_wake, caw_open_set_body, caw_owed_worker_fn, caw_release_mark, caw_slot, dlm_bast_cb, dlm_lock_impl, dlm_membership_settling, killpoint_run, lreq_clr_still_good, ls_rt_fn, membership_stab_worker_fn
  fn mxfs_pal_sleep_ms_interruptible(uint32_t ms) -> void
    called_by: v5_fence_retry_worker_fn
  fn mxfs_pal_cond_resched(void) -> void
    called_by: caw_purge_dead_nodes_body, caw_release_all_body, mxfs_dlm_caw_footprint_scan
  fn mxfs_pal_dump_stack(void) -> void
    called_by: mxfs_dlm_lock_retries
  fn mxfs_pal_failstop_fn(const char *fmt, ...) -> void
  fn static mxfs_defer_work_fn(struct work_struct *w) -> void
    calls: container_of
  fn mxfs_pal_dump_task_stack(int pid) -> void
    called_by: disklock_hb_watchdog_fn
  fn mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    calls: crc32c
    called_by: build_symlink_hdr_v5, flush_superblock_counters, hb_feature_crc, hb_prov_crc, mxfs_journal_txn_commit, mxfs_mepoch_rec_seal, mxfs_mepoch_rec_valid, mxfs_mount, read_entry_at, recov_outcome_crc, sector_crc, serialize_entry
  fn mxfs_pal_log(int level, const char *fmt, ...) -> void
    calls: pr_err, pr_info
    called_by: ack_process, bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bast_submit, caw_bastq_init, caw_check_exclusion, caw_convert_body, caw_count_resource_slots, caw_flush_held_body, caw_force_release_self_body, caw_grant_epoch_update, caw_grant_meta_seq
  fn static get_pr_ops(struct mxfs_bdev *dev) -> const struct pr_ops
    called_by: mxfs_pal_scsi_pr_preempt, mxfs_pal_scsi_pr_read_keys, mxfs_pal_scsi_pr_read_reservation, mxfs_pal_scsi_pr_register, mxfs_pal_scsi_pr_reserve, mxfs_pal_scsi_pr_unregister
  fn mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key) -> int
    calls: get_pr_ops, mxfs_pal_log
    called_by: mxfs_scsipr_register
  fn mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key, uint32_t type) -> int
    calls: get_pr_ops
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_reserve
  fn static mxfs_pal_prout_preempt_abort(struct scsi_device *sdev, uint64_t my_key, uint64_t victim_key, uint32_t type) -> int
    called_by: mxfs_pal_scsi_pr_preempt
  fn mxfs_pal_scsi_pr_report_capabilities(mxfs_bdev_t *dev, struct mxfs_pal_pr_caps *out) -> int
    calls: mxfs_bdev_to_sdev
    called_by: mxfs_scsipr_validate_admission
  fn mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key, uint64_t victim_key, bool abort, uint32_t type) -> int
    calls: get_pr_ops, mxfs_bdev_to_sdev, mxfs_pal_prout_preempt_abort
    called_by: mxfs_scsipr_preempt
  fn mxfs_pal_scsi_pr_read_reservation(mxfs_bdev_t *dev, struct mxfs_pal_pr_reservation *out) -> int
    calls: get_pr_ops
  fn static mxfs_pr_key_present_bdev(struct block_device *bdev, uint64_t key, bool *present) -> int
    called_by: mxfs_pal_scsi_pr_unregister_bdev
  fn mxfs_pal_scsi_pr_unregister_bdev(struct block_device *bdev, uint64_t key) -> int
    calls: mxfs_pal_log, mxfs_pr_key_present_bdev
    called_by: mxfs_pal_scsi_pr_unregister
  fn mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key) -> int
    calls: get_pr_ops, mxfs_pal_scsi_pr_unregister_bdev
    called_by: mxfs_scsipr_unregister
  fn mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    calls: get_pr_ops
    called_by: mxfs_scsipr_read_keys
  fn mxfs_pal_scsi_pr_read_full_status(mxfs_bdev_t *dev, uint64_t key, int *present, uint32_t *generation) -> int
    calls: mxfs_bdev_to_sdev, round_up
    called_by: mxfs_scsipr_fenced_check
  fn static caw_manual_bio(struct scsi_device *sdev, u64 lba, const void *compare_buf, const void *write_buf, struct scsi_sense_hdr *sshdr_out, int *resid_out) -> int
    called_by: mxfs_pal_bdev_compare_and_write
  fn mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset, const void *compare_buf, const void *write_buf) -> int
    calls: caw_manual_bio, mxfs_bdev_to_sdev, mxfs_pal_bdev_read_prio
    called_by: caw_repair_slot, caw_slot, caw_watch_armed, hb_cas_own_slot, mxfs_disklock_claim_slot, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_release_slot, mxfs_disklock_unguard, mxfs_disklock_withdraw, mxfs_mount, purge_cas_zero, recov_cas_durable
  fn mxfs_pal_bdev_get_bdev(mxfs_bdev_t *dev) -> struct block_device
  fn mxfs_pal_bdev_get_base_offset(mxfs_bdev_t *dev) -> uint64_t
  fn mxfs_pal_get_hostname(char *buf, size_t len) -> int
  fn mxfs_pal_read_file(const char *path, void *buf, size_t buf_size) -> int
    called_by: load_node_uuid
  fn mxfs_pal_get_random_bytes(void *buf, size_t len) -> void
    called_by: caw_inode_backoff, caw_mint_lineage, hb_draw_incarnation, hb_prov_derive, mxfs_generate_random_uuid, mxfs_v5_dlm_init, net2_membership_boot_nonce, net2_selftest_fn
  fn mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev, uint64_t *writes, uint64_t *write_bytes, uint64_t *writes_fua, uint64_t *write_fua_bytes, uint64_t *flushes) -> void
  struct mxfs_bdev { bdev, bdev_file, handle, base_offset, is_clone, path, stat_writes, stat_write_bytes, stat_write_ns, stat_writes_fua }
  struct mxfs_bio_ctx { done, status }
  struct mxfs_inflight { bio, ctx, len }
  struct mxfs_sdev_cache_ent { devt, sdev, retry_at }
  struct mxfs_thread { task, arg, started, exited }
  struct mxfs_mutex { mtx }
  struct mxfs_spinlock { lock }
  struct mxfs_rwlock { sem, write_held }
  struct mxfs_cond { wq, generation }
  struct mxfs_sock { sk, is_udp }
  struct mxfs_defer_work { work, arg }

[pal/linux/user.c]
  fn mxfs_pal_bdev_open(const char *path) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close(mxfs_bdev_t *dev) -> void
    called_by: mxfs_mount, mxfs_unmount
  fn mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev, uint64_t base_offset) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev, uint64_t *writes, uint64_t *write_bytes, uint64_t *writes_fua, uint64_t *write_fua_bytes, uint64_t *flushes) -> void
  fn mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    called_by: disklock_hb_fn, fs_identity_changed, hb_report_claim_exhausted, mxfs_disklock_claim_slot, mxfs_disklock_find_node_slot, mxfs_disklock_get_slot_node_id, mxfs_disklock_get_stale_slot_mask, mxfs_mount, mxfs_pal_bdev_read_async, mxfs_pal_bdev_read_prio, mxfs_write_direct, read_sector, readlink_remote
  fn mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: mxfs_pal_bdev_read
    called_by: caw_purge_dead_nodes_body, caw_slot, disklock_hb_fn, hb_cas_own_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_join_gate, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_retryable, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_read
  fn mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    called_by: is_revoked, mxfs_journal_replay, mxfs_journal_txn_commit, mxfs_pal_bdev_write_async, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather, mxfs_pal_bdev_write_gather_fua, mxfs_write_direct, write_sector
  fn mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: mxfs_pal_bdev_flush, mxfs_pal_bdev_write
    called_by: mxfs_pal_bdev_write_gather_fua, write_sector_fua
  fn mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    calls: mxfs_pal_bdev_write
    called_by: mxfs_write_direct
  fn mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev, const uint64_t *offsets, void * const *bufs, const uint32_t *lens, int count) -> int
  fn mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    calls: mxfs_pal_bdev_read
  fn mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset, void **bufs, int nbufs, uint32_t blocksize) -> int
    calls: mxfs_pal_bdev_flush, mxfs_pal_bdev_write
  fn mxfs_pal_bdev_flush(mxfs_bdev_t *dev) -> int
    called_by: checkpoint_locked, mxfs_fsync, mxfs_journal_checkpoint, mxfs_journal_flush, mxfs_journal_format, mxfs_journal_replay, mxfs_journal_write_unmount, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather_fua, mxfs_sync_fs, mxfs_v5_dlm_recovery_complete, recov_cas_durable
  fn mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out) -> int
    called_by: mxfs_mount
  fn mxfs_pal_alloc(size_t size) -> void
    called_by: bast_poll_fn, caw_bastq_init, caw_convert_body, caw_count_resource_slots, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole, fallocate_zero_range, flush_superblock_counters
  fn mxfs_pal_free(void *ptr) -> void
    called_by: bast_poll_fn, bast_worker_fn, caw_bastq_free, caw_convert_body, caw_count_resource_slots, caw_create_unwind, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole
  fn mxfs_pal_realloc(void *ptr, size_t new_size) -> void
  fn static thread_wrapper(void *arg) -> void
  fn mxfs_pal_thread_join(mxfs_thread_t *t) -> void
    called_by: mxfs_discovery_start, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_lease_start, mxfs_lease_stop, mxfs_mount, mxfs_net2_selftest_stop, mxfs_net2_stop, mxfs_peer_accept_fn, mxfs_peer_shutdown, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, net2_link_reap, net2_link_shutdown_all, net2_lockspace_stop
  fn mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms) -> int
    called_by: caw_join_bounded, mxfs_disklock_stop_heartbeat
  fn mxfs_pal_thread_pid(mxfs_thread_t *t) -> int
    called_by: mxfs_disklock_start_heartbeat
  fn mxfs_pal_dump_task_stack(int pid) -> void
    called_by: disklock_hb_watchdog_fn
  fn mxfs_pal_mutex_create(void) -> mxfs_mutex_t
    called_by: caw_bastq_init, mep_env_start, mxfs_disklock_create, mxfs_dlm_create, mxfs_journal_create, mxfs_mount, mxfs_net2_create, mxfs_peer_accept_fn, mxfs_peer_add, mxfs_peer_init, mxfs_v5_dlm_init, net2_lockspace_create, net2_membership_create, net2_mepoch_create, net2_selftest_fn
  fn mxfs_pal_mutex_destroy(mxfs_mutex_t *m) -> void
    called_by: caw_bastq_free, caw_create_unwind, mep_env_stop, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_destroy, mxfs_journal_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_peer_init, mxfs_peer_shutdown
  fn mxfs_pal_mutex_lock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_mutex_unlock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_spinlock_create(void) -> mxfs_spinlock_t
  fn mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s) -> void
    called_by: caw_create_unwind, mxfs_dlm_caw_destroy
  fn mxfs_pal_spinlock_lock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_rwlock_create(void) -> mxfs_rwlock_t
    called_by: mxfs_dlm_create
  fn mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_destroy
  fn mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_withdraw_release_all
  fn mxfs_pal_may_sleep(void) -> int
    called_by: mxfs_dlm_held_mode
  fn mxfs_pal_rwlock_tryrdlock(mxfs_rwlock_t *rw) -> int
    called_by: mxfs_dlm_held_mode_nb
  fn mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_unlock_gen, mxfs_dlm_update_active_nodes
  fn mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_unlock_gen
  fn mxfs_pal_cond_create(void) -> mxfs_cond_t
    called_by: caw_bastq_init, mxfs_disklock_create, mxfs_mount, mxfs_net2_create, net2_lockspace_create, pending_alloc
  fn mxfs_pal_cond_destroy(mxfs_cond_t *c) -> void
    called_by: caw_bastq_free, caw_create_unwind, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_unmount, net2_lockspace_destroy, pending_alloc, pending_free
  fn mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m) -> void
    called_by: bast_worker_fn
  fn mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m, uint64_t timeout_ms) -> int
    called_by: bast_poll_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_nudge_ring_wants_wake, caw_owed_worker_fn, creq_wait, disklock_hb_fn, disklock_hb_watchdog_fn, mxfs_discovery_send_fn, mxfs_dlm_caw_stop, mxfs_lease_monitor_fn, mxfs_lease_renew_fn, net2_link_egress_fn, pending_wait
  fn mxfs_pal_cond_signal(mxfs_cond_t *c) -> void
    called_by: caw_bast_disp_fn, dlm_membership_cb, mxfs_dlm_caw_start, mxfs_dlm_caw_stop, mxfs_mount, mxfs_unmount, net2_link_kick, queue_membership_update
  fn mxfs_pal_cond_broadcast(mxfs_cond_t *c) -> void
    called_by: bast_recv_fn, caw_bastq_join_workers, caw_op_leave, caw_owe_residue, lreq_clr_end, lreq_finish, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_stop, mxfs_lease_stop, net2_link_down, net2_link_shutdown_all, net2_lock_client_rx, net2_lockspace_stop
  fn mxfs_pal_tcp_connect(const char *host, uint16_t port) -> mxfs_sock_t
    called_by: net2_link_conn_fn, scen_mc_malformed_cross
  fn mxfs_pal_tcp_listen(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_peer_init, net2_link_listen_start
  fn mxfs_pal_tcp_accept(mxfs_sock_t *listener) -> mxfs_sock_t
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len) -> int
    calls: send
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, net2_link_accept_fn, net2_link_conn_fn, net2_link_send_bytes, scen_mc_malformed_cross
  fn mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len) -> int
    called_by: mxfs_peer_accept_fn, mxfs_peer_recv_fn, mxfs_peer_shutdown, net2_read_frame
  fn mxfs_pal_tcp_set_opts(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn, net2_link_conn_fn
  fn mxfs_pal_tcp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, mxfs_peer_shutdown, net2_link_connect, net2_link_down, net2_link_install, net2_link_shutdown_all, peer_handle_disconnect
  fn mxfs_pal_tcp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_shutdown, net2_fault_check, net2_link_accept_fn, net2_link_conn_fn, net2_link_install, net2_link_listen_start, net2_link_reap, net2_link_shutdown_all, scen_mc_malformed_cross
  fn mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len) -> int
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_udp_open(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_stop, mxfs_dlm_caw_stop, mxfs_lease_stop
  fn mxfs_pal_udp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_caw_start, mxfs_lease_destroy
  fn mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len, const char *host, uint16_t port) -> int
    called_by: caw_send_bast_mcast, caw_send_grant_mcast, mxfs_discovery_send_fn, mxfs_lease_renew_fn
  fn mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len, char *from_host, size_t host_len, uint16_t *from_port) -> int
    called_by: bast_recv_fn, mxfs_discovery_recv_fn, mxfs_lease_udp_recv_fn, mxfs_mount
  fn mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_set_broadcast(mxfs_sock_t *s) -> int
  fn mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_time_ms(void) -> uint64_t
    called_by: bast_poll_fn, bast_worker_fn, caw_acquire_poll_sleep, caw_bast_disp_fn, caw_convert_body, caw_force_release_self_body, caw_grant_meta_seq, caw_join_bounded, caw_nudge_ring_wants_wake, caw_open_clear_body, caw_open_set_body, caw_owed_dispatch, caw_owed_fail_latch, caw_owed_release, caw_owed_sweep
  fn mxfs_pal_time_real_ms(void) -> uint64_t
    called_by: caw_exwin_log, caw_yield_stamp
  fn mxfs_pal_sleep_ms(uint32_t ms) -> void
    called_by: caw_grant_meta_store_unless_releasing, caw_grant_seq_prebump, caw_inode_backoff, caw_nudge_ring_wants_wake, caw_open_set_body, caw_owed_worker_fn, caw_release_mark, caw_slot, dlm_bast_cb, dlm_lock_impl, dlm_membership_settling, killpoint_run, lreq_clr_still_good, ls_rt_fn, membership_stab_worker_fn
  fn mxfs_pal_sleep_ms_interruptible(uint32_t ms) -> void
    calls: mxfs_pal_sleep_ms
    called_by: v5_fence_retry_worker_fn
  fn mxfs_pal_cond_resched(void) -> void
    called_by: caw_purge_dead_nodes_body, caw_release_all_body, mxfs_dlm_caw_footprint_scan
  fn mxfs_pal_log(int level, const char *fmt, ...) -> void
    called_by: ack_process, bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bast_submit, caw_bastq_init, caw_check_exclusion, caw_convert_body, caw_count_resource_slots, caw_flush_held_body, caw_force_release_self_body, caw_grant_epoch_update, caw_grant_meta_seq
  fn mxfs_pal_failstop_fn(const char *fmt, ...) -> void
  fn static mxfs_defer_thread(void *p) -> void
  fn static scsi_pr_out(int fd, uint8_t sa, uint64_t key, uint64_t sa_key, uint8_t type) -> int
    called_by: mxfs_pal_scsi_pr_preempt, mxfs_pal_scsi_pr_register, mxfs_pal_scsi_pr_reserve, mxfs_pal_scsi_pr_unregister
  fn static scsi_pr_in_read_keys(int fd, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    called_by: mxfs_pal_scsi_pr_read_keys
  fn mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key) -> int
    calls: scsi_pr_out
    called_by: mxfs_scsipr_register
  fn mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key, uint32_t type) -> int
    calls: scsi_pr_out
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_reserve
  fn mxfs_pal_scsi_pr_report_capabilities(mxfs_bdev_t *dev, struct mxfs_pal_pr_caps *out) -> int
    called_by: mxfs_scsipr_validate_admission
  fn mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key, uint64_t victim_key, bool abort, uint32_t type) -> int
    calls: scsi_pr_out
    called_by: mxfs_scsipr_preempt
  fn mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key) -> int
    calls: scsi_pr_out
    called_by: mxfs_scsipr_unregister
  fn mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    calls: scsi_pr_in_read_keys
    called_by: mxfs_scsipr_read_keys
  fn mxfs_pal_scsi_pr_read_reservation(mxfs_bdev_t *dev, struct mxfs_pal_pr_reservation *out) -> int
  fn mxfs_pal_scsi_pr_read_full_status(mxfs_bdev_t *dev, uint64_t key, int *present, uint32_t *generation) -> int
    called_by: mxfs_scsipr_fenced_check
  fn mxfs_pal_sdev_cache_release(void) -> void
  fn mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset, const void *compare_buf, const void *write_buf) -> int
    called_by: caw_repair_slot, caw_slot, caw_watch_armed, hb_cas_own_slot, mxfs_disklock_claim_slot, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_release_slot, mxfs_disklock_unguard, mxfs_disklock_withdraw, mxfs_mount, purge_cas_zero, recov_cas_durable
  fn mxfs_pal_get_hostname(char *buf, size_t len) -> int
  fn mxfs_pal_read_file(const char *path, void *buf, size_t buf_size) -> int
    called_by: load_node_uuid
  fn mxfs_pal_get_random_bytes(void *buf, size_t len) -> void
    calls: read
    called_by: caw_inode_backoff, caw_mint_lineage, hb_draw_incarnation, hb_prov_derive, mxfs_generate_random_uuid, mxfs_v5_dlm_init, net2_membership_boot_nonce, net2_selftest_fn
  fn static crc32c_table_init(void) -> void
  fn mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: build_symlink_hdr_v5, flush_superblock_counters, hb_feature_crc, hb_prov_crc, mxfs_journal_txn_commit, mxfs_mepoch_rec_seal, mxfs_mepoch_rec_valid, mxfs_mount, read_entry_at, recov_outcome_crc, sector_crc, serialize_entry
  struct mxfs_bdev { fd, base_offset, is_clone, path }
  struct mxfs_thread { tid, arg }
  struct mxfs_mutex { mtx }
  struct mxfs_spinlock { mtx }
  struct mxfs_rwlock { rwl }
  struct mxfs_cond { cv }
  struct mxfs_sock { fd, is_udp }
  struct mxfs_defer_arg { arg }

[pal/linux/xfs_aops.c]
  fn static xfs_ioend_is_append(struct iomap_ioend *ioend) -> bool
  fn static mxfs_ailstuck_probe_param_set(const char *val, const struct kernel_param *kp) -> int
  fn static mxfs_ailstuck_probe_param_get(char *buffer, const struct kernel_param *kp) -> int
    calls: atomic_read
  struct xfs_writepage_ctx { ctx, data_seq, cow_seq }
  struct xfs_wptask { node, task }

[pal/linux/xfs_bio_io.c]
  fn static bio_max_vecs(unsigned int count) -> unsigned int

[pal/linux/xfs_buf.c]
  fn static xfs_buf_is_uncached(struct xfs_buf *bp) -> bool
  fn xfs_buf_set_ref(struct xfs_buf *bp, int lru_ref) -> void
  struct mxfs_wrtr_ent { ns, daddr, owner, mask, crc, cnt, pid, flags, type, gmode }

[pal/linux/xfs_buf_item.c]
  fn static BUF_ITEM(struct xfs_log_item *lip) -> struct xfs_buf_log_item
    calls: container_of
  struct mxfs_buf_owner { ino, valid }
  struct mxfs_ownauth_snap { epoch, res, lineage, gen, try_gen, try_epoch, auth_line, try_line, dlm_mode, try }

[pal/linux/xfs_buf_item_recover.c]
  struct xfs_buf_cancel { bc_blkno, bc_len, bc_refcount, bc_list }

[pal/linux/xfs_drain.c]
  fn static xfs_defer_drain_grab(struct xfs_defer_drain *dr) -> void
  fn static has_waiters(struct wait_queue_head *wq_head) -> bool
    called_by: xfs_defer_drain_rele
  fn static xfs_defer_drain_rele(struct xfs_defer_drain *dr) -> void
    calls: has_waiters
  fn static xfs_defer_drain_busy(struct xfs_defer_drain *dr) -> bool
    calls: atomic_read
    called_by: xfs_defer_drain_wait
  fn static xfs_defer_drain_wait(struct xfs_defer_drain *dr) -> int
    calls: xfs_defer_drain_busy

[pal/linux/xfs_export.c]
  fn static xfs_fileid_length(int fileid_type) -> int
    calls: xfs_nfs_get_inode

[pal/linux/xfs_file.c]
  fn static xfs_file_sync_writes(struct file *filp) -> bool

[pal/linux/xfs_healthmon.c]
  fn static xfs_healthmon_bump_events(struct xfs_healthmon *hm) -> void
  fn static xfs_healthmon_bump_lost(struct xfs_healthmon *hm) -> void
  fn static file_ioerr_type(enum fserror_type action) -> enum xfs_healthmon_type
  fn static shutdown_mask(unsigned int in) -> unsigned int
  struct flags_map { in_mask, out_mask }

[pal/linux/xfs_mru_cache.c]
  struct xfs_mru_cache { store, lists, reap_list, lock, grp_count, grp_time, lru_grp, time_zero, free_func, work }

[pal/linux/xfs_notify_failure.c]
  struct xfs_failure_info { startblock, blockcount, mf_flags, want_shutdown }

[pal/linux/xfs_stats.c]
  fn static counter_val(struct xfsstats __percpu *stats, int idx) -> int
    called_by: xfs_stats_format, xqm_proc_show, xqmstat_proc_show
  fn xfs_stats_format(struct xfsstats __percpu *stats, char *buf) -> int
    calls: counter_val
  fn xfs_stats_clearall(struct xfsstats __percpu *stats) -> void
  fn static xqm_proc_show(struct seq_file *m, void *v) -> int
    calls: counter_val
  fn static xqmstat_proc_show(struct seq_file *m, void *v) -> int
    calls: counter_val

[pal/linux/xfs_super.c]
  fn static mxfs_resolve_dead_timeout_ms(void) -> unsigned int
  fn static mxfs_compute_cache_caps(void) -> void
    calls: pr_info
  enum xfs_dax_mode { XFS_DAX_INODE, XFS_DAX_ALWAYS, XFS_DAX_NEVER }
  struct proc_xfs_info { flag, str }
  struct mxfs_cache_caps { inode, dlm_lock, dir, block }

[pal/linux/xfs_sysfs.c]
  fn static zoned_to_mp(struct kobject *kobj) -> struct xfs_mount
    calls: container_of
  struct xfs_sysfs_attr { attr }
  struct xfs_error_init { name, max_retries, retry_timeout }

[pal/linux/xfs_verify_media.c]
  struct xfs_group_data_lost { startblock, blockcount }

[pal/pal.h]
  fn mxfs_pal_bdev_open(const char *path) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close(mxfs_bdev_t *dev) -> void
    called_by: mxfs_mount, mxfs_unmount
  fn mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    called_by: disklock_hb_fn, fs_identity_changed, hb_report_claim_exhausted, mxfs_disklock_claim_slot, mxfs_disklock_find_node_slot, mxfs_disklock_get_slot_node_id, mxfs_disklock_get_stale_slot_mask, mxfs_mount, mxfs_pal_bdev_read_async, mxfs_pal_bdev_read_prio, mxfs_write_direct, read_sector, readlink_remote
  fn mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
    called_by: caw_purge_dead_nodes_body, caw_slot, disklock_hb_fn, hb_cas_own_slot, mxfs_disklock_claim_slot_noncaw, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_join_gate, mxfs_disklock_recovery_advance, mxfs_disklock_recovery_backfill_legacy, mxfs_disklock_recovery_claim, mxfs_disklock_recovery_fence_arm_submit, mxfs_disklock_recovery_fence_retryable, mxfs_disklock_recovery_fence_takeover, mxfs_disklock_recovery_read
  fn mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    called_by: is_revoked, mxfs_journal_replay, mxfs_journal_txn_commit, mxfs_pal_bdev_write_async, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather, mxfs_pal_bdev_write_gather_fua, mxfs_write_direct, write_sector
  fn mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    called_by: mxfs_pal_bdev_write_gather_fua, write_sector_fua
  fn mxfs_pal_bdev_flush(mxfs_bdev_t *dev) -> int
    called_by: checkpoint_locked, mxfs_fsync, mxfs_journal_checkpoint, mxfs_journal_flush, mxfs_journal_format, mxfs_journal_replay, mxfs_journal_write_unmount, mxfs_pal_bdev_write_fua, mxfs_pal_bdev_write_gather_fua, mxfs_sync_fs, mxfs_v5_dlm_recovery_complete, recov_cas_durable
  fn mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out) -> int
    called_by: mxfs_mount
  fn mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len) -> int
    called_by: mxfs_write_direct
  fn mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev, const uint64_t *offsets, void * const *bufs, const uint32_t *lens, int count) -> int
  fn mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len) -> int
  fn mxfs_pal_bdev_write_gather(mxfs_bdev_t *dev, uint64_t offset, void **bufs, int nbufs, uint32_t blocksize) -> int
    called_by: mxfs_pal_bdev_write, mxfs_pal_bdev_write_gather_fua
  fn mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset, void **bufs, int nbufs, uint32_t blocksize) -> int
  fn mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev, uint64_t base_offset) -> mxfs_bdev_t
    called_by: mxfs_mount
  fn mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev) -> void
    called_by: mxfs_mount, mxfs_unmount, mxfs_v5_dlm_init, mxfs_v5_dlm_shutdown_defer_release, mxfs_v5_dlm_slot_release_commit
  fn mxfs_pal_bdev_wrap(struct block_device *bdev) -> mxfs_bdev_t
    called_by: mxfs_v5_dlm_init
  fn mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev, uint64_t *writes, uint64_t *write_bytes, uint64_t *writes_fua, uint64_t *write_fua_bytes, uint64_t *flushes) -> void
  fn mxfs_pal_alloc(size_t size) -> void
    called_by: bast_poll_fn, caw_bastq_init, caw_convert_body, caw_count_resource_slots, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole, fallocate_zero_range, flush_superblock_counters
  fn mxfs_pal_free(void *ptr) -> void
    called_by: bast_poll_fn, bast_worker_fn, caw_bastq_free, caw_convert_body, caw_count_resource_slots, caw_create_unwind, caw_force_release_self_body, caw_open_clear_body, caw_open_set_body, caw_owed_resolve, caw_purge_dead_nodes_body, caw_release_all_body, caw_verify_grant_persisted, disklock_hb_fn, fallocate_punch_hole
  fn mxfs_pal_realloc(void *ptr, size_t new_size) -> void
  fn mxfs_pal_thread_join(mxfs_thread_t *t) -> void
    called_by: mxfs_discovery_start, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_lease_start, mxfs_lease_stop, mxfs_mount, mxfs_net2_selftest_stop, mxfs_net2_stop, mxfs_peer_accept_fn, mxfs_peer_shutdown, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, net2_link_reap, net2_link_shutdown_all, net2_lockspace_stop
  fn mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms) -> int
    called_by: caw_join_bounded, mxfs_disklock_stop_heartbeat
  fn mxfs_pal_thread_pid(mxfs_thread_t *t) -> int
    called_by: mxfs_disklock_start_heartbeat
  fn mxfs_pal_mutex_create(void) -> mxfs_mutex_t
    called_by: caw_bastq_init, mep_env_start, mxfs_disklock_create, mxfs_dlm_create, mxfs_journal_create, mxfs_mount, mxfs_net2_create, mxfs_peer_accept_fn, mxfs_peer_add, mxfs_peer_init, mxfs_v5_dlm_init, net2_lockspace_create, net2_membership_create, net2_mepoch_create, net2_selftest_fn
  fn mxfs_pal_mutex_destroy(mxfs_mutex_t *m) -> void
    called_by: caw_bastq_free, caw_create_unwind, mep_env_stop, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_destroy, mxfs_journal_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_peer_init, mxfs_peer_shutdown
  fn mxfs_pal_mutex_lock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_mutex_unlock(mxfs_mutex_t *m) -> void
    called_by: bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bastq_join_workers, caw_convert_body, caw_flush_held_body, caw_grant_meta_get, caw_grant_meta_get_epoch, caw_grant_meta_store, caw_grant_seq_prebump, caw_join_bounded, caw_nudge_check, caw_nudge_prepare
  fn mxfs_pal_spinlock_create(void) -> mxfs_spinlock_t
  fn mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s) -> void
    called_by: caw_create_unwind, mxfs_dlm_caw_destroy
  fn mxfs_pal_spinlock_lock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s) -> void
    called_by: mxfs_dlm_caw_orphan_clock_get, mxfs_dlm_caw_orphan_clock_set
  fn mxfs_pal_rwlock_create(void) -> mxfs_rwlock_t
    called_by: mxfs_dlm_create
  fn mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_destroy
  fn mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw) -> void
    called_by: mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_withdraw_release_all
  fn mxfs_pal_rwlock_tryrdlock(mxfs_rwlock_t *rw) -> int
    called_by: mxfs_dlm_held_mode_nb
  fn mxfs_pal_may_sleep(void) -> int
    called_by: mxfs_dlm_held_mode
  fn mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_unlock_gen, mxfs_dlm_update_active_nodes
  fn mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw) -> void
    called_by: dlm_lock_impl, mxfs_dlm_destroy, mxfs_dlm_grant_dir_epoch, mxfs_dlm_grant_gen, mxfs_dlm_grant_was_handoff, mxfs_dlm_granted_mode, mxfs_dlm_held_mode, mxfs_dlm_held_mode_nb, mxfs_dlm_lock_convert, mxfs_dlm_process_remote_release, mxfs_dlm_purge_node, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_release_all, mxfs_dlm_release_orphan_if_unheld, mxfs_dlm_unlock_gen
  fn mxfs_pal_cond_create(void) -> mxfs_cond_t
    called_by: caw_bastq_init, mxfs_disklock_create, mxfs_mount, mxfs_net2_create, net2_lockspace_create, pending_alloc
  fn mxfs_pal_cond_destroy(mxfs_cond_t *c) -> void
    called_by: caw_bastq_free, caw_create_unwind, mxfs_discovery_destroy, mxfs_disklock_create, mxfs_disklock_destroy, mxfs_dlm_caw_destroy, mxfs_lease_destroy, mxfs_mount, mxfs_net2_create, mxfs_net2_destroy, mxfs_unmount, net2_lockspace_destroy, pending_alloc, pending_free
  fn mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m) -> void
    called_by: bast_worker_fn
  fn mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m, uint64_t timeout_ms) -> int
    called_by: bast_poll_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_nudge_ring_wants_wake, caw_owed_worker_fn, creq_wait, disklock_hb_fn, disklock_hb_watchdog_fn, mxfs_discovery_send_fn, mxfs_dlm_caw_stop, mxfs_lease_monitor_fn, mxfs_lease_renew_fn, net2_link_egress_fn, pending_wait
  fn mxfs_pal_cond_signal(mxfs_cond_t *c) -> void
    called_by: caw_bast_disp_fn, dlm_membership_cb, mxfs_dlm_caw_start, mxfs_dlm_caw_stop, mxfs_mount, mxfs_unmount, net2_link_kick, queue_membership_update
  fn mxfs_pal_cond_broadcast(mxfs_cond_t *c) -> void
    called_by: bast_recv_fn, caw_bastq_join_workers, caw_op_leave, caw_owe_residue, lreq_clr_end, lreq_finish, mxfs_discovery_stop, mxfs_disklock_stop_heartbeat, mxfs_dlm_caw_stop, mxfs_lease_stop, net2_link_down, net2_link_shutdown_all, net2_lock_client_rx, net2_lockspace_stop
  fn mxfs_pal_tcp_connect(const char *host, uint16_t port) -> mxfs_sock_t
    called_by: net2_link_conn_fn, scen_mc_malformed_cross
  fn mxfs_pal_tcp_listen(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_peer_init, net2_link_listen_start
  fn mxfs_pal_tcp_accept(mxfs_sock_t *listener) -> mxfs_sock_t
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len) -> int
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, net2_link_accept_fn, net2_link_conn_fn, net2_link_send_bytes, scen_mc_malformed_cross
  fn mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len) -> int
    called_by: mxfs_peer_accept_fn, mxfs_peer_recv_fn, mxfs_peer_shutdown, net2_read_frame
  fn mxfs_pal_tcp_set_opts(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn, net2_link_conn_fn
  fn mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len) -> int
    called_by: mxfs_peer_accept_fn, net2_link_accept_fn
  fn mxfs_pal_tcp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_send, mxfs_peer_shutdown, net2_link_connect, net2_link_down, net2_link_install, net2_link_shutdown_all, peer_handle_disconnect
  fn mxfs_pal_tcp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_peer_accept_fn, mxfs_peer_shutdown, net2_fault_check, net2_link_accept_fn, net2_link_conn_fn, net2_link_install, net2_link_listen_start, net2_link_reap, net2_link_shutdown_all, scen_mc_malformed_cross
  fn mxfs_pal_udp_open(uint16_t port) -> mxfs_sock_t
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_shutdown(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_stop, mxfs_dlm_caw_stop, mxfs_lease_stop
  fn mxfs_pal_udp_close(mxfs_sock_t *s) -> void
    called_by: mxfs_discovery_destroy, mxfs_dlm_caw_destroy, mxfs_dlm_caw_start, mxfs_lease_destroy
  fn mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len, const char *host, uint16_t port) -> int
    called_by: caw_send_bast_mcast, caw_send_grant_mcast, mxfs_discovery_send_fn, mxfs_lease_renew_fn
  fn mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len, char *from_host, size_t host_len, uint16_t *from_port) -> int
    called_by: bast_recv_fn, mxfs_discovery_recv_fn, mxfs_lease_udp_recv_fn, mxfs_mount
  fn mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_udp_set_broadcast(mxfs_sock_t *s) -> int
  fn mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms) -> int
    called_by: mxfs_dlm_caw_start
  fn mxfs_pal_time_ms(void) -> uint64_t
    called_by: bast_poll_fn, bast_worker_fn, caw_acquire_poll_sleep, caw_bast_disp_fn, caw_convert_body, caw_force_release_self_body, caw_grant_meta_seq, caw_join_bounded, caw_nudge_ring_wants_wake, caw_open_clear_body, caw_open_set_body, caw_owed_dispatch, caw_owed_fail_latch, caw_owed_release, caw_owed_sweep
  fn mxfs_pal_time_real_sec(void) -> uint64_t
    called_by: fallocate_prealloc, fallocate_punch_hole, fallocate_zero_range, mxfs_chmod, mxfs_chown, mxfs_utimes, mxfs_write
  fn mxfs_pal_time_real_ms(void) -> uint64_t
    called_by: caw_exwin_log, caw_yield_stamp
  fn mxfs_pal_sleep_ms(uint32_t ms) -> void
    called_by: caw_grant_meta_store_unless_releasing, caw_grant_seq_prebump, caw_inode_backoff, caw_nudge_ring_wants_wake, caw_open_set_body, caw_owed_worker_fn, caw_release_mark, caw_slot, dlm_bast_cb, dlm_lock_impl, dlm_membership_settling, killpoint_run, lreq_clr_still_good, ls_rt_fn, membership_stab_worker_fn
  fn mxfs_pal_sleep_ms_interruptible(uint32_t ms) -> void
    called_by: v5_fence_retry_worker_fn
  fn mxfs_pal_cond_resched(void) -> void
    called_by: caw_purge_dead_nodes_body, caw_release_all_body, mxfs_dlm_caw_footprint_scan
  fn mxfs_pal_log(int level, const char *fmt, ...) -> void
    called_by: ack_process, bast_poll_fn, bast_recv_fn, bast_worker_fn, cache_flush_worker_fn, caw_bast_disp_fn, caw_bast_submit, caw_bastq_init, caw_check_exclusion, caw_convert_body, caw_count_resource_slots, caw_flush_held_body, caw_force_release_self_body, caw_grant_epoch_update, caw_grant_meta_seq
  fn mxfs_pal_dump_stack(void) -> void
    called_by: mxfs_dlm_lock_retries
  fn mxfs_pal_dump_task_stack(int pid) -> void
    called_by: disklock_hb_watchdog_fn
  fn mxfs_pal_failstop_fn(const char *fmt, ...) -> void
  fn mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: build_symlink_hdr_v5, flush_superblock_counters, hb_feature_crc, hb_prov_crc, mxfs_journal_txn_commit, mxfs_mepoch_rec_seal, mxfs_mepoch_rec_valid, mxfs_mount, read_entry_at, recov_outcome_crc, sector_crc, serialize_entry
  fn mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key) -> int
    called_by: mxfs_scsipr_register
  fn mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key, uint32_t type) -> int
    called_by: mxfs_scsipr_check_reservation_health, mxfs_scsipr_reserve
  fn mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key, uint64_t victim_key, bool abort, uint32_t type) -> int
    called_by: mxfs_scsipr_preempt
  fn mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key) -> int
    called_by: mxfs_scsipr_unregister
  fn mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys, int max_keys, int *count, uint32_t *generation, int *total) -> int
    called_by: mxfs_scsipr_read_keys
  fn mxfs_pal_scsi_pr_read_full_status(mxfs_bdev_t *dev, uint64_t key, int *present, uint32_t *generation) -> int
    called_by: mxfs_scsipr_fenced_check
  fn mxfs_pal_scsi_pr_read_reservation(mxfs_bdev_t *dev, struct mxfs_pal_pr_reservation *out) -> int
  fn mxfs_pal_scsi_pr_report_capabilities(mxfs_bdev_t *dev, struct mxfs_pal_pr_caps *out) -> int
    called_by: mxfs_scsipr_validate_admission
  fn mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset, const void *compare_buf, const void *write_buf) -> int
    called_by: caw_repair_slot, caw_slot, caw_watch_armed, hb_cas_own_slot, mxfs_disklock_claim_slot, mxfs_disklock_guard_refresh, mxfs_disklock_guard_slot, mxfs_disklock_release_slot, mxfs_disklock_unguard, mxfs_disklock_withdraw, mxfs_mount, purge_cas_zero, recov_cas_durable
  fn mxfs_pal_sdev_cache_release(void) -> void
  fn mxfs_pal_bdev_get_bdev(mxfs_bdev_t *dev) -> struct block_device
  fn mxfs_pal_bdev_get_base_offset(mxfs_bdev_t *dev) -> uint64_t
  fn mxfs_pal_io_budget_enter(struct mxfs_pal_io_budget *b, uint32_t ms) -> void
  fn mxfs_pal_io_budget_exit(struct mxfs_pal_io_budget *b) -> void
  fn mxfs_pal_get_hostname(char *buf, size_t len) -> int
  fn mxfs_pal_read_file(const char *path, void *buf, size_t buf_size) -> int
    called_by: load_node_uuid
  fn mxfs_pal_get_random_bytes(void *buf, size_t len) -> void
    called_by: caw_inode_backoff, caw_mint_lineage, hb_draw_incarnation, hb_prov_derive, mxfs_generate_random_uuid, mxfs_v5_dlm_init, net2_membership_boot_nonce, net2_selftest_fn
  fn atomic_read(&a->val) -> return
    called_by: inode_dio_probe_init, inode_dio_release_init, mxfs_ailstuck_probe_param_get, mxfs_dlm_open_last_close, mxfs_dlm_open_protect, mxfs_lru_sweep_fn, mxfs_pin_census_set, xfs_defer_drain_busy
  fn atomic_inc_return(&a->val) -> return
    called_by: dg_grant_ex, dlm_lock_impl, fire_bast_records, lock_alloc, lock_free, mxfs_dlm_audit_double_grant, mxfs_dlm_grant_dir_epoch, mxfs_dlm_lock_retries, mxfs_dlm_open_protect, mxfs_dlm_unlock_gen, mxfs_iunl_discrim, mxfs_iunl_store_purge_ag, mxfs_pal_scsi_read_fua_bdev, promote_waiters
  fn atomic_dec_return(&a->val) -> return
  fn __atomic_load_n(&a->val, __ATOMIC_SEQ_CST) -> return
  fn __atomic_add_fetch(&a->val, 1, __ATOMIC_SEQ_CST) -> return
  fn __atomic_sub_fetch(&a->val, 1, __ATOMIC_SEQ_CST) -> return
  fn bswap_16(v) -> return
  fn bswap_32(v) -> return
  fn bswap_64(v) -> return
  fn bswap_16(v) -> return
  fn bswap_32(v) -> return
  fn bswap_64(v) -> return
  struct mxfs_pal_pr_reservation { key, generation, type, held }
  struct mxfs_pal_pr_caps { type_mask, ptpl_c, ptpl_a, crh, sip_c, atp_c, tmv, we_ro, we_ar, abort_capable }
  struct mxfs_pal_io_budget { task, deadline_j, node }
  struct mxfs_atomic32 { val }
  struct mxfs_atomic32 { val }

[scripts/caw_slot_dump.py]
  fn main()

[scripts/caw_slot_sampler.py]
  fn find_slot(dev, offset, ino, args_ltype=1)
    called_by: caw_convert_body, caw_open_clear_body, caw_open_set_body, mxfs_dlm_caw_dump_slot, mxfs_dlm_caw_granted_mode, mxfs_dlm_caw_held, mxfs_dlm_caw_open_holders, mxfs_dlm_caw_open_probe, mxfs_dlm_caw_read_generation, mxfs_dlm_caw_set_dir_block0
  fn main()

[scripts/ccloop_behavior_audit.py]
  fn session_ids(run, lo, hi)
  fn handoff_freshness(run, pairs)
  fn walk_tools(path)
  fn classify(name, inp)
  fn main()

[scripts/ccloop_quota_probe.py]
  fn parse_ts(rec)
  fn collect(projects_dir, exclude)
  fn weeks(turns, n_weeks)
  fn totals(turns, lo, hi)
    called_by: validate_inobt_leaf
  fn m(x)
  fn main()

[scripts/ccloop_request_audit.py]
  fn bucket(peak)
    called_by: mxfs_dlm_caw_orphan_clock_set
  fn family(model)
  fn scan(path)
    called_by: mxfs_v5_dlm_shutdown_withdraw
  fn main()
  fn parse(s)

[scripts/ccloop_subagent_billing_check.py]
  fn scan(path)
    called_by: mxfs_v5_dlm_shutdown_withdraw
  fn main()

[scripts/ccloop_token_audit.py]
  fn parse_ts(rec)
  fn audit_file(path, win=None)
  fn fmt(n)
  fn main()
  fn parse_bound(s, default)

[scripts/decode_bufev.py]
  fn flags_str(f)
  fn decode_val(v)
  fn decode_line(line)
  fn main()

[scripts/dir_leaf_dump.py]
  fn be32(b, o)
  fn be16(b, o)
  fn be64(b, o)
  fn rol32(x, r)
  fn xfs_da_hashname(name: bytes) -> int
  fn main()
  fn fsb_to_byte(fsb)

[scripts/gen_criteria.py]
  fn default_max_nodes(category, name)
  fn load_json(path)

[scripts/inode_dio_probe/inode_dio_probe.c]
  fn static inode_dio_probe_init(void) -> int __init
    calls: atomic_read, pr_err, pr_info
  fn static inode_dio_probe_exit(void) -> void __exit

[scripts/inode_dio_release/inode_dio_release.c]
  fn static owner_task_live_pid(unsigned long ownraw) -> long
    called_by: inode_dio_release_init
  fn static wake_dio_waiters(struct inode *inode) -> void
    called_by: inode_dio_release_init
  fn static inode_dio_release_init(void) -> int __init
    calls: atomic_read, owner_task_live_pid, pr_err, pr_info, wake_dio_waiters
  fn static inode_dio_release_exit(void) -> void __exit

[scripts/loop_unwedge/kcore_walk.py]
  fn __init__(self, path="/proc/kcore")
  fn read(self, addr, size)
    called_by: bast_recv_fn, disklock_hb_fn, main, mxfs_disklock_claim_slot, mxfs_pal_get_random_bytes, mxfs_pal_scsi_read_fua_bdev, run_child, v5_membership_beacon_caw
  fn u64(self, a)
  fn u32(self, a)
  fn s32(self, a)
  fn u8(self, a)
  fn cstr(self, a, maxlen=64)
  fn __init__(self)
  fn sym(self, addr)
  fn walk_list(head, entry_off, cap=64)
  fn rb_walk(node, depth=0)
  fn task_info(t)
  class Kcore
  class Ksyms

[scripts/loop_unwedge/loop_unwedge.c]
  fn static lu_survey_bio(struct bio *bio, int rqidx, int bidx) -> int
    called_by: lu_iter
  fn static lu_kill_bio(struct bio *bio) -> void
    called_by: lu_iter
  fn static lu_iter(struct request *rq, void *priv) -> bool
    calls: lu_kill_bio, lu_survey_bio, pr_info
  fn static loop_unwedge_init(void) -> int __init
    calls: pr_err, pr_info
  fn static loop_unwedge_exit(void) -> void __exit
  struct lu_ctx { pass, nr_inflight, nr_suspect, nr_completed, nr_bios }

[scripts/loop_unwedge/wq_probe.py]
  fn sym(addr)
  fn safe_str(obj)

[scripts/matrix_check.py]
  fn parse_iso(s)
  fn base_transport(cond)
  fn check_cond(d, cond, nodes, since, since_raw)
  fn main()

[scripts/mxfs_dirdump.py]
  fn be(b, off, n)
  fn xfs_hash(name: bytes) -> int
  fn __init__(self, path)
  fn rd(self, byteoff, n)
  fn daddr_bytes(self, daddr)
  fn fsb_to_daddr(self, fsbno)
  fn ino_daddr_off(self, ino)
  fn read_dinode(self, ino)
  fn extents(self, dinode)
    called_by: mxfs_seek_data, mxfs_write
  fn walk_data_block(img, blk, daddr)
  fn walk_leaf(img, blk)
  fn main()
  class Img

[scripts/p291_aggregate.py]
  fn parse(d)
  fn main()

[scripts/p29_replay.py]
  fn parse(paths)
  fn fmt(r, t0)
  fn main()

[scripts/scst_atomic_edges.py]
  fn offsetof(struct, member)
  fn walk_list(head_addr, struct, member)
  fn kallsyms(name)
  fn main()

[scripts/scst_atomic_wedge_diag.py]
  fn offsetof(struct, member)
  fn walk_list(head_addr, struct, member)
  fn dump_dev(dev)
  fn kallsyms(name)
  fn main()

[scripts/scst_block_diag.py]
  fn dwarf_offsets(ko)
  fn kallsym(name)
  fn main()
  fn rd(addr, n)
  fn ru64(addr)
  fn ri32(addr)
  fn ru32(addr)
  fn cstr(addr)
  fn list_count(lh)

[scripts/scst_mon.py]
  fn gdb_off()
  fn kallsym(n)
  fn cstr(a)
  fn blkcnt(lh)
  fn stop(*a)
    called_by: caw_owed_release, caw_owed_worker_fn, caw_release_all_body, lreq_finish, mxfs_dlm_caw_destroy, mxfs_unmount, mxfs_v5_dlm_shutdown_defer_release, net2_midcomms_bind

[scripts/scst_unwedge/scst_unwedge.c]
  fn static scst_unwedge_init(void) -> int __init
    calls: pr_err, pr_info
  fn static scst_unwedge_exit(void) -> void __exit

[scripts/sess33_bmbt_dump.py]
  fn rd(off, n)
  fn fsb_to_daddr(fsb)
  fn ino_to_daddr_off(ino)
  fn unpack_rec(l0, l1)

[scripts/vm_console_type.py]
  fn send(dom, codes)
    called_by: mxfs_pal_tcp_send
  fn type_char(dom, ch)
  fn type_string(dom, s)
  fn main()

[scripts/xlog_slice_scan.py]
  fn load(path)
  fn cycle_lsn(lsn)
  fn main()

[scripts/xref_owners.py]
  fn main()
  fn agb_bytes(agno, agbno)
  fn fsb_split(fsb)
  fn rawfsb(agno, agbno)
  fn claim(agno, agbno, count, tag)
    called_by: mxfs_disklock_claim_slot, mxfs_v5_dlm_init
  fn walk_inobt(agbno, lvl)
    called_by: check_inode_btrees

[tests/caw/caw_align_probe.c]
  fn static sgio(int fd, unsigned char *cdb, int cdb_len, void *buf, int len, int dir, int *miscompare) -> int
    called_by: main
  fn static read16_fua(int fd, uint64_t lba, void *buf) -> int
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: read16_fua, sgio

[tests/closure_foot_parse.py]
  fn res_agno(typename, ag_field, ino, inoshift)
  fn do_slots(path, bit, inoshift)
  fn do_strips(path, inoshift)

[tests/d3_ring_analyze.py]
  fn parse(harvest_dir)
  fn fmt(r, extra='')
  fn analyze_daddr(recs, daddr, slot=None)
  fn bits_of(v)
  fn auto_scan(recs, p26s, show_all)
  fn main()

[tests/drc_analyze.py]
  fn parse(path)
  fn main()
  fn f(x)

[tests/drc_lap_analyze.py]
  fn parse(path)
  fn main()

[tests/drc_phase_census.py]
  fn parse(path)
  fn main()

[tests/fence_inflight/prprobe.c]
  fn static mono(void) -> double
    called_by: do_clearua, do_dread, do_dwrite, do_poll, do_prin, do_prout, do_write, report
  fn static put_be64(uint8_t *p, uint64_t v) -> void
    called_by: build_xfs_sb_sector, can_repair, do_prout, do_write, print_summary, write_inode, write_sb_sector
  fn static put_be32(uint8_t *p, uint32_t v) -> void
    called_by: build_xfs_sb_sector, check_freespace_btrees, check_inode_btrees, do_prout, do_upgrade_protogate, do_write, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static get_be64(const uint8_t *p) -> uint64_t
    called_by: check_inode_spotcheck, check_one_inode, do_prin, orphan_collect_leaf, parse_xfs_sb, report, validate_inobt_leaf
  fn static get_be32(const uint8_t *p) -> uint32_t
    called_by: check_inode_spotcheck, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, do_prin, do_upgrade_protogate, orphan_collect_leaf, orphan_walk_chain, parse_xfs_sb, read_ag_block, read_at, report, validate_freespace_leaf, validate_inobt_leaf
  fn static report(const char *tag, struct sg_io_hdr *io, int rc, int saved_errno, double t0, double t1, const uint8_t *sense) -> int
    calls: get_be32, get_be64, mono
    called_by: do_prin, do_prout, do_write
  fn static do_prout(int argc, char **argv) -> int
    calls: mono, put_be32, put_be64, report
    called_by: main
  fn static do_prin(int argc, char **argv) -> int
    calls: get_be32, get_be64, mono, report
    called_by: main
  fn static do_clearua(int argc, char **argv) -> int
    calls: mono
    called_by: main
  fn static do_write(int argc, char **argv) -> int
    calls: mono, put_be32, put_be64, report
    called_by: main
  fn static do_poll(int argc, char **argv) -> int
    calls: mono
    called_by: main
  fn static do_dwrite(int argc, char **argv) -> int
    calls: mono
    called_by: main
  fn static do_dread(int argc, char **argv) -> int
    calls: mono
    called_by: main
  fn static do_fiemap(int argc, char **argv) -> int
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: do_clearua, do_dread, do_dwrite, do_fiemap, do_poll, do_prin, do_prout, do_write

[tests/fence_inflight/verdict.py]
  fn split_stacks(dmesg)
  fn readenv(p)
  fn kv(line)
  fn find_line(path, prefix)
  fn parse_trace(path, majmin_loop, majmin_dm, lba, nsect)
  fn first(lst)
    called_by: main, mxfs_disklock_find_node_slot, mxfs_peer_shutdown, mxfs_unmount, net2_midcomms_rx, promote_waiters
  fn last(lst)
  fn fmt(t, base)
  fn main()
  fn majmin(devno)
  fn blk_ts(ev, dev, rw_has="W")

[tests/mxfs_stackprof.py]
  fn frames(pid, tid)
  fn signature(fr)
    called_by: mxfs_lease_udp_recv_fn
  fn main()

[tests/net2/harness/harness.h]
  fn vc_create(struct vcluster **vc_out, int n, uint64_t seed, uint32_t compress, uint16_t tx_win_override) -> int
    called_by: mep_env_start, scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart
  fn vc_node_start(struct vcluster *vc, int i) -> int
    called_by: vc_create, vc_node_restart
  fn vc_node_kill(struct vcluster *vc, int i) -> void
    called_by: scen_mc_ambiguity, scen_mc_restart, scen_mep_prepared_adoption, scen_mep_stall, shenv_kill, vc_destroy, vc_node_restart
  fn vc_node_restart(struct vcluster *vc, int i) -> int
    called_by: scen_mc_ambiguity, scen_mc_restart, scen_sh_reconfig, scen_sh_xfer_no_vote
  fn vc_view_node(struct vcluster *vc, int i, uint64_t mask, uint64_t epoch) -> void
    called_by: mep_committed_cb, scen_mc_epoch_change, scen_mep_disk_self_fence, vc_node_restart, vc_view_all
  fn vc_view_all(struct vcluster *vc, uint64_t mask, uint64_t epoch) -> void
    called_by: scen_mc_epoch_change, vc_create
  fn vc_destroy(struct vcluster *vc) -> void
    called_by: mep_env_stop, scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart
  fn vc_send(struct vcluster *vc, int from, int to, uint16_t type, uint32_t tag, int reliable, uint32_t msg_id) -> int
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_window_sack, send_burst
  fn vc_send_inc(struct vcluster *vc, int from, int to, uint32_t inc, uint16_t type, uint32_t tag, int reliable, uint32_t msg_id) -> int
    called_by: scen_mc_restart, vc_send
  fn vc_count(struct vcluster *vc, int node, int from_slot, uint16_t type, uint32_t tag) -> int
    called_by: scen_mc_epoch_change, scen_mc_restart, vc_wait_count
  fn vc_wait_count(struct vcluster *vc, int node, int from_slot, uint16_t type, uint32_t tag, int want, int timeout_ms) -> int
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  fn vc_unique_from(struct vcluster *vc, int node, int from_slot, int *dups) -> int
    called_by: scen_mc_delay, scen_mc_dup, scen_mc_loss_ack, scen_mc_reorder, scen_mc_reset_framing, scen_mc_window_sack, vc_assert_invariants
  fn vc_quiesce(struct vcluster *vc, int timeout_ms) -> int
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_window_sack
  fn vc_assert_invariants(struct scenario_ctx *sc, struct vcluster *vc, unsigned flags) -> int
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  fn vc_dump_stats(struct vcluster *vc) -> void
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  struct scenario_ctx { vectors_dir, seed, write_vectors, real_time, checks, failed }
  typedef_fn scenario_fn
  struct scenario { name, fn, real_time_subset }
  struct vc_rec { src_slot, type, src_inc, tag, len }
  struct vc_node { up, slot, inc, nonce, ctx, vc, log_lock, log, log_n, log_overflow }
  struct vcluster { n, base_port, seed, compress, uuid, uuid_hash, epoch, tun, tx_win_override, nodes }

[tests/net2/harness/net2_harness.c]
  fn static vec_path(char *out, size_t cap, const struct scenario_ctx *sc, const char *name) -> int
    called_by: vec_check, vec_write
  fn static vec_write(const struct scenario_ctx *sc, const char *name, const void *buf, size_t len) -> int
    calls: vec_path
    called_by: scen_fault_engine, scen_tlv_roundtrip, scen_wire_golden
  fn static vec_check(const struct scenario_ctx *sc, const char *name, const void *buf, size_t len) -> int
    calls: vec_path
    called_by: scen_fault_engine, scen_tlv_roundtrip, scen_wire_golden
  fn static canonical_hdr(struct mxfs_net2_hdr *h, uint8_t fc) -> void
    called_by: scen_wire_fuzz, scen_wire_golden
  fn static canonical_tlv(uint8_t *buf, int cap) -> int
    called_by: scen_tlv_roundtrip
  fn static canonical_fault_prng(uint8_t *buf /* 8*FAULT_PRNG_COUNT */) -> void
    calls: mxfs_net2_fault_prng_next
    called_by: scen_fault_engine
  fn static canonical_fault_seq(uint8_t *buf /* FAULT_SEQ_COUNT */) -> void
    calls: mxfs_net2_fault_eval, mxfs_net2_fault_init, mxfs_net2_fault_parse_rule, mxfs_net2_fault_set
    called_by: scen_fault_engine
  fn static scen_wire_golden(struct scenario_ctx *sc) -> int
    calls: canonical_hdr, vec_check, vec_write
  fn static scen_wire_fuzz(struct scenario_ctx *sc) -> int
    calls: canonical_hdr, mxfs_net2_fault_prng_next
  fn static scen_tlv_roundtrip(struct scenario_ctx *sc) -> int
    calls: canonical_tlv, vec_check, vec_write
  fn static scen_fault_engine(struct scenario_ctx *sc) -> int
    calls: canonical_fault_prng, canonical_fault_seq, mxfs_net2_fault_eval, mxfs_net2_fault_init, mxfs_net2_fault_parse_rule, mxfs_net2_fault_set, vec_check, vec_write
  fn static run_one(const struct scenario *s, struct scenario_ctx *base) -> int
    called_by: main
  fn static usage(void) -> void
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: run_one, usage

[tests/net2/harness/scen_mepoch.c]
  fn static mep_st_read(void *data, uint16_t slot, struct mxfs_mepoch_rec *out) -> int
  fn static mep_st_write(void *data, const struct mxfs_mepoch_rec *rec) -> int
    called_by: scen_mep_membership
  fn static mep_disk(struct mepenv *env, uint16_t slot, struct mxfs_mepoch_rec *out) -> int
    calls: mxfs_mepoch_rec_valid
    called_by: mep_wait_disk, scen_mep_bootstrap, scen_mep_membership, scen_mep_no_fence_proof
  fn static mep_committed_cb(void *cb_data, const struct mxfs_mepoch_rec *r, const uint32_t *member_incs) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, vc_view_node
  fn static mep_freeze_cb(void *cb_data, bool frozen) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static mep_fence_cb(void *cb_data, uint64_t epoch) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static mep_recv_cb(void *data, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_rx
  fn static mep_node_up(struct mepenv *env, int i, uint32_t lease_ms) -> int
    calls: mxfs_net2_register_recv_cb, net2_mepoch_create
    called_by: mep_env_start, scen_mep_restart_all
  fn static mep_node_down(struct mepenv *env, int i) -> void
    calls: mxfs_net2_register_recv_cb, net2_mepoch_destroy
    called_by: mep_env_stop, scen_mep_prepared_adoption, scen_mep_restart_all, scen_mep_stall
  fn static mep_env_stop(struct mepenv *env) -> void
    calls: mep_node_down, mxfs_pal_mutex_destroy, vc_destroy
    called_by: mep_env_start, scen_mep_bootstrap, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_membership, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_restart_all, scen_mep_stall
  fn static mep_env_start(struct scenario_ctx *sc, struct mepenv *env, int n, uint32_t lease_ms) -> int
    calls: mep_env_stop, mep_node_up, mxfs_pal_mutex_create, vc_create
    called_by: scen_mep_bootstrap, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_membership, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_restart_all, scen_mep_stall
  fn static mep_pump(struct mepenv *env, uint32_t ms) -> void
    calls: mxfs_pal_time_ms, net2_mepoch_tick
    called_by: mep_wait_disk, scen_mep_no_fence_proof, scen_mep_stall
  fn static mep_epoch_of(struct mepenv *env, int i) -> uint64_t
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_stall
  fn static mep_wait_epoch(struct mepenv *env, int i, uint64_t epoch, uint32_t timeout_ms) -> int
    calls: mep_incs, mep_mask, net2_mepoch_bootstrap, net2_mepoch_propose
    called_by: mep_form, scen_mep_bootstrap, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_prepared_adoption, scen_mep_restart_all
  fn static mep_wait_disk(struct mepenv *env, uint16_t slot, uint64_t epoch, int prepared, uint32_t timeout_ms) -> int
    calls: mep_disk, mep_pump, mxfs_pal_time_ms
    called_by: scen_mep_prepared_adoption
  fn static mep_mask(struct mepenv *env, int upto) -> uint64_t
    called_by: mep_form, mep_wait_epoch, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_restart_all, scen_mep_stall
  fn static mep_incs(struct mepenv *env, uint32_t *incs) -> void
    called_by: mep_form, mep_wait_epoch, scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_stall
  fn static mep_form(struct mepenv *env, int count) -> int
    calls: mep_incs, mep_mask, mep_wait_epoch, net2_mepoch_bootstrap, net2_mepoch_propose
    called_by: scen_mep_disk_self_fence, scen_mep_join_leave, scen_mep_no_fence_proof, scen_mep_prepared_adoption, scen_mep_restart_all, scen_mep_stall
  fn static mep_drop_all_rx(struct mepenv *env, int i) -> int
    calls: mxfs_net2_fault_rule_set
    called_by: scen_mep_disk_self_fence, scen_mep_prepared_adoption
  fn static scen_mep_bootstrap(struct scenario_ctx *sc) -> int
    calls: mep_disk, mep_env_start, mep_env_stop, mep_wait_epoch, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_bootstrap
  fn static scen_mep_join_leave(struct scenario_ctx *sc) -> int
    calls: mep_env_start, mep_env_stop, mep_form, mep_incs, mep_mask, mep_wait_epoch, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_propose
  fn static scen_mep_prepared_adoption(struct scenario_ctx *sc) -> int
    calls: mep_drop_all_rx, mep_env_start, mep_env_stop, mep_epoch_of, mep_form, mep_incs, mep_mask, mep_node_down, mep_wait_disk, mep_wait_epoch, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_propose, net2_mepoch_suspect, vc_node_kill
  fn static scen_mep_stall(struct scenario_ctx *sc) -> int
    calls: mep_env_start, mep_env_stop, mep_epoch_of, mep_form, mep_incs, mep_mask, mep_node_down, mep_pump, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_propose, net2_mepoch_round_status, net2_mepoch_suspect, vc_node_kill
  fn static scen_mep_restart_all(struct scenario_ctx *sc) -> int
    calls: mep_env_start, mep_env_stop, mep_form, mep_mask, mep_node_down, mep_node_up, mep_wait_epoch, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_bootstrap
  fn static scen_mep_disk_self_fence(struct scenario_ctx *sc) -> int
    calls: mep_drop_all_rx, mep_env_start, mep_env_stop, mep_form, mep_incs, mep_mask, mep_wait_epoch, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, net2_mepoch_propose, vc_view_node
  fn static scen_mep_no_fence_proof(struct scenario_ctx *sc) -> int
    calls: mep_disk, mep_env_start, mep_env_stop, mep_epoch_of, mep_form, mep_incs, mep_mask, mep_pump, net2_mepoch_propose, net2_mepoch_round_status
  fn static mb_state_cb(void *cb_data, uint16_t slot, enum net2_member_state from, enum net2_member_state to) -> void
  fn static scen_mep_membership(struct scenario_ctx *sc) -> int
    calls: mep_disk, mep_env_start, mep_env_stop, mep_st_write, mxfs_mepoch_rec_seal, mxfs_pal_time_ms, net2_membership_boot_nonce, net2_membership_create, net2_membership_destroy, net2_membership_fence_done, net2_membership_inc_bump, net2_membership_observe, net2_membership_state, net2_membership_tick, net2_membership_track
  struct mepnode { idx, env, mp, commits, last, last_incs, freezes, unfreezes, frozen, self_fences }
  struct mepenv { sc, vc, n, fd, img, lock, nodes }
  struct mb_ev { n, slot }

[tests/net2/harness/scen_midcomms.c]
  fn static rule_set(struct vcluster *vc, int node, int idx, const char *str) -> int
    calls: mxfs_net2_fault_parse_rule, mxfs_net2_fault_rule_set
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_reorder, scen_mc_reset_framing, scen_mc_window_sack
  fn static send_burst(struct vcluster *vc, int from, int to, uint16_t type, uint32_t tag0, int count, int reliable) -> int
    calls: mxfs_pal_sleep_ms, mxfs_pal_time_ms, vc_send
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  fn static get_sess(struct vcluster *vc, int node, int peer, struct mxfs_net2_session_stats *st) -> void
    calls: mxfs_net2_get_session_stats
    called_by: scen_mc_basic, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_reset_framing, scen_mc_window_sack
  fn static get_mount(struct vcluster *vc, int node, struct mxfs_net2_stats *st) -> void
    calls: mxfs_net2_get_stats
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_malformed_cross, scen_mc_reset_framing, scen_mc_restart
  fn static scen_mc_basic(struct scenario_ctx *sc) -> int
    calls: get_sess, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_wait_count
  fn static scen_mc_loss_data(struct scenario_ctx *sc) -> int
    calls: get_sess, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_wait_count
  fn static scen_mc_loss_ack(struct scenario_ctx *sc) -> int
    calls: get_sess, mxfs_pal_sleep_ms, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_unique_from, vc_wait_count
  fn static scen_mc_dup(struct scenario_ctx *sc) -> int
    calls: get_sess, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_unique_from, vc_wait_count
  fn static scen_mc_reorder(struct scenario_ctx *sc) -> int
    calls: rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_unique_from, vc_wait_count
  fn static scen_mc_delay(struct scenario_ctx *sc) -> int
    calls: get_sess, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_unique_from, vc_wait_count
  fn static scen_mc_burst_loss(struct scenario_ctx *sc) -> int
    calls: rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_wait_count
  fn static scen_mc_reset_framing(struct scenario_ctx *sc) -> int
    calls: get_mount, get_sess, mxfs_net2_link_reset, mxfs_pal_sleep_ms, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_unique_from, vc_wait_count
  fn static scen_mc_backpressure_grant(struct scenario_ctx *sc) -> int
    calls: get_mount, mxfs_net2_fault_reset, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_send, vc_wait_count
  fn static scen_mc_backpressure_release(struct scenario_ctx *sc) -> int
    calls: get_mount, mxfs_net2_fault_reset, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_send, vc_wait_count
  fn static scen_mc_restart(struct scenario_ctx *sc) -> int
    calls: get_mount, send_burst, vc_assert_invariants, vc_count, vc_create, vc_destroy, vc_dump_stats, vc_node_kill, vc_node_restart, vc_send_inc, vc_wait_count
  fn static scen_mc_epoch_change(struct scenario_ctx *sc) -> int
    calls: get_sess, mxfs_pal_sleep_ms, mxfs_pal_time_ms, send_burst, vc_assert_invariants, vc_count, vc_create, vc_destroy, vc_dump_stats, vc_view_all, vc_view_node, vc_wait_count
  fn static scen_mc_window_sack(struct scenario_ctx *sc) -> int
    calls: get_sess, mxfs_pal_sleep_ms, mxfs_pal_time_ms, rule_set, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_send, vc_unique_from, vc_wait_count
  fn static scen_mc_malformed_cross(struct scenario_ctx *sc) -> int
    calls: get_mount, mxfs_pal_sleep_ms, mxfs_pal_tcp_close, mxfs_pal_tcp_connect, mxfs_pal_tcp_send, mxfs_pal_time_ms, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_quiesce, vc_wait_count
  fn static scen_mc_ambiguity(struct scenario_ctx *sc) -> int
    calls: get_mount, mxfs_pal_sleep_ms, mxfs_pal_time_ms, send_burst, vc_assert_invariants, vc_create, vc_destroy, vc_dump_stats, vc_node_kill, vc_node_restart, vc_wait_count

[tests/net2/harness/scen_shard.c]
  fn static shenv_bast_cb(void *data, const struct mxfs_resource_id *res, uint8_t wanted, uint64_t gen) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static shenv_stop(struct shenv *env) -> void
    calls: mxfs_pal_mutex_destroy, net2_lockspace_destroy, vc_destroy
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote
  fn static shenv_start(struct scenario_ctx *sc, struct shenv *env, int n) -> int
    calls: net2_lock_acquire, net2_lock_release
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote
  fn static shenv_mask(struct shenv *env) -> uint64_t
    called_by: scen_sh_epoch_mid_op, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote
  fn static node_by_slot(struct shenv *env, uint16_t slot) -> int
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_two_loss
  fn static shenv_kill(struct shenv *env, int i) -> void
    calls: net2_lockspace_destroy, net2_lockspace_poison, vc_node_kill
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_recovery, scen_sh_two_loss
  fn static shenv_epoch_bump(struct shenv *env, uint64_t new_mask) -> void
    calls: net2_lockspace_epoch_commit
    called_by: scen_sh_epoch_mid_op, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_xfer_no_vote
  fn static shenv_suspect(struct shenv *env, uint16_t slot) -> void
    calls: net2_lockspace_suspect
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_xfer_no_vote
  fn static shenv_partition(struct shenv *env, uint32_t idx_a, uint32_t idx_b) -> void
    calls: mxfs_net2_link_reset, mxfs_net2_set_peer_addr
    called_by: scen_sh_partitions
  fn static shenv_heal(struct shenv *env) -> void
    calls: mxfs_net2_set_peer_addr
    called_by: scen_sh_partitions
  fn static res_make(uint32_t k) -> struct mxfs_resource_id
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions, scen_sh_reconfig, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order, scen_sh_xfer_no_vote
  fn static shard_leader_slot(struct shenv *env, int via, const struct mxfs_resource_id *res) -> uint16_t
    calls: net2_lockspace_shard_probe, net2_shard_get, net2_shard_id_for
    called_by: killpoint_run, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions
  fn static assert_single_leader(struct shenv *env, const struct mxfs_resource_id *res, const char *ctx) -> void
    calls: net2_lockspace_shard_probe, net2_shard_id_for, net2_shard_replica_index
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_killpoints, scen_sh_leader_dead, scen_sh_partitions
  fn static probe_monotone(struct shenv *env, const struct mxfs_resource_id *res, const char *ctx) -> void
    calls: net2_lockspace_shard_probe, net2_shard_id_for
    called_by: killpoint_run, scen_sh_basic, scen_sh_partitions, scen_sh_two_loss, scen_sh_waiter_order
  fn static assert_no_overlap(struct shenv *env, const struct mxfs_resource_id *res, const char *ctx) -> void
    calls: net2_lock_held_mode
    called_by: killpoint_run, scen_sh_basic, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_partitions, scen_sh_two_loss
  fn static pick_grants(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_truncations(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_recov_barriers(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_recov_recs(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_xfer_done(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_votes_refused_xfer(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_dup_idem(const struct net2_lockspace_stats *s) -> uint64_t
  fn static pick_stale_epoch(const struct net2_lockspace_stats *s) -> uint64_t
  fn static op_acquire_fn(void *arg) -> void
    calls: mxfs_pal_time_ms, net2_lock_acquire
  fn static op_release_fn(void *arg) -> void
    calls: mxfs_pal_time_ms, net2_lock_release
  fn static op_start_release(struct op_thread *op, struct shenv *env, int node, const struct mxfs_resource_id *res, uint64_t gen, uint32_t deadline_ms) -> void
    called_by: killpoint_run
  fn static op_start(struct op_thread *op, struct shenv *env, int node, const struct mxfs_resource_id *res, uint8_t mode, uint32_t deadline_ms) -> void
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order
  fn static op_join(struct op_thread *op) -> int
    calls: mxfs_pal_thread_join
    called_by: killpoint_run, scen_sh_basic, scen_sh_epoch_mid_op, scen_sh_idempotent_failover, scen_sh_killpoints, scen_sh_partitions, scen_sh_recovery, scen_sh_two_loss, scen_sh_waiter_order
  fn static scen_sh_basic(struct scenario_ctx *sc) -> int
    calls: assert_no_overlap, assert_single_leader, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_lock_acquire, net2_lock_release, op_join, op_start, probe_monotone, res_make, shenv_start, shenv_stop
  fn static scen_sh_waiter_order(struct scenario_ctx *sc) -> int
    calls: mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, op_join, op_start, probe_monotone, res_make, shenv_start, shenv_stop
  fn static kill_hook(void *data, enum n2_hook_point p, uint32_t shard_id, uint16_t detail) -> bool
  fn static killpoint_run(struct scenario_ctx *sc, enum n2_hook_point point, uint16_t op_filter, int release_phase, const char *label) -> int
    calls: assert_no_overlap, assert_single_leader, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_set_hook, node_by_slot, op_join, op_start, op_start_release, probe_monotone, res_make, shard_leader_slot, shenv_kill
    called_by: scen_sh_killpoints
  fn static scen_sh_killpoints(struct scenario_ctx *sc) -> int
    calls: assert_no_overlap, assert_single_leader, killpoint_run, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_set_hook, node_by_slot, op_join, op_start, res_make, shard_leader_slot
  fn static scen_sh_leader_dead(struct scenario_ctx *sc) -> int
    calls: assert_single_leader, net2_lock_acquire, net2_lock_release, node_by_slot, res_make, shard_leader_slot, shenv_kill, shenv_start, shenv_stop, shenv_suspect
  fn static scen_sh_partitions(struct scenario_ctx *sc) -> int
    calls: assert_no_overlap, assert_single_leader, mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_shard_probe, net2_shard_id_for, node_by_slot, op_join, op_start, probe_monotone, res_make, shard_leader_slot, shenv_heal, shenv_partition
  fn static scen_sh_reconfig(struct scenario_ctx *sc) -> int
    calls: mxfs_net2_get_session_stats, mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_create, net2_lockspace_destroy, net2_lockspace_set_bast_cb, net2_lockspace_start, res_make, shenv_epoch_bump, shenv_mask, shenv_start, shenv_stop, vc_node_restart
  fn static scen_sh_recovery(struct scenario_ctx *sc) -> int
    calls: mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_shard_probe, net2_shard_get, net2_shard_id_for, net2_shard_replica_index, op_join, op_start, res_make, shenv_epoch_bump, shenv_kill, shenv_mask, shenv_start, shenv_stop
  fn static scen_sh_two_loss(struct scenario_ctx *sc) -> int
    calls: assert_no_overlap, mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_shard_probe, net2_shard_get, net2_shard_id_for, net2_shard_replica_index, node_by_slot, op_join, op_start, probe_monotone, res_make, shenv_epoch_bump, shenv_kill
  fn static scen_sh_epoch_mid_op(struct scenario_ctx *sc) -> int
    calls: assert_single_leader, net2_lock_release, op_join, op_start, res_make, shenv_epoch_bump, shenv_mask, shenv_start, shenv_stop
  fn static scen_sh_idempotent_failover(struct scenario_ctx *sc) -> int
    calls: assert_no_overlap, mxfs_pal_sleep_ms, mxfs_pal_time_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_set_hook, node_by_slot, op_join, op_start, res_make, shard_leader_slot, shenv_kill, shenv_start, shenv_stop, shenv_suspect
  fn static scen_sh_xfer_no_vote(struct scenario_ctx *sc) -> int
    calls: mxfs_pal_sleep_ms, net2_lock_acquire, net2_lock_release, net2_lockspace_create, net2_lockspace_destroy, net2_lockspace_set_bast_cb, net2_lockspace_shard_probe, net2_lockspace_start, net2_shard_id_for, net2_shard_replica_index, res_make, shenv_epoch_bump, shenv_mask, shenv_start, shenv_stop
  struct shenv { sc, vc, ls, incs, epoch, n, bast_lock, bast_count, bast_last, seen_commit }
  struct bast_binding { env }
  struct op_thread { env, node, res, mode, deadline_ms, rc, done_at_ms, t }
  struct kill_arm { env, point, op_filter, fired }

[tests/net2/harness/vcluster.c]
  fn static vc_fnv1a(const uint8_t *p, size_t len) -> uint32_t
    called_by: vc_create
  fn static vc_mix(uint64_t x) -> uint64_t
    calls: vc_div
    called_by: vc_create, vc_node_nonce
  fn static vc_node_nonce(const struct vcluster *vc, int slot, uint32_t inc) -> uint64_t
    calls: vc_mix
    called_by: vc_create, vc_node_restart
  fn static vc_div(uint32_t v, uint32_t d) -> uint32_t
    called_by: vc_create, vc_mix
  fn static vc_recv_cb(void *data, const struct mxfs_net2_id *src, const void *payload, uint32_t len) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn static vc_ambiguous_cb(void *data, uint16_t peer_slot, uint32_t peer_inc, uint64_t age_ms) -> void
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
  fn vc_node_start(struct vcluster *vc, int i) -> int
    calls: mxfs_net2_create, mxfs_net2_destroy, mxfs_net2_register_recv_cb, mxfs_net2_set_ambiguous_cb, mxfs_net2_set_peer_addr, mxfs_net2_start
    called_by: vc_create, vc_node_restart
  fn vc_create(struct vcluster **vc_out, int n, uint64_t seed, uint32_t compress, uint16_t tx_win_override) -> int
    calls: mxfs_pal_alloc, mxfs_pal_mutex_create, vc_destroy, vc_div, vc_fnv1a, vc_mix, vc_node_nonce, vc_node_start, vc_view_all
    called_by: mep_env_start, scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart
  fn vc_node_kill(struct vcluster *vc, int i) -> void
    calls: mxfs_net2_destroy
    called_by: scen_mc_ambiguity, scen_mc_restart, scen_mep_prepared_adoption, scen_mep_stall, shenv_kill, vc_destroy, vc_node_restart
  fn vc_node_restart(struct vcluster *vc, int i) -> int
    calls: vc_node_kill, vc_node_nonce, vc_node_start, vc_view_node
    called_by: scen_mc_ambiguity, scen_mc_restart, scen_sh_reconfig, scen_sh_xfer_no_vote
  fn vc_view_node(struct vcluster *vc, int i, uint64_t mask, uint64_t epoch) -> void
    calls: mxfs_net2_update_view
    called_by: mep_committed_cb, scen_mc_epoch_change, scen_mep_disk_self_fence, vc_node_restart, vc_view_all
  fn vc_view_all(struct vcluster *vc, uint64_t mask, uint64_t epoch) -> void
    calls: vc_view_node
    called_by: scen_mc_epoch_change, vc_create
  fn vc_destroy(struct vcluster *vc) -> void
    calls: mxfs_pal_free, mxfs_pal_mutex_destroy, vc_node_kill
    called_by: mep_env_stop, scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart
  fn vc_send_inc(struct vcluster *vc, int from, int to, uint32_t inc, uint16_t type, uint32_t tag, int reliable, uint32_t msg_id) -> int
    calls: mxfs_net2_send, net2_pri_for_type
    called_by: scen_mc_restart, vc_send
  fn vc_send(struct vcluster *vc, int from, int to, uint16_t type, uint32_t tag, int reliable, uint32_t msg_id) -> int
    calls: vc_send_inc
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_window_sack, send_burst
  fn vc_count(struct vcluster *vc, int node, int from_slot, uint16_t type, uint32_t tag) -> int
    calls: mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mc_epoch_change, scen_mc_restart, vc_wait_count
  fn vc_wait_count(struct vcluster *vc, int node, int from_slot, uint16_t type, uint32_t tag, int want, int timeout_ms) -> int
    calls: mxfs_pal_sleep_ms, mxfs_pal_time_ms, vc_count
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  fn vc_unique_from(struct vcluster *vc, int node, int from_slot, int *dups) -> int
    calls: mxfs_pal_alloc, mxfs_pal_free, mxfs_pal_mutex_lock, mxfs_pal_mutex_unlock
    called_by: scen_mc_delay, scen_mc_dup, scen_mc_loss_ack, scen_mc_reorder, scen_mc_reset_framing, scen_mc_window_sack, vc_assert_invariants
  fn vc_quiesce(struct vcluster *vc, int timeout_ms) -> int
    calls: mxfs_net2_get_session_stats, mxfs_pal_sleep_ms, mxfs_pal_time_ms
    called_by: scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_window_sack
  fn vc_dump_stats(struct vcluster *vc) -> void
    calls: mxfs_net2_get_session_stats, mxfs_net2_get_stats
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  fn vc_assert_invariants(struct scenario_ctx *sc, struct vcluster *vc, unsigned flags) -> int
    calls: mxfs_net2_get_session_stats, mxfs_net2_get_stats, vc_unique_from
    called_by: scen_mc_ambiguity, scen_mc_backpressure_grant, scen_mc_backpressure_release, scen_mc_basic, scen_mc_burst_loss, scen_mc_delay, scen_mc_dup, scen_mc_epoch_change, scen_mc_loss_ack, scen_mc_loss_data, scen_mc_malformed_cross, scen_mc_reorder, scen_mc_reset_framing, scen_mc_restart, scen_mc_window_sack
  struct vc_inner { hdr, tag, pad }

[tests/scst_pr_fullstatus_bounds.c]
  fn static build_registrants(int n) -> struct reg
    called_by: main
  fn static guarded_buffer(int size) -> uint8_t
    called_by: run_child
  fn static loop_old(uint8_t *buffer, int buffer_size, int bufflen, struct reg *regs, int n, int *reported_addl) -> int
    called_by: run_child
  fn static loop_new(uint8_t *buffer, int buffer_size, int bufflen, struct reg *regs, int n, int *reported_addl) -> int
    called_by: run_child
  fn static run_child(int which, int buffer_size, int bufflen, struct reg *regs, int n) -> struct outcome
    calls: guarded_buffer, loop_new, loop_old, read
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: build_registrants, run_child
  struct reg { tid, tid_size }
  struct outcome { signalled, sig, offset, addl }

[tests/sf_storm_ledger.py]
  fn collect(run, pino, rnd, start, slot)
  fn order(pubs)
    called_by: check_journal
  fn main()

[tests/suite/tools/fsx.c]
  fn static round_ptr_up(void *ptr, unsigned long align, unsigned long offset) -> void
    calls: roundup_64
  fn static op_name(int operation) -> const char
  fn static op_code(const char *name) -> int
  fn static is_power_of_2(unsigned n) -> int
    called_by: rounddown_pow_of_2
  fn static rounddown_pow_of_2(int n) -> int
    calls: is_power_of_2
  fn static generate_dest_range(bool bdy_align, unsigned long max_range_end, unsigned long *src_offset, unsigned long *size, unsigned long *dst_offset) -> void
  enum opflags { FL_NONE, FL_SKIPPED, FL_CLOSE_OPEN, FL_KEEP_SIZE, FL_UNSHARE }
  struct log_entry { operation, nr_args, args, flags }
  struct hugepages_collapse_info { orig_good_buf, good_buf_size, orig_temp_buf, temp_buf_size }

[tools/caw_slot_hash.py]
  fn fnv1a(b)
  fn res_bytes(volume, ino, offset, ag, rtype)
  fn home(volume, rtype, ino, ag, offset=0)
  fn parse_dump(path)
  fn cmd_verify(path)
  fn cmd_collide(dumppath, inolist, shift)
  fn cmd_pick(dumppath, inolist, shift)

[tools/caw_slotdump.c]
  fn static type_name(uint8_t t) -> const char
    called_by: do_scsi_read_fua, main
  fn static mode_name(uint8_t m) -> const char
    called_by: dg_grant_ex, dlm_lock_impl, do_scsi_read_fua, fire_bast_records, main, mxfs_dlm_audit_double_grant, mxfs_dlm_lock_retries, mxfs_dlm_process_remote_release, mxfs_dlm_purge_stale_for_resource, mxfs_dlm_unlock_gen, promote_waiters
  fn static do_scsi_read_fua(int fd, uint64_t lba, void *buf, uint32_t blocks) -> int
    calls: mode_name, print_bits, type_name
    called_by: main
  fn static print_bits(const char *label, uint64_t v) -> void
    called_by: do_scsi_read_fua, main
  fn main(int argc, char **argv) -> int
    calls: do_scsi_read_fua, mode_name, print_bits, type_name
  struct resid { volume, ino, offset, ag_number, type, pad }
  struct caw_slot { magic, generation, resource, holders_ex, holders_pw, holders_pr, holders_cw, holders_cr, waiters, granted_mode }

[tools/caw_verify.c]
  fn static do_scsi_io(int fd, unsigned char *cdb, int cdb_len, void *buf, int len, int dxfer_dir, int *miscompare) -> int
  fn static scsi_read16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks) -> int
    called_by: do_scsi_io, main
  fn static scsi_compare_and_write(int fd, uint64_t lba, void *cmp_buf, void *write_buf, int *miscompare) -> int
    called_by: main
  fn static usage(const char *prog) -> void
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: scsi_compare_and_write, scsi_read16_fua, usage

[tools/chk_mxfs.c]
  fn static crc32c_init(void) -> void
    called_by: crc32c
  fn static crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: check_journal, desc_crc, dump_slot, main, mxfs_pal_crc32c, mxfs_super_crc, oc_crc, xfs_set_crc
  fn static get_be16(const void *p) -> uint16_t
    calls: err
    called_by: check_inode_spotcheck, check_one_inode, orphan_collect_leaf, orphan_walk_chain, parse_xfs_sb, validate_inobt_leaf
  fn static get_be32(const void *p) -> uint32_t
    called_by: check_inode_spotcheck, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, do_prin, do_upgrade_protogate, orphan_collect_leaf, orphan_walk_chain, parse_xfs_sb, read_ag_block, read_at, report, validate_freespace_leaf, validate_inobt_leaf
  fn static get_be64(const void *p) -> uint64_t
    called_by: check_inode_spotcheck, check_one_inode, do_prin, orphan_collect_leaf, parse_xfs_sb, report, validate_inobt_leaf
  fn static put_be32(void *p, uint32_t v) -> void
    called_by: build_xfs_sb_sector, check_freespace_btrees, check_inode_btrees, do_prout, do_upgrade_protogate, do_write, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static put_be64(void *p, uint64_t v) -> void
    called_by: build_xfs_sb_sector, can_repair, do_prout, do_write, print_summary, write_inode, write_sb_sector
  fn static popcount64(uint64_t v) -> int
    called_by: validate_inobt_leaf
  fn static err(const char *fmt, ...) -> void
    called_by: check_disklock, check_freespace_btrees, check_inode_btrees, check_journal, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, chk_print_guard, decode_mepoch, do_show_quarantine, get_be16, orphan_collect_leaf, orphan_repair_insert, orphan_walk_chain, print_summary
  fn static info(const char *fmt, ...) -> void
    called_by: check_disklock, check_journal, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, decode_mepoch, validate_inobt_leaf
  fn static format_size(uint64_t bytes, char *buf, size_t buflen) -> void
  fn static format_uuid(const uint8_t *uuid, char *buf, size_t buflen) -> void
  fn static read_at(int fd, void *buf, size_t len, off_t offset) -> int
    calls: get_be32
    called_by: can_repair, check_disklock, check_freespace_btrees, check_inode_btrees, check_inode_spotcheck, check_journal, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, do_show_quarantine, do_upgrade_protogate, orphan_collect_leaf, orphan_walk_chain, print_summary
  fn static write_at(int fd, const void *buf, size_t len, off_t offset) -> int
    called_by: check_journal
  fn static can_repair(void) -> bool
    calls: put_be64, read_at, xfs_fix_crc_and_write
    called_by: check_freespace_btrees, check_inode_btrees, check_journal, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, main, print_summary, xfs_verify_crc
  fn static xfs_fix_crc_and_write(int fd, void *buf, size_t len, size_t crc_off, off_t disk_offset) -> int
    called_by: can_repair, check_freespace_btrees, check_inode_btrees, check_one_inode, check_xfs_ag_headers, do_upgrade_protogate, print_summary, xfs_verify_crc
  fn static mxfs_fix_crc_and_write(int fd, void *buf, size_t len, size_t crc_off, off_t disk_offset) -> int
    called_by: check_journal, do_upgrade_protogate
  fn static xfs_verify_crc(void *buf, size_t len, size_t crc_off) -> bool
    calls: can_repair, err, xfs_fix_crc_and_write
    called_by: check_one_inode, check_xfs_ag_headers
  fn static read_ag_block(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agbno, void *buf) -> int
    calls: get_be32
    called_by: check_inode_spotcheck
  fn static check_mxfs_super(int fd, struct mxfs_ondisk_super *super) -> int
    called_by: main
  fn static check_journal(int fd, const struct mxfs_ondisk_super *super) -> void
    calls: can_repair, crc32c, err, info, mxfs_fix_crc_and_write, order, read_at, write_at
    called_by: main
  fn static crc32c_raw(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: chk_recov_body_crc, chk_verdict_digest, decode_mepoch
  fn static chk_recov_body_crc(uint32_t fs_gen, uint32_t node_id, uint64_t epoch, const void *rec, size_t len) -> uint32_t
    calls: crc32c_raw
    called_by: chk_print_guard
  fn static chk_verdict_digest(const uint8_t *uuid16, uint32_t slot, const uint8_t *sector512) -> uint64_t
    calls: crc32c_raw
    called_by: chk_print_guard
  fn static chk_refusal_reason_name(uint16_t r) -> const char
    called_by: chk_print_guard
  fn static chk_print_guard(uint32_t slot, const uint8_t *sec, const uint8_t *fsuuid, uint16_t slice_count_hint) -> int
    calls: chk_recov_body_crc, chk_refusal_reason_name, chk_verdict_digest, err, mxfs_unclaimed_bucket_scan
    called_by: do_show_quarantine
  fn static decode_mepoch(const uint8_t *slot_buf, int slot, uint64_t *members_out) -> uint64_t
    calls: crc32c_raw, err, info
    called_by: check_disklock
  fn static check_disklock(int fd, const struct mxfs_ondisk_super *super) -> void
    calls: decode_mepoch, err, info, read_at
    called_by: main
  fn static check_xfs_superblock(int fd, const struct mxfs_ondisk_super *super, struct xfs_geo *geo) -> int
    called_by: main
  fn static check_xfs_ag_headers(int fd, const struct xfs_geo *geo, uint32_t agno, struct ag_info *agi_out) -> void
    calls: can_repair, err, get_be32, info, read_at, xfs_fix_crc_and_write, xfs_verify_crc
    called_by: main
  fn static validate_btree_sblock(uint8_t *blk, uint32_t blocksize, uint32_t expected_magic, uint32_t agno, const char *name, int fd, off_t disk_offset) -> int
  fn static validate_freespace_leaf(const uint8_t *blk, uint16_t numrecs, uint32_t agno, const char *name, bool sort_by_bno, uint32_t ag_length) -> uint64_t
    calls: err, get_be32
  fn static walk_freespace_btree(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agbno, uint32_t expected_magic, const char *name, bool sort_by_bno, uint32_t expected_level, uint32_t ag_length) -> uint64_t
    called_by: check_freespace_btrees
  fn static rebuild_freespace_btrees(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agf_length) -> int
    called_by: check_freespace_btrees
  fn static check_freespace_btrees(int fd, const struct xfs_geo *geo, uint32_t agno, const struct ag_info *agi, struct ag_summary *summary) -> void
    calls: can_repair, err, put_be32, read_at, rebuild_freespace_btrees, walk_freespace_btree, xfs_fix_crc_and_write
    called_by: main
  fn static validate_inobt_leaf(const uint8_t *blk, uint16_t numrecs, uint32_t agno, const char *name, const struct xfs_geo *geo, struct inobt_totals *totals) -> void
    calls: err, get_be16, get_be32, get_be64, info, popcount64, totals
  fn static walk_inobt(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agbno, uint32_t expected_magic, const char *name, uint32_t expected_level, uint32_t ag_length, struct inobt_totals *totals) -> void
    calls: err
    called_by: check_inode_btrees
  fn static reset_inobt_root(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t root_agbno, uint32_t magic) -> int
    called_by: check_inode_btrees
  fn static reset_agi_level(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agi_level_off) -> int
    called_by: check_inode_btrees
  fn static check_inode_btrees(int fd, const struct xfs_geo *geo, uint32_t agno, const struct ag_info *agi, struct ag_summary *summary) -> void
    calls: can_repair, err, put_be32, read_at, reset_agi_level, reset_inobt_root, walk_inobt, xfs_fix_crc_and_write
    called_by: main
  fn static check_one_inode(int fd, const struct xfs_geo *geo, uint64_t ino, const char *label) -> int
    calls: can_repair, err, get_be16, get_be32, get_be64, info, read_at, xfs_fix_crc_and_write, xfs_verify_crc
    called_by: check_inode_spotcheck
  fn static check_inode_spotcheck(int fd, const struct xfs_geo *geo) -> void
    calls: check_one_inode, get_be16, get_be32, get_be64, read_ag_block, read_at
    called_by: main
  fn static orphan_push(struct orphan_list *l, uint64_t val) -> void
    called_by: orphan_collect_leaf, orphan_walk_chain
  fn static orphan_cmp_u64(const void *a, const void *b) -> int
  fn static inode_disk_offset(const struct xfs_geo *geo, uint32_t agno, uint32_t agino) -> uint64_t
    called_by: orphan_collect_leaf, orphan_walk_chain
  fn static orphan_walk_chain(int fd, const struct xfs_geo *geo, uint32_t agno, int bucket, uint32_t head, struct orphan_list *members) -> void
    calls: err, get_be16, get_be32, inode_disk_offset, orphan_push, read_at
    called_by: check_orphan_inodes
  fn static orphan_collect_leaf(int fd, const struct xfs_geo *geo, uint32_t agno, const uint8_t *blk, uint16_t numrecs, struct orphan_list *cand, uint64_t *scanned) -> void
    calls: err, get_be16, get_be32, get_be64, inode_disk_offset, orphan_push, read_at
  fn static orphan_walk_inobt(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agbno, int depth, struct orphan_list *cand, uint64_t *scanned) -> void
    called_by: check_orphan_inodes
  fn static orphan_repair_insert(int fd, const struct xfs_geo *geo, uint32_t agno, uint32_t agino, uint32_t heads[XFS_AGI_UNLINKED_BUCKETS]) -> int
    calls: err
    called_by: check_orphan_inodes
  fn static check_orphan_inodes(int fd, const struct xfs_geo *geo) -> void
    calls: can_repair, err, get_be32, info, orphan_repair_insert, orphan_walk_chain, orphan_walk_inobt, read_at
    called_by: main
  fn static print_summary(int fd, const struct xfs_geo *geo, const struct ag_summary *ag_summaries) -> void
    calls: can_repair, err, put_be64, read_at, xfs_fix_crc_and_write
    called_by: main
  fn static sha256_block(struct sha256_ctx *c, const uint8_t *p) -> void
  fn static sha256_init(struct sha256_ctx *c) -> void
  fn static sha256_update(struct sha256_ctx *c, const void *data, size_t len) -> void
    called_by: sha256_final
  fn static sha256_final(struct sha256_ctx *c, uint8_t out[32]) -> void
    calls: sha256_update
  fn static sha256_hex(const uint8_t d[32], char out[65]) -> void
  fn static do_show_quarantine(const char *device) -> int
    calls: chk_print_guard, err, read_at
    called_by: main
  fn static chk_pr_read_keys(int fd, uint64_t *keys, int max, int *unsupported) -> int
    called_by: do_pr_keys
  fn static chk_leaf_add(struct chk_leafset *s, const char *name) -> void
    called_by: chk_collect_leaves
  fn static chk_collect_leaves(const char *devname, struct chk_leafset *s, int depth) -> void
    calls: chk_leaf_add
    called_by: chk_archive_dest_disjoint
  fn static chk_devname_of(dev_t rdev, char *out, size_t outsz) -> int
    called_by: chk_archive_dest_disjoint
  fn static chk_dest_backing_dev(dev_t st_dev, char *out, size_t outsz, char *fstype, size_t ftsz) -> int
    called_by: chk_archive_dest_disjoint
  fn static chk_archive_dest_disjoint(const char *device, int destdirfd, const char *destdirpath) -> int
    calls: chk_collect_leaves, chk_dest_backing_dev, chk_devname_of
  fn static chk_read_sector_direct(int dfd, uint64_t off, uint8_t *out512) -> int
    called_by: chk_repair_table_clear
  fn static chk_repair_table_clear(int dfd, const struct mxfs_ondisk_super *sup, uint32_t keep_slot) -> int
    calls: chk_read_sector_direct
  fn static chk_write_archive(const char *archive_path, const char *device, const struct chk_quar_ctx *q) -> int
  fn static do_pr_keys(const char *device) -> int
    calls: chk_pr_read_keys
    called_by: main
  fn static do_accept_quarantine_loss(const char *device, long slice_arg, const char *confirm, const char *archive) -> int
    calls: do_upgrade_protogate
    called_by: main
  fn static do_upgrade_protogate(int fd) -> int
    calls: get_be32, mxfs_fix_crc_and_write, put_be32, read_at, xfs_fix_crc_and_write
    called_by: do_accept_quarantine_loss, main
  fn static usage(const char *prog) -> void
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: can_repair, check_disklock, check_freespace_btrees, check_inode_btrees, check_inode_spotcheck, check_journal, check_mxfs_super, check_orphan_inodes, check_xfs_ag_headers, check_xfs_superblock, do_accept_quarantine_loss, do_pr_keys, do_show_quarantine, do_upgrade_protogate, print_summary
  enum repair_mode { REPAIR_NONE, n, check, only, no, writes, REPAIR_AUTO, a, p, auto }
  struct xfs_geo { blocksize, agcount, agblocks, inodesize, inopblock, inopblog, agblklog, dblocks, rootino, icount }
  struct ag_summary { bno_freeblks, agf_freeblks, agi_count, agi_freecount, inobt_total, inobt_free }
  struct chk_recov_desc { magic, victim_epoch, owner_stamp_ms, victim_node, flags, victim_slot, slice_idx, stage_seq, fence_kind, fence_victim_key }
  struct chk_recov_outcome { magic, reason, victim_slot, victim_epoch, ag_mask, victim_node, owner_node, refused_items, crc32c }
  struct chk_hb_hdr
  struct ag_info { bno_root, cnt_root, bno_level, cnt_level, agf_freeblks, agf_longest, agf_length, ino_root, ino_level, agi_count }
  struct inobt_totals { total_inodes, total_free, num_records }
  struct orphan_list { v, oom }
  struct sha256_ctx { h, len, buf, n }
  struct chk_leafset { n, overflow }
  struct chk_quar_ctx { sup, sector, superblk, slot, sector_off, digest, d, oc }
  struct mxfs_disklock_heartbeat_hdr
  struct mxfs_disklock_heartbeat_hdr

[tools/fua_verify.c]
  fn static do_scsi_io(int fd, unsigned char *cdb, int cdb_len, void *buf, int len, int dxfer_dir) -> int
    calls: scsi_read16_fua, scsi_synchronize_cache16, scsi_write16_fua
  fn static scsi_write16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks) -> int
    called_by: do_scsi_io, main
  fn static scsi_read16_fua(int fd, uint64_t lba, void *buf, uint32_t blocks) -> int
    called_by: do_scsi_io, main
  fn static scsi_synchronize_cache16(int fd) -> int
    called_by: do_scsi_io, main
  fn main(int argc, char **argv) -> int
    calls: scsi_read16_fua, scsi_synchronize_cache16, scsi_write16_fua

[tools/mkfs_mxfs.c]
  fn static crc32c_init(void) -> void
    called_by: crc32c
  fn static crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    calls: crc32c_init
    called_by: check_journal, desc_crc, dump_slot, main, mxfs_pal_crc32c, mxfs_super_crc, oc_crc, xfs_set_crc
  fn static put_be16(void *p, uint16_t v) -> void
    called_by: build_xfs_sb_sector, write_inode, write_sb_sector
  fn static put_be32(void *p, uint32_t v) -> void
    called_by: build_xfs_sb_sector, check_freespace_btrees, check_inode_btrees, do_prout, do_upgrade_protogate, do_write, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static put_be64(void *p, uint64_t v) -> void
    called_by: build_xfs_sb_sector, can_repair, do_prout, do_write, print_summary, write_inode, write_sb_sector
  fn static xfs_set_crc(void *buf, size_t len, size_t crc_off) -> void
    calls: crc32c
    called_by: build_xfs_sb_sector, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static gen_uuid(uint8_t *uuid) -> int
    called_by: main
  fn static pr_info(const char *fmt, ...) -> void
    called_by: caw_bastq_report, inode_dio_probe_init, inode_dio_release_init, loop_unwedge_init, lu_iter, main, mxfs_bdev_to_sdev, mxfs_compute_cache_caps, mxfs_iunl_store_purge_ag, mxfs_lru_sweep_fn, mxfs_pal_bdev_close_clone, mxfs_pal_log, scst_unwedge_init
  fn static pr_verbose(const char *fmt, ...) -> void
    called_by: main
  fn static pr_err(const char *fmt, ...) -> void
    called_by: caw_join_bounded, caw_release_all_body, caw_teardown_escalate_queue, format_xfs_native, inode_dio_probe_init, inode_dio_release_init, loop_unwedge_init, main, mxfs_dlm_caw_destroy, mxfs_dlm_caw_pin_resource, mxfs_dlm_caw_stop, mxfs_dlm_caw_unsafe_to_free, mxfs_pal_log, scst_unwedge_init, write_new_ag
  fn static human_size(uint64_t bytes, char *buf, size_t buflen) -> const char
    called_by: main
  fn static ceil_log2(uint32_t v) -> uint32_t
  fn static write_sectors(int fd, uint64_t offset, const void *buf, uint64_t len) -> int
    called_by: main
  fn static zero_region(int fd, uint64_t offset, uint64_t len) -> int
    called_by: main
  fn static format_journal(int fd, uint64_t journal_offset, uint32_t max_nodes, const uint8_t *uuid) -> int
    called_by: main
  fn static write_mxfs_super(int fd, uint64_t super_offset, uint64_t device_size, uint64_t xfs_data_size, uint64_t journal_offset, uint64_t journal_size, uint64_t disklock_offset, uint64_t disklock_size, uint64_t xfs_data_offset, uint32_t max_nodes, uint32_t log_node_count, uint32_t log_slice_bblks, const uint8_t *uuid) -> int
    called_by: main
  fn static calc_ag_layout(const struct xfs_geom *geom, uint32_t agno, uint32_t *out_aglen, uint32_t *out_freeblks, uint32_t *out_free_start, uint32_t *out_free_len, uint32_t *out_free2_start, uint32_t *out_free2_len, uint32_t agfl_blocks[4]) -> void
  fn static write_sb_sector(uint8_t *sec, const struct xfs_geom *geom, uint32_t agno) -> void
    calls: put_be16, put_be32, put_be64, xfs_set_crc
  fn static write_agf_sector(uint8_t *sec, const struct xfs_geom *geom, uint32_t agno, uint32_t aglen, uint32_t freeblks, uint32_t longest) -> void
    calls: put_be32, xfs_set_crc
  fn static write_agi_sector(uint8_t *sec, const struct xfs_geom *geom, uint32_t agno, uint32_t aglen) -> void
    calls: put_be32, xfs_set_crc
  fn static write_agfl_sector(uint8_t *sec, const struct xfs_geom *geom, uint32_t agno, const uint32_t agfl_blocks[4]) -> void
    calls: put_be32, xfs_set_crc
  fn static write_btree_block(uint8_t *blk, uint32_t magic, uint32_t agno, uint64_t blkno_abs, uint16_t numrecs, const uint8_t *rec_data, size_t rec_len, const uint8_t *uuid) -> void
  fn static write_inode(uint8_t *buf, uint64_t ino, const uint8_t *uuid, int itype, time_t now) -> void
    calls: put_be16, put_be32, put_be64, xfs_set_crc
  fn static format_xfs_native(int fd, uint64_t data_size, uint64_t base_offset, const uint8_t *uuid, uint32_t *log_node_count_io, uint32_t *logblocks_out) -> int
    calls: pr_err
    called_by: main
  fn static usage(const char *prog) -> void
    called_by: main
  fn main(int argc, char *argv[]) -> int
    calls: format_journal, format_xfs_native, gen_uuid, human_size, pr_err, pr_info, pr_verbose, usage, write_mxfs_super, write_sectors, zero_region
  struct journal_super { magic, version, slot_count, slot_size_sectors, sector_size, crc, fs_uuid, reserved }
  struct journal_slot_hdr { magic, flags, owner, head_sector, tail_sector, crc, seq_head, seq_tail, reserved }
  struct xfs_geom { dblocks, agcount, agblocks, last_agblocks, agblklog, log_ag, logblocks, logstart, rootino, rbmino }

[tools/mxfs_bench.c]
  fn static stats_init(struct bench_stats *s) -> void
    called_by: main
  fn static stats_add(struct bench_stats *s, double us) -> void
    called_by: main
  fn static stats_avg(struct bench_stats *s) -> double
    called_by: dlm_op, main, print_comparison, print_stats
  fn static now_us(void) -> double
    called_by: main
  fn static read_full(int fd, void *buf, size_t len) -> int
    called_by: main
  fn static write_full(int fd, const void *buf, size_t len) -> int
    called_by: dlm_lock, main
  fn static dlm_op(uint8_t cmd, uint8_t mode, uint64_t volume, uint64_t ino) -> int
    calls: stats_avg
    called_by: dlm_unlock
  fn static dlm_lock(uint64_t volume, uint64_t ino, uint8_t mode) -> int
    calls: write_full
    called_by: main
  fn static dlm_unlock(uint64_t volume, uint64_t ino) -> int
    calls: dlm_op
    called_by: main
  fn static print_stats(const char *label, struct bench_stats *s) -> void
    calls: stats_avg
    called_by: main
  fn static print_comparison(const char *label, struct bench_stats *base, struct bench_stats *locked) -> void
    calls: stats_avg
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: dlm_lock, dlm_unlock, now_us, print_comparison, print_stats, read, stats_add, stats_avg, stats_init, write_full
  struct ctrl_req { cmd, mode, pad, flags, resource }
  struct ctrl_resp { status, mode, pad }
  struct bench_stats { min_us, max_us, total_us, count }

[tools/mxfs_lock.c]
  fn static read_full(int fd, void *buf, size_t len) -> int
    called_by: main
  fn static write_full(int fd, const void *buf, size_t len) -> int
    called_by: dlm_lock, main
  fn static usage(const char *prog) -> void
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: read_full, usage, write_full
  struct ctrl_req { cmd, mode, pad, flags, resource }
  struct ctrl_resp { status, mode, pad }

[tools/recov_forge.c]
  fn static crc_init(void) -> void
  fn static crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: check_journal, desc_crc, dump_slot, main, mxfs_pal_crc32c, mxfs_super_crc, oc_crc, xfs_set_crc
  fn static desc_crc(const struct hb_rec *hb, const struct recov_desc *d) -> uint32_t
    calls: crc32c
    called_by: dump_slot, main
  fn static oc_crc(const struct hb_rec *hb, const struct recov_outcome *oc) -> uint32_t
    calls: crc32c
    called_by: dump_slot, main
  fn static sg_rw(int fd, int write, uint64_t lba, void *buf, uint32_t blocks) -> int
    called_by: main, slot_write
  fn static slot_read(int fd, int slot, struct hb_rec *hb) -> int
    called_by: main
  fn static slot_write(int fd, int slot, const struct hb_rec *hb) -> int
    calls: sg_rw
    called_by: main
  fn static flag_name(uint32_t f) -> const char
    called_by: dump_slot
  fn static desc_present(const struct hb_rec *hb) -> bool
    called_by: dump_slot
  fn static oc_present(const struct hb_rec *hb) -> bool
    called_by: dump_slot, main
  fn static dump_slot(int slot, const struct hb_rec *hb) -> void
    calls: crc32c, desc_crc, desc_present, flag_name, oc_crc, oc_present
    called_by: main
  fn static usage(void) -> void
    called_by: main
  fn main(int argc, char **argv) -> int
    calls: crc32c, desc_crc, dump_slot, oc_crc, oc_present, sg_rw, slot_read, slot_write, usage
  struct recov_desc { magic, version, stage, victim_epoch, owner_epoch, recovery_gen, owner_stamp_ms, victim_node, owner_node, victim_fs_gen }
  struct recov_outcome { magic, version, outcome, reason, domain_kind, victim_slot, owner_slot, victim_epoch, owner_epoch, recovery_gen }
  struct hb_rec { magic, flags, node_id, fs_gen, timestamp_ms, epoch, lock_count, desc, outcome, pad }
  struct ident { fs_gen, node_id, epoch }

[tools/resize_mxfs.c]
  fn static crc32c_init(void) -> void
    called_by: crc32c
  fn static crc32c(uint32_t crc, const void *data, size_t len) -> uint32_t
    called_by: check_journal, desc_crc, dump_slot, main, mxfs_pal_crc32c, mxfs_super_crc, oc_crc, xfs_set_crc
  fn static get_be16(const void *p) -> uint16_t
    called_by: check_inode_spotcheck, check_one_inode, orphan_collect_leaf, orphan_walk_chain, parse_xfs_sb, validate_inobt_leaf
  fn static get_be32(const void *p) -> uint32_t
    called_by: check_inode_spotcheck, check_one_inode, check_orphan_inodes, check_xfs_ag_headers, do_prin, do_upgrade_protogate, orphan_collect_leaf, orphan_walk_chain, parse_xfs_sb, read_ag_block, read_at, report, validate_freespace_leaf, validate_inobt_leaf
  fn static get_be64(const void *p) -> uint64_t
    called_by: check_inode_spotcheck, check_one_inode, do_prin, orphan_collect_leaf, parse_xfs_sb, report, validate_inobt_leaf
  fn static put_be16(void *p, uint16_t v) -> void
    called_by: build_xfs_sb_sector, write_inode, write_sb_sector
  fn static put_be32(void *p, uint32_t v) -> void
    called_by: build_xfs_sb_sector, check_freespace_btrees, check_inode_btrees, do_prout, do_upgrade_protogate, do_write, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static put_be64(void *p, uint64_t v) -> void
    called_by: build_xfs_sb_sector, can_repair, do_prout, do_write, print_summary, write_inode, write_sb_sector
  fn static xfs_set_crc(void *buf, size_t len, size_t crc_off) -> void
    calls: crc32c
    called_by: build_xfs_sb_sector, write_agf_sector, write_agfl_sector, write_agi_sector, write_inode, write_sb_sector
  fn static pr_info(const char *fmt, ...) -> void
    called_by: caw_bastq_report, inode_dio_probe_init, inode_dio_release_init, loop_unwedge_init, lu_iter, main, mxfs_bdev_to_sdev, mxfs_compute_cache_caps, mxfs_iunl_store_purge_ag, mxfs_lru_sweep_fn, mxfs_pal_bdev_close_clone, mxfs_pal_log, scst_unwedge_init
  fn static pr_verbose(const char *fmt, ...) -> void
    called_by: main
  fn static pr_err(const char *fmt, ...) -> void
    called_by: caw_join_bounded, caw_release_all_body, caw_teardown_escalate_queue, format_xfs_native, inode_dio_probe_init, inode_dio_release_init, loop_unwedge_init, main, mxfs_dlm_caw_destroy, mxfs_dlm_caw_pin_resource, mxfs_dlm_caw_stop, mxfs_dlm_caw_unsafe_to_free, mxfs_pal_log, scst_unwedge_init, write_new_ag
  fn static human_size(uint64_t bytes, char *buf, size_t buflen) -> const char
    called_by: main
  fn static read_sectors(int fd, uint64_t offset, void *buf, uint64_t len) -> int
    called_by: main
  fn static write_sectors(int fd, uint64_t offset, const void *buf, uint64_t len) -> int
    calls: pr_err
    called_by: main
  fn static parse_xfs_sb(const uint8_t *sec, struct xfs_sb_info *sb) -> void
    calls: get_be16, get_be32, get_be64
    called_by: main
  fn static build_xfs_sb_sector(uint8_t *sec, const struct xfs_sb_info *sb, bool primary) -> void
    calls: put_be16, put_be32, put_be64, xfs_set_crc
    called_by: main
  fn static write_agf_sector(uint8_t *sec, uint32_t agno, uint32_t aglen, uint32_t freeblks, const uint8_t *uuid) -> void
    calls: put_be32, xfs_set_crc
  fn static write_agi_sector(uint8_t *sec, uint32_t agno, uint32_t aglen, const uint8_t *uuid) -> void
    calls: put_be32, xfs_set_crc
  fn static write_agfl_sector(uint8_t *sec, uint32_t agno, const uint8_t *uuid) -> void
    calls: put_be32, xfs_set_crc
  fn static write_btree_block(uint8_t *blk, uint32_t magic, uint32_t agno, uint64_t blkno_abs, uint16_t numrecs, const uint8_t *rec_data, size_t rec_len, const uint8_t *uuid) -> void
  fn static write_new_ag(int fd, uint32_t agno, uint32_t aglen, uint64_t xfs_data_offset, const struct xfs_sb_info *sb, const uint8_t *uuid) -> int
    calls: pr_err
    called_by: main
  fn static mxfs_super_crc(const struct mxfs_ondisk_super *sup) -> uint32_t
    calls: crc32c
    called_by: main
  fn static usage(const char *prog) -> void
    called_by: main
  fn main(int argc, char *argv[]) -> int
    calls: build_xfs_sb_sector, first, human_size, mxfs_super_crc, parse_xfs_sb, pr_err, pr_info, pr_verbose, read_sectors, usage, write_new_ag, write_sectors
  struct xfs_sb_info { magic, blocksize, dblocks, uuid, logstart, rootino, rbmino, rsumino, agblocks, agcount }

[worker.py]
  fn load_system_prompt()
  fn main()
  fn drain_stderr()

[xfs/libxfs/xfs_ag.c]
  struct xfs_aghdr_grow_data { daddr, numblks, ops, work, bc_ops, need_init }

[xfs/libxfs/xfs_ag.h]
  fn container_of(xg, struct xfs_perag, pag_group) -> return
    called_by: ATTRD_ITEM, ATTRI_ITEM, BUF_ITEM, DQUOT_ITEM, INODE_ITEM, IUL_ITEM, mxfs_defer_work_fn, mxfs_reap_worker, zoned_to_mp
  fn test_bit(XFS_AGSTATE_ ## NAME, &pag->pag_opstate) -> return
    called_by: mxfs_reap_worker
  fn xfs_initialize_perag(struct xfs_mount *mp, xfs_agnumber_t orig_agcount, xfs_agnumber_t new_agcount, xfs_rfsblock_t dcount, xfs_agnumber_t *maxagi) -> int
  fn xfs_free_perag_range(struct xfs_mount *mp, xfs_agnumber_t first_agno, xfs_agnumber_t end_agno) -> void
  fn xfs_initialize_perag_data(struct xfs_mount *mp, xfs_agnumber_t agno) -> int
  fn xfs_update_last_ag_size(struct xfs_mount *mp, xfs_agnumber_t prev_agcount) -> int
  fn xfs_perag_next_range(mp, pag, start_agno, mp->m_sb.sb_agcount - 1) -> return
  fn xfs_perag_next_from(mp, pag, 0) -> return
  fn xfs_ag_block_count(struct xfs_mount *mp, xfs_agnumber_t agno) -> xfs_agblock_t
  fn xfs_agino_range(struct xfs_mount *mp, xfs_agnumber_t agno, xfs_agino_t *first, xfs_agino_t *last) -> void
  fn xfs_verify_agino(pag, agino) -> return
  fn xfs_ag_init_headers(struct xfs_mount *mp, struct aghdr_init_data *id) -> int
  fn xfs_ag_shrink_space(struct xfs_perag *pag, struct xfs_trans **tpp, xfs_extlen_t delta) -> int
  fn xfs_ag_extend_space(struct xfs_perag *pag, struct xfs_trans *tp, xfs_extlen_t len) -> int
  fn xfs_ag_get_geometry(struct xfs_perag *pag, struct xfs_ag_geometry *ageo) -> int
  struct xfs_ag_resv { ar_orig_reserved, ar_reserved, ar_asked }
  struct xfs_perag { pag_group, pag_opstate, pagf_bno_level, pagf_cnt_level, pagf_rmap_level, pagf_flcount, pagf_freeblks, pagf_longest, pagf_btreeblks, pagi_freecount }
  struct aghdr_init_data { agno, agsize, buffer_list, nfree, daddr, numblks, bc_ops }

[xfs/libxfs/xfs_ag_resv.h]
  fn xfs_ag_resv_free(struct xfs_perag *pag) -> void
  fn xfs_ag_resv_init(struct xfs_perag *pag, struct xfs_trans *tp) -> int
  fn xfs_ag_resv_critical(struct xfs_perag *pag, enum xfs_ag_resv_type type) -> bool
  fn xfs_ag_resv_needed(struct xfs_perag *pag, enum xfs_ag_resv_type type) -> xfs_extlen_t
  fn xfs_ag_resv_alloc_extent(struct xfs_perag *pag, enum xfs_ag_resv_type type, struct xfs_alloc_arg *args) -> void
  fn xfs_ag_resv_free_extent(struct xfs_perag *pag, enum xfs_ag_resv_type type, struct xfs_trans *tp, xfs_extlen_t len) -> void

[xfs/libxfs/xfs_alloc.c]
  struct xfs_alloc_cur { cnt, bnolt, bnogt, cur_len, rec_bno, rec_len, bno, len, diff, busy_gen }
  struct xfs_alloc_query_range_info { fn, priv }

[xfs/libxfs/xfs_alloc.h]
  fn xfs_agfl_size(struct xfs_mount *mp) -> unsigned int
  fn xfs_alloc_set_aside(struct xfs_mount *mp) -> unsigned int
  fn xfs_alloc_ag_max_usable(struct xfs_mount *mp) -> unsigned int
  fn xfs_alloc_longest_free_extent(struct xfs_perag *pag, xfs_extlen_t need, xfs_extlen_t reserved) -> xfs_extlen_t
  fn xfs_alloc_min_freelist(struct xfs_mount *mp, struct xfs_perag *pag) -> unsigned int
  fn xfs_alloc_get_freelist(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf *agfbp, xfs_agblock_t *bnop, int	 btreeblk) -> int
  fn xfs_alloc_put_freelist(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf *agfbp, struct xfs_buf *agflbp, xfs_agblock_t bno, int btreeblk) -> int
  fn xfs_free_ag_extent(struct xfs_trans *tp, struct xfs_buf *agbp, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo, enum xfs_ag_resv_type type) -> int
  fn xfs_alloc_vextent_this_ag(struct xfs_alloc_arg *args, xfs_agnumber_t agno) -> int
  fn xfs_alloc_vextent_near_bno(struct xfs_alloc_arg *args, xfs_fsblock_t target) -> int
  fn xfs_alloc_vextent_exact_bno(struct xfs_alloc_arg *args, xfs_fsblock_t target) -> int
  fn xfs_alloc_vextent_start_ag(struct xfs_alloc_arg *args, xfs_fsblock_t target) -> int
  fn xfs_alloc_vextent_first_ag(struct xfs_alloc_arg *args, xfs_fsblock_t target) -> int
  fn __xfs_free_extent(tp, pag, agbno, len, oinfo, type, false) -> return
  fn xfs_alloc_btrec_to_irec(const union xfs_btree_rec *rec, struct xfs_alloc_rec_incore *irec) -> void
  fn xfs_alloc_check_irec(struct xfs_perag *pag, const struct xfs_alloc_rec_incore *irec) -> xfs_failaddr_t
  fn xfs_read_agf(struct xfs_perag *pag, struct xfs_trans *tp, int flags, struct xfs_buf **agfbpp) -> int
  fn xfs_alloc_read_agf(struct xfs_perag *pag, struct xfs_trans *tp, int flags, struct xfs_buf **agfbpp) -> int
  fn xfs_alloc_read_agfl(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf **bpp) -> int
  fn xfs_alloc_fix_freelist(struct xfs_alloc_arg *args, uint32_t alloc_flags) -> int
  fn xfs_free_extent_fix_freelist(struct xfs_trans *tp, struct xfs_perag *pag, struct xfs_buf **agbp) -> int
  fn xfs_prealloc_blocks(struct xfs_mount *mp) -> xfs_extlen_t
  fn xfs_alloc_query_range(struct xfs_btree_cur *cur, const struct xfs_alloc_rec_incore *low_rec, const struct xfs_alloc_rec_incore *high_rec, xfs_alloc_query_range_fn fn, void *priv) -> int
  fn xfs_alloc_query_all(struct xfs_btree_cur *cur, xfs_alloc_query_range_fn fn, void *priv) -> int
  fn xfs_alloc_has_records(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, enum xbtree_recpacking *outcome) -> int
  fn xfs_agfl_walk(struct xfs_mount *mp, struct xfs_agf *agf, struct xfs_buf *agflbp, xfs_agfl_walk_fn walk_fn, void *priv) -> int
  fn xfs_free_extent_later(struct xfs_trans *tp, xfs_fsblock_t bno, xfs_filblks_t len, const struct xfs_owner_info *oinfo, enum xfs_ag_resv_type type, unsigned int free_flags) -> int
  fn xfs_alloc_schedule_autoreap(const struct xfs_alloc_arg *args, unsigned int free_flags, struct xfs_alloc_autoreap *aarp) -> int
  fn xfs_alloc_cancel_autoreap(struct xfs_trans *tp, struct xfs_alloc_autoreap *aarp) -> void
  fn xfs_alloc_commit_autoreap(struct xfs_trans *tp, struct xfs_alloc_autoreap *aarp) -> void
  fn xfs_extfree_intent_init_cache(void) -> int __init
  fn xfs_extfree_intent_destroy_cache(void) -> void
  fn xfs_validate_ag_length(struct xfs_buf *bp, uint32_t seqno, uint32_t length) -> xfs_failaddr_t
  struct xfs_alloc_arg { tp, mp, agbp, pag, fsbno, agno, agbno, minlen, maxlen, mod }
  typedef_fn xfs_alloc_query_range_fn
  typedef_fn xfs_agfl_walk_fn
  struct xfs_extent_free_item { xefi_list, xefi_owner, xefi_startblock, xefi_blockcount, xefi_group, xefi_flags, xefi_agresv, xefi_agwait }
  struct xfs_alloc_autoreap { dfp }

[xfs/libxfs/xfs_alloc_btree.h]
  fn xfs_bnobt_init_cursor(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_buf *bp, struct xfs_perag *pag) -> struct xfs_btree_cur
  fn xfs_cntbt_init_cursor(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_buf *bp, struct xfs_perag *pag) -> struct xfs_btree_cur
  fn xfs_allocbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_allocbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> xfs_extlen_t
  fn xfs_allocbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp, struct xfs_buf *agbp) -> void
  fn xfs_allocbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_allocbt_init_cur_cache(void) -> int __init
  fn xfs_allocbt_destroy_cur_cache(void) -> void

[xfs/libxfs/xfs_attr.c]
  fn xfs_attr_node_removename_setup(struct xfs_attr_intent		*attr) -> int
    calls: xfs_attr_rmtval_invalidate, xfs_da_state_free
  fn xfs_attr_sf_totsize(struct xfs_inode *dp) -> int
    calls: be16_to_cpu
  fn xfs_attr_check_namespace(unsigned int attr_flags) -> bool

[xfs/libxfs/xfs_attr.h]
  fn xfs_attr_inactive(struct xfs_inode *dp) -> int
  fn xfs_attr_list_ilocked(struct xfs_attr_list_context *) -> int
  fn xfs_attr_list(struct xfs_attr_list_context *) -> int
  fn xfs_inode_hasattr(struct xfs_inode *ip) -> int
  fn xfs_attr_is_leaf(struct xfs_inode *ip) -> bool
  fn xfs_attr_get_ilocked(struct xfs_da_args *args) -> int
  fn xfs_attr_get(struct xfs_da_args *args) -> int
  fn xfs_attr_set(struct xfs_da_args *args, enum xfs_attr_update op, bool rsvd) -> int
  fn xfs_attr_set_iter(struct xfs_attr_intent *attr) -> int
  fn xfs_attr_remove_iter(struct xfs_attr_intent *attr) -> int
  fn xfs_attr_check_namespace(unsigned int attr_flags) -> bool
  fn xfs_attr_namecheck(unsigned int attr_flags, const void *name, size_t length) -> bool
  fn xfs_attr_calc_size(struct xfs_da_args *args, int *local) -> int
  fn xfs_attr_set_resv(const struct xfs_da_args *args) -> struct xfs_trans_res
  fn xfs_attr_init_remove_state(args) -> return
  fn xfs_attr_init_add_state(args) -> return
  fn xfs_attr_hashname(const uint8_t *name, int namelen) -> xfs_dahash_t
  fn xfs_attr_hashval(struct xfs_mount *mp, unsigned int attr_flags, const uint8_t *name, int namelen, const void *value, int valuelen) -> xfs_dahash_t
  fn xfs_attr_intent_init_cache(void) -> int __init
  fn xfs_attr_intent_destroy_cache(void) -> void
  fn xfs_attr_sf_totsize(struct xfs_inode *dp) -> int
  fn xfs_attr_add_fork(struct xfs_inode *ip, int size, int rsvd) -> int
  fn xfs_attr_setname(struct xfs_da_args *args, int rmt_blks) -> int
  fn xfs_attr_removename(struct xfs_da_args *args) -> int
  fn xfs_attr_replacename(struct xfs_da_args *args, int rmt_blks) -> int
  struct xfs_attrlist_cursor_kern { hashval, blkno, offset, pad1, pad2, initted }
  typedef_fn put_listent_func_t
  struct xfs_attr_list_context { tp, dp, cursor, buffer, seen_enough, allow_incomplete, count, dupcnt, bufsize, firstu }
  enum xfs_delattr_state { XFS_DAS_UNINIT, No, state, has, been, set, yet, Initial, sequence, states }
  struct xfs_attr_intent { xattri_list, xattri_da_state, xattri_da_args, xattri_nameval, xattri_dela_state, xattri_op_flags, xattri_lblkno, xattri_blkcnt, xattri_map }
  enum xfs_attr_update { XFS_ATTRUPDATE_REMOVE, remove, attr, XFS_ATTRUPDATE_UPSERT, set, value, replace, any, existing, attr }

[xfs/libxfs/xfs_attr_leaf.c]
  fn static xfs_attr_match_mask(const struct xfs_da_args *args) -> unsigned int

[xfs/libxfs/xfs_attr_leaf.h]
  fn xfs_attr_shortform_create(struct xfs_da_args *args) -> void
  fn xfs_attr_shortform_replace(struct xfs_da_args *args) -> int
  fn xfs_attr_shortform_add(struct xfs_da_args *args, int forkoff) -> void
  fn xfs_attr_shortform_getvalue(struct xfs_da_args *args) -> int
  fn xfs_attr_shortform_to_leaf(struct xfs_da_args *args) -> int
  fn xfs_attr_sf_removename(struct xfs_da_args *args) -> int
  fn xfs_attr_sf_findname(struct xfs_da_args *args) -> struct xfs_attr_sf_entry
  fn xfs_attr_shortform_allfit(struct xfs_buf *bp, struct xfs_inode *dp) -> int
  fn xfs_attr_shortform_bytesfit(struct xfs_inode *dp, int bytes) -> int
  fn xfs_attr_shortform_verify(struct xfs_attr_sf_hdr *sfp, size_t size) -> xfs_failaddr_t
  fn xfs_attr_fork_remove(struct xfs_inode *ip, struct xfs_trans *tp) -> void
  fn xfs_attr3_leaf_to_node(struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_to_shortform(struct xfs_buf *bp, struct xfs_da_args *args, int forkoff) -> int
  fn xfs_attr3_leaf_clearflag(struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_setflag(struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_flipflags(struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_split(struct xfs_da_state *state, struct xfs_da_state_blk *oldblk, struct xfs_da_state_blk *newblk) -> int
  fn xfs_attr3_leaf_lookup_int(struct xfs_buf *leaf, struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_getvalue(struct xfs_buf *bp, struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_add(struct xfs_buf *leaf_buffer, struct xfs_da_args *args) -> bool
  fn xfs_attr3_leaf_remove(struct xfs_buf *leaf_buffer, struct xfs_da_args *args) -> int
  fn xfs_attr3_leaf_list_int(struct xfs_buf *bp, struct xfs_attr_list_context *context) -> int
  fn xfs_attr3_leaf_toosmall(struct xfs_da_state *state, int *retval) -> int
  fn xfs_attr3_leaf_unbalance(struct xfs_da_state *state, struct xfs_da_state_blk *drop_blk, struct xfs_da_state_blk *save_blk) -> void
  fn xfs_attr_leaf_lasthash(struct xfs_buf *bp, int *count) -> xfs_dahash_t
  fn xfs_attr_leaf_order(struct xfs_buf *leaf1_bp, struct xfs_buf *leaf2_bp) -> int
  fn xfs_attr_leaf_newentsize(struct xfs_da_args *args, int *local) -> int
  fn xfs_attr3_leaf_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, xfs_dablk_t bno, struct xfs_buf **bpp) -> int
  fn xfs_attr3_leaf_hdr_from_disk(struct xfs_da_geometry *geo, struct xfs_attr3_icleaf_hdr *to, struct xfs_attr_leafblock *from) -> void
  fn xfs_attr3_leaf_hdr_to_disk(struct xfs_da_geometry *geo, struct xfs_attr_leafblock *to, struct xfs_attr3_icleaf_hdr *from) -> void
  fn xfs_attr3_leaf_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  struct xfs_attr3_icleaf_hdr { forw, back, magic, count, usedbytes, firstused, holes, base, size }

[xfs/libxfs/xfs_attr_remote.h]
  fn xfs_attr3_rmt_blocks(struct xfs_mount *mp, unsigned int attrlen) -> unsigned int
  fn xfs_attr3_rmt_blocks(mp, XFS_XATTR_SIZE_MAX) -> return
  fn xfs_attr_rmtval_get(struct xfs_da_args *args) -> int
  fn xfs_attr_rmtval_stale(struct xfs_inode *ip, struct xfs_bmbt_irec *map, xfs_buf_flags_t incore_flags) -> int
  fn xfs_attr_rmtval_invalidate(struct xfs_da_args *args) -> int
    called_by: xfs_attr_node_removename_setup
  fn xfs_attr_rmtval_remove(struct xfs_attr_intent *attr) -> int
  fn xfs_attr_rmt_find_hole(struct xfs_da_args *args) -> int
  fn xfs_attr_rmtval_set_value(struct xfs_da_args *args) -> int
  fn xfs_attr_rmtval_set_blk(struct xfs_attr_intent *attr) -> int
  fn xfs_attr_rmtval_find_space(struct xfs_attr_intent *attr) -> int

[xfs/libxfs/xfs_attr_sf.h]
  fn struct_size(sfep, nameval, sfep->namelen + sfep->valuelen) -> return
  struct xfs_attr_sf_sort { entno, namelen, valuelen, flags, hash, name, value }

[xfs/libxfs/xfs_bit.c]
  fn xfs_next_bit(uint *map, uint size, uint start_bit) -> int

[xfs/libxfs/xfs_bit.h]
  fn xfs_bitmap_empty(uint *map, uint size) -> int
  fn xfs_contig_bits(uint *map, uint size, uint start_bit) -> int
  fn xfs_next_bit(uint *map, uint size, uint start_bit) -> int

[xfs/libxfs/xfs_bmap.c]
  fn static xfs_bmap_needs_btree(struct xfs_inode *ip, int whichfork) -> bool
  fn static xfs_bmap_wants_extents(struct xfs_inode *ip, int whichfork) -> bool
  struct xfs_iread_state { icur, loaded }
  struct xfs_bmap_query_range { fn, priv }

[xfs/libxfs/xfs_bmap.h]
  fn xfs_bmap_alloc_account(struct xfs_bmalloca *ap) -> void
  fn xfs_bmap_longest_free_extent(struct xfs_perag *pag, struct xfs_trans *tp, xfs_extlen_t *blen) -> int
  fn xfs_trim_extent(struct xfs_bmbt_irec *irec, xfs_fileoff_t bno, xfs_filblks_t len) -> void
  fn xfs_bmap_compute_attr_offset(struct xfs_mount *mp) -> unsigned int
  fn xfs_bmap_add_attrfork(struct xfs_trans *tp, struct xfs_inode *ip, int size, int rsvd) -> int
  fn xfs_bmap_local_to_extents_empty(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork) -> void
  fn xfs_bmap_compute_maxlevels(struct xfs_mount *mp, int whichfork) -> void
  fn xfs_bmap_first_unused(struct xfs_trans *tp, struct xfs_inode *ip, xfs_extlen_t len, xfs_fileoff_t *unused, int whichfork) -> int
  fn xfs_bmap_last_before(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t *last_block, int whichfork) -> int
  fn xfs_bmap_last_offset(struct xfs_inode *ip, xfs_fileoff_t *unused, int whichfork) -> int
  fn xfs_bmapi_read(struct xfs_inode *ip, xfs_fileoff_t bno, xfs_filblks_t len, struct xfs_bmbt_irec *mval, int *nmap, uint32_t flags) -> int
  fn xfs_bmapi_write(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t bno, xfs_filblks_t len, uint32_t flags, xfs_extlen_t total, struct xfs_bmbt_irec *mval, int *nmap) -> int
  fn xfs_bunmapi(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t bno, xfs_filblks_t len, uint32_t flags, xfs_extnum_t nexts, int *done) -> int
  fn xfs_bmap_del_extent_delay(struct xfs_inode *ip, int whichfork, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *got, struct xfs_bmbt_irec *del, uint32_t bflags) -> void
  fn xfs_bmap_del_extent_cow(struct xfs_inode *ip, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *got, struct xfs_bmbt_irec *del) -> void
  fn xfs_default_attroffset(struct xfs_inode *ip) -> uint
  fn xfs_bmap_collapse_extents(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t *next_fsb, xfs_fileoff_t offset_shift_fsb, bool *done) -> int
  fn xfs_bmap_can_insert_extents(struct xfs_inode *ip, xfs_fileoff_t off, xfs_fileoff_t shift) -> int
  fn xfs_bmap_insert_extents(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t *next_fsb, xfs_fileoff_t offset_shift_fsb, bool *done, xfs_fileoff_t stop_fsb) -> int
  fn xfs_bmap_split_extent(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t split_offset) -> int
  fn xfs_bmapi_convert_delalloc(struct xfs_inode *ip, int whichfork, xfs_off_t offset, struct iomap *iomap, unsigned int *seq) -> int
  fn xfs_bmap_add_extent_unwritten_real(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_iext_cursor *icur, struct xfs_btree_cur **curp, struct xfs_bmbt_irec *new, int *logflagsp) -> int
  fn xfs_bmapi_minleft(struct xfs_trans *tp, struct xfs_inode *ip, int fork) -> xfs_extlen_t
  fn xfs_bmap_btalloc_low_space(struct xfs_bmalloca *ap, struct xfs_alloc_arg *args) -> int
  fn xfs_bmap_worst_indlen(struct xfs_inode *ip, xfs_filblks_t len) -> xfs_filblks_t
  fn xfs_bmap_finish_one(struct xfs_trans *tp, struct xfs_bmap_intent *bi) -> int
  fn xfs_bmap_map_extent(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *imap) -> void
  fn xfs_bmap_unmap_extent(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *imap) -> void
  fn xfs_bmap_validate_extent_raw(struct xfs_mount *mp, bool rtfile, int whichfork, struct xfs_bmbt_irec *irec) -> xfs_failaddr_t
  fn xfs_bmap_validate_extent(struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *irec) -> xfs_failaddr_t
  fn xfs_bmap_complain_bad_rec(struct xfs_inode *ip, int whichfork, xfs_failaddr_t fa, const struct xfs_bmbt_irec *irec) -> int
  fn xfs_bmapi_remap(struct xfs_trans *tp, struct xfs_inode *ip, xfs_fileoff_t bno, xfs_filblks_t len, xfs_fsblock_t startblock, uint32_t flags) -> int
  fn xfs_bunmapi_range(struct xfs_trans **tpp, struct xfs_inode *ip, uint32_t flags, xfs_fileoff_t startoff, xfs_fileoff_t endoff) -> int
  fn xfs_bmap_intent_init_cache(void) -> int __init
  fn xfs_bmap_intent_destroy_cache(void) -> void
  fn xfs_bmap_query_all(struct xfs_btree_cur *cur, xfs_bmap_query_range_fn fn, void *priv) -> int
  fn xfs_get_extsz_hint(struct xfs_inode *ip) -> xfs_extlen_t
  fn xfs_get_cowextsz_hint(struct xfs_inode *ip) -> xfs_extlen_t
  struct xfs_bmalloca { tp, ip, prev, got, offset, length, blkno, cur, icur, nallocs }
  enum xfs_bmap_intent_type { XFS_BMAP_MAP, XFS_BMAP_UNMAP }
  struct xfs_bmap_intent { bi_list, bi_type, bi_whichfork, bi_owner, bi_group, bi_bmap }
  typedef_fn xfs_bmap_query_range_fn

[xfs/libxfs/xfs_bmap_btree.h]
  fn xfs_bmdr_to_bmbt(struct xfs_inode *, xfs_bmdr_block_t *, int, struct xfs_btree_block *, int) -> void
  fn xfs_bmbt_disk_set_all(struct xfs_bmbt_rec *r, struct xfs_bmbt_irec *s) -> void
  fn xfs_bmbt_disk_get_blockcount(const struct xfs_bmbt_rec *r) -> xfs_filblks_t
  fn xfs_bmbt_disk_get_startoff(const struct xfs_bmbt_rec *r) -> xfs_fileoff_t
  fn xfs_bmbt_disk_get_all(const struct xfs_bmbt_rec *r, struct xfs_bmbt_irec *s) -> void
  fn xfs_bmbt_to_bmdr(struct xfs_mount *, struct xfs_btree_block *, int, xfs_bmdr_block_t *, int) -> void
  fn xfs_bmbt_get_maxrecs(struct xfs_btree_cur *, int level) -> int
  fn xfs_bmdr_maxrecs(int blocklen, int leaf) -> int
  fn xfs_bmbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_bmbt_change_owner(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, xfs_ino_t new_owner, struct list_head *buffer_list, bool mxfs_foreign_recovery) -> int
  fn xfs_bmbt_init_cursor(struct xfs_mount *, struct xfs_trans *, struct xfs_inode *, int) -> struct xfs_btree_cur
  fn xfs_bmbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp, int whichfork) -> void
  fn xfs_bmbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> unsigned long long
  fn xfs_bmbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_bmbt_init_cur_cache(void) -> int __init
  fn xfs_bmbt_destroy_cur_cache(void) -> void
  fn xfs_bmbt_init_block(struct xfs_inode *ip, struct xfs_btree_block *buf, struct xfs_buf *bp, __u16 level, __u16 numrecs) -> void
  fn xfs_bmap_broot_realloc(struct xfs_inode *ip, int whichfork, unsigned int new_numrecs) -> struct xfs_btree_block

[xfs/libxfs/xfs_btree.c]
  fn static xfs_btree_block_errtag(struct xfs_btree_cur *cur) -> unsigned int
  fn static xfs_btree_block_len(struct xfs_btree_cur *cur) -> size_t
  struct xfs_btree_split_args { cur, level, ptrp, key, stat, result, kswapd, done, work }
  struct xfs_btree_block_change_owner_info { new_owner, buffer_list, mxfs_foreign_recovery }
  struct xfs_btree_has_records { start_key, end_key, key_mask, high_key, outcome }

[xfs/libxfs/xfs_btree.h]
  fn xfs_btree_magic(struct xfs_mount *mp, const struct xfs_btree_ops *ops) -> uint32_t
  fn struct_size_t(struct xfs_btree_cur, bc_levels, nlevels) -> return
  fn __xfs_btree_check_block(struct xfs_btree_cur *cur, struct xfs_btree_block *block, int level, struct xfs_buf *bp) -> xfs_failaddr_t
  fn __xfs_btree_check_ptr(struct xfs_btree_cur *cur, const union xfs_btree_ptr *ptr, int index, int level) -> int
  fn xfs_btree_init_buf(struct xfs_mount *mp, struct xfs_buf *bp, const struct xfs_btree_ops *ops, __u16 level, __u16 numrecs, __u64 owner) -> void
  fn xfs_btree_init_block(struct xfs_mount *mp, struct xfs_btree_block *buf, const struct xfs_btree_ops *ops, __u16 level, __u16 numrecs, __u64 owner) -> void
  fn xfs_btree_increment(struct xfs_btree_cur *, int, int *) -> int
  fn xfs_btree_decrement(struct xfs_btree_cur *, int, int *) -> int
  fn xfs_btree_lookup(struct xfs_btree_cur *, xfs_lookup_t, int *) -> int
  fn xfs_btree_update(struct xfs_btree_cur *, union xfs_btree_rec *) -> int
  fn xfs_btree_new_iroot(struct xfs_btree_cur *, int *, int *) -> int
  fn xfs_btree_insert(struct xfs_btree_cur *, int *) -> int
  fn xfs_btree_delete(struct xfs_btree_cur *, int *) -> int
  fn xfs_btree_get_rec(struct xfs_btree_cur *, union xfs_btree_rec **, int *) -> int
  fn xfs_btree_change_owner(struct xfs_btree_cur *cur, uint64_t new_owner, struct list_head *buffer_list, bool mxfs_foreign_recovery) -> int
  fn xfs_btree_fsblock_calc_crc(struct xfs_buf *) -> void
  fn xfs_btree_fsblock_verify_crc(struct xfs_buf *) -> bool
  fn xfs_btree_agblock_calc_crc(struct xfs_buf *) -> void
  fn xfs_btree_agblock_verify_crc(struct xfs_buf *) -> bool
  fn xfs_btree_log_block(struct xfs_btree_cur *, struct xfs_buf *, uint32_t) -> void
  fn xfs_btree_log_recs(struct xfs_btree_cur *, struct xfs_buf *, int, int) -> void
  fn be16_to_cpu(block->bb_numrecs) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range, xfs_attr_sf_totsize
  fn be16_to_cpu(block->bb_level) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range, xfs_attr_sf_totsize
  fn xfs_btree_agblock_v5hdr_verify(struct xfs_buf *bp) -> xfs_failaddr_t
  fn xfs_btree_agblock_verify(struct xfs_buf *bp, unsigned int max_recs) -> xfs_failaddr_t
  fn xfs_btree_fsblock_v5hdr_verify(struct xfs_buf *bp, uint64_t owner) -> xfs_failaddr_t
  fn xfs_btree_fsblock_verify(struct xfs_buf *bp, unsigned int max_recs) -> xfs_failaddr_t
  fn xfs_btree_memblock_verify(struct xfs_buf *bp, unsigned int max_recs) -> xfs_failaddr_t
  fn xfs_btree_compute_maxlevels(const unsigned int *limits, unsigned long long records) -> unsigned int
  fn xfs_btree_calc_size(const unsigned int *limits, unsigned long long records) -> unsigned long long
  fn xfs_btree_space_to_height(const unsigned int *limits, unsigned long long blocks) -> unsigned int
  fn xfs_btree_query_range(struct xfs_btree_cur *cur, const union xfs_btree_irec *low_rec, const union xfs_btree_irec *high_rec, xfs_btree_query_range_fn fn, void *priv) -> int
  fn xfs_btree_query_all(struct xfs_btree_cur *cur, xfs_btree_query_range_fn fn, void *priv) -> int
  fn xfs_btree_visit_blocks(struct xfs_btree_cur *cur, xfs_btree_visit_blocks_fn fn, unsigned int flags, void *data) -> int
  fn xfs_btree_count_blocks(struct xfs_btree_cur *cur, xfs_filblks_t *blocks) -> int
  fn xfs_btree_rec_addr(struct xfs_btree_cur *cur, int n, struct xfs_btree_block *block) -> union xfs_btree_rec
  fn xfs_btree_key_addr(struct xfs_btree_cur *cur, int n, struct xfs_btree_block *block) -> union xfs_btree_key
  fn xfs_btree_high_key_addr(struct xfs_btree_cur *cur, int n, struct xfs_btree_block *block) -> union xfs_btree_key
  fn xfs_btree_ptr_addr(struct xfs_btree_cur *cur, int n, struct xfs_btree_block *block) -> union xfs_btree_ptr
  fn xfs_btree_lookup_get_block(struct xfs_btree_cur *cur, int level, const union xfs_btree_ptr *pp, struct xfs_btree_block **blkp) -> int
  fn xfs_btree_get_block(struct xfs_btree_cur *cur, int level, struct xfs_buf **bpp) -> struct xfs_btree_block
  fn xfs_btree_ptr_is_null(struct xfs_btree_cur *cur, const union xfs_btree_ptr *ptr) -> bool
  fn xfs_btree_cmp_two_ptrs(struct xfs_btree_cur *cur, const union xfs_btree_ptr *a, const union xfs_btree_ptr *b) -> int
  fn xfs_btree_get_sibling(struct xfs_btree_cur *cur, struct xfs_btree_block *block, union xfs_btree_ptr *ptr, int lr) -> void
  fn xfs_btree_get_keys(struct xfs_btree_cur *cur, struct xfs_btree_block *block, union xfs_btree_key *key) -> void
  fn xfs_btree_high_key_from_key(struct xfs_btree_cur *cur, union xfs_btree_key *key) -> union xfs_btree_key
  fn xfs_btree_has_records(struct xfs_btree_cur *cur, const union xfs_btree_irec *low, const union xfs_btree_irec *high, const union xfs_btree_key *mask, enum xbtree_recpacking *outcome) -> int
  fn xfs_btree_has_more_records(struct xfs_btree_cur *cur) -> bool
  fn xfs_btree_ifork_ptr(struct xfs_btree_cur *cur) -> struct xfs_ifork
  fn xfs_btree_set_ptr_null(struct xfs_btree_cur *cur, union xfs_btree_ptr *ptr) -> void
  fn xfs_btree_get_buf_block(struct xfs_btree_cur *cur, const union xfs_btree_ptr *ptr, struct xfs_btree_block **block, struct xfs_buf **bpp) -> int
  fn xfs_btree_read_buf_block(struct xfs_btree_cur *cur, const union xfs_btree_ptr *ptr, int flags, struct xfs_btree_block **block, struct xfs_buf **bpp) -> int
  fn xfs_btree_set_sibling(struct xfs_btree_cur *cur, struct xfs_btree_block *block, const union xfs_btree_ptr *ptr, int lr) -> void
  fn xfs_btree_init_block_cur(struct xfs_btree_cur *cur, struct xfs_buf *bp, int level, int numrecs) -> void
  fn xfs_btree_copy_ptrs(struct xfs_btree_cur *cur, union xfs_btree_ptr *dst_ptr, const union xfs_btree_ptr *src_ptr, int numptrs) -> void
  fn xfs_btree_copy_keys(struct xfs_btree_cur *cur, union xfs_btree_key *dst_key, const union xfs_btree_key *src_key, int numkeys) -> void
  fn xfs_btree_init_ptr_from_cur(struct xfs_btree_cur *cur, union xfs_btree_ptr *ptr) -> void
  fn xfs_btree_init_cur_caches(void) -> int __init
  fn xfs_btree_destroy_cur_caches(void) -> void
  fn xfs_btree_goto_left_edge(struct xfs_btree_cur *cur) -> int
  fn xfs_btree_alloc_metafile_block(struct xfs_btree_cur *cur, const union xfs_btree_ptr *start, union xfs_btree_ptr *newp, int *stat) -> int
  fn xfs_btree_free_metafile_block(struct xfs_btree_cur *cur, struct xfs_buf *bp) -> int
  union xfs_btree_ptr { s, l }
  union xfs_btree_key { bmbt, bmbr, alloc, inobt, rmap, __rmap_bigkey, refc }
  union xfs_btree_rec { bmbt, bmbr, alloc, inobt, rmap, refc }
  enum xbtree_key_contig { XBTREE_KEY_GAP, XBTREE_KEY_CONTIGUOUS, XBTREE_KEY_OVERLAP }
  enum xfs_btree_type { XFS_BTREE_TYPE_AG, XFS_BTREE_TYPE_INODE, XFS_BTREE_TYPE_MEM }
  struct xfs_btree_ops { name, type, geom_flags, key_len, ptr_len, rec_len, lru_refs, statoff, sick_mask, buf_ops }
  union xfs_btree_irec { a, b, i, r, rc }
  struct xfs_btree_level { bp, ptr, ra }
  typedef_fn xfs_btree_query_range_fn
  typedef_fn xfs_btree_visit_blocks_fn
  typedef_fn xfs_btree_key_gap_fn

[xfs/libxfs/xfs_btree_mem.h]
  fn xfbtree_set_root(struct xfs_btree_cur *cur, const union xfs_btree_ptr *ptr, int inc) -> void
  fn xfbtree_init_ptr_from_cur(struct xfs_btree_cur *cur, union xfs_btree_ptr *ptr) -> void
  fn xfbtree_dup_cursor(struct xfs_btree_cur *cur) -> struct xfs_btree_cur
  fn xfbtree_get_minrecs(struct xfs_btree_cur *cur, int level) -> int
  fn xfbtree_get_maxrecs(struct xfs_btree_cur *cur, int level) -> int
  fn xfbtree_alloc_block(struct xfs_btree_cur *cur, const union xfs_btree_ptr *start, union xfs_btree_ptr *ptr, int *stat) -> int
  fn xfbtree_free_block(struct xfs_btree_cur *cur, struct xfs_buf *bp) -> int
  fn xfbtree_init(struct xfs_mount *mp, struct xfbtree *xfbt, struct xfs_buftarg *btp, const struct xfs_btree_ops *ops) -> int
  fn xfbtree_destroy(struct xfbtree *xfbt) -> void
  fn xfbtree_trans_commit(struct xfbtree *xfbt, struct xfs_trans *tp) -> int
  fn xfbtree_trans_cancel(struct xfbtree *xfbt, struct xfs_trans *tp) -> void
  struct xfbtree { target, highest_bno, owner, root, nlevels, maxrecs, minrecs }

[xfs/libxfs/xfs_btree_staging.h]
  fn xfs_btree_stage_afakeroot(struct xfs_btree_cur *cur, struct xbtree_afakeroot *afake) -> void
  fn xfs_btree_commit_afakeroot(struct xfs_btree_cur *cur, struct xfs_trans *tp, struct xfs_buf *agbp) -> void
  fn xfs_btree_stage_ifakeroot(struct xfs_btree_cur *cur, struct xbtree_ifakeroot *ifake) -> void
  fn xfs_btree_commit_ifakeroot(struct xfs_btree_cur *cur, struct xfs_trans *tp, int whichfork) -> void
  fn xfs_btree_bload_compute_geometry(struct xfs_btree_cur *cur, struct xfs_btree_bload *bbl, uint64_t nr_records) -> int
  fn xfs_btree_bload(struct xfs_btree_cur *cur, struct xfs_btree_bload *bbl, void *priv) -> int
  struct xbtree_afakeroot { af_root, af_levels, af_blocks }
  struct xbtree_ifakeroot { if_fork, if_blocks, if_levels, if_fork_size }
  typedef_fn xfs_btree_bload_get_records_fn
  typedef_fn xfs_btree_bload_claim_block_fn
  typedef_fn xfs_btree_bload_iroot_size_fn
  struct xfs_btree_bload { get_records, claim_block, iroot_size, nr_records, leaf_slack, node_slack, nr_blocks, btree_height, max_dirty, nr_dirty }

[xfs/libxfs/xfs_cksum.h]
  fn crc32c(XFS_CRC_SEED, buffer, length) -> return
    called_by: check_journal, desc_crc, dump_slot, main, mxfs_pal_crc32c, mxfs_super_crc, oc_crc, xfs_set_crc

[xfs/libxfs/xfs_da_btree.c]
  fn static xfs_dabuf_nfsb(struct xfs_mount *mp, int whichfork) -> int

[xfs/libxfs/xfs_da_btree.h]
  fn xfs_da3_node_create(struct xfs_da_args *args, xfs_dablk_t blkno, int level, struct xfs_buf **bpp, int whichfork) -> int
  fn xfs_da3_split(xfs_da_state_t *state) -> int
  fn xfs_da3_join(xfs_da_state_t *state) -> int
  fn xfs_da3_fixhashpath(struct xfs_da_state *state, struct xfs_da_state_path *path_to_to_fix) -> void
  fn xfs_da3_node_lookup_int(xfs_da_state_t *state, int *result) -> int
  fn xfs_da3_path_shift(xfs_da_state_t *state, xfs_da_state_path_t *path, int forward, int release, int *result) -> int
  fn xfs_da3_blk_link(xfs_da_state_t *state, xfs_da_state_blk_t *old_blk, xfs_da_state_blk_t *new_blk) -> int
  fn xfs_da3_node_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_dablk_t bno, struct xfs_buf **bpp, int whichfork) -> int
  fn xfs_da3_node_read_mapped(struct xfs_trans *tp, struct xfs_inode *dp, xfs_daddr_t mappedbno, struct xfs_buf **bpp, int whichfork) -> int
  fn xfs_da_grow_inode(xfs_da_args_t *args, xfs_dablk_t *new_blkno) -> int
  fn xfs_da_grow_inode_int(struct xfs_da_args *args, xfs_fileoff_t *bno, int count) -> int
  fn xfs_da_get_buf(struct xfs_trans *trans, struct xfs_inode *dp, xfs_dablk_t bno, struct xfs_buf **bp, int whichfork) -> int
  fn xfs_da_read_buf(struct xfs_trans *trans, struct xfs_inode *dp, xfs_dablk_t bno, unsigned int flags, struct xfs_buf **bpp, int whichfork, const struct xfs_buf_ops *ops) -> int
  fn xfs_da_reada_buf(struct xfs_inode *dp, xfs_dablk_t bno, unsigned int flags, int whichfork, const struct xfs_buf_ops *ops) -> int
  fn xfs_da_shrink_inode(xfs_da_args_t *args, xfs_dablk_t dead_blkno, struct xfs_buf *dead_buf) -> int
  fn xfs_da_buf_copy(struct xfs_buf *dst, struct xfs_buf *src, size_t size) -> void
  fn xfs_da_hashname(const uint8_t *name_string, int name_length) -> uint
  fn xfs_da_compname(struct xfs_da_args *args, const unsigned char *name, int len) -> enum xfs_dacmp
  fn xfs_da_state_alloc(struct xfs_da_args *args) -> struct xfs_da_state
  fn xfs_da_state_free(xfs_da_state_t *state) -> void
    called_by: xfs_attr_node_removename_setup
  fn xfs_da_state_reset(struct xfs_da_state *state, struct xfs_da_args *args) -> void
  fn xfs_da3_node_hdr_from_disk(struct xfs_mount *mp, struct xfs_da3_icnode_hdr *to, struct xfs_da_intnode *from) -> void
  fn xfs_da3_node_hdr_to_disk(struct xfs_mount *mp, struct xfs_da_intnode *to, struct xfs_da3_icnode_hdr *from) -> void
  fn xfs_da3_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  fn xfs_da3_node_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  struct xfs_da_geometry { blksize, fsbcount, fsblog, blklog, node_hdr_size, node_ents, magicpct, datablk, leaf_hdr_size, leaf_max_ents }
  enum xfs_dacmp { XFS_CMP_DIFFERENT, names, are, completely, different, XFS_CMP_EXACT, names, are, exactly, the }
  struct xfs_da_args { geo, name, new_name, value, new_value, dp, trans, inumber, owner, valuelen }
  struct xfs_da_state_blk { bp, blkno, disk_blkno, index, hashval, magic }
  struct xfs_da_state_path { active, blk }
  struct xfs_da_state { args, mp, path, altpath, inleaf, extravalid, extraafter, extrablk }
  struct xfs_da3_icnode_hdr { forw, back, magic, count, level, btree }

[xfs/libxfs/xfs_da_format.h]
  fn get_unaligned_be16(sfep->offset) -> return
  fn round_up(remotesize + nlen, XFS_ATTR_LEAF_NAME_ALIGN) -> return
    called_by: mxfs_pal_scsi_pr_read_full_status
  fn round_up(localsize + nlen + vlen, XFS_ATTR_LEAF_NAME_ALIGN) -> return
    called_by: mxfs_pal_scsi_pr_read_full_status
  fn xfs_attr3_rmt_buf_space(struct xfs_mount *mp) -> unsigned int
  fn xfs_da3_blkinfo_verify(struct xfs_buf *bp, struct xfs_da3_blkinfo *hdr3) -> xfs_failaddr_t
  struct xfs_da_blkinfo { forw, back, magic, pad }
  struct xfs_da3_blkinfo { hdr, crc, blkno, lsn, uuid, owner }
  struct xfs_da_node_hdr { info, __count, __level }
  struct xfs_da3_node_hdr { info, __count, __level, __pad32 }
  struct xfs_da_node_entry { hashval, before }
  struct xfs_da_intnode { hdr, __btree }
  struct xfs_da3_intnode { hdr, __btree }
  struct xfs_dir2_sf_hdr { count, i8count, parent }
  struct xfs_dir2_sf_entry { namelen, offset, name }
  struct xfs_dir2_data_free { offset, length }
  struct xfs_dir2_data_hdr { magic, bestfree }
  struct xfs_dir3_blk_hdr { magic, crc, blkno, lsn, uuid, owner }
  struct xfs_dir3_data_hdr { hdr, best_free, pad }
  struct xfs_dir2_data_entry { inumber, namelen, name }
  struct xfs_dir2_data_unused { freetag, length, tag }
  struct xfs_dir2_leaf_hdr { info, count, stale }
  struct xfs_dir3_leaf_hdr { info, count, stale, pad }
  struct xfs_dir2_leaf_entry { hashval, address }
  struct xfs_dir2_leaf_tail { bestcount }
  struct xfs_dir2_leaf { hdr, __ents }
  struct xfs_dir3_leaf { hdr, __ents }
  struct xfs_dir2_free_hdr { magic, firstdb, nvalid, nused }
  struct xfs_dir2_free { hdr, bests }
  struct xfs_dir3_free_hdr { hdr, firstdb, nvalid, nused, pad }
  struct xfs_dir3_free { hdr, bests }
  struct xfs_dir2_block_tail { count, stale }
  struct xfs_attr_sf_hdr { totsize, count, padding }
  struct xfs_attr_sf_entry { namelen, valuelen, flags, nameval }
  struct xfs_attr_leaf_map { base, size }
  struct xfs_attr_leaf_hdr { info, count, usedbytes, firstused, holes, pad1, freemap }
  struct xfs_attr_leaf_entry { hashval, nameidx, flags, pad2 }
  struct xfs_attr_leaf_name_local { valuelen, namelen, nameval }
  struct xfs_attr_leaf_name_remote { valueblk, valuelen, namelen, name }
  struct xfs_attr_leafblock { hdr, entries }
  struct xfs_attr3_leaf_hdr { info, count, usedbytes, firstused, holes, pad1, freemap, pad2 }
  struct xfs_attr3_leafblock { hdr, entries }
  struct xfs_attr3_rmt_hdr { rm_magic, rm_offset, rm_bytes, rm_crc, rm_uuid, rm_owner, rm_blkno, rm_lsn }
  struct xfs_parent_rec { p_ino, p_gen }

[xfs/libxfs/xfs_defer.h]
  fn xfs_defer_item_pause(struct xfs_trans *tp, struct xfs_defer_pending *dfp) -> void
  fn xfs_defer_item_unpause(struct xfs_trans *tp, struct xfs_defer_pending *dfp) -> void
  fn xfs_defer_add(struct xfs_trans *tp, struct list_head *h, const struct xfs_defer_op_type *ops) -> struct xfs_defer_pending
  fn xfs_defer_finish_noroll(struct xfs_trans **tp) -> int
  fn xfs_defer_finish(struct xfs_trans **tp) -> int
    called_by: xreap_want_defer_finish
  fn xfs_defer_finish_one(struct xfs_trans *tp, struct xfs_defer_pending *dfp) -> int
  fn xfs_defer_cancel(struct xfs_trans *) -> void
  fn xfs_defer_move(struct xfs_trans *dtp, struct xfs_trans *stp) -> void
  fn xfs_defer_ops_capture_and_commit(struct xfs_trans *tp, struct list_head *capture_list) -> int
  fn xfs_defer_ops_continue(struct xfs_defer_capture *d, struct xfs_trans *tp, struct xfs_defer_resources *dres) -> void
  fn xfs_defer_ops_capture_abort(struct xfs_mount *mp, struct xfs_defer_capture *d) -> void
  fn xfs_defer_resources_rele(struct xfs_defer_resources *dres) -> void
  fn xfs_defer_start_recovery(struct xfs_log_item *lip, struct list_head *r_dfops, const struct xfs_defer_op_type *ops) -> void
  fn xfs_defer_cancel_recovery(struct xfs_mount *mp, struct xfs_defer_pending *dfp) -> void
  fn xfs_defer_finish_recovery(struct xfs_mount *mp, struct xfs_defer_pending *dfp, struct list_head *capture_list) -> int
  fn xfs_defer_init_item_caches(void) -> int __init
  fn xfs_defer_destroy_item_caches(void) -> void
  fn xfs_defer_add_barrier(struct xfs_trans *tp) -> void
  struct xfs_defer_pending { dfp_list, dfp_work, dfp_intent, dfp_done, dfp_ops, dfp_count, dfp_flags }
  struct xfs_defer_op_type { name, max_items }
  struct xfs_defer_resources { dr_bp, dr_ip, dr_bufs, dr_ordered, dr_inos }
  struct xfs_defer_capture { dfc_list, dfc_dfops, dfc_tpflags, dfc_blkres, dfc_rtxres, dfc_logres, dfc_held }

[xfs/libxfs/xfs_dir2.h]
  fn xfs_dir2_format(struct xfs_da_args *args, int *error) -> enum xfs_dir2_fmt
  fn xfs_mode_to_ftype(int mode) -> unsigned char
  fn xfs_dir_startup(void) -> void
  fn xfs_da_mount(struct xfs_mount *mp) -> int
  fn xfs_da_unmount(struct xfs_mount *mp) -> void
  fn xfs_dir_init(struct xfs_trans *tp, struct xfs_inode *dp, struct xfs_inode *pdp) -> int
  fn xfs_dir_createname(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t inum, xfs_extlen_t tot) -> int
  fn xfs_dir_lookup(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t *inum, struct xfs_name *ci_name, uint8_t *ftypep) -> int
  fn xfs_dir_lookup_locked(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t *inum) -> int
  fn xfs_dir_removename(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t ino, xfs_extlen_t tot) -> int
  fn xfs_dir_replace(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t inum, xfs_extlen_t tot) -> int
  fn xfs_dir_canenter(struct xfs_trans *tp, struct xfs_inode *dp, const struct xfs_name *name) -> int
  fn xfs_dir_lookup_args(struct xfs_da_args *args) -> int
  fn xfs_dir_createname_args(struct xfs_da_args *args) -> int
  fn xfs_dir_removename_args(struct xfs_da_args *args) -> int
  fn xfs_dir_replace_args(struct xfs_da_args *args) -> int
  fn xfs_dir2_sf_to_block(struct xfs_da_args *args) -> int
  fn xfs_dir2_shrink_inode(struct xfs_da_args *args, xfs_dir2_db_t db, struct xfs_buf *bp) -> int
  fn xfs_dir2_data_freescan(struct xfs_mount *mp, struct xfs_dir2_data_hdr *hdr, int *loghead) -> void
  fn xfs_dir2_data_log_entry(struct xfs_da_args *args, struct xfs_buf *bp, struct xfs_dir2_data_entry *dep) -> void
  fn xfs_dir2_data_log_header(struct xfs_da_args *args, struct xfs_buf *bp) -> void
  fn xfs_dir2_data_log_unused(struct xfs_da_args *args, struct xfs_buf *bp, struct xfs_dir2_data_unused *dup) -> void
  fn xfs_dir2_data_make_free(struct xfs_da_args *args, struct xfs_buf *bp, xfs_dir2_data_aoff_t offset, xfs_dir2_data_aoff_t len, int *needlogp, int *needscanp) -> void
  fn xfs_dir2_data_use_free(struct xfs_da_args *args, struct xfs_buf *bp, struct xfs_dir2_data_unused *dup, xfs_dir2_data_aoff_t offset, xfs_dir2_data_aoff_t len, int *needlogp, int *needscanp) -> int
  fn xfs_dir2_data_freefind(struct xfs_dir2_data_hdr *hdr, struct xfs_dir2_data_free *bf, struct xfs_dir2_data_unused *dup) -> struct xfs_dir2_data_free
  fn xfs_dir_ino_validate(struct xfs_mount *mp, xfs_ino_t ino) -> int
  fn xfs_dir3_leaf_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  fn xfs_dir3_data_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  fn xfs_dir3_block_header_check(struct xfs_buf *bp, xfs_ino_t owner) -> xfs_failaddr_t
  fn xfs_dir3_get_dtype(struct xfs_mount *mp, uint8_t filetype) -> unsigned char
  fn xfs_dir3_data_end_offset(struct xfs_da_geometry *geo, struct xfs_dir2_data_hdr *hdr) -> unsigned int
  fn xfs_dir2_namecheck(const void *name, size_t length) -> bool
  fn xfs_dir_update_hook(struct xfs_inode *dp, struct xfs_inode *ip, int delta, const struct xfs_name *name) -> void
  fn xfs_dir_hook_disable(void) -> void
  fn xfs_dir_hook_enable(void) -> void
  fn xfs_dir_hook_add(struct xfs_mount *mp, struct xfs_dir_hook *hook) -> int
  fn xfs_dir_hook_del(struct xfs_mount *mp, struct xfs_dir_hook *hook) -> void
  fn xfs_dir_hook_setup(struct xfs_dir_hook *hook, notifier_fn_t mod_fn) -> void
  fn xfs_dir_create_child(struct xfs_trans *tp, unsigned int resblks, struct xfs_dir_update *du) -> int
  fn xfs_dir_add_child(struct xfs_trans *tp, unsigned int resblks, struct xfs_dir_update *du) -> int
  fn xfs_dir_remove_child(struct xfs_trans *tp, unsigned int resblks, struct xfs_dir_update *du) -> int
  fn xfs_dir_exchange_children(struct xfs_trans *tp, struct xfs_dir_update *du1, struct xfs_dir_update *du2, unsigned int spaceres) -> int
  fn xfs_dir_rename_children(struct xfs_trans *tp, struct xfs_dir_update *du_src, struct xfs_dir_update *du_tgt, unsigned int spaceres, struct xfs_dir_update *du_wip) -> int
  enum xfs_dir2_fmt { XFS_DIR2_FMT_SF, XFS_DIR2_FMT_BLOCK, XFS_DIR2_FMT_LEAF, XFS_DIR2_FMT_NODE, XFS_DIR2_FMT_ERROR }
  struct xfs_dir_update_params { dp, ip, name, delta }
  struct xfs_dir_hook { dirent_hook }
  struct xfs_dir_update { dp, name, ip, ppargs }

[xfs/libxfs/xfs_dir2_priv.h]
  fn xfs_ascii_ci_hashname(const struct xfs_name *name) -> xfs_dahash_t
  fn xfs_ascii_ci_compname(struct xfs_da_args *args, const unsigned char *name, int len) -> enum xfs_dacmp
  fn xfs_dir2_grow_inode(struct xfs_da_args *args, int space, xfs_dir2_db_t *dbp) -> int
  fn xfs_dir_cilookup_result(struct xfs_da_args *args, const unsigned char *name, int len) -> int
  fn xfs_dir3_block_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, struct xfs_buf **bpp) -> int
  fn xfs_dir2_block_addname(struct xfs_da_args *args) -> int
  fn xfs_dir2_block_lookup(struct xfs_da_args *args) -> int
  fn xfs_dir2_block_removename(struct xfs_da_args *args) -> int
  fn xfs_dir2_block_replace(struct xfs_da_args *args) -> int
  fn xfs_dir2_leaf_to_block(struct xfs_da_args *args, struct xfs_buf *lbp, struct xfs_buf *dbp) -> int
  fn xfs_dir2_data_bestfree_p(struct xfs_mount *mp, struct xfs_dir2_data_hdr *hdr) -> struct xfs_dir2_data_free
  fn xfs_dir2_data_entry_tag_p(struct xfs_mount *mp, struct xfs_dir2_data_entry *dep) -> __be16
  fn xfs_dir2_data_get_ftype(struct xfs_mount *mp, struct xfs_dir2_data_entry *dep) -> uint8_t
  fn xfs_dir2_data_put_ftype(struct xfs_mount *mp, struct xfs_dir2_data_entry *dep, uint8_t ftype) -> void
  fn xfs_dir3_data_check(struct xfs_inode *dp, struct xfs_buf *bp) -> void
  fn __xfs_dir3_data_check(struct xfs_inode *dp, struct xfs_buf *bp) -> xfs_failaddr_t
  fn xfs_dir3_data_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, xfs_dablk_t bno, unsigned int flags, struct xfs_buf **bpp) -> int
  fn xfs_dir3_data_readahead(struct xfs_inode *dp, xfs_dablk_t bno, unsigned int flags) -> int
  fn xfs_dir3_data_init(struct xfs_da_args *args, xfs_dir2_db_t blkno, struct xfs_buf **bpp) -> int
  fn xfs_dir2_leaf_hdr_from_disk(struct xfs_mount *mp, struct xfs_dir3_icleaf_hdr *to, struct xfs_dir2_leaf *from) -> void
  fn xfs_dir2_leaf_hdr_to_disk(struct xfs_mount *mp, struct xfs_dir2_leaf *to, struct xfs_dir3_icleaf_hdr *from) -> void
  fn xfs_dir3_leaf_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, xfs_dablk_t fbno, struct xfs_buf **bpp) -> int
  fn xfs_dir3_leafn_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, xfs_dablk_t fbno, struct xfs_buf **bpp) -> int
  fn xfs_dir2_block_to_leaf(struct xfs_da_args *args, struct xfs_buf *dbp) -> int
  fn xfs_dir2_leaf_addname(struct xfs_da_args *args) -> int
  fn xfs_dir3_leaf_compact(struct xfs_da_args *args, struct xfs_dir3_icleaf_hdr *leafhdr, struct xfs_buf *bp) -> void
  fn xfs_dir3_leaf_compact_x1(struct xfs_dir3_icleaf_hdr *leafhdr, struct xfs_dir2_leaf_entry *ents, int *indexp, int *lowstalep, int *highstalep, int *lowlogp, int *highlogp) -> void
  fn xfs_dir3_leaf_get_buf(struct xfs_da_args *args, xfs_dir2_db_t bno, struct xfs_buf **bpp, uint16_t magic) -> int
  fn xfs_dir3_leaf_log_ents(struct xfs_da_args *args, struct xfs_dir3_icleaf_hdr *hdr, struct xfs_buf *bp, int first, int last) -> void
  fn xfs_dir3_leaf_log_header(struct xfs_da_args *args, struct xfs_buf *bp) -> void
  fn xfs_dir2_leaf_lookup(struct xfs_da_args *args) -> int
  fn xfs_dir2_leaf_removename(struct xfs_da_args *args) -> int
  fn xfs_dir2_leaf_replace(struct xfs_da_args *args) -> int
  fn xfs_dir2_leaf_search_hash(struct xfs_da_args *args, struct xfs_buf *lbp) -> int
  fn xfs_dir2_leaf_trim_data(struct xfs_da_args *args, struct xfs_buf *lbp, xfs_dir2_db_t db) -> int
  fn xfs_dir2_node_to_leaf(struct xfs_da_state *state) -> int
  fn xfs_dir3_leaf_check_int(struct xfs_mount *mp, struct xfs_dir3_icleaf_hdr *hdr, struct xfs_dir2_leaf *leaf, bool expensive_checks) -> xfs_failaddr_t
  fn xfs_dir2_free_hdr_from_disk(struct xfs_mount *mp, struct xfs_dir3_icfree_hdr *to, struct xfs_dir2_free *from) -> void
  fn xfs_dir2_leaf_to_node(struct xfs_da_args *args, struct xfs_buf *lbp) -> int
  fn xfs_dir2_leaf_lasthash(struct xfs_inode *dp, struct xfs_buf *bp, int *count) -> xfs_dahash_t
  fn xfs_dir2_leafn_lookup_int(struct xfs_buf *bp, struct xfs_da_args *args, int *indexp, struct xfs_da_state *state) -> int
  fn xfs_dir2_leafn_order(struct xfs_inode *dp, struct xfs_buf *leaf1_bp, struct xfs_buf *leaf2_bp) -> int
  fn xfs_dir2_leafn_split(struct xfs_da_state *state, struct xfs_da_state_blk *oldblk, struct xfs_da_state_blk *newblk) -> int
  fn xfs_dir2_leafn_toosmall(struct xfs_da_state *state, int *action) -> int
  fn xfs_dir2_leafn_unbalance(struct xfs_da_state *state, struct xfs_da_state_blk *drop_blk, struct xfs_da_state_blk *save_blk) -> void
  fn xfs_dir2_node_addname(struct xfs_da_args *args) -> int
  fn xfs_dir2_node_lookup(struct xfs_da_args *args) -> int
  fn xfs_dir2_node_removename(struct xfs_da_args *args) -> int
  fn xfs_dir2_node_replace(struct xfs_da_args *args) -> int
  fn xfs_dir2_node_trim_free(struct xfs_da_args *args, xfs_fileoff_t fo, int *rvalp) -> int
  fn xfs_dir2_free_read(struct xfs_trans *tp, struct xfs_inode *dp, xfs_ino_t owner, xfs_dablk_t fbno, struct xfs_buf **bpp) -> int
  fn xfs_dir2_sf_get_ino(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *hdr, struct xfs_dir2_sf_entry *sfep) -> xfs_ino_t
  fn xfs_dir2_sf_get_parent_ino(struct xfs_dir2_sf_hdr *hdr) -> xfs_ino_t
  fn xfs_dir2_sf_put_parent_ino(struct xfs_dir2_sf_hdr *hdr, xfs_ino_t ino) -> void
  fn xfs_dir2_sf_get_ftype(struct xfs_mount *mp, struct xfs_dir2_sf_entry *sfep) -> uint8_t
  fn xfs_dir2_sf_nextentry(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *hdr, struct xfs_dir2_sf_entry *sfep) -> struct xfs_dir2_sf_entry
  fn xfs_dir2_block_sfsize(struct xfs_inode *dp, struct xfs_dir2_data_hdr *block, struct xfs_dir2_sf_hdr *sfhp) -> int
  fn xfs_dir2_block_to_sf(struct xfs_da_args *args, struct xfs_buf *bp, int size, xfs_dir2_sf_hdr_t *sfhp) -> int
  fn xfs_dir2_sf_addname(struct xfs_da_args *args) -> int
  fn xfs_dir2_sf_create(struct xfs_da_args *args, xfs_ino_t pino) -> int
  fn xfs_dir2_sf_lookup(struct xfs_da_args *args) -> int
  fn xfs_dir2_sf_removename(struct xfs_da_args *args) -> int
  fn xfs_dir2_sf_replace(struct xfs_da_args *args) -> int
  fn xfs_dir2_sf_verify(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *sfp, int64_t size) -> xfs_failaddr_t
  fn xfs_dir2_sf_entsize(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *hdr, int len) -> int
  fn xfs_dir2_sf_put_ino(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *hdr, struct xfs_dir2_sf_entry *sfep, xfs_ino_t ino) -> void
  fn xfs_dir2_sf_put_ftype(struct xfs_mount *mp, struct xfs_dir2_sf_entry *sfep, uint8_t ftype) -> void
  fn xfs_readdir(struct xfs_trans *tp, struct xfs_inode *dp, struct dir_context *ctx, size_t bufsize) -> int
  fn mxfs_dirblk_count_active(struct xfs_mount *mp, void *blk, uint32_t blen) -> int
  fn mxfs_dirblk_platter_active(struct xfs_mount *mp, xfs_daddr_t daddr) -> int
  fn mxfs_dirdump(struct xfs_inode *dp, const char *why) -> void
  fn round_up(len, XFS_DIR2_DATA_ALIGN) -> return
    called_by: mxfs_pal_scsi_pr_read_full_status
  fn round_up(len, XFS_DIR2_DATA_ALIGN) -> return
    called_by: mxfs_pal_scsi_pr_read_full_status
  fn xfs_dir2_hashname(struct xfs_mount *mp, const struct xfs_name *name) -> xfs_dahash_t
  fn xfs_dir2_compname(struct xfs_da_args *args, const unsigned char *name, int len) -> enum xfs_dacmp
  fn mxfs_dir_rebuild_leaf_from_data(struct xfs_da_args *args) -> int
  fn mxfs_dir2_datascan_lookup(struct xfs_da_args *args) -> int
  fn mxfs_dir2_leafless_removename(struct xfs_da_args *args) -> int
  struct xfs_dir3_icleaf_hdr { forw, back, magic, count, stale, ents }
  struct xfs_dir3_icfree_hdr { magic, firstdb, nvalid, nused, bests }

[xfs/libxfs/xfs_exchmaps.c]
  struct xfs_exchmaps_adjacent { left1, right1, left2, right2 }

[xfs/libxfs/xfs_exchmaps.h]
  fn xfs_exchmaps_estimate_overhead(struct xfs_exchmaps_req *req) -> int
  fn xfs_exchmaps_estimate(struct xfs_exchmaps_req *req) -> int
  fn xfs_exchmaps_intent_init_cache(void) -> int __init
  fn xfs_exchmaps_intent_destroy_cache(void) -> void
  fn xfs_exchmaps_init_intent(const struct xfs_exchmaps_req *req) -> struct xfs_exchmaps_intent
  fn xfs_exchmaps_ensure_reflink(struct xfs_trans *tp, const struct xfs_exchmaps_intent *xmi) -> void
  fn xfs_exchmaps_upgrade_extent_counts(struct xfs_trans *tp, const struct xfs_exchmaps_intent *xmi) -> void
  fn xfs_exchmaps_finish_one(struct xfs_trans *tp, struct xfs_exchmaps_intent *xmi) -> int
  fn xfs_exchmaps_check_forks(struct xfs_mount *mp, const struct xfs_exchmaps_req *req) -> int
  fn xfs_exchange_mappings(struct xfs_trans *tp, const struct xfs_exchmaps_req *req) -> void
  struct xfs_exchmaps_intent { xmi_list, xmi_ip1, xmi_ip2, xmi_startoff1, xmi_startoff2, xmi_blockcount, xmi_isize1, xmi_isize2, xmi_flags }
  struct xfs_exchmaps_req { ip1, ip2, startoff1, startoff2, blockcount, flags, ip1_bcount, ip2_bcount, ip1_rtbcount, ip2_rtbcount }

[xfs/libxfs/xfs_format.h]
  fn xfs_refc_block(struct xfs_mount *mp) -> unsigned int
  struct xfs_sb { sb_magicnum, sb_blocksize, sb_dblocks, sb_rblocks, sb_rextents, sb_uuid, sb_logstart, sb_rootino, sb_rbmino, sb_rsumino }
  struct xfs_dsb { sb_magicnum, sb_blocksize, sb_dblocks, sb_rblocks, sb_rextents, sb_uuid, sb_logstart, sb_rootino, sb_rbmino, sb_rsumino }
  struct xfs_agf { agf_magicnum, agf_versionnum, agf_seqno, agf_length, agf_bno_root, agf_cnt_root, agf_rmap_root, agf_bno_level, agf_cnt_level, agf_rmap_level }
  struct xfs_agi { agi_magicnum, agi_versionnum, agi_seqno, agi_length, agi_count, agi_root, agi_level, agi_freecount, agi_newino, agi_dirino }
  struct xfs_agfl { agfl_magicnum, agfl_seqno, agfl_uuid, agfl_lsn, agfl_crc }
  union xfs_rtword_raw { old, rtg }
  union xfs_suminfo_raw { old, rtg }
  struct xfs_rtsb { rsb_magicnum, rsb_crc, rsb_pad, rsb_fname, rsb_uuid, rsb_meta_uuid }
  struct xfs_legacy_timestamp { t_sec, t_nsec }
  enum xfs_metafile_type { XFS_METAFILE_UNKNOWN, unknown, XFS_METAFILE_DIR, metadir, directory, XFS_METAFILE_USRQUOTA, user, quota, XFS_METAFILE_GRPQUOTA, group }
  struct xfs_dinode { di_magic, di_mode, di_version, di_format, di_metatype, di_uid, di_gid, di_nlink, di_projid_lo, di_projid_hi }
  enum xfs_dinode_fmt { XFS_DINODE_FMT_DEV, xfs_dev_t, XFS_DINODE_FMT_LOCAL, bulk, data, XFS_DINODE_FMT_EXTENTS, struct, xfs_bmbt_rec, XFS_DINODE_FMT_BTREE, struct }
  struct xfs_rtbuf_blkinfo { rt_magic, rt_crc, rt_owner, rt_blkno, rt_lsn, rt_uuid }
  struct xfs_disk_dquot { d_magic, d_version, d_type, d_id, d_blk_hardlimit, d_blk_softlimit, d_ino_hardlimit, d_ino_softlimit, d_bcount, d_icount }
  struct xfs_dqblk { dd_diskdq, dd_fill, dd_crc, dd_lsn, dd_uuid }
  struct xfs_dsymlink_hdr { sl_magic, sl_offset, sl_bytes, sl_crc, sl_uuid, sl_owner, sl_blkno, sl_lsn }
  struct xfs_alloc_rec { ar_startblock, ar_blockcount }
  struct xfs_alloc_rec_incore { ar_startblock, ar_blockcount }
  struct xfs_inobt_rec { ir_startino, ir_freecount, ir_holemask, ir_count, ir_freecount, ir_free }
  struct xfs_inobt_rec_incore { ir_startino, ir_holemask, ir_count, ir_freecount, ir_free }
  struct xfs_inobt_key { ir_startino }
  struct xfs_owner_info { oi_owner, oi_offset, oi_flags }
  struct xfs_rmap_rec { rm_startblock, rm_blockcount, rm_owner, rm_offset }
  struct xfs_rmap_key { rm_startblock, rm_owner, rm_offset }
  struct xfs_rtrmap_root { bb_level, bb_numrecs }
  struct xfs_refcount_rec { rc_startblock, rc_blockcount, rc_refcount }
  struct xfs_refcount_key { rc_startblock }
  struct xfs_rtrefcount_root { bb_level, bb_numrecs }
  struct xfs_bmdr_block { bb_level, bb_numrecs }
  struct xfs_bmbt_rec
  struct xfs_bmbt_key { br_startoff }
  struct xfs_btree_block_shdr { bb_leftsib, bb_rightsib, bb_blkno, bb_lsn, bb_uuid, bb_owner, bb_crc }
  struct xfs_btree_block_lhdr { bb_leftsib, bb_rightsib, bb_blkno, bb_lsn, bb_uuid, bb_owner, bb_crc, bb_pad }
  struct xfs_btree_block { bb_magic, bb_level, bb_numrecs, s, l }
  struct xfs_acl_entry { ae_tag, ae_id, ae_perm, ae_pad }
  struct xfs_acl { acl_cnt, acl_entry }

[xfs/libxfs/xfs_fs.h]
  struct dioattr { d_mem, d_miniosz, d_maxiosz }
  struct getbmap { bmv_offset, bmv_block, bmv_length, bmv_count, bmv_entries }
  struct getbmapx { bmv_offset, bmv_block, bmv_length, bmv_count, bmv_entries, bmv_iflags, bmv_oflags, bmv_unused1, bmv_unused2 }
  struct xfs_flock64 { l_type, l_whence, l_start, l_len, l_sysid, l_pid, l_pad }
  struct xfs_fsop_geom_v1 { blocksize, rtextsize, agblocks, agcount, logblocks, sectsize, inodesize, imaxpct, datablocks, rtblocks }
  struct xfs_fsop_geom_v4 { blocksize, rtextsize, agblocks, agcount, logblocks, sectsize, inodesize, imaxpct, datablocks, rtblocks }
  struct xfs_fsop_geom { blocksize, rtextsize, agblocks, agcount, logblocks, sectsize, inodesize, imaxpct, datablocks, rtblocks }
  struct xfs_fsop_counts { freedata, freertx, freeino, allocino }
  struct xfs_fsop_resblks { resblks, resblks_avail }
  struct xfs_ag_geometry { ag_number, ag_length, ag_freeblks, ag_icount, ag_ifree, ag_sick, ag_checked, ag_flags, ag_reserved }
  struct xfs_growfs_data { newblocks, imaxpct }
  struct xfs_growfs_log { newblocks, isint }
  struct xfs_growfs_rt { newblocks, extsize }
  struct xfs_bstime { tv_sec, tv_nsec }
  struct xfs_bstat { bs_ino, bs_mode, bs_nlink, bs_uid, bs_gid, bs_rdev, bs_blksize, bs_size, bs_atime, bs_mtime }
  struct xfs_bulkstat { bs_ino, bs_size, bs_blocks, bs_xflags, bs_atime, bs_mtime, bs_ctime, bs_btime, bs_gen, bs_uid }
  struct xfs_fsop_bulkreq { lastip, icount, ubuffer, ocount }
  struct xfs_inogrp { xi_startino, xi_alloccount, xi_allocmask }
  struct xfs_inumbers { xi_startino, xi_allocmask, xi_alloccount, xi_version, xi_padding }
  struct xfs_bulk_ireq { ino, flags, icount, ocount, agno, reserved }
  struct xfs_bulkstat_req { hdr, bulkstat }
  struct xfs_inumbers_req { hdr, inumbers }
  struct xfs_error_injection { fd, errtag }
  struct xfs_fs_eofblocks { eof_version, eof_flags, eof_uid, eof_gid, eof_prid, pad32, eof_min_file_size, pad64 }
  struct xfs_fsop_handlereq { fd, path, oflags, ihandle, ihandlen, ohandle, ohandlen }
  struct xfs_attrlist_cursor { opaque }
  struct xfs_attrlist { al_count, al_more, al_offset }
  struct xfs_attrlist_ent { a_valuelen, a_name }
  struct xfs_fsop_attrlist_handlereq { hreq, pos, flags, buflen, buffer }
  struct xfs_attr_multiop { am_opcode, am_error, am_attrname, am_attrvalue, am_length, am_flags }
  struct xfs_fsop_attrmulti_handlereq { hreq, opcount, ops }
  struct xfs_fsid { val }
  struct xfs_fid { fid_len, fid_pad, fid_gen, fid_ino }
  struct xfs_handle { align, _ha_fsid, ha_fid }
  struct xfs_scrub_metadata { sm_type, sm_flags, sm_ino, sm_gen, sm_agno, sm_reserved }
  struct xfs_scrub_vec { sv_type, sv_flags, sv_ret, sv_reserved }
  struct xfs_scrub_vec_head { svh_ino, svh_gen, svh_agno, svh_flags, svh_rest_us, svh_nr, svh_reserved, svh_vectors }
  struct xfs_exchange_range { file1_fd, pad, file1_offset, file2_offset, length, flags }
  struct xfs_commit_range { file1_fd, pad, file1_offset, file2_offset, length, flags, file2_freshness }
  struct xfs_getparents_rec { gpr_parent, gpr_reclen, gpr_reserved, gpr_name }
  struct xfs_getparents { gp_cursor, gp_iflags, gp_oflags, gp_bufsize, gp_reserved, gp_buffer }
  struct xfs_getparents_by_handle { gph_handle, gph_request }
  struct xfs_rtgroup_geometry { rg_number, rg_length, rg_sick, rg_checked, rg_flags, rg_reserved }
  struct xfs_health_monitor_lost { count }
  struct xfs_health_monitor_fs { mask }
  struct xfs_health_monitor_group { mask, gno }
  struct xfs_health_monitor_inode { mask, gen, ino }
  struct xfs_health_monitor_shutdown { reasons }
  struct xfs_health_monitor_filerange { pos, len, ino, gen, error }
  struct xfs_health_monitor_media { daddr, bbcount }
  struct xfs_health_monitor_event { domain, type, time_ns, lost, fs, group, inode, shutdown, media, filerange }
  struct xfs_health_monitor { flags, format, pad }
  struct xfs_health_file_on_monitored_fs { fd, flags }
  struct xfs_verify_media { me_dev, me_flags, me_start_daddr, me_end_daddr, me_ioerror, me_max_io_size, me_rest_us, me_pad }
  enum xfs_device { XFS_DEV_DATA, XFS_DEV_LOG, XFS_DEV_RT }

[xfs/libxfs/xfs_group.h]
  fn xfs_group_get(struct xfs_mount *mp, uint32_t index, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_get_by_fsb(struct xfs_mount *mp, xfs_fsblock_t fsbno, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_hold(struct xfs_group *xg) -> struct xfs_group
  fn xfs_group_put(struct xfs_group *xg) -> void
  fn xfs_group_grab(struct xfs_mount *mp, uint32_t index, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_next_range(struct xfs_mount *mp, struct xfs_group *xg, uint32_t start_index, uint32_t end_index, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_grab_next_mark(struct xfs_mount *mp, struct xfs_group *xg, xa_mark_t mark, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_rele(struct xfs_group *xg) -> void
  fn xfs_group_insert(struct xfs_mount *mp, struct xfs_group *xg, uint32_t index, enum xfs_group_type) -> int
  fn XFS_FSB_TO_BB(mp, g->start_fsb + fsbno) -> return
  struct xfs_group { xg_mount, xg_gno, xg_type, xg_ref, xg_active_ref, xg_block_count, xg_min_gbno, xg_busy_extents, xg_next_reset, xg_checked }

[xfs/libxfs/xfs_health.h]
  fn xfs_fs_mark_sick(struct xfs_mount *mp, unsigned int mask) -> void
  fn xfs_fs_mark_corrupt(struct xfs_mount *mp, unsigned int mask) -> void
  fn xfs_fs_mark_healthy(struct xfs_mount *mp, unsigned int mask) -> void
  fn xfs_fs_measure_sickness(struct xfs_mount *mp, unsigned int *sick, unsigned int *checked) -> void
  fn xfs_rgno_mark_sick(struct xfs_mount *mp, xfs_rgnumber_t rgno, unsigned int mask) -> void
  fn xfs_agno_mark_sick(struct xfs_mount *mp, xfs_agnumber_t agno, unsigned int mask) -> void
  fn xfs_group_mark_sick(struct xfs_group *xg, unsigned int mask) -> void
  fn xfs_group_mark_corrupt(struct xfs_group *xg, unsigned int mask) -> void
  fn xfs_group_mark_healthy(struct xfs_group *xg, unsigned int mask) -> void
  fn xfs_group_measure_sickness(struct xfs_group *xg, unsigned int *sick, unsigned int *checked) -> void
  fn xfs_inode_mark_sick(struct xfs_inode *ip, unsigned int mask) -> void
  fn xfs_inode_mark_corrupt(struct xfs_inode *ip, unsigned int mask) -> void
  fn xfs_inode_mark_healthy(struct xfs_inode *ip, unsigned int mask) -> void
  fn xfs_inode_measure_sickness(struct xfs_inode *ip, unsigned int *sick, unsigned int *checked) -> void
  fn xfs_health_unmount(struct xfs_mount *mp) -> void
  fn xfs_bmap_mark_sick(struct xfs_inode *ip, int whichfork) -> void
  fn xfs_btree_mark_sick(struct xfs_btree_cur *cur) -> void
  fn xfs_dirattr_mark_sick(struct xfs_inode *ip, int whichfork) -> void
  fn xfs_da_mark_sick(struct xfs_da_args *args) -> void
  fn xfs_fsop_geom_health(struct xfs_mount *mp, struct xfs_fsop_geom *geo) -> void
  fn xfs_ag_geom_health(struct xfs_perag *pag, struct xfs_ag_geometry *ageo) -> void
  fn xfs_rtgroup_geom_health(struct xfs_rtgroup *rtg, struct xfs_rtgroup_geometry *rgeo) -> void
  fn xfs_bulkstat_health(struct xfs_inode *ip, struct xfs_bulkstat *bs) -> void
  fn xfs_healthmon_inode_mask(unsigned int sick_mask) -> unsigned int
  fn xfs_healthmon_rtgroup_mask(unsigned int sick_mask) -> unsigned int
  fn xfs_healthmon_perag_mask(unsigned int sick_mask) -> unsigned int
  fn xfs_healthmon_fs_mask(unsigned int sick_mask) -> unsigned int

[xfs/libxfs/xfs_ialloc.c]
  struct xfs_ialloc_count_inodes { count, freecount }

[xfs/libxfs/xfs_ialloc.h]
  fn xfs_dialloc(struct xfs_trans **tpp, const struct xfs_icreate_args *args, xfs_ino_t *new_ino) -> int
  fn xfs_difree(struct xfs_trans *tp, struct xfs_perag *pag, xfs_ino_t ino, struct xfs_icluster *ifree) -> int
  fn xfs_read_agi(struct xfs_perag *pag, struct xfs_trans *tp, xfs_buf_flags_t flags, struct xfs_buf **agibpp) -> int
  fn xfs_ialloc_read_agi(struct xfs_perag *pag, struct xfs_trans *tp, int flags, struct xfs_buf **agibpp) -> int
  fn xfs_inobt_lookup(struct xfs_btree_cur *cur, xfs_agino_t ino, xfs_lookup_t dir, int *stat) -> int
  fn xfs_inobt_get_rec(struct xfs_btree_cur *cur, xfs_inobt_rec_incore_t *rec, int *stat) -> int
  fn xfs_inobt_rec_freecount(const struct xfs_inobt_rec_incore *irec) -> uint8_t
  fn xfs_ialloc_inode_init(struct xfs_mount *mp, struct xfs_trans *tp, struct list_head *buffer_list, bool mxfs_foreign_recovery, int icount, xfs_agnumber_t agno, xfs_agblock_t agbno, xfs_agblock_t length, unsigned int gen) -> int
  fn xfs_inobt_btrec_to_irec(struct xfs_mount *mp, const union xfs_btree_rec *rec, struct xfs_inobt_rec_incore *irec) -> void
  fn xfs_inobt_check_irec(struct xfs_perag *pag, const struct xfs_inobt_rec_incore *irec) -> xfs_failaddr_t
  fn xfs_ialloc_has_inodes_at_extent(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, enum xbtree_recpacking *outcome) -> int
  fn xfs_ialloc_count_inodes(struct xfs_btree_cur *cur, xfs_agino_t *count, xfs_agino_t *freecount) -> int
  fn xfs_inobt_insert_rec(struct xfs_btree_cur *cur, uint16_t holemask, uint8_t count, int32_t freecount, xfs_inofree_t free, int *stat) -> int
  fn xfs_ialloc_cluster_alignment(struct xfs_mount *mp) -> int
  fn xfs_ialloc_setup_geometry(struct xfs_mount *mp) -> void
  fn xfs_ialloc_calc_rootino(struct xfs_mount *mp, int sunit) -> xfs_ino_t
  fn xfs_ialloc_check_shrink(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf *agibp, xfs_agblock_t new_length) -> int
  struct xfs_icluster { deleted, first_ino, alloc }

[xfs/libxfs/xfs_ialloc_btree.h]
  fn xfs_inobt_init_cursor(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf *agbp) -> struct xfs_btree_cur
  fn xfs_finobt_init_cursor(struct xfs_perag *pag, struct xfs_trans *tp, struct xfs_buf *agbp) -> struct xfs_btree_cur
  fn xfs_inobt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_inobt_irec_to_allocmask(const struct xfs_inobt_rec_incore *irec) -> uint64_t
  fn xfs_inobt_rec_check_count(struct xfs_mount *, struct xfs_inobt_rec_incore *) -> int
  fn xfs_finobt_calc_reserves(struct xfs_perag *perag, struct xfs_trans *tp, xfs_extlen_t *ask, xfs_extlen_t *used) -> int
  fn xfs_iallocbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> xfs_extlen_t
  fn xfs_inobt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp, struct xfs_buf *agbp) -> void
  fn xfs_iallocbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_inobt_init_cur_cache(void) -> int __init
  fn xfs_inobt_destroy_cur_cache(void) -> void

[xfs/libxfs/xfs_iext_tree.c]
  fn static xfs_iext_rec_is_empty(struct xfs_iext_rec *rec) -> bool
    called_by: xfs_iext_max_recs
  fn static xfs_iext_rec_clear(struct xfs_iext_rec *rec) -> void
  fn xfs_iext_count(struct xfs_ifork *ifp) -> xfs_extnum_t
  fn static xfs_iext_max_recs(struct xfs_ifork *ifp) -> int
    calls: cur_rec, xfs_iext_rec_is_empty
  fn static cur_rec(struct xfs_iext_cursor *cur) -> struct xfs_iext_rec
    called_by: xfs_iext_max_recs
  fn static xfs_iext_valid(struct xfs_ifork *ifp, struct xfs_iext_cursor *cur) -> bool
  fn static xfs_iext_inc_seq(struct xfs_ifork *ifp) -> void
  struct xfs_iext_rec { lo, hi }
  struct xfs_iext_node { keys, ptrs }
  struct xfs_iext_leaf { recs, prev, next }

[xfs/libxfs/xfs_inode_buf.c]
  fn static xfs_inode_decode_bigtime(uint64_t ts) -> struct timespec64

[xfs/libxfs/xfs_inode_buf.h]
  fn xfs_imap_to_bp(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_imap *imap, struct xfs_buf **bpp) -> int
  fn xfs_dinode_calc_crc(struct xfs_mount *mp, struct xfs_dinode *dip) -> void
    called_by: mxfs_iunl_store_overlay
  fn xfs_inode_to_disk(struct xfs_inode *ip, struct xfs_dinode *to, xfs_lsn_t lsn) -> void
  fn xfs_inode_from_disk(struct xfs_inode *ip, struct xfs_dinode *from) -> int
  fn xfs_dinode_verify(struct xfs_mount *mp, xfs_ino_t ino, struct xfs_dinode *dip) -> xfs_failaddr_t
  fn xfs_dinode_verify_metadir(struct xfs_mount *mp, struct xfs_dinode *dip, uint16_t mode, uint16_t flags, uint64_t flags2) -> xfs_failaddr_t
  fn xfs_inode_validate_extsize(struct xfs_mount *mp, uint32_t extsize, uint16_t mode, uint16_t flags) -> xfs_failaddr_t
  fn xfs_inode_validate_cowextsize(struct xfs_mount *mp, uint32_t cowextsize, uint16_t mode, uint16_t flags, uint64_t flags2) -> xfs_failaddr_t
  fn xfs_inode_from_disk_ts(struct xfs_dinode *dip, const xfs_timestamp_t ts) -> struct timespec64
  struct xfs_imap { im_blkno, im_len, im_boffset }

[xfs/libxfs/xfs_inode_fork.h]
  fn be64_to_cpu(dip->di_big_nextents) -> return
  fn be32_to_cpu(dip->di_nextents) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range
  fn be32_to_cpu(dip->di_big_anextents) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range
  fn be16_to_cpu(dip->di_anextents) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range, xfs_attr_sf_totsize
  fn xfs_dfork_data_extents(dip) -> return
  fn xfs_dfork_attr_extents(dip) -> return
  fn xfs_ifork_zap_attr(struct xfs_inode *ip) -> void
  fn xfs_ifork_init_attr(struct xfs_inode *ip, enum xfs_dinode_fmt format, xfs_extnum_t nextents) -> void
  fn xfs_iext_state_to_fork(struct xfs_inode *ip, int state) -> struct xfs_ifork
  fn xfs_iformat_data_fork(struct xfs_inode *, struct xfs_dinode *) -> int
  fn xfs_iformat_attr_fork(struct xfs_inode *, struct xfs_dinode *) -> int
  fn xfs_iflush_fork(struct xfs_inode *, struct xfs_dinode *, struct xfs_inode_log_item *, int) -> void
  fn xfs_idestroy_fork(struct xfs_ifork *ifp) -> void
  fn xfs_idata_realloc(struct xfs_inode *ip, int64_t byte_diff, int whichfork) -> void *
  fn xfs_broot_alloc(struct xfs_ifork *ifp, size_t new_size) -> struct xfs_btree_block
  fn xfs_broot_realloc(struct xfs_ifork *ifp, size_t new_size) -> struct xfs_btree_block
  fn xfs_iread_extents(struct xfs_trans *, struct xfs_inode *, int) -> int
  fn xfs_iextents_copy(struct xfs_inode *, struct xfs_bmbt_rec *, int) -> int
  fn xfs_init_local_fork(struct xfs_inode *ip, int whichfork, const void *data, int64_t size) -> void
  fn xfs_iext_count(struct xfs_ifork *ifp) -> xfs_extnum_t
  fn xfs_iext_insert_raw(struct xfs_ifork *ifp, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *irec) -> void
  fn xfs_iext_insert(struct xfs_inode *, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *, int) -> void
  fn xfs_iext_remove(struct xfs_inode *, struct xfs_iext_cursor *, int) -> void
  fn xfs_iext_destroy(struct xfs_ifork *) -> void
  fn xfs_iext_lookup_extent(struct xfs_inode *ip, struct xfs_ifork *ifp, xfs_fileoff_t bno, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *gotp) -> bool
  fn xfs_iext_lookup_extent_before(struct xfs_inode *ip, struct xfs_ifork *ifp, xfs_fileoff_t *end, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *gotp) -> bool
  fn xfs_iext_get_extent(struct xfs_ifork *ifp, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *gotp) -> bool
  fn xfs_iext_update_extent(struct xfs_inode *ip, int state, struct xfs_iext_cursor *cur, struct xfs_bmbt_irec *gotp) -> void
  fn xfs_iext_first(struct xfs_ifork *, struct xfs_iext_cursor *) -> void
  fn xfs_iext_last(struct xfs_ifork *, struct xfs_iext_cursor *) -> void
  fn xfs_iext_next(struct xfs_ifork *, struct xfs_iext_cursor *) -> void
  fn xfs_iext_prev(struct xfs_ifork *, struct xfs_iext_cursor *) -> void
  fn xfs_iext_get_extent(ifp, cur, gotp) -> return
  fn xfs_iext_get_extent(ifp, cur, gotp) -> return
  fn xfs_iext_get_extent(ifp, &ncur, gotp) -> return
  fn xfs_iext_get_extent(ifp, &ncur, gotp) -> return
  fn xfs_ifork_init_cow(struct xfs_inode *ip) -> void
  fn xfs_ifork_verify_local_data(struct xfs_inode *ip) -> int
  fn xfs_ifork_verify_local_attr(struct xfs_inode *ip) -> int
  fn xfs_iext_count_extend(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, uint nr_to_add) -> int
  fn xfs_ifork_is_realtime(struct xfs_inode *ip, int whichfork) -> bool
  struct xfs_ifork { if_bytes, if_broot, if_seq, if_height, if_data, if_nextents, if_broot_bytes, if_format, if_needextents }

[xfs/libxfs/xfs_inode_util.h]
  fn xfs_flags2diflags(struct xfs_inode *ip, unsigned int xflags) -> uint16_t
  fn xfs_flags2diflags2(struct xfs_inode *ip, unsigned int xflags) -> uint64_t
  fn xfs_dic2xflags(struct xfs_inode *ip) -> uint32_t
  fn xfs_ip2xflags(struct xfs_inode *ip) -> uint32_t
  fn xfs_get_initial_prid(struct xfs_inode *dp) -> prid_t
  fn xfs_trans_ichgtime(struct xfs_trans *tp, struct xfs_inode *ip, int flags) -> void
  fn xfs_inode_init(struct xfs_trans *tp, const struct xfs_icreate_args *args, struct xfs_inode *ip) -> void
  fn xfs_inode_uninit(struct xfs_trans *tp, struct xfs_perag *pag, struct xfs_inode *ip, struct xfs_icluster *xic) -> int
  fn xfs_iunlink(struct xfs_trans *tp, struct xfs_inode *ip) -> int
  fn xfs_iunlink_remove(struct xfs_trans *tp, struct xfs_perag *pag, struct xfs_inode *ip) -> int
  fn xfs_droplink(struct xfs_trans *tp, struct xfs_inode *ip) -> int
  fn xfs_bumplink(struct xfs_trans *tp, struct xfs_inode *ip) -> void
  struct xfs_icreate_args { idmap, pip, rdev, mode, flags }

[xfs/libxfs/xfs_log_format.h]
  struct xfs_unmount_log_format { magic, pad1, pad2 }
  struct xlog_op_header { oh_tid, oh_len, oh_clientid, oh_flags, oh_res2 }
  struct xlog_rec_ext_header { xh_cycle, xh_cycle_data, xh_reserved }
  struct xlog_rec_header { h_magicno, h_cycle, h_version, h_len, h_lsn, h_tail_lsn, h_crc, h_prev_block, h_num_logops, h_cycle_data }
  struct xfs_trans_header { th_magic, th_type, th_tid, th_num_items }
  struct xfs_inode_log_format { ilf_type, ilf_size, ilf_fields, ilf_asize, ilf_dsize, ilf_pad, ilf_ino, ilfu_rdev, __pad, ilf_blkno }
  struct xfs_inode_log_format_32 { ilf_type, ilf_size, ilf_fields, ilf_asize, ilf_dsize, ilf_ino, ilfu_rdev, __pad, ilf_blkno, ilf_len }
  struct xfs_log_legacy_timestamp { t_sec, t_nsec }
  struct xfs_log_dinode { di_magic, di_mode, di_version, di_format, di_metatype, di_uid, di_gid, di_nlink, di_projid_lo, di_projid_hi }
  struct mxfs_blf_authority { mba_version, mba_class, mba_resource, mba_grant_epoch, mba_owner_slot, mba_owner_boot }
  struct mxfs_blf_authority_v2 { mba_version, mba_class, mba_flags, mba_resource, mba_grant_epoch, mba_owner_epoch, mba_owner_slot, mba_owner_node }
  struct mxfs_blf_authority_v3 { mba_version, mba_class, mba_flags, mba_resource, mba_grant_epoch, mba_owner_epoch, mba_owner_slot, mba_owner_node, mba_lineage }
  struct mxfs_auth_view { av_version, av_class, av_status, av_resource, av_grant_epoch, av_owner_epoch, av_owner_slot, av_owner_node, av_lineage }
  enum mxfs_auth_parse { MXFS_AUTH_PARSE_NOT_BUF, not, a, buffer, log, item, at, all, MXFS_AUTH_PARSE_UNTAGGED, buffer }
  struct xfs_buf_log_format { blf_type, blf_size, blf_flags, blf_len, blf_blkno, blf_map_size, blf_data_map }
  enum xfs_blft { XFS_BLFT_UNKNOWN_BUF, XFS_BLFT_UDQUOT_BUF, XFS_BLFT_PDQUOT_BUF, XFS_BLFT_GDQUOT_BUF, XFS_BLFT_BTREE_BUF, XFS_BLFT_AGF_BUF, XFS_BLFT_AGFL_BUF, XFS_BLFT_AGI_BUF, XFS_BLFT_DINO_BUF, XFS_BLFT_SYMLINK_BUF }
  struct xfs_extent { ext_start, ext_len }
  struct xfs_extent_32 { ext_start, ext_len }
  struct xfs_extent_64 { ext_start, ext_len, ext_pad }
  struct xfs_efi_log_format { efi_type, efi_size, efi_nextents, efi_id, efi_extents }
  struct xfs_efi_log_format_32 { efi_type, efi_size, efi_nextents, efi_id, efi_extents }
  struct xfs_efi_log_format_64 { efi_type, efi_size, efi_nextents, efi_id, efi_extents }
  struct xfs_efd_log_format { efd_type, efd_size, efd_nextents, efd_efi_id, efd_extents }
  struct xfs_efd_log_format_32 { efd_type, efd_size, efd_nextents, efd_efi_id, efd_extents }
  struct xfs_efd_log_format_64 { efd_type, efd_size, efd_nextents, efd_efi_id, efd_extents }
  struct xfs_map_extent { me_owner, me_startblock, me_startoff, me_len, me_flags }
  struct xfs_rui_log_format { rui_type, rui_size, rui_nextents, rui_id, rui_extents }
  struct xfs_rud_log_format { rud_type, rud_size, __pad, rud_rui_id }
  struct xfs_phys_extent { pe_startblock, pe_len, pe_flags }
  struct xfs_cui_log_format { cui_type, cui_size, cui_nextents, cui_id, cui_extents }
  struct xfs_cud_log_format { cud_type, cud_size, __pad, cud_cui_id }
  struct xfs_bui_log_format { bui_type, bui_size, bui_nextents, bui_id, bui_extents }
  struct xfs_bud_log_format { bud_type, bud_size, __pad, bud_bui_id }
  struct xfs_xmi_log_format { xmi_type, xmi_size, __pad, xmi_id, xmi_inode1, xmi_inode2, xmi_igen1, xmi_igen2, xmi_startoff1, xmi_startoff2 }
  struct xfs_xmd_log_format { xmd_type, xmd_size, __pad, xmd_xmi_id }
  struct xfs_dq_logformat { qlf_type, qlf_size, qlf_id, qlf_blkno, qlf_len, qlf_boffset }
  struct xfs_qoff_logformat { qf_type, qf_size, qf_flags, qf_pad }
  struct xfs_icreate_log { icl_type, icl_size, icl_ag, icl_agbno, icl_count, icl_isize, icl_length, icl_gen }
  struct xfs_attri_log_format { alfi_type, alfi_size, alfi_igen, alfi_id, alfi_ino, alfi_op_flags, alfi_name_len, alfi_old_name_len, alfi_new_name_len, alfi_value_len }
  struct xfs_attrd_log_format { alfd_type, alfd_size, __pad, alfd_alf_id }

[xfs/libxfs/xfs_log_recover.h]
  fn xlog_buf_readahead(struct xlog *log, xfs_daddr_t blkno, uint len, const struct xfs_buf_ops *ops) -> void
  fn xlog_is_buffer_cancelled(struct xlog *log, xfs_daddr_t blkno, uint len) -> bool
  fn xlog_recover_iget(struct xfs_mount *mp, xfs_ino_t ino, struct xfs_inode **ipp) -> int
  fn xlog_recover_iget_handle(struct xfs_mount *mp, xfs_ino_t ino, uint32_t gen, struct xfs_inode **ipp) -> int
  fn xlog_recover_release_intent(struct xlog *log, unsigned short intent_type, uint64_t intent_id) -> void
  fn xlog_alloc_buf_cancel_table(struct xlog *log) -> int
  fn xlog_free_buf_cancel_table(struct xlog *log) -> void
  fn xlog_check_buf_cancel_table(struct xlog *log) -> void
  fn xlog_recover_intent_item(struct xlog *log, struct xfs_log_item *lip, xfs_lsn_t lsn, const struct xfs_defer_op_type *ops) -> void
  fn xlog_recover_finish_intent(struct xfs_trans *tp, struct xfs_defer_pending *dfp) -> int
  enum xlog_recover_reorder { XLOG_REORDER_BUFFER_LIST, XLOG_REORDER_ITEM_LIST, XLOG_REORDER_INODE_BUFFER_LIST, XLOG_REORDER_CANCEL_LIST }
  struct xlog_recover_item_ops { item_type }
  struct xlog_recover_item { ri_list, ri_cnt, ri_total, ri_buf, ri_ops }
  struct xlog_recover { r_list, r_log_tid, r_theader, r_state, r_lsn, r_itemq }

[xfs/libxfs/xfs_metadir.h]
  fn xfs_metadir_load(struct xfs_trans *tp, struct xfs_inode *dp, const char *path, enum xfs_metafile_type metafile_type, struct xfs_inode **ipp) -> int
  fn xfs_metadir_start_create(struct xfs_metadir_update *upd) -> int
  fn xfs_metadir_create(struct xfs_metadir_update *upd, umode_t mode) -> int
  fn xfs_metadir_start_link(struct xfs_metadir_update *upd) -> int
  fn xfs_metadir_link(struct xfs_metadir_update *upd) -> int
  fn xfs_metadir_commit(struct xfs_metadir_update *upd) -> int
  fn xfs_metadir_cancel(struct xfs_metadir_update *upd, int error) -> void
  fn xfs_metadir_mkdir(struct xfs_inode *dp, const char *path, struct xfs_inode **ipp) -> int
  struct xfs_metadir_update { dp, path, ppargs, ip, tp, metafile_type }

[xfs/libxfs/xfs_metafile.h]
  fn xfs_metafile_type_str(enum xfs_metafile_type metatype) -> const char
  fn xfs_metafile_set_iflag(struct xfs_trans *tp, struct xfs_inode *ip, enum xfs_metafile_type metafile_type) -> void
  fn xfs_metafile_clear_iflag(struct xfs_trans *tp, struct xfs_inode *ip) -> void
  fn xfs_metafile_resv_critical(struct xfs_mount *mp) -> bool
  fn xfs_metafile_resv_alloc_space(struct xfs_inode *ip, struct xfs_alloc_arg *args) -> void
  fn xfs_metafile_resv_free_space(struct xfs_inode *ip, struct xfs_trans *tp, xfs_filblks_t len) -> void
  fn xfs_metafile_resv_free(struct xfs_mount *mp) -> void
  fn xfs_metafile_resv_init(struct xfs_mount *mp) -> int
  fn xfs_trans_metafile_iget(struct xfs_trans *tp, xfs_ino_t ino, enum xfs_metafile_type metafile_type, struct xfs_inode **ipp) -> int
  fn xfs_metafile_iget(struct xfs_mount *mp, xfs_ino_t ino, enum xfs_metafile_type metafile_type, struct xfs_inode **ipp) -> int

[xfs/libxfs/xfs_parent.h]
  fn xfs_parent_namecheck(unsigned int attr_flags, const void *name, size_t length) -> bool
  fn xfs_parent_valuecheck(struct xfs_mount *mp, const void *value, size_t valuelen) -> bool
  fn xfs_parent_hashval(struct xfs_mount *mp, const uint8_t *name, int namelen, xfs_ino_t parent_ino) -> xfs_dahash_t
  fn xfs_parent_hashattr(struct xfs_mount *mp, const uint8_t *name, int namelen, const void *value, int valuelen) -> xfs_dahash_t
  fn xfs_parent_addname(struct xfs_trans *tp, struct xfs_parent_args *ppargs, struct xfs_inode *dp, const struct xfs_name *parent_name, struct xfs_inode *child) -> int
  fn xfs_parent_removename(struct xfs_trans *tp, struct xfs_parent_args *ppargs, struct xfs_inode *dp, const struct xfs_name *parent_name, struct xfs_inode *child) -> int
  fn xfs_parent_replacename(struct xfs_trans *tp, struct xfs_parent_args *ppargs, struct xfs_inode *old_dp, const struct xfs_name *old_name, struct xfs_inode *new_dp, const struct xfs_name *new_name, struct xfs_inode *child) -> int
  fn xfs_parent_from_attr(struct xfs_mount *mp, unsigned int attr_flags, const unsigned char *name, unsigned int namelen, const void *value, unsigned int valuelen, xfs_ino_t *parent_ino, uint32_t *parent_gen) -> int
  fn xfs_parent_lookup(struct xfs_trans *tp, struct xfs_inode *ip, const struct xfs_name *name, struct xfs_parent_rec *pptr, struct xfs_da_args *scratch) -> int
  fn xfs_parent_set(struct xfs_inode *ip, xfs_ino_t owner, const struct xfs_name *name, struct xfs_parent_rec *pptr, struct xfs_da_args *scratch) -> int
  fn xfs_parent_unset(struct xfs_inode *ip, xfs_ino_t owner, const struct xfs_name *name, struct xfs_parent_rec *pptr, struct xfs_da_args *scratch) -> int
  struct xfs_parent_args { rec, new_rec, args }

[xfs/libxfs/xfs_quota_defs.h]
  fn xfs_dquot_verify(struct xfs_mount *mp, struct xfs_disk_dquot *ddq, xfs_dqid_t id) -> xfs_failaddr_t
  fn xfs_dqblk_verify(struct xfs_mount *mp, struct xfs_dqblk *dqb, xfs_dqid_t id) -> xfs_failaddr_t
  fn xfs_calc_dquots_per_chunk(unsigned int nbblks) -> int
  fn xfs_dqblk_repair(struct xfs_mount *mp, struct xfs_dqblk *dqb, xfs_dqid_t id, xfs_dqtype_t type) -> void
  fn xfs_dquot_from_disk_ts(struct xfs_disk_dquot *ddq, __be32 dtimer) -> time64_t
  fn xfs_dquot_to_disk_ts(struct xfs_dquot *ddq, time64_t timer) -> __be32
  fn xfs_dqinode_sick_mask(xfs_dqtype_t type) -> unsigned int
  fn xfs_dqinode_load(struct xfs_trans *tp, struct xfs_inode *dp, xfs_dqtype_t type, struct xfs_inode **ipp) -> int
  fn xfs_dqinode_metadir_create(struct xfs_inode *dp, xfs_dqtype_t type, struct xfs_inode **ipp) -> int
  fn xfs_dqinode_metadir_link(struct xfs_inode *dp, xfs_dqtype_t type, struct xfs_inode *ip) -> int
  fn xfs_dqinode_mkdir_parent(struct xfs_mount *mp, struct xfs_inode **dpp) -> int
  fn xfs_dqinode_load_parent(struct xfs_trans *tp, struct xfs_inode **dpp) -> int

[xfs/libxfs/xfs_refcount.c]
  enum xfs_refc_adjust_op { XFS_REFCOUNT_ADJUST_INCREASE, XFS_REFCOUNT_ADJUST_DECREASE, XFS_REFCOUNT_ADJUST_COW_ALLOC, XFS_REFCOUNT_ADJUST_COW_FREE }
  struct xfs_refcount_recovery { rr_list, rr_rrec }
  struct xfs_refcount_query_range_info { fn, priv }

[xfs/libxfs/xfs_refcount.h]
  fn xfs_refcount_lookup_le(struct xfs_btree_cur *cur, enum xfs_refc_domain domain, xfs_agblock_t bno, int *stat) -> int
  fn xfs_refcount_lookup_ge(struct xfs_btree_cur *cur, enum xfs_refc_domain domain, xfs_agblock_t bno, int *stat) -> int
  fn xfs_refcount_lookup_eq(struct xfs_btree_cur *cur, enum xfs_refc_domain domain, xfs_agblock_t bno, int *stat) -> int
  fn xfs_refcount_get_rec(struct xfs_btree_cur *cur, struct xfs_refcount_irec *irec, int *stat) -> int
  fn xfs_refcount_increase_extent(struct xfs_trans *tp, bool isrt, struct xfs_bmbt_irec *irec) -> void
  fn xfs_refcount_decrease_extent(struct xfs_trans *tp, bool isrt, struct xfs_bmbt_irec *irec) -> void
  fn xfs_refcount_finish_one(struct xfs_trans *tp, struct xfs_refcount_intent *ri, struct xfs_btree_cur **pcur) -> int
  fn xfs_rtrefcount_finish_one(struct xfs_trans *tp, struct xfs_refcount_intent *ri, struct xfs_btree_cur **pcur) -> int
  fn xfs_refcount_find_shared(struct xfs_btree_cur *cur, xfs_agblock_t agbno, xfs_extlen_t aglen, xfs_agblock_t *fbno, xfs_extlen_t *flen, bool find_end_of_shared) -> int
  fn xfs_refcount_alloc_cow_extent(struct xfs_trans *tp, bool isrt, xfs_fsblock_t fsb, xfs_extlen_t len) -> void
  fn xfs_refcount_free_cow_extent(struct xfs_trans *tp, bool isrt, xfs_fsblock_t fsb, xfs_extlen_t len) -> void
  fn xfs_refcount_recover_cow_leftovers(struct xfs_group *xg) -> int
  fn xfs_refcount_has_records(struct xfs_btree_cur *cur, enum xfs_refc_domain domain, xfs_agblock_t bno, xfs_extlen_t len, enum xbtree_recpacking *outcome) -> int
  fn xfs_refcount_btrec_to_irec(const union xfs_btree_rec *rec, struct xfs_refcount_irec *irec) -> void
  fn xfs_refcount_check_irec(struct xfs_perag *pag, const struct xfs_refcount_irec *irec) -> xfs_failaddr_t
  fn xfs_rtrefcount_check_irec(struct xfs_rtgroup *rtg, const struct xfs_refcount_irec *irec) -> xfs_failaddr_t
  fn xfs_refcount_insert(struct xfs_btree_cur *cur, struct xfs_refcount_irec *irec, int *stat) -> int
  fn xfs_refcount_intent_init_cache(void) -> int __init
  fn xfs_refcount_intent_destroy_cache(void) -> void
  fn xfs_refcount_query_range(struct xfs_btree_cur *cur, const struct xfs_refcount_irec *low_rec, const struct xfs_refcount_irec *high_rec, xfs_refcount_query_range_fn fn, void *priv) -> int
  enum xfs_refcount_intent_type { XFS_REFCOUNT_INCREASE, XFS_REFCOUNT_DECREASE, XFS_REFCOUNT_ALLOC_COW, XFS_REFCOUNT_FREE_COW }
  struct xfs_refcount_intent { ri_list, ri_group, ri_type, ri_blockcount, ri_startblock, ri_realtime }
  typedef_fn xfs_refcount_query_range_fn

[xfs/libxfs/xfs_refcount_btree.h]
  fn xfs_refcountbt_init_cursor(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_buf *agbp, struct xfs_perag *pag) -> struct xfs_btree_cur
  fn xfs_refcountbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_refcountbt_compute_maxlevels(struct xfs_mount *mp) -> void
  fn xfs_refcountbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> xfs_extlen_t
  fn xfs_refcountbt_max_size(struct xfs_mount *mp, xfs_agblock_t agblocks) -> xfs_extlen_t
  fn xfs_refcountbt_calc_reserves(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_perag *pag, xfs_extlen_t *ask, xfs_extlen_t *used) -> int
  fn xfs_refcountbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp, struct xfs_buf *agbp) -> void
  fn xfs_refcountbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_refcountbt_init_cur_cache(void) -> int __init
  fn xfs_refcountbt_destroy_cur_cache(void) -> void

[xfs/libxfs/xfs_rmap.c]
  struct xfs_find_left_neighbor_info { high, irec }
  struct xfs_rmap_query_range_info { fn, priv }
  struct xfs_rmap_ownercount { good, low, high, results, stop_on_nonmatch }

[xfs/libxfs/xfs_rmap.h]
  fn xfs_rmap_alloc(struct xfs_trans *tp, struct xfs_buf *agbp, struct xfs_perag *pag, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo) -> int
  fn xfs_rmap_free(struct xfs_trans *tp, struct xfs_buf *agbp, struct xfs_perag *pag, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo) -> int
  fn xfs_rmap_lookup_le(struct xfs_btree_cur *cur, xfs_agblock_t bno, uint64_t owner, uint64_t offset, unsigned int flags, struct xfs_rmap_irec *irec, int *stat) -> int
  fn xfs_rmap_lookup_eq(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, uint64_t owner, uint64_t offset, unsigned int flags, int *stat) -> int
  fn xfs_rmap_insert(struct xfs_btree_cur *rcur, xfs_agblock_t agbno, xfs_extlen_t len, uint64_t owner, uint64_t offset, unsigned int flags) -> int
  fn xfs_rmap_get_rec(struct xfs_btree_cur *cur, struct xfs_rmap_irec *irec, int *stat) -> int
  fn xfs_rmap_query_range(struct xfs_btree_cur *cur, const struct xfs_rmap_irec *low_rec, const struct xfs_rmap_irec *high_rec, xfs_rmap_query_range_fn fn, void *priv) -> int
  fn xfs_rmap_query_all(struct xfs_btree_cur *cur, xfs_rmap_query_range_fn fn, void *priv) -> int
  fn xfs_rmap_map_extent(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *imap) -> void
  fn xfs_rmap_unmap_extent(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *imap) -> void
  fn xfs_rmap_convert_extent(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *imap) -> void
  fn xfs_rmap_alloc_extent(struct xfs_trans *tp, bool isrt, xfs_fsblock_t fsbno, xfs_extlen_t len, uint64_t owner) -> void
  fn xfs_rmap_free_extent(struct xfs_trans *tp, bool isrt, xfs_fsblock_t fsbno, xfs_extlen_t len, uint64_t owner) -> void
  fn xfs_rmap_finish_one(struct xfs_trans *tp, struct xfs_rmap_intent *ri, struct xfs_btree_cur **pcur) -> int
  fn __xfs_rmap_finish_intent(struct xfs_btree_cur *rcur, enum xfs_rmap_intent_type op, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo, bool unwritten) -> int
  fn xfs_rmap_lookup_le_range(struct xfs_btree_cur *cur, xfs_agblock_t bno, uint64_t owner, uint64_t offset, unsigned int flags, struct xfs_rmap_irec *irec, int	*stat) -> int
  fn xfs_rmap_compare(const struct xfs_rmap_irec *a, const struct xfs_rmap_irec *b) -> int
  fn xfs_rmap_btrec_to_irec(const union xfs_btree_rec *rec, struct xfs_rmap_irec *irec) -> xfs_failaddr_t
  fn xfs_rmap_check_irec(struct xfs_perag *pag, const struct xfs_rmap_irec *irec) -> xfs_failaddr_t
  fn xfs_rtrmap_check_irec(struct xfs_rtgroup *rtg, const struct xfs_rmap_irec *irec) -> xfs_failaddr_t
  fn xfs_rmap_has_records(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, enum xbtree_recpacking *outcome) -> int
  fn xfs_rmap_count_owners(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo, struct xfs_rmap_matches *rmatch) -> int
  fn xfs_rmap_has_other_keys(struct xfs_btree_cur *cur, xfs_agblock_t bno, xfs_extlen_t len, const struct xfs_owner_info *oinfo, bool *has_other) -> int
  fn xfs_rmap_map_raw(struct xfs_btree_cur *cur, struct xfs_rmap_irec *rmap) -> int
  fn xfs_rmap_intent_init_cache(void) -> int __init
  fn xfs_rmap_intent_destroy_cache(void) -> void
  fn xfs_rmap_hook_disable(void) -> void
  fn xfs_rmap_hook_enable(void) -> void
  fn xfs_rmap_hook_add(struct xfs_group *xg, struct xfs_rmap_hook *hook) -> int
  fn xfs_rmap_hook_del(struct xfs_group *xg, struct xfs_rmap_hook *hook) -> void
  fn xfs_rmap_hook_setup(struct xfs_rmap_hook *hook, notifier_fn_t mod_fn) -> void
  typedef_fn xfs_rmap_query_range_fn
  enum xfs_rmap_intent_type { XFS_RMAP_MAP, XFS_RMAP_MAP_SHARED, XFS_RMAP_UNMAP, XFS_RMAP_UNMAP_SHARED, XFS_RMAP_CONVERT, XFS_RMAP_CONVERT_SHARED, XFS_RMAP_ALLOC, XFS_RMAP_FREE }
  struct xfs_rmap_intent { ri_list, ri_type, ri_whichfork, ri_owner, ri_bmap, ri_group, ri_realtime }
  struct xfs_rmap_matches { matches, non_owner_matches, bad_non_owner_matches }
  struct xfs_rmap_update_params { startblock, blockcount, oinfo, unwritten }
  struct xfs_rmap_hook { rmap_hook }

[xfs/libxfs/xfs_rmap_btree.c]
  fn static ondisk_rec_offset_to_key(const union xfs_btree_rec *rec) -> __be64
  fn static offset_keymask(uint64_t offset) -> uint64_t

[xfs/libxfs/xfs_rmap_btree.h]
  fn xfs_rmapbt_init_cursor(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_buf *bp, struct xfs_perag *pag) -> struct xfs_btree_cur
  fn xfs_rmapbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp, struct xfs_buf *agbp) -> void
  fn xfs_rmapbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_rmapbt_compute_maxlevels(struct xfs_mount *mp) -> void
  fn xfs_rmapbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> xfs_extlen_t
  fn xfs_rmapbt_max_size(struct xfs_mount *mp, xfs_agblock_t agblocks) -> xfs_extlen_t
  fn xfs_rmapbt_calc_reserves(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_perag *pag, xfs_extlen_t *ask, xfs_extlen_t *used) -> int
  fn xfs_rmapbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_rmapbt_init_cur_cache(void) -> int __init
  fn xfs_rmapbt_destroy_cur_cache(void) -> void
  fn xfs_rmapbt_mem_cursor(struct xfs_perag *pag, struct xfs_trans *tp, struct xfbtree *xfbtree) -> struct xfs_btree_cur
  fn xfs_rmapbt_mem_init(struct xfs_mount *mp, struct xfbtree *xfbtree, struct xfs_buftarg *btp, xfs_agnumber_t agno) -> int

[xfs/libxfs/xfs_rtbitmap.h]
  fn div_u64(blen, mp->m_sb.sb_rextsize) -> return
  fn do_div(blen, mp->m_sb.sb_rextsize) -> return
  fn roundup_64(blen, mp->m_sb.sb_rextsize) -> return
    called_by: round_ptr_up
  fn div_u64(rtbno, mp->m_sb.sb_rextsize) -> return
  fn do_div(rtbno, mp->m_sb.sb_rextsize) -> return
  fn roundup_64(off, mp->m_sb.sb_rextsize) -> return
    called_by: round_ptr_up
  fn rounddown_64(off, mp->m_sb.sb_rextsize) -> return
  fn div_u64(rtx, mp->m_rtx_per_rbmblock) -> return
  fn be32_to_cpu(word->rtg) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range
  fn be32_to_cpu(info->rtg) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range
  fn be32_to_cpu(info->rtg) -> return
    called_by: mxfs_iunl_discrim, mxfs_iunl_store_overlay, mxfs_iunl_store_retire_range
  fn xfs_rtbuf_cache_relse(struct xfs_rtalloc_args *args) -> void
  fn xfs_rtbitmap_read_buf(struct xfs_rtalloc_args *args, xfs_fileoff_t block) -> int
  fn xfs_rtsummary_read_buf(struct xfs_rtalloc_args *args, xfs_fileoff_t block) -> int
  fn xfs_rtcheck_range(struct xfs_rtalloc_args *args, xfs_rtxnum_t start, xfs_rtxlen_t len, int val, xfs_rtxnum_t *new, int *stat) -> int
  fn xfs_rtfind_back(struct xfs_rtalloc_args *args, xfs_rtxnum_t start, xfs_rtxnum_t *rtblock) -> int
  fn xfs_rtfind_forw(struct xfs_rtalloc_args *args, xfs_rtxnum_t start, xfs_rtxnum_t limit, xfs_rtxnum_t *rtblock) -> int
  fn xfs_rtmodify_range(struct xfs_rtalloc_args *args, xfs_rtxnum_t start, xfs_rtxlen_t len, int val) -> int
  fn xfs_rtget_summary(struct xfs_rtalloc_args *args, int log, xfs_fileoff_t bbno, xfs_suminfo_t *sum) -> int
  fn xfs_rtmodify_summary(struct xfs_rtalloc_args *args, int log, xfs_fileoff_t bbno, int delta) -> int
  fn xfs_rtfree_range(struct xfs_rtalloc_args *args, xfs_rtxnum_t start, xfs_rtxlen_t len) -> int
  fn xfs_rtalloc_query_range(struct xfs_rtgroup *rtg, struct xfs_trans *tp, xfs_rtxnum_t start, xfs_rtxnum_t end, xfs_rtalloc_query_range_fn fn, void *priv) -> int
  fn xfs_rtalloc_query_all(struct xfs_rtgroup *rtg, struct xfs_trans *tp, xfs_rtalloc_query_range_fn fn, void *priv) -> int
  fn xfs_rtalloc_extent_is_free(struct xfs_rtgroup *rtg, struct xfs_trans *tp, xfs_rtxnum_t start, xfs_rtxlen_t len, bool *is_free) -> int
  fn xfs_rtfree_extent(struct xfs_trans *tp, struct xfs_rtgroup *rtg, xfs_rtxnum_t start, xfs_rtxlen_t len) -> int
  fn xfs_rtfree_blocks(struct xfs_trans *tp, struct xfs_rtgroup *rtg, xfs_fsblock_t rtbno, xfs_filblks_t rtlen) -> int
  fn xfs_rtbitmap_rtx_per_rbmblock(struct xfs_mount *mp) -> xfs_rtxnum_t
  fn xfs_rtbitmap_blockcount(struct xfs_mount *mp) -> xfs_filblks_t
  fn xfs_rtbitmap_blockcount_len(struct xfs_mount *mp, xfs_rtbxlen_t rtextents) -> xfs_filblks_t
  fn xfs_rtsummary_blockcount(struct xfs_mount *mp, unsigned int *rsumlevels) -> xfs_filblks_t
  fn xfs_rtfile_initialize_blocks(struct xfs_rtgroup *rtg, enum xfs_rtg_inodes type, xfs_fileoff_t offset_fsb, xfs_fileoff_t end_fsb, void *data) -> int
  fn xfs_rtbitmap_create(struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xfs_trans *tp, bool init) -> int
  fn xfs_rtsummary_create(struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xfs_trans *tp, bool init) -> int
  struct xfs_rtalloc_args { rtg, mp, tp, rbmbp, sumbp, rbmoff, sumoff }
  struct xfs_rtalloc_rec { ar_startext, ar_extcount }
  typedef_fn xfs_rtalloc_query_range_fn

[xfs/libxfs/xfs_rtgroup.c]
  struct xfs_rtginode_ops { name, metafile_type, sick, fmt_mask }

[xfs/libxfs/xfs_rtgroup.h]
  fn container_of(xg, struct xfs_rtgroup, rtg_group) -> return
    called_by: ATTRD_ITEM, ATTRI_ITEM, BUF_ITEM, DQUOT_ITEM, INODE_ITEM, IUL_ITEM, mxfs_defer_work_fn, mxfs_reap_worker, zoned_to_mp
  fn xfs_rtgroup_next_range(mp, rtg, 0, mp->m_sb.sb_rgcount - 1) -> return
  fn xfs_fsb_to_gno(mp, rtbno, XG_TYPE_RTG) -> return
  fn xfs_fsb_to_gbno(mp, rtbno, XG_TYPE_RTG) -> return
  fn XFS_FSB_TO_BB(mp, g->start_fsb + rtbno) -> return
  fn xfs_rtgroup_alloc(struct xfs_mount *mp, xfs_rgnumber_t rgno, xfs_rgnumber_t rgcount, xfs_rtbxlen_t rextents) -> int
  fn xfs_rtgroup_free(struct xfs_mount *mp, xfs_rgnumber_t rgno) -> void
  fn xfs_free_rtgroups(struct xfs_mount *mp, xfs_rgnumber_t first_rgno, xfs_rgnumber_t end_rgno) -> void
  fn xfs_initialize_rtgroups(struct xfs_mount *mp, xfs_rgnumber_t first_rgno, xfs_rgnumber_t end_rgno, xfs_rtbxlen_t rextents) -> int
  fn xfs_rtgroup_extents(struct xfs_mount *mp, xfs_rgnumber_t rgno) -> xfs_rtxnum_t
  fn xfs_rtgroup_calc_geometry(struct xfs_mount *mp, struct xfs_rtgroup *rtg, xfs_rgnumber_t rgno, xfs_rgnumber_t rgcount, xfs_rtbxlen_t rextents) -> void
  fn xfs_update_last_rtgroup_size(struct xfs_mount *mp, xfs_rgnumber_t prev_rgcount) -> int
  fn xfs_rtgroup_lock(struct xfs_rtgroup *rtg, unsigned int rtglock_flags) -> void
  fn xfs_rtgroup_unlock(struct xfs_rtgroup *rtg, unsigned int rtglock_flags) -> void
  fn xfs_rtgroup_trans_join(struct xfs_trans *tp, struct xfs_rtgroup *rtg, unsigned int rtglock_flags) -> void
  fn xfs_rtgroup_get_geometry(struct xfs_rtgroup *rtg, struct xfs_rtgroup_geometry *rgeo) -> int
  fn xfs_rtginode_mkdir_parent(struct xfs_mount *mp) -> int
  fn xfs_rtginode_load_parent(struct xfs_trans *tp) -> int
  fn xfs_rtginode_name(enum xfs_rtg_inodes type) -> const char
  fn xfs_rtginode_metafile_type(enum xfs_rtg_inodes type) -> enum xfs_metafile_type
  fn xfs_rtginode_enabled(struct xfs_rtgroup *rtg, enum xfs_rtg_inodes type) -> bool
  fn xfs_rtginode_mark_sick(struct xfs_rtgroup *rtg, enum xfs_rtg_inodes type) -> void
  fn xfs_rtginode_load(struct xfs_rtgroup *rtg, enum xfs_rtg_inodes type, struct xfs_trans *tp) -> int
  fn xfs_rtginode_create(struct xfs_rtgroup *rtg, enum xfs_rtg_inodes type, bool init) -> int
  fn xfs_rtginode_irele(struct xfs_inode **ipp) -> void
  fn xfs_rtginode_irele(struct xfs_inode **ipp) -> void
  fn xfs_update_rtsb(struct xfs_buf *rtsb_bp, const struct xfs_buf *sb_bp) -> void
  fn xfs_log_rtsb(struct xfs_trans *tp, const struct xfs_buf *sb_bp) -> struct xfs_buf
  fn xfs_groups_to_rfsbs(mp, nr_groups, XG_TYPE_RTG) -> return
  enum xfs_rtg_inodes { XFS_RTGI_BITMAP, allocation, bitmap, XFS_RTGI_SUMMARY, allocation, summary, XFS_RTGI_RMAP, rmap, btree, inode }
  struct xfs_rtgroup { rtg_group, rtg_inodes, rtg_extents, rtg_rsum_cache, rtg_open_zone, rtg_gccount }

[xfs/libxfs/xfs_rtrefcount_btree.h]
  fn xfs_rtrefcountbt_init_cursor(struct xfs_trans *tp, struct xfs_rtgroup *rtg) -> struct xfs_btree_cur
  fn xfs_rtrefcountbt_stage_cursor(struct xfs_mount *mp, struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xbtree_ifakeroot *ifake) -> struct xfs_btree_cur
  fn xfs_rtrefcountbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp) -> void
  fn xfs_rtrefcountbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_rtrefcountbt_compute_maxlevels(struct xfs_mount *mp) -> void
  fn xfs_rtrefcountbt_droot_maxrecs(unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_rtrefcountbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_rtrefcountbt_init_cur_cache(void) -> int __init
  fn xfs_rtrefcountbt_destroy_cur_cache(void) -> void
  fn xfs_rtrefcountbt_calc_reserves(struct xfs_mount *mp) -> xfs_filblks_t
  fn xfs_rtrefcountbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> unsigned long long
  fn xfs_iformat_rtrefcount(struct xfs_inode *ip, struct xfs_dinode *dip) -> int
  fn xfs_rtrefcountbt_to_disk(struct xfs_mount *mp, struct xfs_btree_block *rblock, int rblocklen, struct xfs_rtrefcount_root *dblock, int dblocklen) -> void
  fn xfs_iflush_rtrefcount(struct xfs_inode *ip, struct xfs_dinode *dip) -> void
  fn xfs_rtrefcountbt_create(struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xfs_trans *tp, bool init) -> int

[xfs/libxfs/xfs_rtrmap_btree.c]
  fn static ondisk_rec_offset_to_key(const union xfs_btree_rec *rec) -> __be64
  fn static offset_keymask(uint64_t offset) -> uint64_t

[xfs/libxfs/xfs_rtrmap_btree.h]
  fn xfs_rtrmapbt_init_cursor(struct xfs_trans *tp, struct xfs_rtgroup *rtg) -> struct xfs_btree_cur
  fn xfs_rtrmapbt_stage_cursor(struct xfs_mount *mp, struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xbtree_ifakeroot *ifake) -> struct xfs_btree_cur
  fn xfs_rtrmapbt_commit_staged_btree(struct xfs_btree_cur *cur, struct xfs_trans *tp) -> void
  fn xfs_rtrmapbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_rtrmapbt_compute_maxlevels(struct xfs_mount *mp) -> void
  fn xfs_rtrmapbt_droot_maxrecs(unsigned int blocklen, bool leaf) -> unsigned int
  fn xfs_rtrmapbt_maxlevels_ondisk(void) -> unsigned int
  fn xfs_rtrmapbt_init_cur_cache(void) -> int __init
  fn xfs_rtrmapbt_destroy_cur_cache(void) -> void
  fn xfs_rtrmapbt_calc_reserves(struct xfs_mount *mp) -> xfs_filblks_t
  fn xfs_iformat_rtrmap(struct xfs_inode *ip, struct xfs_dinode *dip) -> int
  fn xfs_rtrmapbt_to_disk(struct xfs_mount *mp, struct xfs_btree_block *rblock, unsigned int rblocklen, struct xfs_rtrmap_root *dblock, unsigned int dblocklen) -> void
  fn xfs_iflush_rtrmap(struct xfs_inode *ip, struct xfs_dinode *dip) -> void
  fn xfs_rtrmapbt_create(struct xfs_rtgroup *rtg, struct xfs_inode *ip, struct xfs_trans *tp, bool init) -> int
  fn xfs_rtrmapbt_init_rtsb(struct xfs_mount *mp, struct xfs_rtgroup *rtg, struct xfs_trans *tp) -> int
  fn xfs_rtrmapbt_calc_size(struct xfs_mount *mp, unsigned long long len) -> unsigned long long
  fn xfs_rtrmapbt_mem_cursor(struct xfs_rtgroup *rtg, struct xfs_trans *tp, struct xfbtree *xfbtree) -> struct xfs_btree_cur
  fn xfs_rtrmapbt_mem_init(struct xfs_mount *mp, struct xfbtree *xfbtree, struct xfs_buftarg *btp, xfs_rgnumber_t rgno) -> int
  fn xfs_rtrmap_highest_rgbno(struct xfs_rtgroup *rtg) -> xfs_rgblock_t

[xfs/libxfs/xfs_sb.h]
  fn xfs_log_sb(struct xfs_trans *tp) -> void
  fn xfs_sync_sb(struct xfs_mount *mp, bool wait) -> int
  fn xfs_sync_sb_buf(struct xfs_mount *mp, bool update_rtsb) -> int
  fn xfs_sb_mount_common(struct xfs_mount *mp, struct xfs_sb *sbp) -> void
  fn xfs_sb_mount_rextsize(struct xfs_mount *mp, struct xfs_sb *sbp) -> void
  fn xfs_mount_sb_set_rextsize(struct xfs_mount *mp, struct xfs_sb *sbp, xfs_agblock_t rextsize) -> void
  fn xfs_sb_from_disk(struct xfs_sb *to, struct xfs_dsb *from) -> void
  fn xfs_sb_to_disk(struct xfs_dsb *to, struct xfs_sb *from) -> void
  fn xfs_sb_quota_from_disk(struct xfs_sb *sbp) -> void
  fn xfs_sb_good_version(struct xfs_sb *sbp) -> bool
  fn xfs_sb_version_to_features(struct xfs_sb *sbp) -> uint64_t
  fn xfs_update_secondary_sbs(struct xfs_mount *mp) -> int
  fn xfs_fs_geometry(struct xfs_mount *mp, struct xfs_fsop_geom *geo, int struct_version) -> void
  fn xfs_sb_read_secondary(struct xfs_mount *mp, struct xfs_trans *tp, xfs_agnumber_t agno, struct xfs_buf **bpp) -> int
  fn xfs_sb_get_secondary(struct xfs_mount *mp, struct xfs_trans *tp, xfs_agnumber_t agno, struct xfs_buf **bpp) -> int
  fn xfs_validate_stripe_geometry(struct xfs_mount *mp, __s64 sunit, __s64 swidth, int sectorsize, bool may_repair, bool silent) -> bool
  fn xfs_validate_rt_geometry(struct xfs_sb *sbp) -> bool
  fn xfs_compute_rextslog(xfs_rtbxlen_t rtextents) -> uint8_t
  fn xfs_compute_rgblklog(xfs_rtxlen_t rgextents, xfs_rgblock_t rextsize) -> int

[xfs/libxfs/xfs_shared.h]
  fn xfs_log_calc_unit_res(struct xfs_mount *mp, int unit_bytes) -> int
  fn xfs_log_calc_minimum_size(struct xfs_mount *) -> int
  fn xfs_log_get_max_trans_res(struct xfs_mount *mp, struct xfs_trans_res *max_resp) -> void
  struct xfs_ino_geometry { maxicount, inode_cluster_size, inode_cluster_size_raw, inodes_per_cluster, blocks_per_cluster, cluster_align, cluster_align_inodes, inoalign_mask, inobt_mxr, inobt_mnr }

[xfs/libxfs/xfs_symlink_remote.h]
  fn xfs_symlink_blocks(struct xfs_mount *mp, int pathlen) -> int
  fn xfs_symlink_hdr_set(struct xfs_mount *mp, xfs_ino_t ino, uint32_t offset, uint32_t size, struct xfs_buf *bp) -> int
  fn xfs_symlink_hdr_ok(xfs_ino_t ino, uint32_t offset, uint32_t size, struct xfs_buf *bp) -> bool
  fn xfs_symlink_local_to_remote(struct xfs_trans *tp, struct xfs_buf *bp, struct xfs_inode *ip, struct xfs_ifork *ifp, void *priv) -> void
  fn xfs_symlink_shortform_verify(void *sfp, int64_t size) -> xfs_failaddr_t
  fn xfs_symlink_remote_read(struct xfs_inode *ip, char *link) -> int
  fn xfs_symlink_write_target(struct xfs_trans *tp, struct xfs_inode *ip, xfs_ino_t owner, const char *target_path, int pathlen, xfs_fsblock_t fs_blocks, uint resblks) -> int
  fn xfs_symlink_remote_truncate(struct xfs_trans *tp, struct xfs_inode *ip) -> int

[xfs/libxfs/xfs_trans_resv.c]
  fn static xfs_calc_pptr_link_overhead(void) -> unsigned int
  fn static xfs_calc_pptr_unlink_overhead(void) -> unsigned int
  fn static xfs_calc_pptr_replace_overhead(void) -> unsigned int

[xfs/libxfs/xfs_trans_resv.h]
  fn xfs_trans_resv_calc(struct xfs_mount *mp, struct xfs_trans_resv *resp) -> void
  fn xfs_allocfree_block_count(struct xfs_mount *mp, uint num_ops) -> uint
  fn xfs_calc_finish_bui_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_efi_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_rt_efi_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_rui_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_rt_rui_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_cui_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_finish_rt_cui_reservation(struct xfs_mount *mp, unsigned int nr_ops) -> unsigned int
  fn xfs_calc_itruncate_reservation_minlogsize(struct xfs_mount *mp) -> unsigned int
  fn xfs_calc_write_reservation_minlogsize(struct xfs_mount *mp) -> unsigned int
  fn xfs_calc_qm_dqalloc_reservation_minlogsize(struct xfs_mount *mp) -> unsigned int
  fn xfs_calc_max_atomic_write_fsblocks(struct xfs_mount *mp) -> xfs_extlen_t
  fn xfs_calc_atomic_write_log_geometry(struct xfs_mount *mp, xfs_extlen_t blockcount, unsigned int *new_logres) -> xfs_extlen_t
  fn xfs_calc_atomic_write_reservation(struct xfs_mount *mp, xfs_extlen_t blockcount) -> int
  struct xfs_trans_res { tr_logres, tr_logcount, tr_logflags }
  struct xfs_trans_resv { tr_write, tr_itruncate, tr_rename, tr_link, tr_remove, tr_symlink, tr_create, tr_create_tmpfile, tr_mkdir, tr_ifree }

[xfs/libxfs/xfs_trans_space.h]
  fn xfs_parent_calc_space_res(struct xfs_mount *mp, unsigned int namelen) -> unsigned int
  fn xfs_create_space_res(struct xfs_mount *mp, unsigned int namelen) -> unsigned int
  fn xfs_mkdir_space_res(struct xfs_mount *mp, unsigned int namelen) -> unsigned int
  fn xfs_link_space_res(struct xfs_mount *mp, unsigned int namelen) -> unsigned int
  fn xfs_symlink_space_res(struct xfs_mount *mp, unsigned int namelen, unsigned int fsblocks) -> unsigned int
  fn xfs_remove_space_res(struct xfs_mount *mp, unsigned int namelen) -> unsigned int
  fn xfs_rename_space_res(struct xfs_mount *mp, unsigned int src_namelen, bool target_exists, unsigned int target_namelen, bool has_whiteout) -> unsigned int

[xfs/libxfs/xfs_types.h]
  fn xfs_verify_fsbno(struct xfs_mount *mp, xfs_fsblock_t fsbno) -> bool
  fn xfs_verify_fsbext(struct xfs_mount *mp, xfs_fsblock_t fsbno, xfs_fsblock_t len) -> bool
  fn xfs_verify_ino(struct xfs_mount *mp, xfs_ino_t ino) -> bool
  fn xfs_is_sb_inum(struct xfs_mount *mp, xfs_ino_t ino) -> bool
  fn xfs_verify_dir_ino(struct xfs_mount *mp, xfs_ino_t ino) -> bool
  fn xfs_verify_rtbno(struct xfs_mount *mp, xfs_rtblock_t rtbno) -> bool
  fn xfs_verify_rtbext(struct xfs_mount *mp, xfs_rtblock_t rtbno, xfs_filblks_t len) -> bool
  fn xfs_verify_icount(struct xfs_mount *mp, unsigned long long icount) -> bool
  fn xfs_verify_dablk(struct xfs_mount *mp, xfs_fileoff_t off) -> bool
  fn xfs_icount_range(struct xfs_mount *mp, unsigned long long *min, unsigned long long *max) -> void
  fn xfs_verify_fileoff(struct xfs_mount *mp, xfs_fileoff_t off) -> bool
  fn xfs_verify_fileext(struct xfs_mount *mp, xfs_fileoff_t off, xfs_fileoff_t len) -> bool
  struct xfs_name { name, len, type }
  struct xfs_iext_cursor { leaf, pos }
  enum xfs_refc_domain { XFS_REFC_DOMAIN_SHARED, XFS_REFC_DOMAIN_COW }
  struct xfs_refcount_irec { rc_startblock, rc_blockcount, rc_refcount, rc_domain }
  struct xfs_rmap_irec { rm_startblock, rm_blockcount, rm_owner, rm_offset, rm_flags }
  enum xfs_ag_resv_type { XFS_AG_RESV_NONE, XFS_AG_RESV_AGFL, XFS_AG_RESV_METADATA, XFS_AG_RESV_RMAPBT, Don, t, increase, fdblocks, when, freeing }
  enum xbtree_recpacking { None, of, the, keyspace, maps, to, records, XBTREE_RECPACKING_EMPTY, Some, but }
  enum xfs_group_type { XG_TYPE_AG, XG_TYPE_RTG, XG_TYPE_MAX }
  enum xfs_free_counter { Number, of, free, blocks, on, the, data, device, XC_FREE_BLOCKS, Number }

[xfs/libxfs/xfs_zones.h]
  fn xfs_validate_blk_zone(struct xfs_mount *mp, struct blk_zone *zone, unsigned int zone_no, uint32_t expected_size, uint32_t expected_capacity, xfs_rgblock_t *write_pointer) -> bool

[xfs/scrub/agb_bitmap.h]
  fn xbitmap32_clear(&bitmap->agbitmap, start, len) -> return
  fn xbitmap32_set(&bitmap->agbitmap, start, len) -> return
  fn xbitmap32_test(&bitmap->agbitmap, start, len) -> return
  fn xbitmap32_disunion(&bitmap->agbitmap, &sub->agbitmap) -> return
  fn xbitmap32_hweight(&bitmap->agbitmap) -> return
  fn xbitmap32_empty(&bitmap->agbitmap) -> return
  fn xbitmap32_walk(&bitmap->agbitmap, fn, priv) -> return
  fn xagb_bitmap_set_btblocks(struct xagb_bitmap *bitmap, struct xfs_btree_cur *cur) -> int
  fn xagb_bitmap_set_btcur_path(struct xagb_bitmap *bitmap, struct xfs_btree_cur *cur) -> int
  fn xbitmap32_count_set_regions(&b->agbitmap) -> return
  struct xagb_bitmap { agbitmap }

[xfs/scrub/agheader.c]
  struct xchk_agfl_info { agflcount, nr_entries, entries, agfl_bp, sc }

[xfs/scrub/agheader_repair.c]
  struct xrep_agf_allocbt { sc, freeblks, longest }
  struct xrep_agfl { crossed, agmetablocks, freesp, rmap_cur, sc }
  struct xrep_agfl_fill { used_extents, sc, agfl_bno, flcount, fl_off }
  struct xrep_agi { sc, agi_bp, fab, old_agi, iunlink_bmp, iunlink_heads, lookup_batch, iunlink_next, iunlink_prev }

[xfs/scrub/agino_bitmap.h]
  fn xbitmap32_clear(&bitmap->aginobitmap, agino, len) -> return
  fn xbitmap32_set(&bitmap->aginobitmap, agino, len) -> return
  fn xbitmap32_test(&bitmap->aginobitmap, agino, len) -> return
  fn xbitmap32_walk(&bitmap->aginobitmap, fn, priv) -> return
  struct xagino_bitmap { aginobitmap }

[xfs/scrub/alloc.c]
  struct xchk_alloc { prev }

[xfs/scrub/alloc_repair.c]
  struct xrep_abt { not_allocbt_blocks, old_allocbt_blocks, new_bnobt, new_cntbt, free_records, sc, nr_real_records, array_cur, next_agbno, nr_blocks }

[xfs/scrub/attr.h]
  fn xchk_xattr_set_map(struct xfs_scrub *sc, unsigned long *map, unsigned int start, unsigned int len) -> bool
  fn xchk_setup_xattr_buf(struct xfs_scrub *sc, size_t value_size) -> int
  struct xchk_xattr_buf { usedmap, freemap, name, value, value_sz }

[xfs/scrub/attr_repair.c]
  struct xrep_xattr_key { name_cookie, value_cookie, flags, valuelen, namelen }
  struct xrep_xattr { sc, tx, xattr_records, xattr_blobs, attrs_found, can_flush, live_update_aborted, lock, pptr_recs, pptr_names }
  struct xrep_xattr_pptr { name_cookie, pptr_rec, namelen, action }

[xfs/scrub/attr_repair.h]
  fn xrep_xattr_swap(struct xfs_scrub *sc, struct xrep_tempexch *tx) -> int
  fn xrep_xattr_reset_fork(struct xfs_scrub *sc) -> int
  fn xrep_xattr_reset_tempfile_fork(struct xfs_scrub *sc) -> int

[xfs/scrub/bitmap.c]
  struct xbitmap64_node { bn_rbnode, bn_start, bn_last, __bn_subtree_last }
  struct xbitmap32_node { bn_rbnode, bn_start, bn_last, __bn_subtree_last }

[xfs/scrub/bitmap.h]
  fn xbitmap64_init(struct xbitmap64 *bitmap) -> void
  fn xbitmap64_destroy(struct xbitmap64 *bitmap) -> void
  fn xbitmap64_clear(struct xbitmap64 *bitmap, uint64_t start, uint64_t len) -> int
  fn xbitmap64_set(struct xbitmap64 *bitmap, uint64_t start, uint64_t len) -> int
  fn xbitmap64_disunion(struct xbitmap64 *bitmap, struct xbitmap64 *sub) -> int
  fn xbitmap64_hweight(struct xbitmap64 *bitmap) -> uint64_t
  fn xbitmap64_walk(struct xbitmap64 *bitmap, xbitmap64_walk_fn fn, void *priv) -> int
  fn xbitmap64_empty(struct xbitmap64 *bitmap) -> bool
  fn xbitmap64_test(struct xbitmap64 *bitmap, uint64_t start, uint64_t *len) -> bool
  fn xbitmap32_init(struct xbitmap32 *bitmap) -> void
  fn xbitmap32_destroy(struct xbitmap32 *bitmap) -> void
  fn xbitmap32_clear(struct xbitmap32 *bitmap, uint32_t start, uint32_t len) -> int
  fn xbitmap32_set(struct xbitmap32 *bitmap, uint32_t start, uint32_t len) -> int
  fn xbitmap32_disunion(struct xbitmap32 *bitmap, struct xbitmap32 *sub) -> int
  fn xbitmap32_hweight(struct xbitmap32 *bitmap) -> uint32_t
  fn xbitmap32_walk(struct xbitmap32 *bitmap, xbitmap32_walk_fn fn, void *priv) -> int
  fn xbitmap32_empty(struct xbitmap32 *bitmap) -> bool
  fn xbitmap32_test(struct xbitmap32 *bitmap, uint32_t start, uint32_t *len) -> bool
  fn xbitmap32_count_set_regions(struct xbitmap32 *bitmap) -> uint32_t
  struct xbitmap64 { xb_root }
  typedef_fn xbitmap64_walk_fn
  struct xbitmap32 { xb_root }
  typedef_fn xbitmap32_walk_fn

[xfs/scrub/bmap.c]
  struct xchk_bmap_info { sc, icur, prev_rec, is_rt, is_shared, was_loaded, whichfork }
  struct xchk_bmap_check_rmap_info { sc, whichfork, icur }

[xfs/scrub/bmap_repair.c]
  enum reflink_scan_state { RLS_IRRELEVANT, not, applicable, to, this, file, RLS_UNKNOWN, shared, extent, scans }
  struct xrep_bmap { old_bmbt_blocks, new_bmapbt, bmap_records, sc, nblocks, old_bmbt_block_count, array_cur, real_mappings, whichfork, reflink_scan }

[xfs/scrub/btree.c]
  struct check_owner { list, daddr, level }

[xfs/scrub/btree.h]
  fn xchk_btree_process_error(struct xfs_scrub *sc, struct xfs_btree_cur *cur, int level, int *error) -> bool
  fn xchk_btree_xref_process_error(struct xfs_scrub *sc, struct xfs_btree_cur *cur, int level, int *error) -> bool
  fn xchk_btree_set_corrupt(struct xfs_scrub *sc, struct xfs_btree_cur *cur, int level) -> void
  fn xchk_btree_set_preen(struct xfs_scrub *sc, struct xfs_btree_cur *cur, int level) -> void
  fn xchk_btree_xref_set_corrupt(struct xfs_scrub *sc, struct xfs_btree_cur *cur, int level) -> void
  fn struct_size_t(struct xchk_btree, lastkey, nlevels - 1) -> return
  fn xchk_btree(struct xfs_scrub *sc, struct xfs_btree_cur *cur, xchk_btree_rec_fn scrub_fn, const struct xfs_owner_info *oinfo, void *private) -> int
  typedef_fn xchk_btree_rec_fn
  struct xchk_btree_key { key, valid }
  struct xchk_btree { sc, cur, scrub_rec, oinfo, private, lastrec_valid, lastrec, to_check, lastkey }

[xfs/scrub/common.c]
  struct xchk_rmap_ownedby_info { oinfo, blocks }

[xfs/scrub/common.h]
  fn xchk_trans_alloc(struct xfs_scrub *sc, uint resblks) -> int
  fn xchk_trans_alloc_empty(struct xfs_scrub *sc) -> void
  fn xchk_trans_cancel(struct xfs_scrub *sc) -> void
  fn xchk_process_error(struct xfs_scrub *sc, xfs_agnumber_t agno, xfs_agblock_t bno, int *error) -> bool
  fn xchk_process_rt_error(struct xfs_scrub *sc, xfs_rgnumber_t rgno, xfs_rgblock_t rgbno, int *error) -> bool
  fn xchk_fblock_process_error(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t offset, int *error) -> bool
  fn xchk_xref_process_error(struct xfs_scrub *sc, xfs_agnumber_t agno, xfs_agblock_t bno, int *error) -> bool
  fn xchk_fblock_xref_process_error(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t offset, int *error) -> bool
  fn xchk_block_set_preen(struct xfs_scrub *sc, struct xfs_buf *bp) -> void
  fn xchk_ino_set_preen(struct xfs_scrub *sc, xfs_ino_t ino) -> void
  fn xchk_set_corrupt(struct xfs_scrub *sc) -> void
  fn xchk_block_set_corrupt(struct xfs_scrub *sc, struct xfs_buf *bp) -> void
  fn xchk_ino_set_corrupt(struct xfs_scrub *sc, xfs_ino_t ino) -> void
  fn xchk_fblock_set_corrupt(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t offset) -> void
  fn xchk_qcheck_set_corrupt(struct xfs_scrub *sc, unsigned int dqtype, xfs_dqid_t id) -> void
  fn xchk_block_xref_set_corrupt(struct xfs_scrub *sc, struct xfs_buf *bp) -> void
  fn xchk_ino_xref_set_corrupt(struct xfs_scrub *sc, xfs_ino_t ino) -> void
  fn xchk_fblock_xref_set_corrupt(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t offset) -> void
  fn xchk_ino_set_warning(struct xfs_scrub *sc, xfs_ino_t ino) -> void
  fn xchk_fblock_set_warning(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t offset) -> void
  fn xchk_set_incomplete(struct xfs_scrub *sc) -> void
  fn xchk_checkpoint_log(struct xfs_mount *mp) -> int
  fn xchk_should_check_xref(struct xfs_scrub *sc, int *error, struct xfs_btree_cur **curpp) -> bool
  fn xchk_setup_agheader(struct xfs_scrub *sc) -> int
  fn xchk_setup_fs(struct xfs_scrub *sc) -> int
  fn xchk_setup_rt(struct xfs_scrub *sc) -> int
  fn xchk_setup_ag_allocbt(struct xfs_scrub *sc) -> int
  fn xchk_setup_ag_iallocbt(struct xfs_scrub *sc) -> int
  fn xchk_setup_ag_rmapbt(struct xfs_scrub *sc) -> int
  fn xchk_setup_ag_refcountbt(struct xfs_scrub *sc) -> int
  fn xchk_setup_inode(struct xfs_scrub *sc) -> int
  fn xchk_setup_inode_bmap(struct xfs_scrub *sc) -> int
  fn xchk_setup_inode_bmap_data(struct xfs_scrub *sc) -> int
  fn xchk_setup_directory(struct xfs_scrub *sc) -> int
  fn xchk_setup_xattr(struct xfs_scrub *sc) -> int
  fn xchk_setup_symlink(struct xfs_scrub *sc) -> int
  fn xchk_setup_parent(struct xfs_scrub *sc) -> int
  fn xchk_setup_dirtree(struct xfs_scrub *sc) -> int
  fn xchk_setup_metapath(struct xfs_scrub *sc) -> int
  fn xchk_setup_rtbitmap(struct xfs_scrub *sc) -> int
  fn xchk_setup_rtsummary(struct xfs_scrub *sc) -> int
  fn xchk_setup_rgsuperblock(struct xfs_scrub *sc) -> int
  fn xchk_setup_rtrmapbt(struct xfs_scrub *sc) -> int
  fn xchk_setup_rtrefcountbt(struct xfs_scrub *sc) -> int
  fn xchk_ino_dqattach(struct xfs_scrub *sc) -> int
  fn xchk_setup_quota(struct xfs_scrub *sc) -> int
  fn xchk_setup_quotacheck(struct xfs_scrub *sc) -> int
  fn xchk_setup_fscounters(struct xfs_scrub *sc) -> int
  fn xchk_setup_nlinks(struct xfs_scrub *sc) -> int
  fn xchk_ag_free(struct xfs_scrub *sc, struct xchk_ag *sa) -> void
  fn xchk_ag_init(struct xfs_scrub *sc, xfs_agnumber_t agno, struct xchk_ag *sa) -> int
  fn xchk_perag_drain_and_lock(struct xfs_scrub *sc) -> int
  fn xchk_rtgroup_init(struct xfs_scrub *sc, xfs_rgnumber_t rgno, struct xchk_rt *sr) -> int
  fn xchk_rtgroup_lock(struct xfs_scrub *sc, struct xchk_rt *sr, unsigned int rtglock_flags) -> int
  fn xchk_rtgroup_unlock(struct xchk_rt *sr) -> void
  fn xchk_rtgroup_btcur_free(struct xchk_rt *sr) -> void
  fn xchk_rtgroup_free(struct xfs_scrub *sc, struct xchk_rt *sr) -> void
  fn xchk_ag_read_headers(struct xfs_scrub *sc, xfs_agnumber_t agno, struct xchk_ag *sa) -> int
  fn xchk_ag_btcur_free(struct xchk_ag *sa) -> void
  fn xchk_ag_btcur_init(struct xfs_scrub *sc, struct xchk_ag *sa) -> void
  fn xchk_count_rmap_ownedby_ag(struct xfs_scrub *sc, struct xfs_btree_cur *cur, const struct xfs_owner_info *oinfo, xfs_filblks_t *blocks) -> int
  fn xchk_setup_ag_btree(struct xfs_scrub *sc, bool force_log) -> int
  fn xchk_iget_for_scrubbing(struct xfs_scrub *sc) -> int
  fn xchk_setup_inode_contents(struct xfs_scrub *sc, unsigned int resblks) -> int
  fn xchk_install_live_inode(struct xfs_scrub *sc, struct xfs_inode *ip) -> int
  fn xchk_ilock(struct xfs_scrub *sc, unsigned int ilock_flags) -> void
  fn xchk_ilock_nowait(struct xfs_scrub *sc, unsigned int ilock_flags) -> bool
  fn xchk_iunlock(struct xfs_scrub *sc, unsigned int ilock_flags) -> void
  fn xchk_buffer_recheck(struct xfs_scrub *sc, struct xfs_buf *bp) -> void
  fn xchk_iget(struct xfs_scrub *sc, xfs_ino_t inum, struct xfs_inode **ipp) -> int
  fn xchk_iget_agi(struct xfs_scrub *sc, xfs_ino_t inum, struct xfs_buf **agi_bpp, struct xfs_inode **ipp) -> int
  fn xchk_irele(struct xfs_scrub *sc, struct xfs_inode *ip) -> void
  fn xchk_install_handle_inode(struct xfs_scrub *sc, struct xfs_inode *ip) -> int
  fn xchk_dir_looks_zapped(struct xfs_inode *dp) -> bool
  fn xchk_pptr_looks_zapped(struct xfs_inode *ip) -> bool
  fn xchk_metadata_inode_forks(struct xfs_scrub *sc) -> int
  fn xchk_fsgates_enable(struct xfs_scrub *sc, unsigned int scrub_fshooks) -> void
  fn xchk_inode_is_allocated(struct xfs_scrub *sc, xfs_agino_t agino, bool *inuse) -> int
  fn xchk_inode_count_blocks(struct xfs_scrub *sc, int whichfork, xfs_extnum_t *nextents, xfs_filblks_t *count) -> int
  fn xchk_inode_is_dirtree_root(const struct xfs_inode *ip) -> bool
  fn xchk_inode_is_sb_rooted(const struct xfs_inode *ip) -> bool
  fn xchk_inode_rootdir_inum(const struct xfs_inode *ip) -> xfs_ino_t

[xfs/scrub/cow_repair.c]
  struct xrep_cow { sc, bad_fileoffs, old_cowfork_fsblocks, old_cowfork_rtblocks, irec, irec_startbno, next_bno }
  struct xrep_cow_extent { fsbno, len }

[xfs/scrub/dab_bitmap.h]
  fn xbitmap32_set(&bitmap->dabitmap, dabno, len) -> return
  fn xbitmap32_test(&bitmap->dabitmap, dabno, len) -> return
  struct xdab_bitmap { dabitmap }

[xfs/scrub/dabtree.h]
  fn xchk_da_process_error(struct xchk_da_btree *ds, int level, int *error) -> bool
  fn xchk_da_set_corrupt(struct xchk_da_btree *ds, int level) -> void
  fn xchk_da_set_preen(struct xchk_da_btree *ds, int level) -> void
  fn xchk_da_set_preen(struct xchk_da_btree *ds, int level) -> void
  fn xchk_da_btree_hash(struct xchk_da_btree *ds, int level, __be32 *hashp) -> int
  fn xchk_da_btree(struct xfs_scrub *sc, int whichfork, xchk_da_btree_rec_fn scrub_fn, void *private) -> int
  struct xchk_da_btree { dargs, hashes, maxrecs, state, sc, private, lowest, highest, tree_level }
  typedef_fn xchk_da_btree_rec_fn

[xfs/scrub/dir.c]
  struct xchk_dirent { name_cookie, ino, namelen }
  struct xchk_dir { sc, pptr_rec, pptr_args, dir_entries, dir_names, need_revalidate, xname, namebuf }

[xfs/scrub/dir_repair.c]
  struct xrep_dirent { name_cookie, ino, namelen, ftype, action }
  struct xrep_dir { sc, dir_entries, dir_names, tx, args, pscan, adoption, subdirs, dirents, needs_adoption }

[xfs/scrub/dirtree.h]
  fn xchk_dirtree_parentless(const struct xchk_dirtree *dl) -> bool
  fn xchk_dirtree_find_paths_to_root(struct xchk_dirtree *dl) -> int
  fn xchk_dirpath_append(struct xchk_dirtree *dl, struct xfs_inode *ip, struct xchk_dirpath *path, const struct xfs_name *name, const struct xfs_parent_rec *pptr) -> int
  fn xchk_dirtree_evaluate(struct xchk_dirtree *dl, struct xchk_dirtree_outcomes *oc) -> void
  struct xchk_dirpath_step { name_cookie, name_len, pptr_rec }
  enum xchk_dirpath_outcome { XCHK_DIRPATH_SCANNING, still, being, put, together, XCHK_DIRPATH_DELETE, delete, this, path, XCHK_DIRPATH_CORRUPT }
  struct xchk_dirpath { list, first_step, second_step, seen_inodes, nr_steps, path_nr, outcome }
  struct xchk_dirtree_outcomes { bad, suspect, good, needs_adoption }
  struct xchk_dirtree { sc, root_ino, scan_ino, parent_ino, pptr_rec, pptr_args, xname, namebuf, adoption, dhook }

[xfs/scrub/findparent.c]
  struct xrep_findparent_info { dp, sc, parent_scan, found_parent, parent_tentative }

[xfs/scrub/findparent.h]
  fn __xrep_findparent_scan_start(struct xfs_scrub *sc, struct xrep_parent_scan_info *pscan, notifier_fn_t custom_fn) -> int
  fn __xrep_findparent_scan_start(sc, pscan, NULL) -> return
  fn xrep_findparent_scan(struct xrep_parent_scan_info *pscan) -> int
  fn xrep_findparent_scan_teardown(struct xrep_parent_scan_info *pscan) -> void
  fn xrep_findparent_scan_finish_early(struct xrep_parent_scan_info *pscan, xfs_ino_t ino) -> void
  fn xrep_findparent_confirm(struct xfs_scrub *sc, xfs_ino_t *parent_ino) -> int
  fn xrep_findparent_self_reference(struct xfs_scrub *sc) -> xfs_ino_t
  fn xrep_findparent_from_dcache(struct xfs_scrub *sc) -> xfs_ino_t
  struct xrep_parent_scan_info { sc, iscan, dhook, lock, parent_ino, lookup_parent }

[xfs/scrub/fsb_bitmap.h]
  fn xbitmap64_set(&bitmap->fsbitmap, start, len) -> return
  fn xbitmap64_walk(&bitmap->fsbitmap, fn, priv) -> return
  struct xfsb_bitmap { fsbitmap }

[xfs/scrub/fscounters.h]
  struct xchk_fscounters { sc, icount, ifree, fdblocks, frextents, frextents_delayed, icount_min, icount_max, frozen }

[xfs/scrub/health.c]
  enum xchk_health_group { XHG_NONE, XHG_FS, XHG_AG, XHG_INO, XHG_RTGROUP }
  struct xchk_health_map { group, sick_mask }

[xfs/scrub/health.h]
  fn xchk_health_mask_for_scrub_type(__u32 scrub_type) -> unsigned int
  fn xchk_update_health(struct xfs_scrub *sc) -> void
  fn xchk_ag_btree_del_cursor_if_sick(struct xfs_scrub *sc, struct xfs_btree_cur **curp, unsigned int sm_type) -> void
  fn xchk_mark_healthy_if_clean(struct xfs_scrub *sc, unsigned int mask) -> void
  fn xchk_file_looks_zapped(struct xfs_scrub *sc, unsigned int mask) -> bool
  fn xchk_health_record(struct xfs_scrub *sc) -> int

[xfs/scrub/ialloc.c]
  struct xchk_iallocbt { inodes, next_startino, next_cluster_ino }

[xfs/scrub/ialloc_repair.c]
  struct xrep_ibt { rie, new_inobt, new_finobt, old_iallocbt_blocks, inode_records, sc, icount, iused, finobt_recs, array_cur }

[xfs/scrub/ino_bitmap.h]
  fn xbitmap64_set(&bitmap->inobitmap, ino, 1) -> return
  fn xbitmap64_test(&bitmap->inobitmap, ino, &len) -> return
  struct xino_bitmap { inobitmap }

[xfs/scrub/inode_repair.c]
  struct xrep_inode { imap, sc, data_blocks, rt_blocks, attr_blocks, data_extents, rt_extents, attr_extents, ino_sick_mask, zap_acls }

[xfs/scrub/iscan.h]
  fn test_bit(XCHK_ISCAN_OPSTATE_ABORTED, &iscan->__opstate) -> return
    called_by: mxfs_reap_worker
  fn test_bit(XCHK_ISCAN_OPSTATE_TRYLOCK_AGI, &iscan->__opstate) -> return
    called_by: mxfs_reap_worker
  fn xchk_iscan_start(struct xfs_scrub *sc, unsigned int iget_timeout, unsigned int iget_retry_delay, struct xchk_iscan *iscan) -> void
  fn xchk_iscan_finish_early(struct xchk_iscan *iscan) -> void
  fn xchk_iscan_teardown(struct xchk_iscan *iscan) -> void
  fn xchk_iscan_iter(struct xchk_iscan *iscan, struct xfs_inode **ipp) -> int
  fn xchk_iscan_iter_finish(struct xchk_iscan *iscan) -> void
  fn xchk_iscan_mark_visited(struct xchk_iscan *iscan, struct xfs_inode *ip) -> void
  fn xchk_iscan_want_live_update(struct xchk_iscan *iscan, xfs_ino_t ino) -> bool
  struct xchk_iscan { sc, lock, scan_start_ino, cursor_ino, skip_ino, __visited_ino, __opstate, __iget_deadline, iget_timeout, iget_retry_delay }

[xfs/scrub/listxattr.h]
  fn xchk_xattr_walk(struct xfs_scrub *sc, struct xfs_inode *ip, xchk_xattr_fn attr_fn, xchk_xattrleaf_fn leaf_fn, void *priv) -> int
  typedef_fn xchk_xattr_fn
  typedef_fn xchk_xattrleaf_fn

[xfs/scrub/metapath.c]
  struct xchk_metapath { sc, xname, du, path, dp, dp_ilock_flags, link_resblks, unlink_resblks, link_ppargs, unlink_ppargs }

[xfs/scrub/newbt.h]
  fn xrep_newbt_init_bare(struct xrep_newbt *xnr, struct xfs_scrub *sc) -> void
  fn xrep_newbt_init_ag(struct xrep_newbt *xnr, struct xfs_scrub *sc, const struct xfs_owner_info *oinfo, xfs_fsblock_t alloc_hint, enum xfs_ag_resv_type resv) -> void
  fn xrep_newbt_init_inode(struct xrep_newbt *xnr, struct xfs_scrub *sc, int whichfork, const struct xfs_owner_info *oinfo) -> int
  fn xrep_newbt_init_metadir_inode(struct xrep_newbt *xnr, struct xfs_scrub *sc) -> int
  fn xrep_newbt_alloc_blocks(struct xrep_newbt *xnr, uint64_t nr_blocks) -> int
  fn xrep_newbt_add_extent(struct xrep_newbt *xnr, struct xfs_perag *pag, xfs_agblock_t agbno, xfs_extlen_t len) -> int
  fn xrep_newbt_cancel(struct xrep_newbt *xnr) -> void
  fn xrep_newbt_commit(struct xrep_newbt *xnr) -> int
  fn xrep_newbt_claim_block(struct xfs_btree_cur *cur, struct xrep_newbt *xnr, union xfs_btree_ptr *ptr) -> int
  fn xrep_newbt_unused_blocks(struct xrep_newbt *xnr) -> unsigned int
  struct xrep_newbt_resv { list, pag, autoreap, agbno, len, used }
  struct xrep_newbt { sc, resv_list, afake, ifake, oinfo, bload, alloc_hint, resv }

[xfs/scrub/nlinks.h]
  struct xchk_nlink_ctrs { sc, nlinks, lock, collect_iscan, compare_iscan, dhook, adoption, xname, namebuf }
  struct xchk_nlink { parents, backrefs, children, flags }

[xfs/scrub/off_bitmap.h]
  fn xbitmap64_set(&bitmap->offbitmap, off, len) -> return
  fn xbitmap64_walk(&bitmap->offbitmap, fn, priv) -> return
  struct xoff_bitmap { offbitmap }

[xfs/scrub/orphanage.h]
  fn xrep_orphanage_create(struct xfs_scrub *sc) -> int
  fn xrep_orphanage_iolock_two(struct xfs_scrub *sc) -> int
  fn xrep_orphanage_ilock(struct xfs_scrub *sc, unsigned int ilock_flags) -> void
  fn xrep_orphanage_ilock_nowait(struct xfs_scrub *sc, unsigned int ilock_flags) -> bool
  fn xrep_orphanage_iunlock(struct xfs_scrub *sc, unsigned int ilock_flags) -> void
  fn xrep_orphanage_rele(struct xfs_scrub *sc) -> void
  fn xrep_orphanage_can_adopt(struct xfs_scrub *sc) -> bool
  fn xrep_adoption_trans_alloc(struct xfs_scrub *sc, struct xrep_adoption *adopt) -> int
  fn xrep_adoption_compute_name(struct xrep_adoption *adopt, struct xfs_name *xname) -> int
  fn xrep_adoption_move(struct xrep_adoption *adopt) -> int
  fn xrep_adoption_trans_roll(struct xrep_adoption *adopt) -> int
  struct xrep_adoption { sc, xname, ppargs, orphanage_blkres, child_blkres }
  struct xrep_adoption { sc, xname, ppargs, orphanage_blkres, child_blkres }

[xfs/scrub/parent.c]
  struct xchk_parent_ctx { sc, nlink }
  struct xchk_pptr { name_cookie, pptr_rec, namelen }
  struct xchk_pptrs { sc, pptrs_found, parent_ino, pptr_entries, pptr_names, pptr_args, need_revalidate, xname, namebuf }

[xfs/scrub/parent_repair.c]
  struct xrep_pptr { name_cookie, pptr_rec, namelen, action }
  struct xrep_parent { sc, pptr_recs, pptr_names, xattr_records, xattr_blobs, xattr_name, xattr_value, xattr_value_sz, tx, pscan }
  struct xrep_parent_xattr { name_cookie, value_cookie, flags, valuelen, namelen }

[xfs/scrub/quota.c]
  struct xchk_quota_info { sc, last_id }

[xfs/scrub/quota.h]
  fn xchk_quota_to_dqtype(struct xfs_scrub *sc) -> xfs_dqtype_t
  fn xchk_dqiter_init(struct xchk_dqiter *cursor, struct xfs_scrub *sc, xfs_dqtype_t dqtype) -> void
  fn xchk_dquot_iter(struct xchk_dqiter *cursor, struct xfs_dquot **dqpp) -> int
  struct xchk_dqiter { sc, quota_ip, bmap, id, dqtype, if_seq }

[xfs/scrub/quota_repair.c]
  struct xrep_quota_info { sc, need_quotacheck }

[xfs/scrub/quotacheck.c]
  struct xqcheck_dqtrx { q_type, q_id, icount_delta, bcount_delta, delbcnt_delta, rtbcount_delta, delrtb_delta }
  struct xqcheck_dqacct { hash, tx_id, dqtrx, refcount }

[xfs/scrub/quotacheck.h]
  struct xqcheck_dquot { bcount, icount, rtbcount, flags }
  struct xqcheck { sc, ucounts, gcounts, pcounts, lock, iscan, qhook, shadow_dquot_acct }

[xfs/scrub/rcbag.c]
  fn static rcbag_rec_next_bno(const struct rcbag_rec *r) -> uint32_t
  struct rcbag { mp, xfbtree, nr_items }

[xfs/scrub/rcbag.h]
  fn rcbag_init(struct xfs_mount *mp, struct xfs_buftarg *btp, struct rcbag **bagp) -> int
  fn rcbag_free(struct rcbag **bagp) -> void
  fn rcbag_add(struct rcbag *bag, struct xfs_trans *tp, const struct xfs_rmap_irec *rmap) -> int
  fn rcbag_count(const struct rcbag *bag) -> uint64_t
  fn rcbag_next_edge(struct rcbag *bag, struct xfs_trans *tp, const struct xfs_rmap_irec *next_rmap, bool next_valid, uint32_t *next_bnop) -> int
  fn rcbag_remove_ending_at(struct rcbag *bag, struct xfs_trans *tp, uint32_t next_bno) -> int
  fn rcbag_dump(struct rcbag *bag, struct xfs_trans *tp) -> void

[xfs/scrub/rcbag_btree.h]
  fn rcbagbt_maxrecs(struct xfs_mount *mp, unsigned int blocklen, bool leaf) -> unsigned int
  fn rcbagbt_calc_size(unsigned long long nr_records) -> unsigned long long
  fn rcbagbt_maxlevels_possible(void) -> unsigned int
  fn rcbagbt_init_cur_cache(void) -> int __init
  fn rcbagbt_destroy_cur_cache(void) -> void
  fn rcbagbt_mem_cursor(struct xfs_mount *mp, struct xfs_trans *tp, struct xfbtree *xfbtree) -> struct xfs_btree_cur
  fn rcbagbt_mem_init(struct xfs_mount *mp, struct xfbtree *xfbtree, struct xfs_buftarg *btp) -> int
  fn rcbagbt_lookup_eq(struct xfs_btree_cur *cur, const struct xfs_rmap_irec *rmap, int *success) -> int
  fn rcbagbt_get_rec(struct xfs_btree_cur *cur, struct rcbag_rec *rec, int *has) -> int
  fn rcbagbt_update(struct xfs_btree_cur *cur, const struct rcbag_rec *rec) -> int
  fn rcbagbt_insert(struct xfs_btree_cur *cur, const struct rcbag_rec *rec, int *success) -> int
  struct rcbag_key { rbg_startblock, rbg_blockcount }
  struct rcbag_rec { rbg_startblock, rbg_blockcount, rbg_refcount }

[xfs/scrub/readdir.h]
  fn xchk_dir_walk(struct xfs_scrub *sc, struct xfs_inode *dp, xchk_dirent_fn dirent_fn, void *priv) -> int
  fn xchk_dir_lookup(struct xfs_scrub *sc, struct xfs_inode *dp, const struct xfs_name *name, xfs_ino_t *ino) -> int
  fn xchk_dir_trylock_for_pptrs(struct xfs_scrub *sc, struct xfs_inode *ip, unsigned int *lockmode) -> int
  typedef_fn xchk_dirent_fn

[xfs/scrub/reap.c]
  fn static xreap_is_dirty(const struct xreap_state *rs) -> bool
    calls: xrep_defer_finish
  fn static xreap_want_binval_roll(const struct xreap_state *rs) -> bool
    called_by: xreap_want_defer_finish
  fn static xreap_binval_reset(struct xreap_state *rs) -> void
    called_by: xreap_want_defer_finish
  fn static xreap_inc_binval(struct xreap_state *rs) -> bool
  fn static xreap_want_defer_finish(const struct xreap_state *rs) -> bool
    calls: xfs_defer_finish, xfs_trans_roll_inode, xreap_binval_reset, xreap_defer_finish_reset, xreap_want_binval_roll
  fn static xreap_defer_finish_reset(struct xreap_state *rs) -> void
    called_by: xreap_want_defer_finish
  fn static xreap_inc_defer(struct xreap_state *rs) -> void
  fn static xreap_force_defer_finish(struct xreap_state *rs) -> void
  struct xreap_state { sc, oinfo, resv, ip, whichfork, nr_binval, max_binval, nr_deferred, max_deferred }

[xfs/scrub/reap.h]
  fn xrep_reap_agblocks(struct xfs_scrub *sc, struct xagb_bitmap *bitmap, const struct xfs_owner_info *oinfo, enum xfs_ag_resv_type type) -> int
  fn xrep_reap_fsblocks(struct xfs_scrub *sc, struct xfsb_bitmap *bitmap, const struct xfs_owner_info *oinfo) -> int
  fn xrep_reap_ifork(struct xfs_scrub *sc, struct xfs_inode *ip, int whichfork) -> int
  fn xrep_reap_metadir_fsblocks(struct xfs_scrub *sc, struct xfsb_bitmap *bitmap) -> int
  fn xrep_reap_rtblocks(struct xfs_scrub *sc, struct xrtb_bitmap *bitmap, const struct xfs_owner_info *oinfo) -> int
  fn xrep_bufscan_max_sectors(struct xfs_mount *mp, xfs_extlen_t fsblocks) -> xfs_daddr_t
  fn xrep_bufscan_advance(struct xfs_mount *mp, struct xrep_bufscan *scan) -> struct xfs_buf
  struct xrep_bufscan { daddr, max_sectors, daddr_step, __sector_count }

[xfs/scrub/refcount.c]
  struct xchk_refcnt_frag { list, rm }
  struct xchk_refcnt_check { sc, fragments, bno, len, refcount, seen }
  struct xchk_refcbt_records { prev_rec, next_unshared_agbno, cow_blocks, prev_domain }

[xfs/scrub/refcount_repair.c]
  struct xrep_refc { refcount_records, new_btree, old_refcountbt_blocks, sc, array_cur, btblocks }

[xfs/scrub/repair.c]
  struct xrep_findroot { sc, agfl_bp, agf, btree_info }

[xfs/scrub/repair.h]
  fn xrep_attempt(struct xfs_scrub *sc, struct xchk_stats_run *run) -> int
  fn xrep_will_attempt(struct xfs_scrub *sc) -> bool
  fn xrep_failure(struct xfs_mount *mp) -> void
  fn xrep_roll_ag_trans(struct xfs_scrub *sc) -> int
  fn xrep_roll_trans(struct xfs_scrub *sc) -> int
  fn xrep_defer_finish(struct xfs_scrub *sc) -> int
    called_by: xreap_is_dirty
  fn xrep_ag_has_space(struct xfs_perag *pag, xfs_extlen_t nr_blocks, enum xfs_ag_resv_type type) -> bool
  fn xrep_calc_ag_resblks(struct xfs_scrub *sc) -> xfs_extlen_t
  fn xrep_fix_freelist(struct xfs_scrub *sc, int alloc_flags) -> int
  fn xrep_find_ag_btree_roots(struct xfs_scrub *sc, struct xfs_buf *agf_bp, struct xrep_find_ag_btree *btree_info, struct xfs_buf *agfl_bp) -> int
  fn xrep_update_qflags(struct xfs_scrub *sc, unsigned int clear_flags, unsigned int set_flags) -> void
  fn xrep_force_quotacheck(struct xfs_scrub *sc, xfs_dqtype_t type) -> void
  fn xrep_ino_dqattach(struct xfs_scrub *sc) -> int
  fn xrep_setup_xfbtree(struct xfs_scrub *sc, const char *descr) -> int
  fn xrep_ino_ensure_extent_count(struct xfs_scrub *sc, int whichfork, xfs_extnum_t nextents) -> int
  fn xrep_reset_perag_resv(struct xfs_scrub *sc) -> int
  fn xrep_bmap(struct xfs_scrub *sc, int whichfork, bool allow_unwritten) -> int
  fn xrep_metadata_inode_forks(struct xfs_scrub *sc) -> int
  fn xrep_setup_ag_rmapbt(struct xfs_scrub *sc) -> int
  fn xrep_setup_ag_refcountbt(struct xfs_scrub *sc) -> int
  fn xrep_setup_xattr(struct xfs_scrub *sc) -> int
  fn xrep_setup_directory(struct xfs_scrub *sc) -> int
  fn xrep_setup_parent(struct xfs_scrub *sc) -> int
  fn xrep_setup_nlinks(struct xfs_scrub *sc) -> int
  fn xrep_setup_symlink(struct xfs_scrub *sc, unsigned int *resblks) -> int
  fn xrep_setup_dirtree(struct xfs_scrub *sc) -> int
  fn xrep_setup_rtrmapbt(struct xfs_scrub *sc) -> int
  fn xrep_setup_rtrefcountbt(struct xfs_scrub *sc) -> int
  fn xrep_setup_ag_allocbt(struct xfs_scrub *sc) -> int
  fn xrep_setup_inode(struct xfs_scrub *sc, const struct xfs_imap *imap) -> int
  fn xrep_ag_btcur_init(struct xfs_scrub *sc, struct xchk_ag *sa) -> void
  fn xrep_ag_init(struct xfs_scrub *sc, struct xfs_perag *pag, struct xchk_ag *sa) -> int
  fn xrep_rtgroup_init(struct xfs_scrub *sc, struct xfs_rtgroup *rtg, struct xchk_rt *sr, unsigned int rtglock_flags) -> int
  fn xrep_rtgroup_btcur_init(struct xfs_scrub *sc, struct xchk_rt *sr) -> void
  fn xrep_require_rtext_inuse(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_filblks_t len) -> int
  fn xrep_calc_rtgroup_resblks(struct xfs_scrub *sc) -> xfs_extlen_t
  fn xrep_check_ino_btree_mapping(struct xfs_scrub *sc, const struct xfs_rmap_irec *rec) -> int
  fn xrep_revalidate_allocbt(struct xfs_scrub *sc) -> int
  fn xrep_revalidate_iallocbt(struct xfs_scrub *sc) -> int
  fn xrep_probe(struct xfs_scrub *sc) -> int
  fn xrep_superblock(struct xfs_scrub *sc) -> int
  fn xrep_agf(struct xfs_scrub *sc) -> int
  fn xrep_agfl(struct xfs_scrub *sc) -> int
  fn xrep_agi(struct xfs_scrub *sc) -> int
  fn xrep_allocbt(struct xfs_scrub *sc) -> int
  fn xrep_iallocbt(struct xfs_scrub *sc) -> int
  fn xrep_rmapbt(struct xfs_scrub *sc) -> int
  fn xrep_refcountbt(struct xfs_scrub *sc) -> int
  fn xrep_inode(struct xfs_scrub *sc) -> int
  fn xrep_bmap_data(struct xfs_scrub *sc) -> int
  fn xrep_bmap_attr(struct xfs_scrub *sc) -> int
  fn xrep_bmap_cow(struct xfs_scrub *sc) -> int
  fn xrep_nlinks(struct xfs_scrub *sc) -> int
  fn xrep_fscounters(struct xfs_scrub *sc) -> int
  fn xrep_xattr(struct xfs_scrub *sc) -> int
  fn xrep_directory(struct xfs_scrub *sc) -> int
  fn xrep_parent(struct xfs_scrub *sc) -> int
  fn xrep_symlink(struct xfs_scrub *sc) -> int
  fn xrep_dirtree(struct xfs_scrub *sc) -> int
  fn xrep_metapath(struct xfs_scrub *sc) -> int
  fn xrep_rtbitmap(struct xfs_scrub *sc) -> int
  fn xrep_rtsummary(struct xfs_scrub *sc) -> int
  fn xrep_rgsuperblock(struct xfs_scrub *sc) -> int
  fn xrep_rtrmapbt(struct xfs_scrub *sc) -> int
  fn xrep_rtrefcountbt(struct xfs_scrub *sc) -> int
  fn xrep_quota(struct xfs_scrub *sc) -> int
  fn xrep_quotacheck(struct xfs_scrub *sc) -> int
  fn xrep_reinit_pagf(struct xfs_scrub *sc) -> int
  fn xrep_reinit_pagi(struct xfs_scrub *sc) -> int
  fn xrep_buf_verify_struct(struct xfs_buf *bp, const struct xfs_buf_ops *ops) -> bool
  fn xrep_inode_set_nblocks(struct xfs_scrub *sc, int64_t new_blocks) -> void
  fn xrep_reset_metafile_resv(struct xfs_scrub *sc) -> int
  struct xrep_find_ag_btree { rmap_owner, buf_ops, maxlevels, root, height }

[xfs/scrub/rgb_bitmap.h]
  fn xbitmap32_set(&bitmap->rgbitmap, start, len) -> return
  fn xbitmap32_walk(&bitmap->rgbitmap, fn, priv) -> return
  struct xrgb_bitmap { rgbitmap }

[xfs/scrub/rmap.c]
  struct xchk_rmap { overlap_rec, prev_rec, fs_owned, log_owned, ag_owned, inobt_owned, refcbt_owned, bitmaps_complete }

[xfs/scrub/rmap_repair.c]
  struct xrep_rmap { new_btree, lock, rmap_btree, sc, mcur, rhook, iscan, nr_records, freesp_btblocks, old_rmapbt_fsbcount }
  struct xrep_rmap_stash_run { rr, owner, rmap_flags }
  struct xrep_rmap_ifork { accum, bmbt_blocks, rr, whichfork }
  struct xrep_rmap_inodes { rr, inobt_blocks, ichunk_blocks }
  struct xrep_rmap_agfl { bitmap, agno }
  struct xrep_rmap_find_gaps { rmap_gaps, next_agbno }

[xfs/scrub/rtb_bitmap.h]
  fn xbitmap64_set(&bitmap->rtbitmap, start, len) -> return
  fn xbitmap64_walk(&bitmap->rtbitmap, fn, priv) -> return
  struct xrtb_bitmap { rtbitmap }

[xfs/scrub/rtbitmap.h]
  fn xrep_setup_rtbitmap(struct xfs_scrub *sc, struct xchk_rtbitmap *rtb) -> int
  struct xchk_rtbitmap { sc, rextents, rbmblocks, rextslog, resblks, next_free_rgbno, args, tempexch, next_rgbno, rtglock_flags }

[xfs/scrub/rtrefcount.c]
  struct xchk_rtrefcnt_frag { list, rm }
  struct xchk_rtrefcnt_check { sc, fragments, bno, len, refcount, seen }
  struct xchk_rtrefcbt_records { prev_rec, next_unshared_rgbno, cow_blocks, prev_domain }

[xfs/scrub/rtrefcount_repair.c]
  struct xrep_rtrefc { refcount_records, new_btree, old_rtrefcountbt_blocks, sc, array_cur, btblocks }

[xfs/scrub/rtrmap.c]
  struct xchk_rtrmap { overlap_rec, prev_rec }

[xfs/scrub/rtrmap_repair.c]
  struct xrep_rtrmap { new_btree, lock, rtrmap_btree, sc, old_rtrmapbt_blocks, rhook, iscan, mcur, nr_records }
  struct xrep_rtrmap_ifork { accum, rr }
  struct xrep_rtrmap_stash_run { rr, owner }

[xfs/scrub/rtsummary.h]
  fn xfsum_copyout(struct xfs_scrub *sc, xfs_rtsumoff_t sumoff, union xfs_suminfo_raw *rawinfo, unsigned int nr_words) -> int
  fn xrep_setup_rtsummary(struct xfs_scrub *sc, struct xchk_rtsummary *rts) -> int
  struct xchk_rtsummary { tempexch, args, rextents, rbmblocks, rsumblocks, rsumlevels, resblks, prep_wordoff, words }

[xfs/scrub/scrub.c]
  fn static xchk_postmortem(struct xfs_scrub *sc) -> void
  fn static xchk_postmortem(struct xfs_scrub *sc) -> void

[xfs/scrub/scrub.h]
  fn xchk_scrub_create_subord(struct xfs_scrub *sc, unsigned int subtype) -> struct xfs_scrub_subord
  fn xchk_scrub_free_subord(struct xfs_scrub_subord *sub) -> void
  fn xchk_tester(struct xfs_scrub *sc) -> int
  fn xchk_superblock(struct xfs_scrub *sc) -> int
  fn xchk_agf(struct xfs_scrub *sc) -> int
  fn xchk_agfl(struct xfs_scrub *sc) -> int
  fn xchk_agi(struct xfs_scrub *sc) -> int
  fn xchk_allocbt(struct xfs_scrub *sc) -> int
  fn xchk_iallocbt(struct xfs_scrub *sc) -> int
  fn xchk_rmapbt(struct xfs_scrub *sc) -> int
  fn xchk_refcountbt(struct xfs_scrub *sc) -> int
  fn xchk_inode(struct xfs_scrub *sc) -> int
  fn xchk_bmap_data(struct xfs_scrub *sc) -> int
  fn xchk_bmap_attr(struct xfs_scrub *sc) -> int
  fn xchk_bmap_cow(struct xfs_scrub *sc) -> int
  fn xchk_directory(struct xfs_scrub *sc) -> int
  fn xchk_xattr(struct xfs_scrub *sc) -> int
  fn xchk_symlink(struct xfs_scrub *sc) -> int
  fn xchk_parent(struct xfs_scrub *sc) -> int
  fn xchk_dirtree(struct xfs_scrub *sc) -> int
  fn xchk_metapath(struct xfs_scrub *sc) -> int
  fn xchk_rtbitmap(struct xfs_scrub *sc) -> int
  fn xchk_rtsummary(struct xfs_scrub *sc) -> int
  fn xchk_rgsuperblock(struct xfs_scrub *sc) -> int
  fn xchk_rtrmapbt(struct xfs_scrub *sc) -> int
  fn xchk_rtrefcountbt(struct xfs_scrub *sc) -> int
  fn xchk_quota(struct xfs_scrub *sc) -> int
  fn xchk_quotacheck(struct xfs_scrub *sc) -> int
  fn xchk_fscounters(struct xfs_scrub *sc) -> int
  fn xchk_nlinks(struct xfs_scrub *sc) -> int
  fn xchk_xref_is_used_space(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_not_inode_chunk(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_inode_chunk(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_only_owned_by(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len, const struct xfs_owner_info *oinfo) -> void
  fn xchk_xref_is_not_owned_by(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len, const struct xfs_owner_info *oinfo) -> void
  fn xchk_xref_has_no_owner(struct xfs_scrub *sc, xfs_agblock_t agbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_cow_staging(struct xfs_scrub *sc, xfs_agblock_t bno, xfs_extlen_t len) -> void
  fn xchk_xref_is_not_shared(struct xfs_scrub *sc, xfs_agblock_t bno, xfs_extlen_t len) -> void
  fn xchk_xref_is_not_cow_staging(struct xfs_scrub *sc, xfs_agblock_t bno, xfs_extlen_t len) -> void
  fn xchk_xref_is_used_rt_space(struct xfs_scrub *sc, xfs_rtblock_t rtbno, xfs_extlen_t len) -> void
  fn xchk_xref_has_no_rt_owner(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len) -> void
  fn xchk_xref_has_rt_owner(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_only_rt_owned_by(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len, const struct xfs_owner_info *oinfo) -> void
  fn xchk_xref_is_rt_cow_staging(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_not_rt_shared(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len) -> void
  fn xchk_xref_is_not_rt_cow_staging(struct xfs_scrub *sc, xfs_rgblock_t rgbno, xfs_extlen_t len) -> void
  struct xchk_relax { next_resched, resched_nr, interruptible }
  enum xchk_type { ST_NONE, disabled, ST_PERAG, per, AG, metadata, ST_FS, per, FS, metadata }
  struct xchk_meta_ops { type }
  struct xchk_ag { pag, agf_bp, agi_bp, bno_cur, cnt_cur, ino_cur, fino_cur, rmap_cur, refc_cur }
  struct xchk_rt { rtg, rtlock_flags, rmap_cur, refc_cur }
  struct xfs_scrub { mp, sm, ops, tp, file, ip, buf, xfile, xmbtp, ilock_flags }
  struct xfs_scrub_subord { sc, parent_sc, old_smtype, old_smflags }

[xfs/scrub/stats.c]
  struct xchk_scrub_stats { invocations, clean, corrupt, preen, xfail, xcorrupt, incomplete, warning, retries, repair_invocations }
  struct xchk_stats { cs_debugfs, cs_stats }

[xfs/scrub/stats.h]
  fn xchk_global_stats_setup(struct dentry *parent) -> int __init
  fn xchk_global_stats_teardown(void) -> void
  fn xchk_mount_stats_alloc(struct xfs_mount *mp) -> int
  fn xchk_mount_stats_free(struct xfs_mount *mp) -> void
  fn xchk_stats_register(struct xchk_stats *cs, struct dentry *parent) -> void
  fn xchk_stats_unregister(struct xchk_stats *cs) -> void
  fn xchk_stats_merge(struct xfs_mount *mp, const struct xfs_scrub_metadata *sm, const struct xchk_stats_run *run) -> void
  struct xchk_stats_run { scrub_ns, repair_ns, retries, repair_attempted, repair_succeeded }

[xfs/scrub/tempexch.h]
  fn xrep_tempexch_trans_reserve(struct xfs_scrub *sc, int whichfork, xfs_fileoff_t off, xfs_filblks_t len, struct xrep_tempexch *ti) -> int
  fn xrep_tempexch_trans_alloc(struct xfs_scrub *sc, int whichfork, struct xrep_tempexch *ti) -> int
  fn xrep_tempexch_contents(struct xfs_scrub *sc, struct xrep_tempexch *ti) -> int
  struct xrep_tempexch { req }

[xfs/scrub/tempfile.h]
  fn xrep_tempfile_create(struct xfs_scrub *sc, uint16_t mode) -> int
  fn xrep_tempfile_rele(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_adjust_directory_tree(struct xfs_scrub *sc) -> int
  fn xrep_tempfile_iolock_nowait(struct xfs_scrub *sc) -> bool
  fn xrep_tempfile_iolock_polled(struct xfs_scrub *sc) -> int
  fn xrep_tempfile_iounlock(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_ilock(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_ilock_nowait(struct xfs_scrub *sc) -> bool
  fn xrep_tempfile_iunlock(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_iunlock_both(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_ilock_both(struct xfs_scrub *sc) -> void
  fn xrep_tempfile_prealloc(struct xfs_scrub *sc, xfs_fileoff_t off, xfs_filblks_t len) -> int
  fn xrep_tempfile_copyin(struct xfs_scrub *sc, xfs_fileoff_t off, xfs_filblks_t len, xrep_tempfile_copyin_fn fn, void *data) -> int
  fn xrep_tempfile_set_isize(struct xfs_scrub *sc, unsigned long long isize) -> int
  fn xrep_tempfile_roll_trans(struct xfs_scrub *sc) -> int
  fn xrep_tempfile_copyout_local(struct xfs_scrub *sc, int whichfork) -> void
  fn xrep_is_tempfile(const struct xfs_inode *ip) -> bool
  typedef_fn xrep_tempfile_copyin_fn

[xfs/scrub/xfarray.c]
  fn static xfarray_scratch(struct xfarray *array) -> void
  fn static xfarray_pos(struct xfarray *array, xfarray_idx_t idx) -> loff_t
  fn static xfarray_sortinfo_lo(struct xfarray_sortinfo *si) -> xfarray_idx_t
    called_by: xfarray_sortinfo_hi
  fn static xfarray_sortinfo_hi(struct xfarray_sortinfo *si) -> xfarray_idx_t
    calls: xfarray_sortinfo_lo
    called_by: xfarray_sortinfo_isort_scratch, xfarray_sortinfo_pivot
  fn static xfarray_sortinfo_isort_scratch(struct xfarray_sortinfo *si) -> void
    calls: xfarray_sortinfo_hi
  fn static xfarray_sortinfo_pivot(struct xfarray_sortinfo *si) -> void
    calls: xfarray_sortinfo_hi

[xfs/scrub/xfarray.h]
  fn xfarray_create(const char *descr, unsigned long long required_capacity, size_t obj_size, struct xfarray **arrayp) -> int
  fn xfarray_destroy(struct xfarray *array) -> void
  fn xfarray_load(struct xfarray *array, xfarray_idx_t idx, void *ptr) -> int
  fn xfarray_unset(struct xfarray *array, xfarray_idx_t idx) -> int
  fn xfarray_store(struct xfarray *array, xfarray_idx_t idx, const void *ptr) -> int
  fn xfarray_store_anywhere(struct xfarray *array, const void *ptr) -> int
  fn xfarray_element_is_null(struct xfarray *array, const void *ptr) -> bool
  fn xfarray_truncate(struct xfarray *array) -> void
  fn xfarray_bytes(struct xfarray *array) -> unsigned long long
  fn xfarray_store(array, array->nr, ptr) -> return
  fn xfarray_length(struct xfarray *array) -> uint64_t
  fn xfarray_load_next(struct xfarray *array, xfarray_idx_t *idx, void *rec) -> int
  fn xfarray_sort(struct xfarray *array, xfarray_cmp_fn cmp_fn, unsigned int flags) -> int
  struct xfarray { xfile, nr, max_nr, unset_slots, obj_size, obj_size_log }
  struct xfarray_sortinfo { array, cmp_fn, max_stack_depth, stack_depth, max_stack_used, flags, relax, folio, first_folio_idx, last_folio_idx }

[xfs/scrub/xfblob.c]
  struct xb_key { xb_magic, xb_size, xb_offset }

[xfs/scrub/xfblob.h]
  fn xfblob_create(const char *descr, struct xfblob **blobp) -> int
  fn xfblob_destroy(struct xfblob *blob) -> void
  fn xfblob_load(struct xfblob *blob, xfblob_cookie cookie, void *ptr, uint32_t size) -> int
  fn xfblob_store(struct xfblob *blob, xfblob_cookie *cookie, const void *ptr, uint32_t size) -> int
  fn xfblob_free(struct xfblob *blob, xfblob_cookie cookie) -> int
  fn xfblob_bytes(struct xfblob *blob) -> unsigned long long
  fn xfblob_truncate(struct xfblob *blob) -> void
  fn xfblob_store(blob, cookie, xname->name, xname->len) -> return
  struct xfblob { xfile, last_offset }

[xfs/scrub/xfile.h]
  fn xfile_create(const char *description, loff_t isize, struct xfile **xfilep) -> int
  fn xfile_destroy(struct xfile *xf) -> void
  fn xfile_load(struct xfile *xf, void *buf, size_t count, loff_t pos) -> int
  fn xfile_store(struct xfile *xf, const void *buf, size_t count, loff_t pos) -> int
  fn xfile_discard(struct xfile *xf, loff_t pos, u64 count) -> void
  fn xfile_seek_data(struct xfile *xf, loff_t pos) -> loff_t
  fn xfile_get_folio(struct xfile *xf, loff_t offset, size_t len, unsigned int flags) -> struct folio
  fn xfile_put_folio(struct xfile *xf, struct folio *folio) -> void
  struct xfile { file }

[xfs/scrub/xfs_scrub.h]
  fn xfs_ioc_scrub_metadata(struct file *file, void __user *arg) -> int
  fn xfs_ioc_scrubv_metadata(struct file *file, void __user *arg) -> int

[xfs/xfs_acl.h]
  fn xfs_get_acl(struct inode *inode, int type, bool rcu) -> struct posix_acl
  fn xfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry, struct posix_acl *acl, int type) -> int
  fn __xfs_set_acl(struct inode *inode, struct posix_acl *acl, int type) -> int
  fn xfs_forget_acl(struct inode *inode, const char *name) -> void

[xfs/xfs_aops.h]
  fn xfs_setfilesize(struct xfs_inode *ip, xfs_off_t offset, size_t size) -> int
  fn xfs_end_bio(struct bio *bio) -> void
  fn xfs_end_io(struct work_struct *work) -> void
  fn xfs_task_in_ioend(void) -> bool
  fn xfs_task_in_writepages(void) -> bool

[xfs/xfs_attr_item.c]
  fn static ATTRI_ITEM(struct xfs_log_item *lip) -> struct xfs_attri_log_item
    calls: container_of
  fn static ATTRD_ITEM(struct xfs_log_item *lip) -> struct xfs_attrd_log_item
    calls: container_of
  fn static attri_entry(const struct list_head *e) -> struct xfs_attr_intent

[xfs/xfs_attr_item.h]
  fn xfs_attr_defer_add(struct xfs_da_args *args, enum xfs_attr_defer_op op) -> void
  struct xfs_attri_log_nameval { name, new_name, value, new_value, refcount }
  struct xfs_attri_log_item { attri_item, attri_refcount, attri_nameval, attri_format }
  struct xfs_attrd_log_item { attrd_item, attrd_attrip, attrd_format }
  enum xfs_attr_defer_op { XFS_ATTR_DEFER_SET, XFS_ATTR_DEFER_REMOVE, XFS_ATTR_DEFER_REPLACE }

[xfs/xfs_bmap_item.c]
  fn static BUI_ITEM(struct xfs_log_item *lip) -> struct xfs_bui_log_item
  fn xfs_bui_log_space(unsigned int nr) -> unsigned int
  fn static BUD_ITEM(struct xfs_log_item *lip) -> struct xfs_bud_log_item
  fn xfs_bud_log_space(void) -> unsigned int
  fn static bi_entry(const struct list_head *e) -> struct xfs_bmap_intent

[xfs/xfs_bmap_item.h]
  fn xfs_bmap_defer_add(struct xfs_trans *tp, struct xfs_bmap_intent *bi) -> void
  fn xfs_bui_log_space(unsigned int nr) -> unsigned int
  fn xfs_bud_log_space(void) -> unsigned int
  struct xfs_bui_log_item { bui_item, bui_refcount, bui_next_extent, bui_format }
  struct xfs_bud_log_item { bud_item, bud_buip, bud_format }

[xfs/xfs_bmap_util.h]
  fn xfs_bmap_rtalloc(struct xfs_bmalloca *ap) -> int
  fn xfs_bmap_punch_delalloc_range(struct xfs_inode *ip, int whichfork, xfs_off_t start_byte, xfs_off_t end_byte, struct xfs_zone_alloc_ctx *ac) -> void
  fn xfs_getbmap(struct xfs_inode *ip, struct getbmapx *bmv, struct kgetbmap *out) -> int
  fn xfs_bmap_extsize_align(struct xfs_mount *mp, struct xfs_bmbt_irec *gotp, struct xfs_bmbt_irec *prevp, xfs_extlen_t extsz, int rt, int eof, int delay, int convert, xfs_fileoff_t *offp, xfs_extlen_t *lenp) -> int
  fn xfs_bmap_adjacent(struct xfs_bmalloca *ap) -> bool
  fn xfs_bmap_last_extent(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, struct xfs_bmbt_irec *rec, int *is_empty) -> int
  fn xfs_alloc_file_space(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t len) -> int
  fn xfs_free_file_space(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t len, struct xfs_zone_alloc_ctx *ac) -> int
  fn xfs_collapse_file_space(struct xfs_inode *, xfs_off_t offset, xfs_off_t len, struct xfs_zone_alloc_ctx *ac) -> int
  fn xfs_insert_file_space(struct xfs_inode *, xfs_off_t offset, xfs_off_t len) -> int
  fn xfs_can_free_eofblocks(struct xfs_inode *ip) -> bool
  fn xfs_free_eofblocks(struct xfs_inode *ip) -> int
  fn xfs_swap_extents(struct xfs_inode *ip, struct xfs_inode *tip, struct xfs_swapext *sx) -> int
  fn xfs_fsb_to_db(struct xfs_inode *ip, xfs_fsblock_t fsb) -> xfs_daddr_t
  fn xfs_bmap_count_leaves(struct xfs_ifork *ifp, xfs_filblks_t *count) -> xfs_extnum_t
  fn xfs_bmap_count_blocks(struct xfs_trans *tp, struct xfs_inode *ip, int whichfork, xfs_extnum_t *nextents, xfs_filblks_t *count) -> int
  fn xfs_flush_unmap_range(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t len) -> int
  struct kgetbmap { bmv_offset, bmv_block, bmv_length, bmv_oflags }

[xfs/xfs_buf.h]
  fn xfs_buf_cache_init(struct xfs_buf_cache *bch) -> int
  fn xfs_buf_cache_destroy(struct xfs_buf_cache *bch) -> void
  fn xfs_buf_get_map(struct xfs_buftarg *target, struct xfs_buf_map *map, int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp) -> int
  fn xfs_buf_read_map(struct xfs_buftarg *target, struct xfs_buf_map *map, int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp, const struct xfs_buf_ops *ops, xfs_failaddr_t fa) -> int
  fn xfs_buf_readahead_map(struct xfs_buftarg *target, struct xfs_buf_map *map, int nmaps, const struct xfs_buf_ops *ops) -> void
  fn xfs_buf_get_map(target, &map, 1, XBF_INCORE | flags, bpp) -> return
  fn xfs_buf_get_map(target, &map, 1, 0, bpp) -> return
  fn xfs_buf_readahead_map(target, &map, 1, ops) -> return
  fn xfs_buf_get_uncached(struct xfs_buftarg *target, size_t numblks, struct xfs_buf **bpp) -> int
  fn xfs_buf_read_uncached(struct xfs_buftarg *target, xfs_daddr_t daddr, size_t numblks, struct xfs_buf **bpp, const struct xfs_buf_ops *ops) -> int
  fn _xfs_buf_read(struct xfs_buf *bp) -> int
  fn xfs_buf_hold(struct xfs_buf *bp) -> void
  fn xfs_buf_rele(struct xfs_buf *) -> void
  fn xfs_buf_trylock(struct xfs_buf *) -> int
  fn xfs_buf_lock(struct xfs_buf *) -> void
    called_by: mxfs_invalidate_ag, mxfs_invalidate_inode
  fn xfs_buf_unlock(struct xfs_buf *) -> void
  fn xfs_bwrite(struct xfs_buf *bp) -> int
  fn __xfs_buf_ioerror(struct xfs_buf *bp, int error, xfs_failaddr_t failaddr) -> void
  fn xfs_buf_ioerror_alert(struct xfs_buf *bp, xfs_failaddr_t fa) -> void
  fn xfs_buf_ioend_fail(struct xfs_buf *) -> void
  fn __xfs_buf_mark_corrupt(struct xfs_buf *bp, xfs_failaddr_t fa) -> void
  fn xfs_buf_stale(struct xfs_buf *bp) -> void
  fn xfs_buf_delwri_cancel(struct list_head *) -> void
  fn xfs_buf_delwri_queue(struct xfs_buf *, struct list_head *) -> bool
  fn xfs_buf_delwri_queue_recovery(struct xfs_buf *bp, struct list_head *buffer_list, bool foreign) -> int
  fn xfs_buf_delwri_queue_here(struct xfs_buf *bp, struct list_head *bl) -> void
  fn xfs_buf_delwri_submit(struct list_head *) -> int
  fn xfs_buf_delwri_fail(struct list_head *, int) -> int
  fn xfs_buf_delwri_submit_nowait(struct list_head *) -> int
  fn xfs_buf_delwri_submit_nopinwait(struct xfs_mount *, struct list_head *) -> int
  fn xfs_buf_set_ref(struct xfs_buf *bp, int lru_ref) -> void
  fn atomic_read(&bp->b_pin_count) -> return
    called_by: inode_dio_probe_init, inode_dio_release_init, mxfs_ailstuck_probe_param_get, mxfs_dlm_open_last_close, mxfs_dlm_open_protect, mxfs_lru_sweep_fn, mxfs_pin_census_set, xfs_defer_drain_busy
  fn xfs_alloc_buftarg(struct xfs_mount *mp, struct file *bdev_file) -> struct xfs_buftarg
  fn xfs_free_buftarg(struct xfs_buftarg *) -> void
  fn xfs_buftarg_wait(struct xfs_buftarg *) -> void
  fn xfs_buftarg_drain(struct xfs_buftarg *) -> void
  fn xfs_configure_buftarg(struct xfs_buftarg *btp, unsigned int sectorsize, xfs_fsblock_t nr_blocks) -> int
  fn xfs_buf_reverify(struct xfs_buf *bp, const struct xfs_buf_ops *ops) -> int
  fn xfs_verify_magic(struct xfs_buf *bp, __be32 dmagic) -> bool
  fn xfs_verify_magic16(struct xfs_buf *bp, __be16 dmagic) -> bool
  fn xfs_init_buftarg(struct xfs_buftarg *btp, size_t logical_sectorsize, const char *descr) -> int
  fn xfs_destroy_buftarg(struct xfs_buftarg *btp) -> void
  struct xfs_buf_cache { bc_hash }
  struct xfs_buftarg { bt_dev, bt_bdev, bt_daxdev, bt_file, bt_dax_part_off, bt_mount, bt_meta_sectorsize, bt_meta_sectormask, bt_logical_sectorsize, bt_logical_sectormask }
  struct xfs_buf_map { bm_bn, bm_len, bm_flags }
  struct xfs_buf_ops { name, magic, magic16 }
  enum mxfs_hold_site { MXFS_HS_ALLOC, _xfs_buf_alloc, initial, b_hold, xfs_buf_try_hold, rcu, cache, hit, hold, MXFS_HS_HOLD }
  struct mxfs_hold_evt { caller, flags, hold_after, site, delta }
  struct xfs_buf { b_rhash_head, b_rhash_key, b_length, b_hold, b_lru_ref, b_flags, b_sema, b_lru, b_lock, b_state }

[xfs/xfs_buf_item.h]
  fn mxfs_bli_auth_capture(struct xfs_trans *tp, struct xfs_buf *bp) -> void
  fn xfs_buf_item_init(struct xfs_buf *, struct xfs_mount *) -> int
  fn xfs_buf_item_done(struct xfs_buf *bp) -> void
  fn xfs_buf_item_put(struct xfs_buf_log_item *bip) -> void
  fn xfs_buf_item_log(struct xfs_buf_log_item *, uint, uint) -> void
  fn xfs_buf_item_dirty_format(struct xfs_buf_log_item *) -> bool
  fn xfs_buf_inode_iodone(struct xfs_buf *) -> void
  fn xfs_buf_dquot_iodone(struct xfs_buf *) -> void
  fn xfs_buf_iodone(struct xfs_buf *) -> void
  fn xfs_buf_log_check_iovec(struct kvec *iovec) -> bool
  fn xfs_buf_inval_log_space(unsigned int map_count, unsigned int blocksize) -> unsigned int
  struct mxfs_bli_auth { mba_capseq, mba_owner_ino, mba_resource, mba_epoch, mba_lineage, mba_auth_gen, mba_class, mba_blft, mba_status, mba_outcome }
  struct xfs_buf_log_item { bli_item, bli_buf, bli_flags, bli_recur, bli_refcount, bli_format_count, bli_formats, bli_mxfs_auth, __bli_format }

[xfs/xfs_buf_mem.h]
  fn xmbuf_alloc(struct xfs_mount *mp, const char *descr, struct xfs_buftarg **btpp) -> int
  fn xmbuf_free(struct xfs_buftarg *btp) -> void
  fn xmbuf_verify_daddr(struct xfs_buftarg *btp, xfs_daddr_t daddr) -> bool
  fn xmbuf_trans_bdetach(struct xfs_trans *tp, struct xfs_buf *bp) -> void
  fn xmbuf_finalize(struct xfs_buf *bp) -> int
  fn xmbuf_map_backing_mem(struct xfs_buf *bp) -> int

[xfs/xfs_dahash_test.h]
  fn xfs_dahash_test(void) -> int

[xfs/xfs_discard.c]
  struct xfs_trim_cur { start, count, end, minlen, by_bno }
  struct xfs_trim_rtdev { extent_list, minlen_fsb, restart_rtx, stop_rtx }
  struct xfs_rtx_busy { list, bno, length }
  struct xfs_trim_rtgroup { extents, minlen_fsb, restart_rtx, batch, queued }

[xfs/xfs_discard.h]
  fn xfs_discard_extents(struct xfs_mount *mp, struct xfs_busy_extents *busy) -> void
  fn xfs_ioc_trim(struct xfs_mount *mp, struct fstrim_range __user *fstrim) -> int

[xfs/xfs_dquot.h]
  fn try_wait_for_completion(&dqp->q_flush) -> return
  fn XFS_IS_UQUOTA_ON(mp) -> return
  fn XFS_IS_GQUOTA_ON(mp) -> return
  fn XFS_IS_PQUOTA_ON(mp) -> return
  fn XFS_IS_UQUOTA_ENFORCED(dqp->q_mount) -> return
  fn XFS_IS_GQUOTA_ENFORCED(dqp->q_mount) -> return
  fn XFS_IS_PQUOTA_ENFORCED(dqp->q_mount) -> return
  fn xfs_dquot_to_disk(struct xfs_disk_dquot *ddqp, struct xfs_dquot *dqp) -> void
  fn xfs_qm_dqdestroy(struct xfs_dquot *dqp) -> void
  fn xfs_qm_dqflush(struct xfs_dquot *dqp, struct xfs_buf *bp) -> int
  fn xfs_qm_dqunpin_wait(struct xfs_dquot *dqp) -> void
  fn xfs_qm_adjust_dqtimers(struct xfs_dquot *d) -> void
  fn xfs_qm_adjust_dqlimits(struct xfs_dquot *d) -> void
  fn xfs_qm_id_for_quotatype(struct xfs_inode *ip, xfs_dqtype_t type) -> xfs_dqid_t
  fn xfs_qm_dqget(struct xfs_mount *mp, xfs_dqid_t id, xfs_dqtype_t type, bool can_alloc, struct xfs_dquot **dqpp) -> int
  fn xfs_qm_dqget_inode(struct xfs_inode *ip, xfs_dqtype_t type, bool can_alloc, struct xfs_dquot **dqpp) -> int
  fn xfs_qm_dqget_next(struct xfs_mount *mp, xfs_dqid_t id, xfs_dqtype_t type, struct xfs_dquot **dqpp) -> int
  fn xfs_qm_dqget_uncached(struct xfs_mount *mp, xfs_dqid_t id, xfs_dqtype_t type, struct xfs_dquot **dqpp) -> int
  fn xfs_dqlock2(struct xfs_dquot *, struct xfs_dquot *) -> void
  fn xfs_dqlockn(struct xfs_dqtrx *q) -> void
  fn xfs_dquot_set_prealloc_limits(struct xfs_dquot *) -> void
  fn xfs_dquot_attach_buf(struct xfs_trans *tp, struct xfs_dquot *dqp) -> int
  fn xfs_dquot_use_attached_buf(struct xfs_dquot *dqp, struct xfs_buf **bpp) -> int
  fn xfs_dquot_detach_buf(struct xfs_dquot *dqp) -> void
  fn xfs_dquot_set_timeout(struct xfs_mount *mp, time64_t timeout) -> time64_t
  fn xfs_dquot_set_grace_period(time64_t grace) -> time64_t
  fn xfs_qm_init_dquot_blk(struct xfs_trans *tp, xfs_dqid_t id, xfs_dqtype_t type, struct xfs_buf *bp) -> void
  struct xfs_dquot_res { reserved, count, hardlimit, softlimit, timer }
  struct xfs_dquot_pre { q_prealloc_lo_wmark, q_prealloc_hi_wmark, q_low_space }
  struct xfs_dquot { q_lru, q_mount, q_type, q_flags, q_id, q_lockref, q_bufoffset, q_blkno, q_fileoffset, q_blk }

[xfs/xfs_dquot_item.c]
  fn static DQUOT_ITEM(struct xfs_log_item *lip) -> struct xfs_dq_logitem
    calls: container_of

[xfs/xfs_dquot_item.h]
  fn xfs_qm_dquot_logitem_init(struct xfs_dquot *dqp) -> void
  struct xfs_dq_logitem { qli_item, qli_dquot, qli_flush_lsn, qli_lock, qli_dirty }

[xfs/xfs_drain.h]
  fn xfs_defer_drain_init(struct xfs_defer_drain *dr) -> void
  fn xfs_defer_drain_free(struct xfs_defer_drain *dr) -> void
  fn xfs_defer_drain_wait_disable(void) -> void
  fn xfs_defer_drain_wait_enable(void) -> void
  fn xfs_group_intent_get(struct xfs_mount *mp, xfs_fsblock_t fsbno, enum xfs_group_type type) -> struct xfs_group
  fn xfs_group_intent_put(struct xfs_group *rtg) -> void
  fn xfs_group_intent_drain(struct xfs_group *xg) -> int
  fn xfs_group_intent_busy(struct xfs_group *xg) -> bool
  struct xfs_defer_drain { dr_count, dr_waiters }
  struct xfs_defer_drain { dr_count, dr_waiters }

[xfs/xfs_error.c]
  struct xfs_errortag_attr { attr, tag }

[xfs/xfs_error.h]
  fn xfs_error_report(const char *tag, int level, struct xfs_mount *mp, const char *filename, int linenum, xfs_failaddr_t failaddr) -> void
  fn xfs_corruption_error(const char *tag, int level, struct xfs_mount *mp, const void *buf, size_t bufsize, const char *filename, int linenum, xfs_failaddr_t failaddr) -> void
  fn xfs_buf_corruption_error(struct xfs_buf *bp, xfs_failaddr_t fa) -> void
  fn xfs_buf_verifier_error(struct xfs_buf *bp, int error, const char *name, const void *buf, size_t bufsz, xfs_failaddr_t failaddr) -> void
  fn xfs_verifier_error(struct xfs_buf *bp, int error, xfs_failaddr_t failaddr) -> void
  fn xfs_inode_verifier_error(struct xfs_inode *ip, int error, const char *name, const void *buf, size_t bufsz, xfs_failaddr_t failaddr) -> void
  fn xfs_errortag_init(struct xfs_mount *mp) -> int
  fn xfs_errortag_del(struct xfs_mount *mp) -> void
  fn xfs_errortag_test(struct xfs_mount *mp, const char *file, int line, unsigned int error_tag) -> bool
  fn xfs_errortag_delay(struct xfs_mount *mp, const char *file, int line, unsigned int error_tag) -> void
  fn xfs_errortag_add(struct xfs_mount *mp, unsigned int error_tag) -> int
  fn xfs_errortag_add_name(struct xfs_mount *mp, const char *tag_name) -> int
  fn xfs_errortag_copy(struct xfs_mount *dst_mp, struct xfs_mount *src_mp) -> void
  fn xfs_errortag_clearall(struct xfs_mount *mp) -> int

[xfs/xfs_exchmaps_item.c]
  fn static XMI_ITEM(struct xfs_log_item *lip) -> struct xfs_xmi_log_item
  fn static XMD_ITEM(struct xfs_log_item *lip) -> struct xfs_xmd_log_item
  fn static xmi_entry(const struct list_head *e) -> struct xfs_exchmaps_intent

[xfs/xfs_exchmaps_item.h]
  fn xfs_exchmaps_defer_add(struct xfs_trans *tp, struct xfs_exchmaps_intent *xmi) -> void
  struct xfs_xmi_log_item { xmi_item, xmi_refcount, xmi_format }
  struct xfs_xmd_log_item { xmd_item, xmd_intent_log_item, xmd_format }

[xfs/xfs_exchrange.c]
  struct xfs_commit_range_fresh { fsid, file2_ino, file2_mtime, file2_ctime, file2_mtime_nsec, file2_ctime_nsec, file2_gen, magic }

[xfs/xfs_exchrange.h]
  fn xfs_ioc_exchange_range(struct file *file, struct xfs_exchange_range __user *argp) -> long
  fn xfs_ioc_start_commit(struct file *file, struct xfs_commit_range __user *argp) -> long
  fn xfs_ioc_commit_range(struct file *file, struct xfs_commit_range __user	*argp) -> long
  fn xfs_exchrange_ilock(struct xfs_trans *tp, struct xfs_inode *ip1, struct xfs_inode *ip2) -> void
  fn xfs_exchrange_iunlock(struct xfs_inode *ip1, struct xfs_inode *ip2) -> void
  fn xfs_exchrange_estimate(struct xfs_exchmaps_req *req) -> int
  struct xfs_exchrange { file1, file2, file1_offset, file2_offset, length, flags, file2_ino, file2_mtime, file2_ctime, file2_gen }

[xfs/xfs_export.h]
  fn xfs_nfs_get_inode(struct super_block *sb, u64 ino, u32 gen) -> struct inode
    called_by: xfs_fileid_length
  struct xfs_fid64 { ino, gen, parent_ino, parent_gen }

[xfs/xfs_extent_busy.c]
  struct xfs_extent_busy_tree { eb_lock, eb_tree, eb_gen, eb_wait }

[xfs/xfs_extent_busy.h]
  fn xfs_extent_busy_insert(struct xfs_trans *tp, struct xfs_group *xg, xfs_agblock_t bno, xfs_extlen_t len, unsigned int flags) -> void
  fn xfs_extent_busy_insert_discard(struct xfs_group *xg, xfs_agblock_t bno, xfs_extlen_t len, struct list_head *busy_list) -> void
  fn xfs_extent_busy_clear(struct list_head *list, bool do_discard) -> void
  fn xfs_extent_busy_search(struct xfs_group *xg, xfs_agblock_t bno, xfs_extlen_t len) -> int
  fn xfs_extent_busy_reuse(struct xfs_group *xg, xfs_agblock_t fbno, xfs_extlen_t flen, bool userdata) -> void
  fn xfs_extent_busy_trim(struct xfs_group *xg, xfs_extlen_t minlen, xfs_extlen_t maxlen, xfs_agblock_t *bno, xfs_extlen_t *len, unsigned *busy_gen) -> bool
  fn xfs_extent_busy_flush(struct xfs_trans *tp, struct xfs_group *xg, unsigned busy_gen, uint32_t alloc_flags) -> int
  fn xfs_extent_busy_wait_all(struct xfs_mount *mp) -> void
  fn xfs_extent_busy_list_empty(struct xfs_group *xg, unsigned int *busy_gen) -> bool
  fn xfs_extent_busy_alloc(void) -> struct xfs_extent_busy_tree
  fn xfs_extent_busy_ag_cmp(void *priv, const struct list_head *a, const struct list_head *b) -> int
  struct xfs_extent_busy { rb_node, list, group, bno, length, flags }
  struct xfs_busy_extents { extent_list, endio_work, owner }

[xfs/xfs_extfree_item.c]
  fn static EFI_ITEM(struct xfs_log_item *lip) -> struct xfs_efi_log_item
  fn xfs_efi_log_space(unsigned int nr) -> unsigned int
  fn static EFD_ITEM(struct xfs_log_item *lip) -> struct xfs_efd_log_item
  fn xfs_efd_log_space(unsigned int nr) -> unsigned int
  fn static xefi_entry(const struct list_head *e) -> struct xfs_extent_free_item

[xfs/xfs_extfree_item.h]
  fn xfs_extent_free_defer_add(struct xfs_trans *tp, struct xfs_extent_free_item *xefi, struct xfs_defer_pending **dfpp) -> void
  fn xfs_efi_log_space(unsigned int nr) -> unsigned int
  fn xfs_efd_log_space(unsigned int nr) -> unsigned int
  struct xfs_efi_log_item { efi_item, efi_refcount, efi_next_extent, efi_format }
  struct xfs_efd_log_item { efd_item, efd_efip, efd_next_extent, efd_format }

[xfs/xfs_file.h]
  fn xfs_is_falloc_aligned(struct xfs_inode *ip, loff_t pos, long long int len) -> bool

[xfs/xfs_filestream.c]
  struct xfs_fstrm_item { mru, pag }
  enum xfs_fstrm_alloc { XFS_PICK_USERDATA, XFS_PICK_LOWSPACE }

[xfs/xfs_filestream.h]
  fn xfs_filestream_mount(struct xfs_mount *mp) -> int
  fn xfs_filestream_unmount(struct xfs_mount *mp) -> void
  fn xfs_filestream_deassociate(struct xfs_inode *ip) -> void
  fn xfs_filestream_select_ag(struct xfs_bmalloca *ap, struct xfs_alloc_arg *args, xfs_extlen_t *blen) -> int

[xfs/xfs_fsmap.c]
  struct xfs_getfsmap_info { head, fsmap_recs, agf_bp, group, next_daddr, low_daddr, end_daddr, missing_owner, dev, low }
  struct xfs_getfsmap_dev { dev, nr_sectors }

[xfs/xfs_fsmap.h]
  fn xfs_ioc_getfsmap(struct xfs_inode *ip, struct fsmap_head __user *arg) -> int
  struct xfs_fsmap { fmr_device, fmr_flags, fmr_physical, fmr_owner, fmr_offset, fmr_length }
  struct xfs_fsmap_head { fmh_iflags, fmh_oflags, fmh_count, fmh_entries, fmh_keys }
  struct xfs_fsmap_irec { start_daddr, len_daddr, owner, offset, rm_flags, rec_key }

[xfs/xfs_fsops.h]
  fn xfs_growfs_data(struct xfs_mount *mp, struct xfs_growfs_data *in) -> int
  fn xfs_growfs_log(struct xfs_mount *mp, struct xfs_growfs_log *in) -> int
  fn xfs_reserve_blocks(struct xfs_mount *mp, enum xfs_free_counter cnt, uint64_t request) -> int
  fn xfs_fs_goingdown(struct xfs_mount *mp, uint32_t inflags) -> int
    called_by: xfs_file_ioctl
  fn xfs_fs_reserve_ag_blocks(struct xfs_mount *mp) -> int
  fn xfs_fs_unreserve_ag_blocks(struct xfs_mount *mp) -> void

[xfs/xfs_handle.c]
  struct xfs_getparents_ctx { context, gph, ip, krecords, lastrec, count }

[xfs/xfs_handle.h]
  fn xfs_attrlist_by_handle(struct file *parfilp, struct xfs_fsop_attrlist_handlereq __user *p) -> int
  fn xfs_attrmulti_by_handle(struct file *parfilp, void __user *arg) -> int
  fn xfs_find_handle(unsigned int cmd, struct xfs_fsop_handlereq *hreq) -> int
  fn xfs_open_by_handle(struct file *parfilp, struct xfs_fsop_handlereq *hreq) -> int
  fn xfs_readlink_by_handle(struct file *parfilp, struct xfs_fsop_handlereq *hreq) -> int
  fn xfs_ioc_attrmulti_one(struct file *parfilp, struct inode *inode, uint32_t opcode, void __user *uname, void __user *value, uint32_t *len, uint32_t flags) -> int
  fn xfs_ioc_attr_list(struct xfs_inode *dp, void __user *ubuf, size_t bufsize, int flags, struct xfs_attrlist_cursor __user *ucursor) -> int
  fn xfs_handle_to_dentry(struct file *parfilp, void __user *uhandle, u32 hlen) -> struct dentry
  fn xfs_ioc_getparents(struct file *file, struct xfs_getparents __user *arg) -> int
  fn xfs_ioc_getparents_by_handle(struct file *file, struct xfs_getparents_by_handle __user *arg) -> int

[xfs/xfs_health.c]
  struct ioctl_sick_map { sick_mask, ioctl_mask }

[xfs/xfs_healthmon.h]
  fn xfs_healthmon_unmount(struct xfs_mount *mp) -> void
  fn xfs_healthmon_report_fs(struct xfs_mount *mp, enum xfs_healthmon_type type, unsigned int old_mask, unsigned int new_mask) -> void
  fn xfs_healthmon_report_group(struct xfs_group *xg, enum xfs_healthmon_type type, unsigned int old_mask, unsigned int new_mask) -> void
  fn xfs_healthmon_report_inode(struct xfs_inode *ip, enum xfs_healthmon_type type, unsigned int old_mask, unsigned int new_mask) -> void
  fn xfs_healthmon_report_shutdown(struct xfs_mount *mp, uint32_t flags) -> void
  fn xfs_healthmon_report_media(struct xfs_mount *mp, enum xfs_device fdev, xfs_daddr_t daddr, uint64_t bbcount) -> void
  fn xfs_healthmon_report_file_ioerror(struct xfs_inode *ip, const struct fserror_event *p) -> void
  fn xfs_ioc_health_monitor(struct file *file, struct xfs_health_monitor __user *arg) -> long
  struct xfs_healthmon { mount_cookie, dev, ref, lock, first_event, last_event, unmount_event, events, wait, buffer }
  enum xfs_healthmon_type { XFS_HEALTHMON_RUNNING, monitor, running, XFS_HEALTHMON_LOST, message, lost, XFS_HEALTHMON_UNMOUNT, filesystem, is, unmounting }
  enum xfs_healthmon_domain { XFS_HEALTHMON_MOUNT, affects, the, whole, fs, metadata, health, events, XFS_HEALTHMON_FS, main }
  struct xfs_healthmon_event { next, type, domain, time_ns, lostcount, fsmask, grpmask, group, imask, gen }

[xfs/xfs_hooks.h]
  fn xfs_hooks_init(struct xfs_hooks *chain) -> void
  fn xfs_hooks_add(struct xfs_hooks *chain, struct xfs_hook *hook) -> int
  fn xfs_hooks_del(struct xfs_hooks *chain, struct xfs_hook *hook) -> void
  fn xfs_hooks_call(struct xfs_hooks *chain, unsigned long action, void *priv) -> int
  struct xfs_hooks { head }
  struct xfs_hook { nb }
  typedef_fn xfs_hook_fn_t
  struct xfs_hooks { head }

[xfs/xfs_icache.c]
  fn static ici_tag_to_mark(unsigned int tag) -> xa_mark_t
  enum xfs_icwalk_goal { Goals, directly, associated, with, tagged, inodes, XFS_ICWALK_BLOCKGC, XFS_ICWALK_RECLAIM }

[xfs/xfs_icache.h]
  fn xfs_iget(struct xfs_mount *mp, struct xfs_trans *tp, xfs_ino_t ino, uint flags, uint lock_flags, xfs_inode_t **ipp) -> int
    called_by: mxfs_reap_worker
  fn xfs_inode_alloc(struct xfs_mount *mp, xfs_ino_t ino) -> struct xfs_inode *
  fn xfs_inode_free(struct xfs_inode *ip) -> void
  fn xfs_reclaim_worker(struct work_struct *work) -> void
  fn xfs_reclaim_inodes(struct xfs_mount *mp) -> void
  fn xfs_reclaim_inodes_count(struct xfs_mount *mp) -> long
  fn xfs_reclaim_inodes_nr(struct xfs_mount *mp, unsigned long nr_to_scan) -> long
  fn xfs_inode_mark_reclaimable(struct xfs_inode *ip) -> void
  fn mxfs_ici_lock(struct xfs_perag *pag) -> void
  fn xfs_blockgc_free_dquots(struct xfs_mount *mp, struct xfs_dquot *udqp, struct xfs_dquot *gdqp, struct xfs_dquot *pdqp, unsigned int iwalk_flags) -> int
  fn xfs_blockgc_free_quota(struct xfs_inode *ip, unsigned int iwalk_flags) -> int
  fn xfs_blockgc_free_space(struct xfs_mount *mp, struct xfs_icwalk *icm) -> int
  fn xfs_blockgc_flush_all(struct xfs_mount *mp) -> int
  fn xfs_inode_set_eofblocks_tag(struct xfs_inode *ip) -> void
  fn xfs_inode_clear_eofblocks_tag(struct xfs_inode *ip) -> void
  fn xfs_inode_set_cowblocks_tag(struct xfs_inode *ip) -> void
  fn xfs_inode_clear_cowblocks_tag(struct xfs_inode *ip) -> void
  fn xfs_blockgc_worker(struct work_struct *work) -> void
  fn xfs_blockgc_stop(struct xfs_mount *mp) -> void
  fn xfs_blockgc_start(struct xfs_mount *mp) -> void
  fn xfs_inodegc_worker(struct work_struct *work) -> void
  fn xfs_inodegc_push(struct xfs_mount *mp) -> void
  fn xfs_inodegc_flush(struct xfs_mount *mp) -> int
  fn xfs_inodegc_stop(struct xfs_mount *mp) -> void
  fn xfs_inodegc_start(struct xfs_mount *mp) -> void
  fn xfs_inodegc_register_shrinker(struct xfs_mount *mp) -> int
  struct xfs_icwalk { icw_flags, icw_uid, icw_gid, icw_prid, icw_min_file_size, icw_scan_limit }

[xfs/xfs_icreate_item.c]
  fn static ICR_ITEM(struct xfs_log_item *lip) -> struct xfs_icreate_item

[xfs/xfs_icreate_item.h]
  fn xfs_icreate_log(struct xfs_trans *tp, xfs_agnumber_t agno, xfs_agblock_t agbno, unsigned int count, unsigned int inode_size, xfs_agblock_t length, unsigned int generation) -> void
  struct xfs_icreate_item { ic_item, ic_format }

[xfs/xfs_inode.c]
  struct mxfs_createint_ent { node, task, dirino }

[xfs/xfs_inode.h]
  fn mxfs_report_leaked_inodes(void) -> void
  fn xfs_inode_fork_boff(ip) -> return
  fn XFS_LITINO(ip->i_mount) -> return
  fn xfs_inode_data_fork_size(ip) -> return
  fn xfs_inode_attr_fork_size(ip) -> return
  fn container_of(inode, struct xfs_inode, i_vnode) -> return
    called_by: ATTRD_ITEM, ATTRI_ITEM, BUF_ITEM, DQUOT_ITEM, INODE_ITEM, IUL_ITEM, mxfs_defer_work_fn, mxfs_reap_worker, zoned_to_mp
  fn xfs_is_metadir_inode(ip) -> return
  fn xfs_is_always_cow_inode(const struct xfs_inode *ip) -> bool
  fn xfs_can_sw_atomic_write(ip->i_mount) -> return
  fn mxfs_createint_dir_armed(struct xfs_inode *ip) -> bool
  fn xfs_inactive(struct xfs_inode *ip) -> int
  fn xfs_lookup(struct xfs_inode *dp, const struct xfs_name *name, struct xfs_inode **ipp, struct xfs_name *ci_name, bool create_intent) -> int
  fn xfs_create(const struct xfs_icreate_args *iargs, struct xfs_name *name, struct xfs_inode **ipp) -> int
  fn xfs_create_tmpfile(const struct xfs_icreate_args *iargs, struct xfs_inode **ipp) -> int
  fn xfs_remove(struct xfs_inode *dp, struct xfs_name *name, struct xfs_inode *ip) -> int
  fn xfs_link(struct xfs_inode *tdp, struct xfs_inode *sip, struct xfs_name *target_name) -> int
  fn xfs_rename(struct mnt_idmap *idmap, struct xfs_inode *src_dp, struct xfs_name *src_name, struct xfs_inode *src_ip, struct xfs_inode *target_dp, struct xfs_name *target_name, struct xfs_inode *target_ip, unsigned int flags) -> int
  fn xfs_ilock(xfs_inode_t *, uint) -> void
    called_by: mxfs_dlm_open_protect, mxfs_reap_worker
  fn xfs_ilock_nowait(xfs_inode_t *, uint) -> int
  fn xfs_iunlock(xfs_inode_t *, uint) -> void
    called_by: mxfs_dlm_open_protect, mxfs_reap_worker
  fn mxfs_ilk_note_lock(struct xfs_inode *ip, uint lock_flags, unsigned long ret_ip) -> void
  fn mxfs_ilk_note_unlock(struct xfs_inode *ip, uint lock_flags, unsigned long ret_ip) -> void
  fn xfs_ilock_demote(xfs_inode_t *, uint) -> void
  fn xfs_assert_ilocked(struct xfs_inode *, uint) -> void
  fn xfs_ilock_data_map_shared(struct xfs_inode *) -> uint
  fn xfs_ilock_attr_map_shared(struct xfs_inode *) -> uint
  fn xfs_ifree(struct xfs_trans *, struct xfs_inode *) -> int
  fn xfs_itruncate_extents_flags(struct xfs_trans **, struct xfs_inode *, int, xfs_fsize_t, int) -> int
  fn xfs_iext_realloc(xfs_inode_t *, int, int) -> void
  fn xfs_log_force_inode(struct xfs_inode *ip) -> int
  fn xfs_iunpin_wait(xfs_inode_t *) -> void
  fn xfs_iflush_cluster(struct xfs_buf *) -> int
  fn xfs_lock_two_inodes(struct xfs_inode *ip0, uint ip0_mode, struct xfs_inode *ip1, uint ip1_mode) -> void
  fn xfs_icreate(struct xfs_trans *tp, xfs_ino_t ino, const struct xfs_icreate_args *args, struct xfs_inode **ipp) -> int
  fn xfs_itruncate_extents_flags(tpp, ip, whichfork, new_size, 0) -> return
  fn xfs_break_dax_layouts(struct inode *inode) -> int
  fn xfs_break_layouts(struct inode *inode, uint *iolock, enum layout_break_reason reason) -> int
  fn xfs_irele(struct xfs_inode *ip) -> void
    called_by: mxfs_reap_worker
  fn xfs_inode_needs_inactive(struct xfs_inode *ip) -> bool
  fn xfs_iunlink_lookup(struct xfs_perag *pag, xfs_agino_t agino) -> struct xfs_inode
  fn xfs_iunlink_reload_next(struct xfs_trans *tp, struct xfs_buf *agibp, xfs_agino_t prev_agino, xfs_agino_t next_agino, short bucket) -> int
  fn xfs_end_io(struct work_struct *work) -> void
  fn xfs_ilock2_io_mmap(struct xfs_inode *ip1, struct xfs_inode *ip2) -> int
  fn xfs_iunlock2_io_mmap(struct xfs_inode *ip1, struct xfs_inode *ip2) -> void
  fn xfs_iunlock2_remapping(struct xfs_inode *ip1, struct xfs_inode *ip2) -> void
  fn xfs_lock_inodes(struct xfs_inode **ips, int inodes, uint lock_mode) -> void
  fn xfs_sort_inodes(struct xfs_inode **i_tab, unsigned int num_inodes) -> void
  fn xfs_inode_reload_unlinked_bucket(struct xfs_trans *tp, struct xfs_inode *ip) -> int
  fn xfs_inode_reload_unlinked(struct xfs_inode *ip) -> int
  fn xfs_ifork_zapped(const struct xfs_inode *ip, int whichfork) -> bool
  fn xfs_inode_count_blocks(struct xfs_trans *tp, struct xfs_inode *ip, xfs_filblks_t *dblocks, xfs_filblks_t *rblocks) -> void
  fn xfs_inode_alloc_unitsize(struct xfs_inode *ip) -> unsigned int
  fn xfs_icreate_dqalloc(const struct xfs_icreate_args *args, struct xfs_dquot **udqpp, struct xfs_dquot **gdqpp, struct xfs_dquot **pdqpp) -> int
  struct xfs_inode { i_mount, i_udquot, i_gdquot, i_pdquot, i_ino, i_imap, i_cowfp, i_df, i_af, i_itemp }
  enum layout_break_reason { BREAK_WRITE, BREAK_UNMAP }

[xfs/xfs_inode_item.c]
  fn static INODE_ITEM(struct xfs_log_item *lip) -> struct xfs_inode_log_item
    calls: container_of

[xfs/xfs_inode_item.h]
  fn xfs_inode_item_init(struct xfs_inode *, struct xfs_mount *) -> void
  fn xfs_inode_item_destroy(struct xfs_inode *) -> void
  fn xfs_iflush_abort(struct xfs_inode *) -> void
  fn xfs_iflush_shutdown_abort(struct xfs_inode *) -> void
  fn xfs_inode_item_format_convert(struct kvec *buf, struct xfs_inode_log_format *in_f) -> int
  struct xfs_inode_log_item { ili_item, ili_inode, ili_lock_flags, ili_dirty_flags, ili_lock, ili_last_fields, ili_fields, ili_flush_lsn, ili_mxfs_buf_gen, ili_commit_seq }

[xfs/xfs_inode_item_recover.c]
  fn static xfs_log_dinode_has_bigtime(const struct xfs_log_dinode *ld) -> bool
  fn static xfs_log_dinode_has_large_extent_counts(const struct xfs_log_dinode *ld) -> bool

[xfs/xfs_ioctl.h]
  fn xfs_fsbulkstat_one_fmt(struct xfs_ibulk *breq, const struct xfs_bulkstat *bstat) -> int
  fn xfs_fsinumbers_fmt(struct xfs_ibulk *breq, const struct xfs_inumbers *igrp) -> int

[xfs/xfs_ioctl32.h]
  struct compat_xfs_bstime { tv_sec, tv_nsec }
  struct compat_xfs_bstat { bs_ino, bs_mode, bs_nlink, bs_uid, bs_gid, bs_rdev, bs_blksize, bs_size, bs_atime, bs_mtime }
  struct compat_xfs_fsop_bulkreq { lastip, icount, ubuffer, ocount }
  struct compat_xfs_fsop_handlereq { fd, path, oflags, ihandle, ihandlen, ohandle, ohandlen }
  struct compat_xfs_swapext { sx_version, sx_fdtarget, sx_fdtmp, sx_offset, sx_length, sx_pad, sx_stat }
  struct compat_xfs_fsop_attrlist_handlereq { hreq, pos, flags, buflen, buffer }
  struct compat_xfs_attr_multiop { am_opcode, am_error, am_attrname, am_attrvalue, am_length, am_flags }
  struct compat_xfs_fsop_attrmulti_handlereq { hreq, opcount, ops }
  struct compat_xfs_fsop_geom_v1 { blocksize, rtextsize, agblocks, agcount, logblocks, sectsize, inodesize, imaxpct, datablocks, rtblocks }
  struct compat_xfs_inogrp { xi_startino, xi_alloccount, xi_allocmask }
  struct compat_xfs_growfs_data { newblocks, imaxpct }
  struct compat_xfs_growfs_rt { newblocks, extsize }

[xfs/xfs_iomap.h]
  fn xfs_iomap_write_direct(struct xfs_inode *ip, xfs_fileoff_t offset_fsb, xfs_fileoff_t count_fsb, unsigned int flags, struct xfs_bmbt_irec *imap, u64 *sequence) -> int
  fn xfs_iomap_write_unwritten(struct xfs_inode *, xfs_off_t, xfs_off_t, bool) -> int
  fn xfs_iomap_eof_align_last_fsb(struct xfs_inode *ip, xfs_fileoff_t end_fsb) -> xfs_fileoff_t
  fn xfs_iomap_inode_sequence(struct xfs_inode *ip, u16 iomap_flags) -> u64
  fn xfs_bmbt_to_iomap(struct xfs_inode *ip, struct iomap *iomap, struct xfs_bmbt_irec *imap, unsigned int mapping_flags, u16 iomap_flags, u64 sequence_cookie) -> int
  fn xfs_zero_range(struct xfs_inode *ip, loff_t pos, loff_t len, struct xfs_zone_alloc_ctx *ac, bool *did_zero) -> int
  fn xfs_truncate_page(struct xfs_inode *ip, loff_t pos, struct xfs_zone_alloc_ctx *ac, bool *did_zero) -> int

[xfs/xfs_iops.h]
  fn xfs_vn_listxattr(struct dentry *, char *data, size_t size) -> ssize_t
  fn xfs_vn_setattr_size(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *vap) -> int
  fn xfs_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr) -> int
  fn xfs_setup_inode(struct xfs_inode *ip) -> void
  fn xfs_setup_iops(struct xfs_inode *ip) -> void
  fn xfs_diflags_to_iflags(struct xfs_inode *ip, bool init) -> void
  fn xfs_get_atomic_write_min(struct xfs_inode *ip) -> unsigned int
  fn xfs_get_atomic_write_max(struct xfs_inode *ip) -> unsigned int
  fn xfs_get_atomic_write_max_opt(struct xfs_inode *ip) -> unsigned int

[xfs/xfs_itable.c]
  struct xfs_bstat_chunk { formatter, breq, buf }
  struct xfs_inumbers_chunk { formatter, breq }

[xfs/xfs_itable.h]
  fn xfs_bulkstat_one(struct xfs_ibulk *breq, bulkstat_one_fmt_pf formatter) -> int
  fn xfs_bulkstat(struct xfs_ibulk *breq, bulkstat_one_fmt_pf formatter) -> int
  fn xfs_bulkstat_to_bstat(struct xfs_mount *mp, struct xfs_bstat *bs1, const struct xfs_bulkstat *bstat) -> void
  fn xfs_inumbers(struct xfs_ibulk *breq, inumbers_fmt_pf formatter) -> int
  fn xfs_inumbers_to_inogrp(struct xfs_inogrp *ig1, const struct xfs_inumbers *ig) -> void
  struct xfs_ibulk { mp, idmap, ubuffer, startino, icount, ocount, flags, iwalk_flags }
  typedef_fn bulkstat_one_fmt_pf
  typedef_fn inumbers_fmt_pf

[xfs/xfs_iunlink_item.c]
  fn static IUL_ITEM(struct xfs_log_item *lip) -> struct xfs_iunlink_item
    calls: container_of

[xfs/xfs_iunlink_item.h]
  fn xfs_iunlink_log_inode(struct xfs_trans *tp, struct xfs_inode *ip, struct xfs_perag *pag, xfs_agino_t next_agino) -> int
  struct xfs_iunlink_item { item, ip, pag, next_agino, old_agino }

[xfs/xfs_iwalk.c]
  struct xfs_iwalk_ag { pwork, mp, tp, pag, startino, lastino, recs, sz_recs, nr_recs, iwalk_fn }

[xfs/xfs_iwalk.h]
  fn xfs_iwalk(struct xfs_mount *mp, struct xfs_trans *tp, xfs_ino_t startino, unsigned int flags, xfs_iwalk_fn iwalk_fn, unsigned int inode_records, void *data) -> int
  fn xfs_iwalk_threaded(struct xfs_mount *mp, xfs_ino_t startino, unsigned int flags, xfs_iwalk_fn iwalk_fn, unsigned int inode_records, bool poll, void *data) -> int
  fn xfs_inobt_walk(struct xfs_mount *mp, struct xfs_trans *tp, xfs_ino_t startino, unsigned int flags, xfs_inobt_walk_fn inobt_walk_fn, unsigned int inobt_records, void *data) -> int
  typedef_fn xfs_iwalk_fn
  typedef_fn xfs_inobt_walk_fn

[xfs/xfs_log.c]
  fn static xlog_write_space_left(struct xlog_write_data *data) -> uint32_t
  struct xlog_write_data { ticket, iclog, bytes_left, record_cnt, data_cnt, log_offset }

[xfs/xfs_log.h]
  fn xlog_format_start(struct xlog_format_buf *lfb, uint16_t type) -> void
  fn xlog_format_commit(struct xlog_format_buf *lfb, unsigned int data_len) -> void
  fn xfs_log_force(struct xfs_mount *mp, uint flags) -> int
    called_by: mxfs_invalidate_inode
  fn xfs_log_force_seq(struct xfs_mount *mp, xfs_csn_t seq, uint flags, int *log_forced) -> int
  fn xfs_log_mount(struct xfs_mount	*mp, struct xfs_buftarg	*log_target, xfs_daddr_t		start_block, int		 	num_bblocks) -> int
  fn xfs_log_mount_finish(struct xfs_mount *mp) -> int
  fn xfs_log_mount_cancel(struct xfs_mount *) -> void
  fn mxfs_xlog_recover_foreign_slice(struct xfs_mount *mp, uint32_t dead_slot, struct mxfs_freplay_verdict *verdict) -> int
  fn xlog_assign_tail_lsn(struct xfs_mount *mp) -> xfs_lsn_t
  fn xlog_assign_tail_lsn_locked(struct xfs_mount *mp) -> xfs_lsn_t
  fn xfs_log_space_wake(struct xfs_mount *mp) -> void
  fn xfs_log_reserve(struct xfs_mount *mp, int length, int count, struct xlog_ticket **ticket, bool permanent) -> int
  fn xfs_log_regrant(struct xfs_mount *mp, struct xlog_ticket *tic) -> int
  fn xfs_log_unmount(struct xfs_mount *mp) -> void
  fn xfs_log_writable(struct xfs_mount *mp) -> bool
  fn xfs_log_ticket_get(struct xlog_ticket *ticket) -> struct xlog_ticket
  fn xfs_log_ticket_put(struct xlog_ticket *ticket) -> void
  fn xlog_cil_process_committed(struct list_head *list) -> void
  fn xfs_log_item_in_current_chkpt(struct xfs_log_item *lip) -> bool
  fn xfs_log_work_queue(struct xfs_mount *mp) -> void
  fn xfs_log_quiesce(struct xfs_mount *mp) -> int
  fn xfs_log_clean(struct xfs_mount *mp) -> void
  fn xfs_log_check_lsn(struct xfs_mount *, xfs_lsn_t) -> bool
  fn xlog_force_shutdown(struct xlog *log, uint32_t shutdown_flags) -> bool
  struct mxfs_freplay_verdict { reason, fswide, digest_valid, ag_mask, slice_digest, refused_items, malformed_items }

[xfs/xfs_log_cil.c]
  struct xlog_format_buf { lv, idx }
  enum _record_type { _START_RECORD, _COMMIT_RECORD }
  struct xlog_cil_trans_hdr { oph, thdr, lhdr }

[xfs/xfs_log_priv.h]
  fn test_bit(XLOG_RECOVERY_NEEDED, &log->l_opstate) -> return
    called_by: mxfs_reap_worker
  fn test_bit(XLOG_ACTIVE_RECOVERY, &log->l_opstate) -> return
    called_by: mxfs_reap_worker
  fn test_bit(XLOG_IO_ERROR, &log->l_opstate) -> return
    called_by: mxfs_reap_worker
  fn test_bit(XLOG_MXFS_FOREIGN_REPLAY, &log->l_opstate) -> return
    called_by: mxfs_reap_worker
  fn test_bit(XLOG_MXFS_ADOPTED_SLICE, &log->l_opstate) -> return
    called_by: mxfs_reap_worker
  fn mxfs_shadow_eval_finish(struct xlog *log) -> void
  fn mxfs_fr_enforce_preflight(struct xlog *log) -> int
  fn xlog_cksum(struct xlog *log, struct xlog_rec_header *rhead, char *dp, unsigned int hdrsize, unsigned int size) -> __le32
  fn xlog_ticket_alloc(struct xlog *log, int unit_bytes, int count, bool permanent) -> struct xlog_ticket
  fn xlog_print_tic_res(struct xfs_mount *mp, struct xlog_ticket *ticket) -> void
  fn xlog_print_trans(struct xfs_trans *) -> void
  fn xlog_write(struct xlog *log, struct xfs_cil_ctx *ctx, struct list_head *lv_chain, struct xlog_ticket *tic, uint32_t len) -> int
  fn xlog_write_one_vec(struct xlog *log, struct xfs_cil_ctx *ctx, struct xfs_log_iovec *reg, struct xlog_ticket *ticket) -> int
  fn xfs_log_ticket_ungrant(struct xlog *log, struct xlog_ticket *ticket) -> void
  fn xfs_log_ticket_regrant(struct xlog *log, struct xlog_ticket *ticket) -> void
  fn xlog_state_switch_iclogs(struct xlog *log, struct xlog_in_core *iclog, int eventual_size) -> void
  fn xlog_state_release_iclog(struct xlog *log, struct xlog_in_core *iclog, struct xlog_ticket *ticket) -> int
  fn xlog_cil_init(struct xlog *log) -> int
  fn xlog_cil_init_post_recovery(struct xlog *log) -> void
  fn xlog_cil_destroy(struct xlog *log) -> void
  fn xlog_cil_empty(struct xlog *log) -> bool
  fn xlog_cil_commit(struct xlog *log, struct xfs_trans *tp, xfs_csn_t *commit_seq, bool regrant) -> void
  fn xlog_cil_set_ctx_write_state(struct xfs_cil_ctx *ctx, struct xlog_in_core *iclog) -> void
  fn xlog_cil_flush(struct xlog *log) -> void
  fn xlog_cil_force_seq(struct xlog *log, xfs_csn_t sequence) -> xfs_lsn_t
  fn BBTOB(hi_block - lo_block) -> return
  fn xlog_grant_return_space(struct xlog *log, xfs_lsn_t old_head, xfs_lsn_t new_head) -> void
  struct xfs_log_iovec { i_addr, i_len, i_type }
  struct xfs_log_vec { lv_list, lv_order_id, lv_niovecs, lv_iovecp, lv_item, lv_buf, lv_bytes, lv_buf_used, lv_alloc_size }
  enum xlog_iclog_state { XLOG_STATE_ACTIVE, Current, IC, log, being, written, to, XLOG_STATE_WANT_SYNC, Want, to }
  struct xlog_ticket { t_queue, t_task, t_tid, t_ref, t_curr_res, t_unit_res, t_ocnt, t_cnt, t_flags, t_iclog_hdrs }
  struct xlog_in_core { ic_force_wait, ic_write_wait, ic_next, ic_prev, ic_log, ic_size, ic_offset, ic_state, ic_flags, ic_datap }
  struct xfs_cil_ctx { cil, sequence, start_lsn, commit_lsn, commit_iclog, ticket, space_used, busy_extents, log_items, lv_chain }
  struct xlog_cil_pcp { space_used, space_reserved, busy_extents, log_items }
  struct xfs_cil { xc_log, xc_flags, xc_iclog_hdrs, xc_push_wq, ____cacheline_aligned_in_smp, xc_ctx, ____cacheline_aligned_in_smp, xc_push_seq, xc_push_commit_stable, xc_committing }
  struct xlog_grant_head { ____cacheline_aligned_in_smp, waiters, grant }
  struct xlog { l_mp, l_ailp, l_cilp, l_targ, l_ioend_workqueue, l_work, l_opstate, l_quotaoffs_flag, l_buf_cancel_table, r_dfops }

[xfs/xfs_log_recover.c]
  struct mxfs_shadow_eval { desc_rc, desc_stage, desc_victim_epoch, desc_victim_node, capable, enforce_cfg, resource, epoch, lineage, rc }
  struct mxfs_shadow_man_ent { resource, epoch, lineage, rc, kind, holds }

[xfs/xfs_message.h]
  fn xfs_printk_level(const char *kern_level, const struct xfs_mount *mp, const char *fmt, ...) -> void
  fn _xfs_alert_tag(const struct xfs_mount *mp, uint32_t tag, const char *fmt, ...) -> void
  fn static DEFINE_RATELIMIT_STATE(_rs, \ DEFAULT_RATELIMIT_INTERVAL, \ DEFAULT_RATELIMIT_BURST) -> static
  fn assfail(struct xfs_mount *mp, char *expr, char *f, int l) -> void
  fn asswarn(struct xfs_mount *mp, char *expr, char *f, int l) -> void
  fn xfs_hex_dump(const void *p, int length) -> void
  fn xfs_buf_alert_ratelimited(struct xfs_buf *bp, const char *rlmsg, const char *fmt, ...) -> void
  fn xfs_warn_experimental(struct xfs_mount *mp, enum xfs_experimental_feat f) -> void
  enum xfs_experimental_feat { XFS_EXPERIMENTAL_SHRINK, XFS_EXPERIMENTAL_LARP, XFS_EXPERIMENTAL_ZONED, XFS_EXPERIMENTAL_MAX }

[xfs/xfs_mount.c]
  fn static xfs_calc_atomic_write_max(struct xfs_mount *mp) -> xfs_extlen_t

[xfs/xfs_mount.h]
  fn xfs_has_metadir(mp) -> return
  fn xfs_has_reflink(mp) -> return
  fn test_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate) -> return
    called_by: mxfs_reap_worker
  fn test_and_clear_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate) -> return
  fn test_and_set_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate) -> return
  fn xfs_do_force_shutdown(struct xfs_mount *mp, uint32_t flags, char *fname, int lnnum) -> void
  fn xfs_uuid_table_free(void) -> void
  fn xfs_default_resblks(struct xfs_mount *mp, enum xfs_free_counter ctr) -> uint64_t
  fn xfs_mountfs(xfs_mount_t *mp) -> int
  fn xfs_unmountfs(xfs_mount_t *) -> void
  fn xfs_freecounter_unavailable(struct xfs_mount *mp, enum xfs_free_counter ctr) -> uint64_t
  fn percpu_counter_sum_positive(&mp->m_free[ctr].count) -> return
  fn percpu_counter_sum(&mp->m_free[ctr].count) -> return
  fn percpu_counter_read_positive(&mp->m_free[ctr].count) -> return
  fn __percpu_counter_compare(&mp->m_free[ctr].count, rhs, batch) -> return
  fn xfs_dec_freecounter(struct xfs_mount *mp, enum xfs_free_counter ctr, uint64_t delta, bool rsvd) -> int
  fn xfs_add_freecounter(struct xfs_mount *mp, enum xfs_free_counter ctr, uint64_t delta) -> void
  fn xfs_dec_freecounter(mp, XC_FREE_BLOCKS, delta, reserved) -> return
  fn xfs_dec_freecounter(mp, XC_FREE_RTEXTENTS, delta, false) -> return
  fn xfs_readsb(xfs_mount_t *, int) -> int
  fn xfs_freesb(xfs_mount_t *) -> void
  fn xfs_fs_writable(struct xfs_mount *mp, int level) -> bool
  fn xfs_sb_validate_fsb_count(struct xfs_sb *, uint64_t) -> int
  fn xfs_dev_is_read_only(struct xfs_mount *, char *) -> int
  fn xfs_set_low_space_thresholds(struct xfs_mount *) -> void
  fn xfs_zero_extent(struct xfs_inode *ip, xfs_fsblock_t start_fsb, xfs_off_t count_fsb) -> int
  fn xfs_error_get_cfg(struct xfs_mount *mp, int error_class, int error) -> struct xfs_error_cfg *
  fn xfs_force_summary_recalc(struct xfs_mount *mp) -> void
  fn xfs_add_incompat_log_feature(struct xfs_mount *mp, uint32_t feature) -> int
  fn xfs_clear_incompat_log_features(struct xfs_mount *mp) -> bool
  fn xfs_mod_delalloc(struct xfs_inode *ip, int64_t data_delta, int64_t ind_delta) -> void
  fn xfs_set_max_atomic_write_opt(struct xfs_mount *mp, unsigned long long new_max_bytes) -> int
  struct xfs_error_cfg { kobj, max_retries, retry_timeout }
  struct xfs_inodegc { mp, list, work, error, items, shrinker_hits, cpu }
  struct xfs_groups { xa, blocks, blklog, has_daddr_gaps, blkmask, start_fsb, awu_max }
  struct xfs_freecounter { count, res_total, res_avail, res_saved }
  struct mxfs_f4_registry { f4_lock, f4_hash, f4_opens, f4_recommits, f4_retires, f4_stale_cancels, f4_shutdown_cancels, f4_abort_keeps, f4_orphans, f4_suppress_skips }
  struct mxfs_icwr_registry { icwr_lock, icwr_hash, icwr_wq, icwr_submits, icwr_completes, icwr_resubmit_keeps, icwr_orphans, icwr_underflows, icwr_untracked, icwr_entries }
  struct xfs_mount { m_sb, m_super, m_ail, m_sb_bp, m_rtsb_bp, m_rtname, m_logname, m_dir_geo, m_attr_geo, m_log }

[xfs/xfs_mru_cache.h]
  fn xfs_mru_cache_init(void) -> int
  fn xfs_mru_cache_uninit(void) -> void
  fn xfs_mru_cache_create(struct xfs_mru_cache **mrup, void *data, unsigned int lifetime_ms, unsigned int grp_count, xfs_mru_cache_free_func_t free_func) -> int
  fn xfs_mru_cache_destroy(struct xfs_mru_cache *mru) -> void
  fn xfs_mru_cache_insert(struct xfs_mru_cache *mru, unsigned long key, struct xfs_mru_cache_elem *elem) -> int
  fn xfs_mru_cache_delete(struct xfs_mru_cache *mru, unsigned long key) -> void
  fn xfs_mru_cache_done(struct xfs_mru_cache *mru) -> void
  struct xfs_mru_cache_elem { list_node, key }
  typedef_fn xfs_mru_cache_free_func_t

[xfs/xfs_mxfs_dlm.c]
  fn static mxfs_dlm_report_stats(void) -> void
    calls: mxfs_pal_log, mxfs_pal_time_ms
  fn mxfs_defer_reap_add(struct xfs_mount *mp, uint64_t ino, uint32_t gen, int16_t bucket) -> void
    calls: mxfs_defer_reap_add_mode
  fn static mxfs_reap_sched(struct xfs_mount *mp, unsigned int delay_ms, const char *why) -> void
    called_by: mxfs_defer_reap_add_mode, mxfs_defer_reap_init, mxfs_reap_worker
  fn mxfs_defer_reap_add_mode(struct xfs_mount *mp, uint64_t ino, uint32_t gen, int16_t bucket, uint8_t kind) -> void
    calls: mxfs_reap_sched
    called_by: mxfs_defer_reap_add, mxfs_dlm_open_last_close
  fn mxfs_defer_reap_done(struct xfs_mount *mp, uint64_t ino) -> void
  fn static mxfs_reap_worker(struct work_struct *work) -> void
    calls: container_of, mxfs_own_bucket_rescan, mxfs_reap_sched, mxfs_survivor_sweep_slot, mxfs_unclaimed_bucket_scan, test_bit, xfs_iget, xfs_ilock, xfs_irele, xfs_iunlock
  fn mxfs_iunl_store_record(struct xfs_mount *mp, uint64_t ino, uint32_t gen, uint32_t next_agino, xfs_daddr_t daddr, uint16_t boffset) -> void
  fn mxfs_iunl_store_query_print(struct xfs_mount *mp, uint64_t ino) -> void
  fn mxfs_iunl_store_fossil_match(struct xfs_mount *mp, uint64_t ino, uint32_t gen, xfs_daddr_t daddr, uint16_t boffset, uint32_t expect) -> bool
  fn mxfs_iunl_store_purge_ag(struct xfs_mount *mp, xfs_agnumber_t agno, const char *why) -> void
    calls: atomic_inc_return, pr_info
  fn mxfs_iunl_store_retire_range(struct xfs_mount *mp, xfs_daddr_t daddr, int bblen, void *base, unsigned int len) -> void
    calls: be16_to_cpu, be32_to_cpu
  fn static mxfs_iunl_discrim(struct xfs_mount *mp, xfs_daddr_t daddr, int bblen, uint16_t boffset, uint64_t ino, uint32_t gen, uint32_t img_next, uint32_t committed, uint64_t wr_epoch) -> void
    calls: atomic_inc_return, be16_to_cpu, be32_to_cpu, mxfs_pal_bdev_read_plain_bdev, mxfs_pal_scsi_read_fua_bdev
    called_by: mxfs_iunl_store_overlay
  fn mxfs_iunl_store_overlay(struct xfs_mount *mp, xfs_daddr_t daddr, int bblen, void *base, unsigned int len) -> int
    calls: be16_to_cpu, be32_to_cpu, mxfs_iunl_discrim, xfs_dinode_calc_crc
  fn mxfs_defer_reap_init(struct xfs_mount *mp) -> void
    calls: mxfs_reap_sched
  fn mxfs_defer_reap_destroy(struct xfs_mount *mp) -> void
  fn static mxfs_dirring_dump_set(const char *val, const struct kernel_param *kp) -> int
  fn mxfs_dlm_open_protect(struct xfs_inode *ip) -> int
    calls: atomic_inc_return, atomic_read, mxfs_dlm_iclus_covered, mxfs_iclus_open_admit, mxfs_v5_dlm_is_single_node, xfs_ilock, xfs_iunlock
  fn mxfs_dlm_open_last_close(struct xfs_inode *ip) -> void
    calls: atomic_read, mxfs_defer_reap_add_mode, mxfs_v5_dlm_inode_open_clear, mxfs_v5_dlm_is_single_node
  fn static mxfs_lktdump_set(const char *val, const struct kernel_param *kp) -> int
    calls: mxfs_dlm_lkt_dump
  fn static mxfs_pin_census_set(const char *val, const struct kernel_param *kp) -> int
    calls: atomic_read
  fn static mxfs_lru_sweep_fn(struct work_struct *work) -> void
    calls: atomic_read, pr_info
  fn mxfs_lru_sweep_start(void) -> void
  fn mxfs_lru_sweep_stop(void) -> void
  fn mxfs_replay_gate_mode(void) -> int
  fn static mxfs_iclus_admission_open(struct mxfs_iclus *ic) -> bool
  fn static mxfs_iclus_release_done_locked(struct mxfs_iclus *ic) -> void
  fn static mxfs_iclus_base(struct xfs_mount *mp, uint64_t ino) -> uint64_t
  fn static mxfs_iclus_hashfn(uint64_t base) -> unsigned int
  struct mxfs_dlmtr_ent { ns, ino, line, pid, comm }
  struct mxfs_pending_ag_unlock { list, pag }
  struct mxfs_merge_ent { inum, ftype, namelen, name }
  struct mxfs_pend_ent { cino, cgen, ftype, namelen, name }
  struct mxfs_dirdrain_task { node, task, mode }
  struct mxfs_recovtask { node, task, phase }
  struct mxfs_f4_record { f4_node, f4_ino, f4_daddr, f4_length, f4_gen, f4_buffer_gone, f4_aborted }
  struct mxfs_icwr_entry { ie_node, ie_daddr, ie_inflight, ie_submit_gen, ie_complete_gen }
  struct mxfs_noino_bast_work { work, mp, ino, rel_gen }
  struct mxfs_noino_inflight { hnode, mp, ino }
  struct mxfs_pub_drain_worker { work, mp, parent_ino, agno, batch, published }
  struct mxfs_pub_drain_batch { w, refs, pending, done, nworkers }
  struct mxfs_reap_entry { l, ino, gen, bucket, kind }
  struct mxfs_iunl_rec { l, ino, gen, next_agino, daddr, boffset, agno, wr_epoch }
  struct mxfs_dland_ent { daddr, owner, realns, incarn, sum, cnt, comm, ops }
  struct mxfs_pending_inode_unlock { list, ip }
  struct mxfs_orphan_scan_ctx { cand, n, overflow }
  struct mxfs_freplay_closure_arg { mp, ag_mask }
  struct mxfs_iclus { hnode, mp, base, lock, disk_mode, busy, bast_pending, grant_seq, auth_epoch, rel_state }

[xfs/xfs_mxfs_dlm.h]
  fn mxfs_destage_kick(struct xfs_mount *mp) -> void
  fn mxfs_dlm_ilock_begin(struct xfs_inode *ip, uint8_t mode) -> void
  fn mxfs_dlm_shutdown_withdraw(struct xfs_mount *mp) -> void
  fn mxfs_dlm_withdraw_work_fn(struct work_struct *work) -> void
  fn mxfs_dlm_ilock_end(struct xfs_inode *ip, uint8_t mode) -> void
  fn mxfs_dlm_dir_hold_ex(struct xfs_inode *dp) -> void
  fn mxfs_dlm_ilock_try(struct xfs_inode *ip, uint8_t mode) -> bool
  fn mxfs_dlm_ilock_demote(struct xfs_inode *ip) -> void
  fn mxfs_dlm_bast_notify(void *data, uint64_t ino, uint8_t requested_mode) -> void
  fn mxfs_dlm_bast_process(struct xfs_inode *ip) -> void
  fn mxfs_dlm_sf_tenure_keep_delay(struct xfs_inode *ip) -> unsigned long
  fn mxfs_dlm_dir_tenure_keep_delay(struct xfs_inode *ip) -> unsigned long
  fn mxfs_dlm_sf_tenure_arm(struct xfs_inode *ip, unsigned long delay_j) -> void
  fn mxfs_ail_drain_inode_sync(struct xfs_inode *ip) -> void
  fn mxfs_dlm_evict(struct xfs_inode *ip) -> void
  fn mxfs_dlm_grant_local_new(struct xfs_inode *ip, uint8_t mode) -> void
  fn mxfs_dlm_rearm_unpublished(struct xfs_inode *ip) -> void
  fn mxfs_dlm_publish_unpublished(struct xfs_mount *mp, xfs_ino_t parent_ino, xfs_agnumber_t agno) -> void
  fn mxfs_dlm_publish_dirs_work(struct work_struct *work) -> void
  fn mxfs_dlm_unpublish_drop(struct xfs_inode *ip) -> bool
  fn mxfs_dir_epoch_superseded(struct xfs_inode *ip, uint32_t cur_ep) -> bool
  fn mxfs_dlm_close_release(struct xfs_inode *ip) -> void
  fn mxfs_survivor_sweep_slot(struct xfs_mount *mp, unsigned int dead_slot) -> int
    called_by: mxfs_reap_worker
  fn mxfs_own_bucket_rescan(struct xfs_mount *mp) -> int
    called_by: mxfs_reap_worker
  fn mxfs_unclaimed_bucket_scan(struct xfs_mount *mp) -> int
    called_by: chk_print_guard, hb_report_claim_exhausted, mxfs_reap_worker
  fn mxfs_orphan_scan(struct xfs_mount *mp) -> int
  fn mxfs_dlm_open_protect(struct xfs_inode *ip) -> int
  fn mxfs_dlm_open_last_close(struct xfs_inode *ip) -> void
  fn mxfs_dlm_pr_sweep_work_fn(struct work_struct *work) -> void
  fn mxfs_dlm_publish_inode(struct xfs_inode *ip) -> void
  fn mxfs_dlm_cache_init(struct xfs_mount *mp) -> void
  fn mxfs_dlm_admission_commit(struct xfs_mount *mp) -> int
  fn mxfs_dlm_mount_recovery_settle(struct xfs_mount *mp) -> void
  fn mxfs_dlm_mount_recovery_barrier(struct xfs_mount *mp) -> int
  fn mxfs_blkdev_flush_durable(struct xfs_mount *mp) -> int
  fn mxfs_dlm_invalidate_cached_views(struct xfs_mount *mp) -> int
  fn mxfs_dlm_inode_init(struct xfs_inode *ip) -> void
  fn mxfs_dlm_inode_final_release(struct xfs_inode *ip) -> void
  fn mxfs_dlm_reload_inode(struct xfs_inode *ip, uint8_t expect_ftype, bool post_release) -> void
  fn mxfs_dir_delalloc_tripwire(struct xfs_inode *ip, const char *site) -> int
  fn mxfs_dir_evict_owned_dir_blocks(struct xfs_inode *ip, bool leaf_only) -> void
  fn mxfs_dir_modify_adopt_disk_format(struct xfs_inode *dp, unsigned int lock_flags) -> bool
  fn mxfs_dlm_note_inode_freed(struct xfs_mount *mp, uint64_t ino, uint32_t gen) -> void
  fn mxfs_dlm_note_dir_modified(struct xfs_mount *mp, uint64_t dir_ino) -> void
  fn mxfs_dlm_dir_durable_signal(struct xfs_inode *dp) -> void
  fn mxfs_dlm_dir_inode_durable(struct xfs_inode *dp) -> void
  fn __mxfs_dlm_dir_inode_durable(struct xfs_inode *dp) -> void
  fn mxfs_dirop_durable_needed(struct xfs_mount *mp) -> bool
  fn mxfs_dlm_dir_consumer_refresh(struct xfs_inode *dp) -> void
  fn mxfs_dlm_dir_modify_refresh(struct xfs_inode *dp) -> void
  fn mxfs_dlm_dir_modify_reload_prelock(struct xfs_inode *dp) -> void
  fn mxfs_dir_merge_peer_blocks(struct xfs_inode *dp) -> void
  fn mxfs_dir_merge_peer_into_tp(struct xfs_trans *tp, struct xfs_inode *dp, int max_ents) -> void
  fn mxfs_dir_reconcile_stale_data_blocks(struct xfs_trans *tp, struct xfs_inode *dp) -> void
  fn mxfs_dir_postrmw_probe(struct xfs_inode *dp) -> void
  fn mxfs_dir_record_removed(struct xfs_inode *dp, xfs_ino_t ino) -> void
  fn mxfs_dir_was_removed(struct xfs_inode *dp, xfs_ino_t ino) -> bool
  fn mxfs_dir_remset_valid(struct xfs_inode *dp) -> bool
  fn mxfs_dir_name_incore_global(struct xfs_inode *dp, const char *name, int namelen, xfs_daddr_t skip_d) -> bool
  fn mxfs_dir_pending_add(struct xfs_inode *dp, const struct xfs_name *name, struct xfs_inode *cip) -> void
  fn mxfs_dir_pending_replay(struct xfs_trans *tp, struct xfs_inode *dp, xfs_extlen_t resblks) -> void
  fn mxfs_dir_should_force_block(struct xfs_inode *dp) -> bool
  fn mxfs_dlm_evict_inode_cb(void *data, uint64_t ino, uint32_t gen, uint32_t type) -> void
  fn mxfs_ag_meta_invalidate_stale(struct xfs_mount *mp, struct xfs_perag *pag, xfs_daddr_t d, int len) -> void
  fn mxfs_dir_bmbt_invalidate_stale(struct xfs_inode *dp, xfs_daddr_t d, int len) -> void
  fn mxfs_dir_gen_bump_on_convert(struct xfs_inode *dp, struct xfs_buf *dbp, struct xfs_buf *lbp) -> void
  fn mxfs_ag_meta_coldread_discard(struct xfs_perag *pag, bool fresh_peer) -> void
  fn mxfs_ag_buf_disk_differs(struct xfs_buf *bp) -> int
  fn mxfs_buf_has_uncheckpointed_mods(struct xfs_buf *bp) -> bool
  fn mxfs_buf_is_undestaged(struct xfs_buf *bp) -> bool
  fn mxfs_dir_buf_is_undestaged(struct xfs_buf *bp) -> bool
  fn mxfs_ag_buf_disk_bnobt(struct xfs_buf *bp, uint16_t *disk_nr, uint32_t *disk_s0, uint32_t *disk_l0) -> int
  fn mxfs_agi_disk_bucket_head(struct xfs_buf *agibp, int bucket) -> uint32_t
  fn mxfs_inode_disk_mode(struct xfs_inode *ip, uint32_t *nlink_out) -> int
  fn mxfs_inode_disk_unlinked(struct xfs_inode *ip, uint32_t *nlink_out, uint32_t *next_out) -> int
  fn mxfs_dlm_reset_inode_for_create(struct xfs_inode *ip) -> void
  fn mxfs_ag_dlm_lock(struct xfs_mount *mp, struct xfs_perag *pag) -> int
  fn mxfs_ag_dlm_trylock(struct xfs_mount *mp, struct xfs_perag *pag) -> int
  fn mxfs_ag_dlm_lock_bounded(struct xfs_mount *mp, struct xfs_perag *pag) -> int
  fn mxfs_ag_dlm_unlock(struct xfs_mount *mp, struct xfs_perag *pag) -> void
  fn xfs_mxfs_ag_pregrant(struct xfs_mount *mp, xfs_agnumber_t agno) -> int
  fn mxfs_ag_dlm_unlock_deferred(struct xfs_trans *tp, struct xfs_perag *pag) -> void
  fn mxfs_trans_drain_ag_unlocks(struct xfs_trans *tp) -> void
  fn mxfs_defer_agwait(struct xfs_trans *tp) -> int
  fn mxfs_trans_migrate_ag_unlocks(struct xfs_trans *tp, struct xfs_trans *ntp) -> void
  fn mxfs_sf_fmt_names(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *sfp, char *buf, size_t sz) -> void
  fn mxfs_trans_preacquire_inode_ags(struct xfs_trans *tp, struct xfs_inode **inodes, int num_inodes, struct xfs_inode **mand_inodes, int num_mand) -> int
  fn mxfs_inode_dlm_defer_bast(struct xfs_trans *tp, struct xfs_inode *ip) -> bool
  fn mxfs_trans_drain_inode_unlocks(struct xfs_trans *tp) -> void
  fn mxfs_buf_is_ag_metadata(struct xfs_buf *bp) -> bool
  fn mxfs_buf_xfsaild_skip_agmeta_write(struct xfs_buf *bp) -> bool
  fn mxfs_buf_xfsaild_skip_bmbt_write(struct xfs_buf *bp) -> bool
  fn mxfs_dir_bmbt_track(struct xfs_buf *bp) -> void
  fn mxfs_dir_data_track(struct xfs_buf *bp) -> void
  fn mxfs_buf_xfsaild_skip_dir_write(struct xfs_buf *bp, struct mxfs_dir_skip_info *info) -> bool
  fn mxfs_dir_zombie_push_retire(struct xfs_buf *bp) -> bool
  fn mxfs_dir_ail_push_defer(struct xfs_buf *bp) -> bool
  fn mxfs_bmbt_write_probe(struct xfs_buf *bp) -> void
  fn mxfs_buf_needs_fua_read(struct xfs_buf *bp) -> bool
  fn mxfs_fua_count(struct xfs_buf *bp) -> void
  fn mxfs_buf_ag_owned_ex(struct xfs_buf *bp) -> bool
  fn mxfs_replay_gate_mode(void) -> int
  fn mxfs_relgate_fault_slow(int stage, uint64_t res) -> int
  fn mxfs_relgate_fault_slow_forced(int stage, uint64_t res) -> bool
  fn mxfs_relgate_fault_slow_forced(stage, res) -> return
  fn mxfs_release_cert_emit(const struct mxfs_release_cert *rc) -> void
  fn mxfs_relcert_count_tripwire_retry(void) -> void
  fn mxfs_f4_registry_init(struct xfs_mount *mp) -> void
  fn mxfs_f4_registry_destroy(struct xfs_mount *mp) -> void
  fn mxfs_f4_commit(struct xfs_buf *bp, unsigned int bli_flags) -> void
  fn mxfs_f4_submit(struct xfs_buf *bp) -> void
  fn mxfs_f4_write_complete(struct xfs_buf *bp) -> void
  fn mxfs_f4_cancel(struct xfs_buf *bp, enum mxfs_f4_cancel_why why) -> void
  fn mxfs_f4_buf_free(struct xfs_buf *bp) -> void
  fn mxfs_icwr_registry_init(struct xfs_mount *mp) -> void
  fn mxfs_icwr_registry_destroy(struct xfs_mount *mp) -> void
  fn mxfs_icwr_submit(struct xfs_buf *bp) -> void
  fn mxfs_icwr_complete(struct xfs_buf *bp) -> void
  fn mxfs_icwr_buf_free(struct xfs_buf *bp) -> void
  fn mxfs_f4_open_for_dir(struct xfs_mount *mp, uint64_t dir_ino, int *unknown_out) -> long
  fn mxfs_ag_meta_track(struct xfs_buf *bp) -> void
  fn mxfs_dlm_ag_meta_iodone(struct xfs_buf *bp) -> void
  fn mxfs_ag_meta_reclaim_abort(struct xfs_buf *bp) -> void
  fn mxfs_note_fork_tear(struct xfs_inode *ip, const char *site) -> void
  fn mxfs_sfconv_disk_check(struct xfs_inode *ip) -> void
  fn mxfs_dir_sf_premerge_for_release(struct xfs_inode *ip) -> void
  fn mxfs_buf_in_fua_window(struct xfs_buf *bp) -> bool
  fn mxfs_dlm_ag_bast_notify(void *data, uint32_t agno, uint8_t mode) -> void
  fn mxfs_dlm_ag_bast_work_fn(struct work_struct *work) -> void
  fn mxfs_dlm_ag_release_work_fn(struct work_struct *work) -> void
  fn mxfs_buf_write_fua(struct xfs_buf *bp) -> int
  fn mxfs_dlm_ag_force_release_all(struct xfs_mount *mp) -> void
  fn mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev, uint64_t lba_512, void *buf, uint32_t len) -> int
    called_by: mxfs_iunl_discrim, mxfs_scsi_read16_fua
  fn mxfs_pal_scsi_write_fua_bdev(struct block_device *bdev, uint64_t lba_512, const void *buf, uint32_t len) -> int
  fn mxfs_pal_scsi_pr_unregister_bdev(struct block_device *bdev, uint64_t key) -> int
    called_by: mxfs_pal_scsi_pr_unregister
  fn mxfs_dbg_disk_di_mode(struct xfs_mount *mp, uint64_t ino, uint32_t *genp) -> uint16_t
  fn mxfs_dlm_claim_demoter(struct xfs_inode *ip) -> void
  fn mxfs_dlm_release_demoter(struct xfs_inode *ip) -> void
  fn mxfs_statfs_perag_sums(struct xfs_mount *mp, uint64_t *icount, uint64_t *ifree, uint64_t *fdblocks) -> bool
  fn mxfs_init_all_perag_data(struct xfs_mount *mp) -> void
  fn mxfs_lru_sweep_start(void) -> void
  fn mxfs_lru_sweep_stop(void) -> void
  fn mxfs_defer_reap_add_mode(struct xfs_mount *mp, uint64_t ino, uint32_t gen, int16_t bucket, uint8_t kind) -> void
    called_by: mxfs_defer_reap_add, mxfs_dlm_open_last_close
  fn mxfs_defer_reap_add(struct xfs_mount *mp, uint64_t ino, uint32_t gen, int16_t bucket) -> void
  fn mxfs_defer_reap_done(struct xfs_mount *mp, uint64_t ino) -> void
  fn mxfs_defer_reap_init(struct xfs_mount *mp) -> void
  fn mxfs_defer_reap_destroy(struct xfs_mount *mp) -> void
  fn mxfs_iclus_lock(struct xfs_mount *mp, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres) -> int
  fn mxfs_iclus_unlock(struct xfs_mount *mp, uint64_t ino, uint8_t mode, bool is_free) -> int
  fn mxfs_iclus_bast_notify(void *data, uint64_t base_ino, uint8_t req_mode) -> void
  fn mxfs_iclus_try_admit(struct xfs_mount *mp, uint64_t ino, uint8_t mode) -> bool
  fn mxfs_iclus_open_admit(struct xfs_mount *mp, uint64_t ino) -> bool
    called_by: mxfs_dlm_open_protect
  fn mxfs_dlm_iclus_covered(struct xfs_inode *ip) -> bool
    called_by: mxfs_dlm_open_protect
  fn mxfs_iclus_granted_mode(struct xfs_mount *mp, uint64_t ino) -> uint8_t
  fn mxfs_iclus_grant_seq(struct xfs_mount *mp, uint64_t ino) -> uint64_t
  fn mxfs_iclus_purge_all(struct xfs_mount *mp) -> void
  struct mxfs_dir_skip_info { owner, is_dir_buf, in_core, mode, tenure_id, cur_epoch, nl_released, tenure_mismatch, incarn_aba, reflush_skip }
  enum mxfs_relgate_class { MXFS_RELCLASS_AG, MXFS_RELCLASS_INODE, MXFS_RELCLASS_ICLUS, MXFS_RELCLASS_DIR }
  enum mxfs_relgate_fault_stage { MXFS_RGF_DEMOTING, entered, DEMOTING, admissions, not, yet, diverted, MXFS_RGF_QUIESCED, admissions, quiesced }
  enum mxfs_release_state { MXFS_RELSTATE_ACTIVE, tenure, live, no, release, in, progress, MXFS_RELSTATE_DEMOTING, release, requested }
  enum mxfs_relcert_defer { MXFS_RELDEFER_NONE, MXFS_RELDEFER_OBLIG, obligations, outstanding, MXFS_RELDEFER_IO, home, I, O, inflight, MXFS_RELDEFER_PINCIL }
  enum mxfs_ticket_status { MXFS_TICKET_NONE, MXFS_TICKET_REAL_FLUSH, flush_epoch, advanced, past, the, stamp, in, fua_disable, operator }
  struct mxfs_release_cert { res_id, rclass, handoff, cas_attempted, timeout, path, old_epoch, new_epoch, dirty_seq_quiesce, dirty_seq_flush }
  enum mxfs_f4_cancel_why { MXFS_F4_CANCEL_STALE, xfs_buf_item_finish_stale, committed, XFS_BLF_CANCEL, MXFS_F4_CANCEL_SHUTDOWN, abort, with, xlog_is_shutdown, terminal, nothing }

[xfs/xfs_platform.h]
  fn READ_ONCE(inode->i_state) -> return
  fn ERR_CAST(handle) -> return
  fn atomic_read(&inode->i_count) -> return
    called_by: inode_dio_probe_init, inode_dio_release_init, mxfs_ailstuck_probe_param_get, mxfs_dlm_open_last_close, mxfs_dlm_open_protect, mxfs_lru_sweep_fn, mxfs_pin_census_set, xfs_defer_drain_busy
  fn sysv_encode_dev(dev) -> return
  fn xfs_rw_bdev(struct block_device *bdev, sector_t sector, unsigned int count, char *data, enum req_op op) -> int
  fn vmalloc_to_page(addr) -> return
    called_by: kaddr_to_page
  fn virt_to_page(addr) -> return
    called_by: kaddr_to_page
  struct iomap_write_ops
  struct xfs_kobj { kobject, complete }
  struct xstats { xs_stats, xs_kobj }

[xfs/xfs_pnfs.h]
  fn xfs_fs_get_uuid(struct super_block *sb, u8 *buf, u32 *len, u64 *offset) -> int
  fn xfs_fs_map_blocks(struct inode *inode, loff_t offset, u64 length, struct iomap *iomap, bool write, u32 *device_generation) -> int
  fn xfs_fs_commit_blocks(struct inode *inode, struct iomap *maps, int nr_maps, struct iattr *iattr) -> int
  fn xfs_break_leased_layouts(struct inode *inode, uint *iolock, bool *did_unlock) -> int

[xfs/xfs_pwork.h]
  fn xfs_pwork_ctl_want_abort(pwork->pctl) -> return
  fn xfs_pwork_init(struct xfs_mount *mp, struct xfs_pwork_ctl *pctl, xfs_pwork_work_fn work_fn, const char *tag) -> int
  fn xfs_pwork_queue(struct xfs_pwork_ctl *pctl, struct xfs_pwork *pwork) -> void
  fn xfs_pwork_destroy(struct xfs_pwork_ctl *pctl) -> int
  fn xfs_pwork_poll(struct xfs_pwork_ctl *pctl) -> void
  typedef_fn xfs_pwork_work_fn
  struct xfs_pwork_ctl { wq, mp, work_fn, poll_wait, nr_work, error }
  struct xfs_pwork { work, pctl }

[xfs/xfs_qm.c]
  struct xfs_qm_isolate { buffers, dispose }

[xfs/xfs_qm.h]
  fn xfs_trans_mod_dquot(struct xfs_trans *tp, struct xfs_dquot *dqp, uint field, int64_t delta) -> void
  fn xfs_trans_dqjoin(struct xfs_trans *, struct xfs_dquot *) -> void
  fn xfs_trans_log_dquot(struct xfs_trans *, struct xfs_dquot *) -> void
  fn xfs_qm_destroy_quotainfo(struct xfs_mount *) -> void
  fn xfs_qm_scall_trunc_qfiles(struct xfs_mount *, uint) -> int
  fn xfs_qm_scall_getquota(struct xfs_mount *mp, xfs_dqid_t id, xfs_dqtype_t type, struct qc_dqblk *dst) -> int
  fn xfs_qm_scall_getquota_next(struct xfs_mount *mp, xfs_dqid_t *id, xfs_dqtype_t type, struct qc_dqblk *dst) -> int
  fn xfs_qm_scall_setqlim(struct xfs_mount *mp, xfs_dqid_t id, xfs_dqtype_t type, struct qc_dqblk *newlim) -> int
  fn xfs_qm_scall_quotaon(struct xfs_mount *, uint) -> int
  fn xfs_qm_scall_quotaoff(struct xfs_mount *, uint) -> int
  fn xfs_qm_qino_load(struct xfs_mount *mp, xfs_dqtype_t type, struct xfs_inode **ipp) -> int
  struct xfs_quota_limits { hard, soft, time }
  struct xfs_def_quota { blk, ino, rtb }
  struct xfs_quotainfo { qi_uquota_tree, qi_gquota_tree, qi_pquota_tree, qi_tree_lock, qi_uquotaip, qi_gquotaip, qi_pquotaip, qi_dirip, qi_lru, qi_dquots }
  struct xfs_mod_ino_dqtrx_params { tx_id, ino, q_type, q_id, delta }
  struct xfs_dquot_acct

[xfs/xfs_quota.h]
  fn xfs_trans_dup_dqinfo(struct xfs_trans *, struct xfs_trans *) -> void
  fn xfs_trans_free_dqinfo(struct xfs_trans *) -> void
  fn xfs_trans_mod_dquot_byino(struct xfs_trans *, struct xfs_inode *, uint, int64_t) -> void
  fn xfs_trans_apply_dquot_deltas(struct xfs_trans *) -> void
  fn xfs_trans_unreserve_and_mod_dquots(struct xfs_trans *tp, bool already_locked) -> void
  fn xfs_trans_reserve_quota_nblks(struct xfs_trans *tp, struct xfs_inode *ip, int64_t dblocks, int64_t rblocks, bool force) -> int
  fn xfs_trans_reserve_quota_bydquots(struct xfs_trans *, struct xfs_mount *, struct xfs_dquot *, struct xfs_dquot *, struct xfs_dquot *, int64_t, long, uint) -> int
  fn xfs_trans_reserve_quota_icreate(struct xfs_trans *tp, struct xfs_dquot *udqp, struct xfs_dquot *gdqp, struct xfs_dquot *pdqp, int64_t dblocks) -> int
  fn xfs_qm_vop_dqalloc(struct xfs_inode *, kuid_t, kgid_t, prid_t, uint, struct xfs_dquot **, struct xfs_dquot **, struct xfs_dquot **) -> int
  fn xfs_qm_vop_create_dqattach(struct xfs_trans *, struct xfs_inode *, struct xfs_dquot *, struct xfs_dquot *, struct xfs_dquot *) -> void
  fn xfs_qm_vop_rename_dqattach(struct xfs_inode **) -> int
  fn xfs_qm_vop_chown(struct xfs_trans *, struct xfs_inode *, struct xfs_dquot **, struct xfs_dquot *) -> struct xfs_dquot
  fn xfs_qm_dqattach(struct xfs_inode *) -> int
  fn xfs_qm_dqattach_locked(struct xfs_inode *ip, bool doalloc) -> int
  fn xfs_qm_dqdetach(struct xfs_inode *) -> void
  fn xfs_qm_dqrele(struct xfs_dquot *) -> void
  fn xfs_qm_statvfs(struct xfs_inode *, struct kstatfs *) -> void
  fn xfs_qm_newmount(struct xfs_mount *, uint *, uint *) -> int
  fn xfs_qm_resume_quotaon(struct xfs_mount *mp) -> void
  fn xfs_qm_mount_quotas(struct xfs_mount *) -> void
  fn xfs_qm_unmount(struct xfs_mount *) -> void
  fn xfs_qm_unmount_quotas(struct xfs_mount *) -> void
  fn xfs_inode_near_dquot_enforcement(struct xfs_inode *ip, xfs_dqtype_t type) -> bool
  fn xfs_quota_reserve_blkres(struct xfs_inode *ip, int64_t blocks) -> int
  fn xfs_trans_mod_ino_dquot(struct xfs_trans *tp, struct xfs_inode *ip, struct xfs_dquot *dqp, unsigned int field, int64_t delta) -> void
  fn xfs_dqtrx_hook_disable(void) -> void
  fn xfs_dqtrx_hook_enable(void) -> void
  fn xfs_dqtrx_hook_add(struct xfs_quotainfo *qi, struct xfs_dqtrx_hook *hook) -> int
  fn xfs_dqtrx_hook_del(struct xfs_quotainfo *qi, struct xfs_dqtrx_hook *hook) -> void
  fn xfs_dqtrx_hook_setup(struct xfs_dqtrx_hook *hook, notifier_fn_t mod_fn, notifier_fn_t apply_fn) -> void
  fn xfs_mount_reset_sbqflags(struct xfs_mount *) -> int
  struct xfs_dqtrx { qt_dquot, qt_blk_res, qt_bcount_delta, qt_delbcnt_delta, qt_rtblk_res, qt_rtblk_res_used, qt_rtbcount_delta, qt_delrtb_delta, qt_ino_res, qt_ino_res_used }
  enum xfs_apply_dqtrx_type { XFS_APPLY_DQTRX_COMMIT, XFS_APPLY_DQTRX_UNRESERVE }
  struct xfs_apply_dqtrx_params { tx_id, ino, q_type, q_id }
  struct xfs_dqtrx_hook { mod_hook, apply_hook }

[xfs/xfs_refcount_item.c]
  fn static CUI_ITEM(struct xfs_log_item *lip) -> struct xfs_cui_log_item
  fn xfs_cui_log_space(unsigned int nr) -> unsigned int
  fn static CUD_ITEM(struct xfs_log_item *lip) -> struct xfs_cud_log_item
  fn xfs_cud_log_space(void) -> unsigned int
  fn static ci_entry(const struct list_head *e) -> struct xfs_refcount_intent

[xfs/xfs_refcount_item.h]
  fn xfs_refcount_defer_add(struct xfs_trans *tp, struct xfs_refcount_intent *ri) -> void
  fn xfs_cui_log_space(unsigned int nr) -> unsigned int
  fn xfs_cud_log_space(void) -> unsigned int
  struct xfs_cui_log_item { cui_item, cui_refcount, cui_next_extent, cui_format }
  struct xfs_cud_log_item { cud_item, cud_cuip, cud_format }

[xfs/xfs_reflink.h]
  fn xfs_reflink_trim_around_shared(struct xfs_inode *ip, struct xfs_bmbt_irec *irec, bool *shared) -> int
  fn xfs_bmap_trim_cow(struct xfs_inode *ip, struct xfs_bmbt_irec *imap, bool *shared) -> int
  fn xfs_reflink_allocate_cow(struct xfs_inode *ip, struct xfs_bmbt_irec *imap, struct xfs_bmbt_irec *cmap, bool *shared, uint *lockmode, bool convert_now) -> int
  fn xfs_reflink_convert_cow(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t count) -> int
  fn xfs_reflink_convert_cow_locked(struct xfs_inode *ip, xfs_fileoff_t offset_fsb, xfs_filblks_t count_fsb) -> int
  fn xfs_reflink_cancel_cow_blocks(struct xfs_inode *ip, struct xfs_trans **tpp, xfs_fileoff_t offset_fsb, xfs_fileoff_t end_fsb, bool cancel_real) -> int
  fn xfs_reflink_cancel_cow_range(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t count, bool cancel_real) -> int
  fn xfs_reflink_end_cow(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t count) -> int
  fn xfs_reflink_end_atomic_cow(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t count) -> int
  fn xfs_reflink_recover_cow(struct xfs_mount *mp) -> int
  fn xfs_reflink_remap_range(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out, loff_t len, unsigned int remap_flags) -> loff_t
  fn xfs_reflink_inode_has_shared_extents(struct xfs_trans *tp, struct xfs_inode *ip, bool *has_shared) -> int
  fn xfs_reflink_clear_inode_flag(struct xfs_inode *ip, struct xfs_trans **tpp) -> int
  fn xfs_reflink_unshare(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t len) -> int
  fn xfs_reflink_remap_prep(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out, loff_t *len, unsigned int remap_flags) -> int
  fn xfs_reflink_remap_blocks(struct xfs_inode *src, loff_t pos_in, struct xfs_inode *dest, loff_t pos_out, loff_t remap_len, loff_t *remapped) -> int
  fn xfs_reflink_update_dest(struct xfs_inode *dest, xfs_off_t newlen, xfs_extlen_t cowextsize, unsigned int remap_flags) -> int
  fn xfs_reflink_supports_rextsize(struct xfs_mount *mp, unsigned int rextsize) -> bool
  fn xfs_reflink_max_atomic_cow(struct xfs_mount *mp) -> xfs_extlen_t

[xfs/xfs_rmap_item.c]
  fn static RUI_ITEM(struct xfs_log_item *lip) -> struct xfs_rui_log_item
  fn xfs_rui_log_space(unsigned int nr) -> unsigned int
  fn static RUD_ITEM(struct xfs_log_item *lip) -> struct xfs_rud_log_item
  fn xfs_rud_log_space(void) -> unsigned int
  fn static ri_entry(const struct list_head *e) -> struct xfs_rmap_intent

[xfs/xfs_rmap_item.h]
  fn xfs_rmap_defer_add(struct xfs_trans *tp, struct xfs_rmap_intent *ri) -> void
  fn xfs_rui_log_space(unsigned int nr) -> unsigned int
  fn xfs_rud_log_space(void) -> unsigned int
  struct xfs_rui_log_item { rui_item, rui_refcount, rui_next_extent, rui_format }
  struct xfs_rud_log_item { rud_item, rud_ruip, rud_format }

[xfs/xfs_rtalloc.h]
  fn xfs_rtmount_readsb(struct xfs_mount *mp) -> int
  fn xfs_rtmount_freesb(struct xfs_mount *mp) -> void
  fn xfs_rtalloc_reinit_frextents(struct xfs_mount *mp) -> int
  fn xfs_growfs_check_rtgeom(const struct xfs_mount *mp, xfs_rfsblock_t dblocks, xfs_rfsblock_t rblocks, xfs_agblock_t rextsize) -> int
  fn xfs_rtallocate_rtgs(struct xfs_trans *tp, xfs_fsblock_t bno_hint, xfs_rtxlen_t minlen, xfs_rtxlen_t maxlen, xfs_rtxlen_t prod, bool wasdel, bool initial_user_data, xfs_rtblock_t *bno, xfs_extlen_t *blen) -> int

[xfs/xfs_stats.h]
  fn xfs_stats_format(struct xfsstats __percpu *stats, char *buf) -> int
  fn xfs_stats_clearall(struct xfsstats __percpu *stats) -> void
  fn xfs_init_procfs(void) -> int
  fn xfs_cleanup_procfs(void) -> void
  struct __xfsstats { xs_allocx, xs_allocb, xs_freex, xs_freeb, xs_abt_lookup, xs_abt_compare, xs_abt_insrec, xs_abt_delrec, xs_blk_mapr, xs_blk_mapw }
  struct xfsstats { s }

[xfs/xfs_stubs.c]
  fn xfs_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg) -> long
    calls: xfs_fs_goingdown
  fn xfs_break_leased_layouts(struct inode *inode, uint *iolock, bool *retry) -> int
  fn bio_add_folio_nofail(struct bio *bio, struct folio *folio, size_t len, size_t off) -> void

[xfs/xfs_super.h]
  fn xfs_qm_init(void) -> int
  fn xfs_qm_exit(void) -> void
  fn xfs_flush_inodes(struct xfs_mount *mp) -> void
  fn xfs_set_inode_alloc(struct xfs_mount *, xfs_agnumber_t agcount) -> xfs_agnumber_t
  fn xfs_reinit_percpu_counters(struct xfs_mount *mp) -> void
  fn xfs_debugfs_mkdir(const char *name, struct dentry *parent) -> struct dentry

[xfs/xfs_symlink.h]
  fn xfs_symlink(struct mnt_idmap *idmap, struct xfs_inode *dp, struct xfs_name *link_name, const char *target_path, umode_t mode, struct xfs_inode **ipp) -> int
  fn xfs_readlink(struct xfs_inode *ip, char *link) -> int
  fn xfs_inactive_symlink(struct xfs_inode *ip) -> int

[xfs/xfs_sysctl.h]
  fn xfs_sysctl_register(void) -> int
  fn xfs_sysctl_unregister(void) -> void
  struct xfs_sysctl_val { min, val, max }
  struct xfs_param { panic_mask, error_level, syncd_timer, stats_clear, inherit_sync, inherit_nodump, inherit_noatim, inherit_nosym, rotorstep, inherit_nodfrg }
  struct xfs_globals { pwork_threads, larp, bload_leaf_slack, bload_node_slack, log_recovery_delay, mount_delay, bug_on_assert, always_cow }

[xfs/xfs_sysfs.h]
  fn container_of(kobject, struct xfs_kobj, kobject) -> return
    called_by: ATTRD_ITEM, ATTRI_ITEM, BUF_ITEM, DQUOT_ITEM, INODE_ITEM, IUL_ITEM, mxfs_defer_work_fn, mxfs_reap_worker, zoned_to_mp
  fn xfs_mount_sysfs_init(struct xfs_mount *mp) -> int
  fn xfs_mount_sysfs_del(struct xfs_mount *mp) -> void

[xfs/xfs_trans.h]
  fn xfs_log_item_init(struct xfs_mount *mp, struct xfs_log_item *item, int type, const struct xfs_item_ops *ops) -> void
  fn xfs_trans_alloc(struct xfs_mount *mp, struct xfs_trans_res *resp, uint blocks, uint rtextents, uint flags, struct xfs_trans **tpp) -> int
  fn xfs_trans_reserve_more(struct xfs_trans *tp, unsigned int blocks, unsigned int rtextents) -> int
  fn xfs_trans_alloc_empty(struct xfs_mount *mp) -> struct xfs_trans
  fn xfs_trans_mod_sb(xfs_trans_t *, uint, int64_t) -> void
  fn xfs_trans_get_buf_map(struct xfs_trans *tp, struct xfs_buftarg *target, struct xfs_buf_map *map, int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp) -> int
  fn xfs_trans_get_buf_map(tp, target, &map, 1, flags, bpp) -> return
  fn xfs_trans_read_buf_map(struct xfs_mount *mp, struct xfs_trans *tp, struct xfs_buftarg *target, struct xfs_buf_map *map, int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp, const struct xfs_buf_ops *ops) -> int
  fn xfs_trans_read_buf_map(mp, tp, target, &map, 1, flags, bpp, ops) -> return
  fn xfs_trans_getsb(struct xfs_trans *) -> struct xfs_buf
  fn xfs_trans_getrtsb(struct xfs_trans *tp) -> struct xfs_buf
  fn xfs_trans_brelse(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_bjoin(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_bdetach(struct xfs_trans *tp, struct xfs_buf *bp) -> void
  fn xfs_trans_bhold(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_bhold_release(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_binval(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_inode_buf(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_stale_inode_buf(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_ordered_buf(xfs_trans_t *, struct xfs_buf *) -> bool
  fn xfs_trans_dquot_buf(xfs_trans_t *, struct xfs_buf *, uint) -> void
  fn xfs_trans_inode_alloc_buf(xfs_trans_t *, struct xfs_buf *) -> void
  fn xfs_trans_ijoin(struct xfs_trans *, struct xfs_inode *, uint) -> void
  fn xfs_trans_log_buf(struct xfs_trans *, struct xfs_buf *, uint, uint) -> void
  fn xfs_trans_dirty_buf(struct xfs_trans *, struct xfs_buf *) -> void
  fn xfs_trans_buf_is_dirty(struct xfs_buf *bp) -> bool
  fn xfs_trans_log_inode(xfs_trans_t *, struct xfs_inode *, uint) -> void
  fn xfs_trans_commit(struct xfs_trans *) -> int
  fn xfs_trans_roll(struct xfs_trans **) -> int
  fn xfs_trans_roll_inode(struct xfs_trans **, struct xfs_inode *) -> int
    called_by: xreap_want_defer_finish
  fn xfs_trans_cancel(xfs_trans_t *) -> void
  fn xfs_trans_ail_init(struct xfs_mount *) -> int
  fn xfs_trans_ail_destroy(struct xfs_mount *) -> void
  fn xfs_trans_buf_set_type(struct xfs_trans *, struct xfs_buf *, enum xfs_blft) -> void
  fn xfs_trans_buf_copy_type(struct xfs_buf *dst_bp, struct xfs_buf *src_bp) -> void
  fn xfs_trans_alloc_inode(struct xfs_inode *ip, struct xfs_trans_res *resv, unsigned int dblocks, unsigned int rblocks, bool force, struct xfs_trans **tpp) -> int
  fn xfs_trans_reserve_more_inode(struct xfs_trans *tp, struct xfs_inode *ip, unsigned int dblocks, unsigned int rblocks, bool force_quota) -> int
  fn xfs_trans_alloc_icreate(struct xfs_mount *mp, struct xfs_trans_res *resv, struct xfs_dquot *udqp, struct xfs_dquot *gdqp, struct xfs_dquot *pdqp, unsigned int dblocks, struct xfs_trans **tpp) -> int
  fn xfs_trans_alloc_ichange(struct xfs_inode *ip, struct xfs_dquot *udqp, struct xfs_dquot *gdqp, struct xfs_dquot *pdqp, bool force, struct xfs_trans **tpp) -> int
  fn xfs_trans_alloc_dir(struct xfs_inode *dp, struct xfs_trans_res *resv, struct xfs_inode *ip, unsigned int *dblocks, struct xfs_trans **tpp, int *nospace_error) -> int
  struct xfs_log_item { li_ail, li_trans, li_lsn, li_log, li_ailp, li_type, li_flags, li_buf, li_bio_list, li_ops }
  struct xfs_item_ops { flags }
  struct xfs_trans { t_log_res, t_log_count, t_blk_res, t_blk_res_used, t_rtx_res, t_rtx_res_used, t_flags, t_highest_agno, t_mxfs_wouldblock_agno, t_mxfs_ag_restart_ok }

[xfs/xfs_trans_priv.h]
  fn xfs_trans_init(struct xfs_mount *) -> void
  fn xfs_trans_add_item(struct xfs_trans *, struct xfs_log_item *) -> void
  fn xfs_trans_del_item(struct xfs_log_item *) -> void
  fn xfs_trans_unreserve_and_mod_sb(struct xfs_trans *tp) -> void
  fn list_first_entry_or_null(&ailp->ail_head, struct xfs_log_item, li_ail) -> return
  fn xfs_trans_ail_insert(struct xfs_ail *ailp, struct xfs_log_item *lip, xfs_lsn_t lsn) -> void
  fn xfs_ail_delete_one(struct xfs_ail *ailp, struct xfs_log_item *lip) -> xfs_lsn_t
  fn xfs_trans_ail_delete(struct xfs_log_item *lip, int shutdown_type) -> void
  fn READ_ONCE(ailp->ail_target) -> return
  fn xfs_ail_push_all_sync(struct xfs_ail *ailp) -> void
  fn xfs_ail_push_all_sync_bounded(struct xfs_ail *ailp, unsigned int max_ms) -> void
  fn xfs_ail_push_upto_sync_bounded(struct xfs_ail *ailp, unsigned int max_ms, xfs_lsn_t *out_target) -> bool
  fn xfs_ail_max_lsn(struct xfs_ail *ailp) -> xfs_lsn_t
  fn xfs_ail_push_ag_sync(struct xfs_ail *ailp, xfs_agnumber_t agno) -> void
  fn xfs_ail_push_ag_sync_bounded(struct xfs_ail *ailp, xfs_agnumber_t agno, unsigned int stall_iters, unsigned int min_iters) -> int
  fn xfs_ail_min_lsn(struct xfs_ail *ailp) -> xfs_lsn_t
  fn xfs_trans_ail_cursor_first(struct xfs_ail *ailp, struct xfs_ail_cursor *cur, xfs_lsn_t lsn) -> struct xfs_log_item *
  fn xfs_trans_ail_cursor_last(struct xfs_ail *ailp, struct xfs_ail_cursor *cur, xfs_lsn_t lsn) -> struct xfs_log_item *
  fn xfs_trans_ail_cursor_next(struct xfs_ail *ailp, struct xfs_ail_cursor *cur) -> struct xfs_log_item *
  fn xfs_trans_ail_cursor_done(struct xfs_ail_cursor *cur) -> void
  fn __xfs_ail_assign_tail_lsn(struct xfs_ail *ailp) -> void
  struct xfs_ail_cursor { list, item }
  struct xfs_ail { ail_log, ail_task, ail_head, ail_cursors, ail_lock, ail_last_pushed_lsn, ail_head_lsn, ail_log_flush, ail_opstate, ail_buf_list }

[xfs/xfs_verify_media.h]
  fn xfs_ioc_verify_media(struct file *file, struct xfs_verify_media __user *arg) -> int

[xfs/xfs_xattr.h]
  fn xfs_attr_change(struct xfs_da_args *args, enum xfs_attr_update op) -> int

[xfs/xfs_zone_alloc.c]
  fn static xfs_inode_write_hint(struct xfs_inode *ip) -> enum rw_hint
  fn static xfs_zoned_pack_tight(struct xfs_inode *ip) -> bool
  enum xfs_zone_alloc_score { Any, open, zone, will, do, it, we, re, desperate, XFS_ZONE_ALLOC_ANY }
  struct xfs_init_zones { zone_size, zone_capacity, available, reclaimable }

[xfs/xfs_zone_alloc.h]
  fn xfs_zoned_space_reserve(struct xfs_mount *mp, xfs_filblks_t count_fsb, unsigned int flags, struct xfs_zone_alloc_ctx *ac) -> int
  fn xfs_zoned_space_unreserve(struct xfs_mount *mp, struct xfs_zone_alloc_ctx *ac) -> void
  fn xfs_zoned_add_available(struct xfs_mount *mp, xfs_filblks_t count_fsb) -> void
  fn xfs_zone_alloc_and_submit(struct iomap_ioend *ioend, struct xfs_open_zone **oz) -> void
  fn xfs_zone_free_blocks(struct xfs_trans *tp, struct xfs_rtgroup *rtg, xfs_fsblock_t fsbno, xfs_filblks_t len) -> int
  fn xfs_zoned_end_io(struct xfs_inode *ip, xfs_off_t offset, xfs_off_t count, xfs_daddr_t daddr, struct xfs_open_zone *oz, xfs_fsblock_t old_startblock) -> int
  fn xfs_open_zone_put(struct xfs_open_zone *oz) -> void
  fn xfs_zoned_wake_all(struct xfs_mount *mp) -> void
  fn xfs_zone_rgbno_is_valid(struct xfs_rtgroup *rtg, xfs_rgnumber_t rgbno) -> bool
  fn xfs_mark_rtg_boundary(struct iomap_ioend *ioend) -> void
  fn xfs_zoned_default_resblks(struct xfs_mount *mp, enum xfs_free_counter ctr) -> uint64_t
  fn xfs_zoned_show_stats(struct seq_file *m, struct xfs_mount *mp) -> void
  fn xfs_mount_zones(struct xfs_mount *mp) -> int
  fn xfs_unmount_zones(struct xfs_mount *mp) -> void
  fn xfs_zone_gc_start(struct xfs_mount *mp) -> void
  fn xfs_zone_gc_stop(struct xfs_mount *mp) -> void
  struct xfs_zone_alloc_ctx { open_zone, reserved_blocks }

[xfs/xfs_zone_gc.c]
  fn static xfs_bio_wait_endio(struct bio *bio) -> void
  struct xfs_gc_bio { data, entry, ip, offset, len, old_startblock, new_daddr, scratch, is_seq, oz }
  struct xfs_zone_gc_iter { victim_rtg, rec_count, rec_idx, next_startblock, recs }
  struct xfs_zone_gc_data { mp, bio_set, scratch_folios, scratch_size, scratch_available, scratch_head, scratch_tail, reading, writing, resetting }

[xfs/xfs_zone_priv.h]
  fn xfs_open_zone(struct xfs_mount *mp, enum rw_hint write_hint, bool is_gc) -> struct xfs_open_zone
  fn xfs_zone_gc_reset_sync(struct xfs_rtgroup *rtg) -> int
  fn xfs_zoned_need_gc(struct xfs_mount *mp) -> bool
  fn xfs_zoned_have_reclaimable(struct xfs_zone_info *zi) -> bool
  fn xfs_zone_gc_mount(struct xfs_mount *mp) -> int
  fn xfs_zone_gc_unmount(struct xfs_mount *mp) -> void
  fn xfs_zoned_resv_wake_all(struct xfs_mount *mp) -> void
  struct xfs_open_zone { oz_entry, oz_ref, oz_alloc_lock, oz_allocated, oz_written, oz_write_hint, oz_is_gc, oz_rtg, oz_rcu }
  struct xfs_zone_info { zi_reservation_lock, zi_reclaim_reservations, zi_open_zones_lock, zi_open_zones, zi_nr_open_zones, zi_nr_free_zones, zi_zone_wait, zi_gc_thread, zi_open_gc_zone, zi_reset_list_lock }

[xfs/xfs_zone_space_resv.c]
  struct xfs_zone_reservation { entry, task, count_fsb }

```

## Cross-File Dependency Summary

```
dlm/discovery.c -> dlm/discovery.h, dlm/net2_wire.h, pal/linux/user.c
dlm/disklock.c -> dlm/disklock.h, dlm/dlm_shared.c, dlm/journal.c, pal/linux/user.c, scripts/loop_unwedge/kcore_walk.py, scripts/xref_owners.py, tests/fence_inflight/verdict.py, xfs/xfs_mxfs_dlm.h
dlm/dlm.c -> dlm/disklock.c, dlm/dlm.h, dlm/dlm_shared.c, dlm/net2_lock.c, dlm/v5_mount.c, pal/linux/kern.c, pal/linux/user.c, pal/pal.h, tests/fence_inflight/verdict.py, tools/caw_slotdump.c
dlm/dlm_caw.c -> dlm/dlm_caw.h, dlm/dlm_shared.c, dlm/journal.c, pal/linux/user.c, scripts/caw_slot_sampler.py, scripts/ccloop_request_audit.py, scripts/loop_unwedge/kcore_walk.py, scripts/scst_mon.py, tools/resize_mxfs.c
dlm/journal.c -> dlm/journal.h, pal/linux/user.c
dlm/lease.c -> dlm/lease.h, dlm/net2_wire.h, pal/linux/user.c, tests/mxfs_stackprof.py
dlm/mount.c -> dlm/discovery.h, dlm/disklock.h, dlm/dlm.h, dlm/dlm_caw.h, dlm/journal.h, dlm/lease.h, dlm/net2_wire.h, dlm/peer.h, dlm/scsipr.h, pal/linux/kern.c, pal/linux/user.c, scripts/mxfs_dirdump.py, scripts/scst_mon.py, tests/fence_inflight/verdict.py
dlm/net2.c -> dlm/net2_fault.c, dlm/net2_link.c, dlm/net2_midcomms.c, dlm/net2_overlay.c, pal/linux/user.c
dlm/net2_epoch.c -> dlm/net2.c, pal/linux/user.c
dlm/net2_link.c -> dlm/net2_ctx.h, dlm/net2_midcomms.c, pal/linux/user.c
dlm/net2_lock.c -> dlm/dlm_shared.c, dlm/net2_shard.c, pal/linux/user.c
dlm/net2_membership.c -> dlm/net2_epoch.c, pal/linux/user.c
dlm/net2_midcomms.c -> dlm/net2_ctx.h, dlm/net2_link.c, pal/linux/user.c, scripts/scst_mon.py, tests/fence_inflight/verdict.py
dlm/net2_overlay.c -> pal/linux/user.c
dlm/net2_shard.c -> dlm/net2.c, dlm/net2_lock.c, pal/linux/user.c
dlm/peer.c -> dlm/peer.h, pal/linux/user.c, tests/fence_inflight/verdict.py
dlm/scsipr.c -> dlm/scsipr.h, pal/linux/user.c
dlm/v5_mount.c -> dlm/discovery.h, dlm/disklock.h, dlm/dlm.h, dlm/dlm_caw.h, dlm/journal.h, dlm/lease.h, dlm/peer.h, dlm/scsipr.h, pal/linux/kern.c, pal/linux/user.c, scripts/ccloop_request_audit.py, scripts/loop_unwedge/kcore_walk.py, scripts/scst_mon.py, scripts/xref_owners.py
mxfs_clayer/invalidate.c -> xfs/xfs_buf.h, xfs/xfs_log.h
pal/linux/kern.c -> pal/linux/user.c, pal/pal.h, scripts/loop_unwedge/kcore_walk.py, tools/resize_mxfs.c, xfs/libxfs/xfs_ag.h, xfs/libxfs/xfs_cksum.h, xfs/libxfs/xfs_dir2_priv.h, xfs/xfs_mxfs_dlm.h, xfs/xfs_platform.h
pal/linux/user.c -> scripts/loop_unwedge/kcore_walk.py, scripts/vm_console_type.py
pal/linux/xfs_aops.c -> xfs/xfs_buf.h
pal/linux/xfs_buf_item.c -> xfs/libxfs/xfs_ag.h
pal/linux/xfs_drain.c -> xfs/xfs_buf.h
pal/linux/xfs_export.c -> xfs/xfs_export.h
pal/linux/xfs_super.c -> tools/resize_mxfs.c
pal/linux/xfs_sysfs.c -> xfs/libxfs/xfs_ag.h
scripts/inode_dio_probe/inode_dio_probe.c -> tools/resize_mxfs.c, xfs/xfs_buf.h
scripts/inode_dio_release/inode_dio_release.c -> tools/resize_mxfs.c, xfs/xfs_buf.h
scripts/loop_unwedge/loop_unwedge.c -> tools/resize_mxfs.c
scripts/scst_unwedge/scst_unwedge.c -> tools/resize_mxfs.c
tests/fence_inflight/prprobe.c -> tools/resize_mxfs.c
tests/net2/harness/net2_harness.c -> dlm/net2_fault.c, tools/recov_forge.c
tests/net2/harness/scen_mepoch.c -> dlm/net2.c, dlm/net2_epoch.c, dlm/net2_membership.c, pal/linux/user.c, tests/net2/harness/harness.h
tests/net2/harness/scen_midcomms.c -> dlm/net2.c, dlm/net2_fault.c, pal/linux/user.c, tests/net2/harness/harness.h
tests/net2/harness/scen_shard.c -> dlm/net2.c, dlm/net2_lock.c, dlm/net2_shard.c, pal/linux/user.c, tests/net2/harness/harness.h
tests/net2/harness/vcluster.c -> dlm/net2.c, pal/linux/user.c, tests/net2/harness/harness.h
tests/scst_pr_fullstatus_bounds.c -> scripts/loop_unwedge/kcore_walk.py
tests/suite/tools/fsx.c -> xfs/libxfs/xfs_rtbitmap.h
tools/caw_verify.c -> tools/fua_verify.c, tools/recov_forge.c
tools/chk_mxfs.c -> scripts/ccloop_quota_probe.py, tests/sf_storm_ledger.py, tools/recov_forge.c, tools/resize_mxfs.c, xfs/libxfs/xfs_cksum.h, xfs/xfs_mxfs_dlm.h
tools/mkfs_mxfs.c -> tools/recov_forge.c, tools/resize_mxfs.c, xfs/libxfs/xfs_cksum.h
tools/mxfs_bench.c -> scripts/loop_unwedge/kcore_walk.py, tools/mxfs_lock.c
tools/mxfs_lock.c -> tools/recov_forge.c
tools/recov_forge.c -> xfs/libxfs/xfs_cksum.h
tools/resize_mxfs.c -> tests/fence_inflight/verdict.py, tools/recov_forge.c, xfs/libxfs/xfs_cksum.h
xfs/libxfs/xfs_attr.c -> xfs/libxfs/xfs_attr_remote.h, xfs/libxfs/xfs_da_btree.h, xfs/libxfs/xfs_inode_fork.h
xfs/scrub/reap.c -> xfs/libxfs/xfs_defer.h, xfs/scrub/repair.h, xfs/xfs_trans.h
xfs/xfs_attr_item.c -> xfs/libxfs/xfs_ag.h
xfs/xfs_dquot_item.c -> xfs/libxfs/xfs_ag.h
xfs/xfs_inode_item.c -> xfs/libxfs/xfs_ag.h
xfs/xfs_iunlink_item.c -> xfs/libxfs/xfs_ag.h
xfs/xfs_mxfs_dlm.c -> dlm/dlm.c, dlm/v5_mount.c, pal/linux/kern.c, pal/linux/user.c, pal/pal.h, tools/resize_mxfs.c, xfs/libxfs/xfs_ag.h, xfs/libxfs/xfs_inode_buf.h, xfs/libxfs/xfs_inode_fork.h, xfs/scrub/iscan.h, xfs/xfs_buf.h, xfs/xfs_icache.h, xfs/xfs_inode.h, xfs/xfs_mxfs_dlm.h
xfs/xfs_stubs.c -> xfs/xfs_fsops.h
```
