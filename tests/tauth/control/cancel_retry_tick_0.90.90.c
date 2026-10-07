static void dlm_cancel_retry_tick(struct mxfs_dlm_ctx *ctx, uint64_t now)
{
	struct mxfs_dlm_pending_cancel *resend[16];
	struct mxfs_dlm_pending_cancel **pp;
	int n = 0, i;

	if (!ctx->cancel_pending)
		return;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	pp = &ctx->cancel_pending;
	while (*pp && n < 16) {
		struct mxfs_dlm_pending_cancel *pc = *pp;

		if (now - pc->sent_ms < MXFS_DLM_RELEASE_RETRY_MS) {
			pp = &pc->next;
			continue;
		}
		if (pc->sends >= MXFS_DLM_RELEASE_MAX_SENDS) {
			*pp = pc->next;
			ctx->cancel_unacked++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P958-ACQ-CANCEL-UNACKED acq=%llu type=%u ino=%llu ag=%u sends=%d total=%llu — the master never acknowledged this abandonment; whatever it holds for the wait stays until a re-request or the recovery purge",
				     (unsigned long long)pc->acq_seq, pc->resource.type,
				     (unsigned long long)pc->resource.ino,
				     pc->resource.ag_number, pc->sends,
				     (unsigned long long)ctx->cancel_unacked);
			mxfs_pal_free(pc);
			continue;
		}
		pc->sends++;
		pc->sent_ms = now;
		resend[n++] = pc;
		pp = &pc->next;
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	for (i = 0; i < n; i++) {
		struct mxfs_dlm_pending_cancel *pc = resend[i];
		mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, &pc->resource);

		ctx->cancel_resends++;
		if (master == ctx->local_node) {
			/* remastered onto us: whatever the old master held is gone
			 * with its view, and a re-send cannot reach us — done */
			mxfs_pal_mutex_lock(ctx->rel_lock);
			for (pp = &ctx->cancel_pending; *pp; pp = &(*pp)->next) {
				if (*pp == pc) {
					*pp = pc->next;
					break;
				}
			}
			mxfs_pal_mutex_unlock(ctx->rel_lock);
			mxfs_pal_free(pc);
			continue;
		}
		dlm_send_cancel_msg(ctx, master, &pc->resource, pc->acq_seq,
				    pc->cancel_id, pc->mode);
	}
}
