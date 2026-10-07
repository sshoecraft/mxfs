void mxfs_dlm_release_retry_tick(struct mxfs_dlm_ctx *ctx)
{
	struct mxfs_dlm_pending_release *resend[16];
	struct mxfs_dlm_pending_release **pp;
	uint64_t now;
	int n = 0, i;

	if (!ctx || !ctx->rel_lock)
		return;
	now = mxfs_pal_time_ms();
	dlm_release_redrive_tick(ctx, now);
	dlm_purge_redrive_tick(ctx, now);
	dlm_settled_rejudge_tick(ctx, now);
	dlm_cancel_retry_tick(ctx, now);
	if (!ctx->rel_pending)
		return;
	/* The pending list is left as it is: those records are the survivor's
	 * manifest evidence now, and the recovery purge retires them. */
	if (dlm_refuse_release_while_poisoned(ctx, "release_retry",
					      &ctx->rel_pending->resource))
		return;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	pp = &ctx->rel_pending;
	while (*pp && n < 16) {
		struct mxfs_dlm_pending_release *pr = *pp;

		if (now - pr->sent_ms < MXFS_DLM_RELEASE_RETRY_MS) {
			pp = &pr->next;
			continue;
		}
		if (pr->sends >= MXFS_DLM_RELEASE_MAX_SENDS) {
			*pp = pr->next;
			ctx->release_unacked++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-RELEASE-UNACKED type=%u ino=%llu ag=%u rel_id=%u "
				     "grant_id={%llu,%llu} sends=%d — record stays a ledger blocker "
				     "until re-request or recovery purge",
				     pr->resource.type, (unsigned long long)pr->resource.ino,
				     pr->resource.ag_number, pr->rel_id,
				     (unsigned long long)pr->auth_epoch,
				     (unsigned long long)pr->grant_seq, pr->sends);
			mxfs_pal_free(pr);
			continue;
		}
		pr->sends++;
		pr->sent_ms = now;
		resend[n++] = pr;
		pp = &pr->next;
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	for (i = 0; i < n; i++) {
		struct mxfs_dlm_pending_release *pr = resend[i];
		mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, &pr->resource);

		ctx->release_resends++;
		if (master == ctx->local_node) {
			/* remastered onto us: the imported record is ours to retire */
			struct mxfs_dlm_lock_release rel;

			memset(&rel, 0, sizeof(rel));
			rel.resource = pr->resource;
			rel.grant_gen = pr->grant_gen;
			rel.rel_id = pr->rel_id;
			rel.authority_epoch = pr->auth_epoch;
			rel.grant_seq64 = pr->grant_seq;
			rel.owner_inc = ctx->local_inc;
			rel.owner_slot = ctx->local_slot;
			rel.lineage = pr->lineage;
			rel.mode = pr->mode;
			rel.open_op = pr->open_op;
			mxfs_dlm_process_remote_release(ctx, ctx->local_node, &rel);
		} else {
			dlm_send_release_msg(ctx, master, &pr->resource, pr->grant_gen,
					     pr->rel_id, pr->auth_epoch, pr->grant_seq,
					     pr->lineage, pr->mode, pr->open_op);
		}
	}
}
