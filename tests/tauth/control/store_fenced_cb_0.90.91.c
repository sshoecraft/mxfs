/*
 * control: dlm_store_fenced_cb as it was through 0.90.91.  A ticket on a
 * page's spare copy could be taken over only from an incarnation THIS mount
 * had purged, so once the mount that recovered the writer was gone, nothing
 * could ever commit the page again.  tests/tauth/abandoned_ticket.sh splices
 * it over the current definition in a copy of dlm/dlm.c.
 */
static bool dlm_store_fenced_cb(void *data, uint32_t node, uint64_t inc)
{
	struct mxfs_dlm_ctx *ctx = data;

	(void)inc;
	return ctx && node && dlm_owner_purged(ctx, node, -1);
}
