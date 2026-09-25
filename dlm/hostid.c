/*
 * MXFS — host and boot identity.  See hostid.h.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include "hostid.h"

static struct mxfs_host_identity mxfs_hostid;

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int mxfs_uuid_parse(const char *s, size_t len, uint8_t u[16])
{
	size_t i = 0, n = 0;
	int hi = -1;

	if (!s || !u)
		return -EINVAL;
	while (i < len && n < 16) {
		char c = s[i++];
		int v;

		if (c == '-')
			continue;
		v = hexval(c);
		if (v < 0)
			break;
		if (hi < 0) {
			hi = v;
		} else {
			u[n++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}
	return (n == 16 && hi < 0) ? 0 : -EINVAL;
}

void mxfs_uuid_format(const uint8_t u[16], char out[37])
{
	static const char hx[] = "0123456789abcdef";
	int i, o = 0;

	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			out[o++] = '-';
		out[o++] = hx[u[i] >> 4];
		out[o++] = hx[u[i] & 0xf];
	}
	out[o] = '\0';
}

/*
 * FNV-1a over the initiator name, folded into 16 bytes with two different
 * offset bases.  The fallback exists for hosts without /etc/machine-id
 * (minimal initramfs, non-systemd); it is a stable HOST identity only as
 * long as the IQN is unique, which iSCSI itself already requires.
 */
static void hostid_hash16(const char *s, size_t len, uint8_t out[16])
{
	uint64_t h1 = 0xcbf29ce484222325ULL, h2 = 0x84222325cbf29ce4ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		h1 = (h1 ^ (uint8_t)s[i]) * 0x100000001b3ULL;
		h2 = (h2 ^ (uint8_t)s[i]) * 0x100000001b3ULL;
	}
	for (i = 0; i < 8; i++) {
		out[i] = (uint8_t)(h1 >> (8 * i));
		out[8 + i] = (uint8_t)(h2 >> (8 * i));
	}
}

static int hostid_read_uuid_file(const char *path, uint8_t u[16])
{
	char buf[128];
	int rc;

	memset(buf, 0, sizeof(buf));
	rc = mxfs_pal_read_file(path, buf, sizeof(buf) - 1);
	if (rc < 0)
		return rc;
	return mxfs_uuid_parse(buf, sizeof(buf) - 1, u);
}

int mxfs_host_identity_init(void)
{
	struct mxfs_host_identity *h = &mxfs_hostid;
	char boot[37] = "-", host[37] = "-";

	if (h->initialised)
		return (h->host_valid && h->boot_valid) ? 0 : -ENOENT;

	if (hostid_read_uuid_file("/proc/sys/kernel/random/boot_id",
				  h->boot_uuid) == 0)
		h->boot_valid = true;

	if (hostid_read_uuid_file("/etc/machine-id", h->host_uuid) == 0) {
		h->host_valid = true;
		h->host_src = MXFS_HOSTID_SRC_MACHINE_ID;
	} else {
		char buf[256];
		int rc;

		memset(buf, 0, sizeof(buf));
		rc = mxfs_pal_read_file("/etc/iscsi/initiatorname.iscsi", buf,
					sizeof(buf) - 1);
		if (rc > 0) {
			const char *p = strstr(buf, "InitiatorName=");
			size_t n;

			if (p) {
				p += strlen("InitiatorName=");
				n = 0;
				while (p[n] && p[n] != '\n' && p[n] != '\r')
					n++;
				if (n > 0) {
					hostid_hash16(p, n, h->host_uuid);
					h->host_valid = true;
					h->host_src = MXFS_HOSTID_SRC_INITIATOR;
				}
			}
		}
	}
	h->initialised = true;

	if (h->boot_valid)
		mxfs_uuid_format(h->boot_uuid, boot);
	if (h->host_valid)
		mxfs_uuid_format(h->host_uuid, host);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-HOSTID host=%s (%s) boot=%s — %s",
		     host,
		     h->host_src == MXFS_HOSTID_SRC_MACHINE_ID ? "machine-id" :
		     h->host_src == MXFS_HOSTID_SRC_INITIATOR ? "initiator-name" :
		     "NONE",
		     boot,
		     (h->host_valid && h->boot_valid) ?
			 "both identities valid; predecessor-boot self-succession "
			 "is decidable" :
			 "identity INCOMPLETE; automatic self-succession over a "
			 "predecessor PR key stays REFUSED on this host");
	return (h->host_valid && h->boot_valid) ? 0 : -ENOENT;
}

const struct mxfs_host_identity *mxfs_host_identity(void)
{
	return &mxfs_hostid;
}
