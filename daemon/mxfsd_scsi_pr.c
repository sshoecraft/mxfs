/*
 * MXFS — Multinode XFS
 * SCSI-3 Persistent Reservations for I/O fencing
 *
 * Hardware-level I/O fencing using SCSI-3 Persistent Reservations.
 * Issues PERSISTENT RESERVE IN/OUT commands via the SG_IO ioctl to
 * register node keys, acquire WRITE EXCLUSIVE - REGISTRANTS ONLY
 * reservations, and preempt dead nodes to fence them from storage.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>

#include "mxfsd_scsi_pr.h"
#include "mxfsd_log.h"

/* SCSI opcodes for Persistent Reserve */
#define PR_OUT_OPCODE   0x5F
#define PR_IN_OPCODE    0x5E

/* PR OUT service actions */
#define PR_OUT_REGISTER             0x00
#define PR_OUT_RESERVE              0x01
#define PR_OUT_RELEASE              0x02
#define PR_OUT_PREEMPT              0x04
#define PR_OUT_REGISTER_AND_IGNORE  0x06

/* PR IN service actions */
#define PR_IN_READ_KEYS             0x00
#define PR_IN_READ_RESERVATION      0x01

/* Reservation type: WRITE EXCLUSIVE - REGISTRANTS ONLY */
#define PR_TYPE_WR_EX_REG_ONLY     5

/* PR OUT parameter data length (bytes 0-23) */
#define PR_OUT_PARAM_LEN           24

/* SG_IO timeout in milliseconds */
#define SGIO_TIMEOUT_MS            20000

/* Maximum sense data buffer */
#define SENSE_BUF_LEN              32

/* Maximum allocation for PR IN READ_KEYS response */
#define READ_KEYS_BUF_LEN          4096

/* Maximum allocation for PR IN READ_RESERVATION response */
#define READ_RESV_BUF_LEN          256

/*
 * Store a 64-bit value big-endian into a byte buffer.
 */
static void put_be64(uint8_t *buf, uint64_t val)
{
	buf[0] = (uint8_t)(val >> 56);
	buf[1] = (uint8_t)(val >> 48);
	buf[2] = (uint8_t)(val >> 40);
	buf[3] = (uint8_t)(val >> 32);
	buf[4] = (uint8_t)(val >> 24);
	buf[5] = (uint8_t)(val >> 16);
	buf[6] = (uint8_t)(val >> 8);
	buf[7] = (uint8_t)(val);
}

/*
 * Read a 64-bit value big-endian from a byte buffer.
 */
static uint64_t get_be64(const uint8_t *buf)
{
	return ((uint64_t)buf[0] << 56) |
	       ((uint64_t)buf[1] << 48) |
	       ((uint64_t)buf[2] << 40) |
	       ((uint64_t)buf[3] << 32) |
	       ((uint64_t)buf[4] << 24) |
	       ((uint64_t)buf[5] << 16) |
	       ((uint64_t)buf[6] << 8) |
	       ((uint64_t)buf[7]);
}

/*
 * Read a 32-bit value big-endian from a byte buffer.
 */
static uint32_t get_be32(const uint8_t *buf)
{
	return ((uint32_t)buf[0] << 24) |
	       ((uint32_t)buf[1] << 16) |
	       ((uint32_t)buf[2] << 8) |
	       ((uint32_t)buf[3]);
}

/*
 * Decode and log SCSI sense data on error.
 * Returns -EIO for check condition, -EPROTO for other failures.
 */
static int decode_sense(const uint8_t *sense, int sense_len, const char *op)
{
	uint8_t sense_key = 0;
	uint8_t asc = 0;
	uint8_t ascq = 0;

	if (sense_len < 1) {
		mxfsd_err("scsi_pr: %s: no sense data available", op);
		return -EIO;
	}

	uint8_t response_code = sense[0] & 0x7F;

	if (response_code == 0x70 || response_code == 0x71) {
		/* Fixed format sense data */
		if (sense_len >= 3)
			sense_key = sense[2] & 0x0F;
		if (sense_len >= 13)
			asc = sense[12];
		if (sense_len >= 14)
			ascq = sense[13];
	} else if (response_code == 0x72 || response_code == 0x73) {
		/* Descriptor format sense data */
		if (sense_len >= 2)
			sense_key = sense[1] & 0x0F;
		if (sense_len >= 3)
			asc = sense[2];
		if (sense_len >= 4)
			ascq = sense[3];
	} else {
		mxfsd_err("scsi_pr: %s: unknown sense response code 0x%02x",
		          op, response_code);
		return -EIO;
	}

	mxfsd_err("scsi_pr: %s: sense_key=0x%x asc=0x%02x ascq=0x%02x",
	          op, sense_key, asc, ascq);

	/* Reservation conflict (sense_key=0 is used with status=0x18) */
	if (sense_key == 0x05)
		return -EINVAL;    /* ILLEGAL REQUEST */
	if (sense_key == 0x06)
		return -EAGAIN;    /* UNIT ATTENTION */

	return -EIO;
}

/*
 * Check SG_IO result for errors.
 * Returns 0 on success, negative errno on failure.
 */
static int check_sgio_result(struct sg_io_hdr *hdr, const char *op)
{
	/* Transport-level error */
	if (hdr->host_status != 0) {
		mxfsd_err("scsi_pr: %s: host_status=0x%x", op,
		          hdr->host_status);
		return -EIO;
	}

	if (hdr->driver_status != 0) {
		mxfsd_err("scsi_pr: %s: driver_status=0x%x", op,
		          hdr->driver_status);
		return -EIO;
	}

	/* GOOD status */
	if (hdr->status == 0)
		return 0;

	/* RESERVATION CONFLICT (status 0x18) */
	if (hdr->status == 0x18) {
		mxfsd_err("scsi_pr: %s: RESERVATION CONFLICT", op);
		return -EBUSY;
	}

	/* CHECK CONDITION (status 0x02) — decode sense data */
	if (hdr->status == 0x02) {
		return decode_sense(hdr->sbp, hdr->sb_len_wr, op);
	}

	mxfsd_err("scsi_pr: %s: unexpected SCSI status 0x%02x", op,
	          hdr->status);
	return -EIO;
}

/*
 * Issue a PERSISTENT RESERVE OUT command.
 *
 * service_action: one of PR_OUT_REGISTER, PR_OUT_RESERVE, etc.
 * reservation_key: current key (0 for initial register)
 * sa_key: service action reservation key (new key for register, victim for preempt)
 * scope_type: (scope << 4) | type, used for RESERVE and PREEMPT
 */
static int pr_out(struct mxfsd_scsi_pr_ctx *ctx, uint8_t service_action,
                  uint64_t reservation_key, uint64_t sa_key,
                  uint8_t scope_type, const char *op_name)
{
	uint8_t cdb[10];
	uint8_t param[PR_OUT_PARAM_LEN];
	uint8_t sense[SENSE_BUF_LEN];
	struct sg_io_hdr hdr;
	int rc;

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = PR_OUT_OPCODE;
	cdb[1] = service_action & 0x1F;
	cdb[2] = scope_type;
	/* Parameter data length in bytes 7-8 (big-endian) */
	cdb[7] = (PR_OUT_PARAM_LEN >> 8) & 0xFF;
	cdb[8] = PR_OUT_PARAM_LEN & 0xFF;

	memset(param, 0, sizeof(param));
	put_be64(&param[0], reservation_key);
	put_be64(&param[8], sa_key);
	/* bytes 16-19: obsolete/reserved */
	/* bytes 20-23: scope-specific + reserved, scope_type already in CDB */

	memset(sense, 0, sizeof(sense));
	memset(&hdr, 0, sizeof(hdr));

	hdr.interface_id = 'S';
	hdr.dxfer_direction = SG_DXFER_TO_DEV;
	hdr.cmd_len = sizeof(cdb);
	hdr.cmdp = cdb;
	hdr.dxfer_len = sizeof(param);
	hdr.dxferp = param;
	hdr.mx_sb_len = sizeof(sense);
	hdr.sbp = sense;
	hdr.timeout = SGIO_TIMEOUT_MS;

	rc = ioctl(ctx->fd, SG_IO, &hdr);
	if (rc < 0) {
		rc = -errno;
		mxfsd_err("scsi_pr: %s: SG_IO ioctl failed: %s",
		          op_name, strerror(-rc));
		return rc;
	}

	return check_sgio_result(&hdr, op_name);
}

/*
 * Issue a PERSISTENT RESERVE IN command.
 *
 * service_action: PR_IN_READ_KEYS or PR_IN_READ_RESERVATION
 * buf/buflen: output buffer for the response
 */
static int pr_in(struct mxfsd_scsi_pr_ctx *ctx, uint8_t service_action,
                 uint8_t *buf, uint16_t buflen, const char *op_name)
{
	uint8_t cdb[10];
	uint8_t sense[SENSE_BUF_LEN];
	struct sg_io_hdr hdr;
	int rc;

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = PR_IN_OPCODE;
	cdb[1] = service_action & 0x1F;
	/* Allocation length in bytes 7-8 (big-endian) */
	cdb[7] = (buflen >> 8) & 0xFF;
	cdb[8] = buflen & 0xFF;

	memset(buf, 0, buflen);
	memset(sense, 0, sizeof(sense));
	memset(&hdr, 0, sizeof(hdr));

	hdr.interface_id = 'S';
	hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	hdr.cmd_len = sizeof(cdb);
	hdr.cmdp = cdb;
	hdr.dxfer_len = buflen;
	hdr.dxferp = buf;
	hdr.mx_sb_len = sizeof(sense);
	hdr.sbp = sense;
	hdr.timeout = SGIO_TIMEOUT_MS;

	rc = ioctl(ctx->fd, SG_IO, &hdr);
	if (rc < 0) {
		rc = -errno;
		mxfsd_err("scsi_pr: %s: SG_IO ioctl failed: %s",
		          op_name, strerror(-rc));
		return rc;
	}

	return check_sgio_result(&hdr, op_name);
}

int mxfsd_scsi_pr_init(struct mxfsd_scsi_pr_ctx *ctx, const char *device,
                        uint64_t key)
{
	if (!ctx || !device || key == 0)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	snprintf(ctx->device, sizeof(ctx->device), "%s", device);
	ctx->local_key = key;
	ctx->fd = -1;

	int rc = pthread_mutex_init(&ctx->lock, NULL);
	if (rc != 0) {
		mxfsd_err("scsi_pr: pthread_mutex_init failed: %s",
		          strerror(rc));
		return -rc;
	}

	ctx->fd = open(device, O_RDWR);
	if (ctx->fd < 0) {
		rc = -errno;
		mxfsd_err("scsi_pr: cannot open device '%s': %s",
		          device, strerror(-rc));
		pthread_mutex_destroy(&ctx->lock);
		return rc;
	}

	mxfsd_info("scsi_pr: initialized for device '%s' key=0x%lx",
	           device, (unsigned long)key);
	return 0;
}

void mxfsd_scsi_pr_shutdown(struct mxfsd_scsi_pr_ctx *ctx)
{
	if (!ctx)
		return;

	pthread_mutex_lock(&ctx->lock);

	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}

	pthread_mutex_unlock(&ctx->lock);
	pthread_mutex_destroy(&ctx->lock);

	mxfsd_info("scsi_pr: shutdown for device '%s'", ctx->device);
}

int mxfsd_scsi_pr_register(struct mxfsd_scsi_pr_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	int rc;

	pthread_mutex_lock(&ctx->lock);

	/*
	 * Use REGISTER_AND_IGNORE (SA 0x06) for the initial registration.
	 * This works regardless of whether we have a previous key registered
	 * (e.g., after a daemon restart where the old key is still on the
	 * device). It sets our key without requiring knowledge of the
	 * existing key.
	 */
	mxfsd_info("scsi_pr: registering key 0x%lx on '%s'",
	           (unsigned long)ctx->local_key, ctx->device);

	rc = pr_out(ctx, PR_OUT_REGISTER_AND_IGNORE,
	            0,                   /* reservation_key (ignored) */
	            ctx->local_key,      /* service_action_reservation_key */
	            0,                   /* scope_type (not used for register) */
	            "register");

	pthread_mutex_unlock(&ctx->lock);

	if (rc == 0)
		mxfsd_info("scsi_pr: registered key 0x%lx on '%s'",
		           (unsigned long)ctx->local_key, ctx->device);
	else
		mxfsd_err("scsi_pr: register failed on '%s': %s",
		          ctx->device, strerror(-rc));

	return rc;
}

int mxfsd_scsi_pr_reserve(struct mxfsd_scsi_pr_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	int rc;

	pthread_mutex_lock(&ctx->lock);

	/*
	 * Acquire a WRITE EXCLUSIVE - REGISTRANTS ONLY reservation (type 5).
	 * All nodes with a registered key can perform I/O. Nodes without a
	 * registered key are fenced.
	 *
	 * scope_type byte: (scope << 4) | type
	 * scope = 0 (LU_SCOPE), type = 5 (WR_EX_REG_ONLY)
	 */
	uint8_t scope_type = (0 << 4) | PR_TYPE_WR_EX_REG_ONLY;

	mxfsd_info("scsi_pr: reserving '%s' with key 0x%lx (type 5)",
	           ctx->device, (unsigned long)ctx->local_key);

	rc = pr_out(ctx, PR_OUT_RESERVE,
	            ctx->local_key,      /* reservation_key (our registered key) */
	            0,                   /* service_action_reservation_key (unused) */
	            scope_type,
	            "reserve");

	pthread_mutex_unlock(&ctx->lock);

	if (rc == 0)
		mxfsd_info("scsi_pr: reservation acquired on '%s'",
		           ctx->device);
	else
		mxfsd_err("scsi_pr: reserve failed on '%s': %s",
		          ctx->device, strerror(-rc));

	return rc;
}

int mxfsd_scsi_pr_preempt(struct mxfsd_scsi_pr_ctx *ctx, uint64_t victim_key)
{
	if (!ctx || victim_key == 0)
		return -EINVAL;

	int rc;

	pthread_mutex_lock(&ctx->lock);

	/*
	 * Preempt the victim's registration. This removes the victim's key
	 * from the device's registration list, causing the storage target to
	 * reject all further I/O from that node. If the victim held the
	 * reservation, it is transferred to us.
	 *
	 * scope_type must match the existing reservation type.
	 */
	uint8_t scope_type = (0 << 4) | PR_TYPE_WR_EX_REG_ONLY;

	mxfsd_notice("scsi_pr: preempting key 0x%lx on '%s' (our key 0x%lx)",
	             (unsigned long)victim_key, ctx->device,
	             (unsigned long)ctx->local_key);

	rc = pr_out(ctx, PR_OUT_PREEMPT,
	            ctx->local_key,      /* reservation_key (our key) */
	            victim_key,          /* service_action_reservation_key (victim) */
	            scope_type,
	            "preempt");

	pthread_mutex_unlock(&ctx->lock);

	if (rc == 0)
		mxfsd_notice("scsi_pr: preempted key 0x%lx on '%s'",
		             (unsigned long)victim_key, ctx->device);
	else
		mxfsd_err("scsi_pr: preempt of key 0x%lx failed on '%s': %s",
		          (unsigned long)victim_key, ctx->device,
		          strerror(-rc));

	return rc;
}

int mxfsd_scsi_pr_read_keys(struct mxfsd_scsi_pr_ctx *ctx, uint64_t *keys,
                             int *count, int max)
{
	if (!ctx || !keys || !count || max <= 0)
		return -EINVAL;

	uint8_t buf[READ_KEYS_BUF_LEN];
	int rc;

	pthread_mutex_lock(&ctx->lock);

	rc = pr_in(ctx, PR_IN_READ_KEYS, buf, sizeof(buf), "read_keys");
	if (rc < 0) {
		pthread_mutex_unlock(&ctx->lock);
		return rc;
	}

	pthread_mutex_unlock(&ctx->lock);

	/*
	 * Response format:
	 *   bytes 0-3: PR generation (32-bit counter)
	 *   bytes 4-7: additional length in bytes
	 *   bytes 8+:  8-byte registration keys
	 */
	uint32_t additional_len = get_be32(&buf[4]);
	int nkeys = (int)(additional_len / 8);

	if (nkeys > max)
		nkeys = max;

	/* Bounds check against our buffer size */
	int max_from_buf = (int)((sizeof(buf) - 8) / 8);
	if (nkeys > max_from_buf)
		nkeys = max_from_buf;

	for (int i = 0; i < nkeys; i++)
		keys[i] = get_be64(&buf[8 + i * 8]);

	*count = nkeys;

	mxfsd_dbg("scsi_pr: read_keys on '%s': %d keys registered",
	          ctx->device, nkeys);

	return 0;
}

int mxfsd_scsi_pr_read_reservation(struct mxfsd_scsi_pr_ctx *ctx,
                                    uint64_t *key, uint8_t *type)
{
	if (!ctx || !key || !type)
		return -EINVAL;

	uint8_t buf[READ_RESV_BUF_LEN];
	int rc;

	pthread_mutex_lock(&ctx->lock);

	rc = pr_in(ctx, PR_IN_READ_RESERVATION, buf, sizeof(buf),
	           "read_reservation");
	if (rc < 0) {
		pthread_mutex_unlock(&ctx->lock);
		return rc;
	}

	pthread_mutex_unlock(&ctx->lock);

	/*
	 * Response format:
	 *   bytes 0-3: PR generation
	 *   bytes 4-7: additional length (0 means no reservation held)
	 *   If additional_length > 0:
	 *     bytes 8-15: reservation key
	 *     bytes 16-19: scope-specific address (obsolete)
	 *     byte 20: reserved
	 *     byte 21: (scope << 4) | type
	 *     bytes 22-23: obsolete
	 */
	uint32_t additional_len = get_be32(&buf[4]);

	if (additional_len == 0) {
		/* No reservation currently held */
		*key = 0;
		*type = 0;
		mxfsd_dbg("scsi_pr: read_reservation on '%s': no reservation",
		          ctx->device);
		return 0;
	}

	*key = get_be64(&buf[8]);
	*type = buf[21] & 0x0F;

	mxfsd_dbg("scsi_pr: read_reservation on '%s': key=0x%lx type=%u",
	          ctx->device, (unsigned long)*key, *type);

	return 0;
}

int mxfsd_scsi_pr_unregister(struct mxfsd_scsi_pr_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	int rc;

	pthread_mutex_lock(&ctx->lock);

	/*
	 * Unregister by setting the service_action_reservation_key to 0.
	 * This removes our key from the device's registration list.
	 * Use the standard REGISTER action (SA 0x00) which requires
	 * providing our current key as the reservation_key.
	 */
	mxfsd_info("scsi_pr: unregistering key 0x%lx from '%s'",
	           (unsigned long)ctx->local_key, ctx->device);

	rc = pr_out(ctx, PR_OUT_REGISTER,
	            ctx->local_key,      /* reservation_key (our current key) */
	            0,                   /* service_action_reservation_key (0 = unregister) */
	            0,                   /* scope_type (not used) */
	            "unregister");

	pthread_mutex_unlock(&ctx->lock);

	if (rc == 0)
		mxfsd_info("scsi_pr: unregistered key 0x%lx from '%s'",
		           (unsigned long)ctx->local_key, ctx->device);
	else
		mxfsd_err("scsi_pr: unregister failed on '%s': %s",
		          ctx->device, strerror(-rc));

	return rc;
}
