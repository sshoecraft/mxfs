/*
 * MXFS — Multinode XFS
 * Daemon configuration
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_CONFIG_H
#define MXFSD_CONFIG_H

#include <mxfs/mxfs_common.h>
#include <stdbool.h>

/* Peer endpoint as defined in config file */
struct mxfsd_peer_entry {
	char             host[256];
	uint16_t         port;
	mxfs_node_id_t   node_id;
};

/* Volume definition from config file */
struct mxfsd_volume_entry {
	char             name[MXFS_VOLUME_NAME_MAX];
	char             device[MXFS_PATH_MAX];
	mxfs_volume_id_t volume_id;
};

/* Parsed daemon configuration */
struct mxfsd_config {
	/* This node */
	mxfs_node_id_t         node_id;
	char                   node_name[MXFS_NODE_NAME_MAX];
	char                   bind_addr[256];
	uint16_t               bind_port;

	/* Peers */
	struct mxfsd_peer_entry   peers[MXFS_MAX_NODES];
	int                       peer_count;

	/* Volumes */
	struct mxfsd_volume_entry volumes[MXFS_MAX_VOLUMES];
	int                       volume_count;

	/* Tuning */
	uint64_t               lease_duration_ms;
	uint64_t               lease_renew_ms;
	uint64_t               node_timeout_ms;
	uint64_t               lock_wait_timeout_ms;

	/* Logging */
	char                   log_file[MXFS_PATH_MAX];
	int                    log_level;    /* syslog levels: LOG_ERR .. LOG_DEBUG */
	bool                   log_to_syslog;
	bool                   daemonize;
};

int  mxfsd_config_load(struct mxfsd_config *cfg, const char *path);
void mxfsd_config_set_defaults(struct mxfsd_config *cfg);
void mxfsd_config_dump(const struct mxfsd_config *cfg);

#endif /* MXFSD_CONFIG_H */
