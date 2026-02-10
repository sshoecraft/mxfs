/*
 * MXFS — Multinode XFS
 * Configuration parsing
 *
 * Reads /etc/mxfs/volumes.conf (or user-specified path) and populates
 * the mxfsd_config structure with node identity, peer list, volume
 * definitions, and tuning parameters.
 *
 * INI-style format with sections: [node], [peer], [volume], [timing],
 * [logging]. Multiple [peer] and [volume] sections are allowed.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>

#include <mxfs/mxfs_dlm.h>
#include "mxfsd_config.h"
#include "mxfsd_log.h"

enum section_type {
	SECTION_NONE = 0,
	SECTION_NODE,
	SECTION_PEER,
	SECTION_VOLUME,
	SECTION_TIMING,
	SECTION_LOGGING,
};

static char *strip(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;

	if (!*s)
		return s;

	char *end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';

	return s;
}

static int parse_log_level(const char *str)
{
	if (strcasecmp(str, "error") == 0 || strcasecmp(str, "err") == 0)
		return LOG_ERR;
	if (strcasecmp(str, "warning") == 0 || strcasecmp(str, "warn") == 0)
		return LOG_WARNING;
	if (strcasecmp(str, "notice") == 0)
		return LOG_NOTICE;
	if (strcasecmp(str, "info") == 0)
		return LOG_INFO;
	if (strcasecmp(str, "debug") == 0)
		return LOG_DEBUG;
	return -1;
}

static int parse_bool(const char *str)
{
	if (strcasecmp(str, "yes") == 0 || strcasecmp(str, "true") == 0 ||
	    strcmp(str, "1") == 0)
		return 1;
	if (strcasecmp(str, "no") == 0 || strcasecmp(str, "false") == 0 ||
	    strcmp(str, "0") == 0)
		return 0;
	return -1;
}

static enum section_type parse_section(const char *name)
{
	if (strcmp(name, "node") == 0)    return SECTION_NODE;
	if (strcmp(name, "peer") == 0)    return SECTION_PEER;
	if (strcmp(name, "volume") == 0)  return SECTION_VOLUME;
	if (strcmp(name, "timing") == 0)  return SECTION_TIMING;
	if (strcmp(name, "logging") == 0) return SECTION_LOGGING;
	return SECTION_NONE;
}

static int handle_node(struct mxfsd_config *cfg, const char *key,
		       const char *val, int line)
{
	if (strcmp(key, "id") == 0) {
		unsigned long v = strtoul(val, NULL, 10);
		if (v == 0 || v > MXFS_MAX_NODES) {
			mxfsd_err("config:%d: invalid node id '%s'", line, val);
			return -1;
		}
		cfg->node_id = (mxfs_node_id_t)v;
	} else if (strcmp(key, "name") == 0) {
		snprintf(cfg->node_name, sizeof(cfg->node_name), "%s", val);
	} else if (strcmp(key, "bind") == 0) {
		snprintf(cfg->bind_addr, sizeof(cfg->bind_addr), "%s", val);
	} else if (strcmp(key, "port") == 0) {
		unsigned long v = strtoul(val, NULL, 10);
		if (v == 0 || v > 65535) {
			mxfsd_err("config:%d: invalid port '%s'", line, val);
			return -1;
		}
		cfg->bind_port = (uint16_t)v;
	} else {
		mxfsd_warn("config:%d: unknown node key '%s'", line, key);
	}
	return 0;
}

static int handle_peer(struct mxfsd_config *cfg, const char *key,
		       const char *val, int line, int idx)
{
	if (idx < 0 || idx >= MXFS_MAX_NODES) {
		mxfsd_err("config:%d: too many peers (max %d)", line, MXFS_MAX_NODES);
		return -1;
	}

	struct mxfsd_peer_entry *p = &cfg->peers[idx];

	if (strcmp(key, "id") == 0) {
		unsigned long v = strtoul(val, NULL, 10);
		if (v == 0 || v > MXFS_MAX_NODES) {
			mxfsd_err("config:%d: invalid peer id '%s'", line, val);
			return -1;
		}
		p->node_id = (mxfs_node_id_t)v;
	} else if (strcmp(key, "host") == 0) {
		snprintf(p->host, sizeof(p->host), "%s", val);
	} else if (strcmp(key, "port") == 0) {
		unsigned long v = strtoul(val, NULL, 10);
		if (v == 0 || v > 65535) {
			mxfsd_err("config:%d: invalid peer port '%s'", line, val);
			return -1;
		}
		p->port = (uint16_t)v;
	} else if (strcmp(key, "name") == 0) {
		/* peer name is informational, not stored */
	} else {
		mxfsd_warn("config:%d: unknown peer key '%s'", line, key);
	}
	return 0;
}

static int handle_volume(struct mxfsd_config *cfg, const char *key,
			 const char *val, int line, int idx)
{
	if (idx < 0 || idx >= MXFS_MAX_VOLUMES) {
		mxfsd_err("config:%d: too many volumes (max %d)", line, MXFS_MAX_VOLUMES);
		return -1;
	}

	struct mxfsd_volume_entry *v = &cfg->volumes[idx];

	if (strcmp(key, "name") == 0) {
		snprintf(v->name, sizeof(v->name), "%s", val);
	} else if (strcmp(key, "device") == 0) {
		snprintf(v->device, sizeof(v->device), "%s", val);
	} else {
		mxfsd_warn("config:%d: unknown volume key '%s'", line, key);
	}
	return 0;
}

static int handle_timing(struct mxfsd_config *cfg, const char *key,
			 const char *val, int line)
{
	unsigned long long v = strtoull(val, NULL, 10);

	if (strcmp(key, "lease_duration_ms") == 0) {
		cfg->lease_duration_ms = v;
	} else if (strcmp(key, "lease_renew_ms") == 0) {
		cfg->lease_renew_ms = v;
	} else if (strcmp(key, "node_timeout_ms") == 0) {
		cfg->node_timeout_ms = v;
	} else if (strcmp(key, "lock_wait_timeout_ms") == 0) {
		cfg->lock_wait_timeout_ms = v;
	} else {
		mxfsd_warn("config:%d: unknown timing key '%s'", line, key);
	}
	return 0;
}

static int handle_logging(struct mxfsd_config *cfg, const char *key,
			  const char *val, int line)
{
	if (strcmp(key, "file") == 0) {
		snprintf(cfg->log_file, sizeof(cfg->log_file), "%s", val);
	} else if (strcmp(key, "level") == 0) {
		int lvl = parse_log_level(val);
		if (lvl < 0) {
			mxfsd_err("config:%d: unknown log level '%s'", line, val);
			return -1;
		}
		cfg->log_level = lvl;
	} else if (strcmp(key, "syslog") == 0) {
		int b = parse_bool(val);
		if (b < 0) {
			mxfsd_err("config:%d: invalid boolean '%s'", line, val);
			return -1;
		}
		cfg->log_to_syslog = b;
	} else if (strcmp(key, "daemonize") == 0) {
		int b = parse_bool(val);
		if (b < 0) {
			mxfsd_err("config:%d: invalid boolean '%s'", line, val);
			return -1;
		}
		cfg->daemonize = b;
	} else {
		mxfsd_warn("config:%d: unknown logging key '%s'", line, key);
	}
	return 0;
}

void mxfsd_config_set_defaults(struct mxfsd_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->bind_port            = 7600;
	cfg->lease_duration_ms    = MXFS_LEASE_DURATION_MS;
	cfg->lease_renew_ms       = MXFS_LEASE_RENEW_MS;
	cfg->node_timeout_ms      = MXFS_NODE_TIMEOUT_MS;
	cfg->lock_wait_timeout_ms = MXFS_LOCK_WAIT_TIMEOUT_MS;
	cfg->log_level            = LOG_INFO;
	cfg->log_to_syslog        = true;
	cfg->daemonize            = true;
}

int mxfsd_config_load(struct mxfsd_config *cfg, const char *path)
{
	FILE *fp;
	char line[1024];
	int lineno = 0;
	enum section_type section = SECTION_NONE;
	int peer_idx = -1;
	int vol_idx = -1;
	int rc = 0;

	fp = fopen(path, "r");
	if (!fp) {
		mxfsd_err("cannot open config '%s': %s", path, strerror(errno));
		return -errno;
	}

	while (fgets(line, sizeof(line), fp)) {
		lineno++;

		/* strip trailing newline */
		char *p = strchr(line, '\n');
		if (p)
			*p = '\0';

		char *s = strip(line);

		/* skip blank lines and comments */
		if (!*s || *s == '#' || *s == ';')
			continue;

		/* section header */
		if (*s == '[') {
			char *end = strchr(s, ']');
			if (!end) {
				mxfsd_err("config:%d: malformed section", lineno);
				rc = -EINVAL;
				goto out;
			}
			*end = '\0';
			char *name = strip(s + 1);

			section = parse_section(name);
			if (section == SECTION_NONE) {
				mxfsd_err("config:%d: unknown section '%s'",
					  lineno, name);
				rc = -EINVAL;
				goto out;
			}

			/* each [peer] / [volume] starts a new entry */
			if (section == SECTION_PEER) {
				peer_idx = cfg->peer_count;
				cfg->peer_count++;
				if (cfg->peer_count > MXFS_MAX_NODES) {
					mxfsd_err("config:%d: too many peers", lineno);
					rc = -EINVAL;
					goto out;
				}
				/* default port for peer */
				cfg->peers[peer_idx].port = 7600;
			} else if (section == SECTION_VOLUME) {
				vol_idx = cfg->volume_count;
				cfg->volume_count++;
				if (cfg->volume_count > MXFS_MAX_VOLUMES) {
					mxfsd_err("config:%d: too many volumes", lineno);
					rc = -EINVAL;
					goto out;
				}
			}
			continue;
		}

		/* key = value */
		char *eq = strchr(s, '=');
		if (!eq) {
			mxfsd_err("config:%d: expected 'key = value'", lineno);
			rc = -EINVAL;
			goto out;
		}

		*eq = '\0';
		char *key = strip(s);
		char *val = strip(eq + 1);

		if (!*key) {
			mxfsd_err("config:%d: empty key", lineno);
			rc = -EINVAL;
			goto out;
		}

		switch (section) {
		case SECTION_NODE:
			rc = handle_node(cfg, key, val, lineno);
			break;
		case SECTION_PEER:
			rc = handle_peer(cfg, key, val, lineno, peer_idx);
			break;
		case SECTION_VOLUME:
			rc = handle_volume(cfg, key, val, lineno, vol_idx);
			break;
		case SECTION_TIMING:
			rc = handle_timing(cfg, key, val, lineno);
			break;
		case SECTION_LOGGING:
			rc = handle_logging(cfg, key, val, lineno);
			break;
		case SECTION_NONE:
			mxfsd_err("config:%d: key outside section", lineno);
			rc = -EINVAL;
			break;
		}

		if (rc)
			goto out;
	}

	/* Validate required fields */
	if (cfg->node_id == 0) {
		mxfsd_err("config: [node] id is required");
		rc = -EINVAL;
	} else if (cfg->node_name[0] == '\0') {
		mxfsd_err("config: [node] name is required");
		rc = -EINVAL;
	}

out:
	fclose(fp);
	return rc;
}

void mxfsd_config_dump(const struct mxfsd_config *cfg)
{
	mxfsd_info("config: node id=%u name='%s' bind=%s:%u",
		   cfg->node_id, cfg->node_name,
		   cfg->bind_addr[0] ? cfg->bind_addr : "0.0.0.0",
		   cfg->bind_port);

	for (int i = 0; i < cfg->peer_count; i++) {
		const struct mxfsd_peer_entry *p = &cfg->peers[i];
		mxfsd_info("config: peer id=%u host=%s:%u",
			   p->node_id, p->host, p->port);
	}

	for (int i = 0; i < cfg->volume_count; i++) {
		const struct mxfsd_volume_entry *v = &cfg->volumes[i];
		mxfsd_info("config: volume '%s' device=%s",
			   v->name, v->device);
	}

	mxfsd_info("config: lease_duration=%lums lease_renew=%lums "
		   "node_timeout=%lums lock_wait=%lums",
		   (unsigned long)cfg->lease_duration_ms,
		   (unsigned long)cfg->lease_renew_ms,
		   (unsigned long)cfg->node_timeout_ms,
		   (unsigned long)cfg->lock_wait_timeout_ms);

	mxfsd_info("config: log_file='%s' log_level=%d syslog=%s daemonize=%s",
		   cfg->log_file,
		   cfg->log_level,
		   cfg->log_to_syslog ? "yes" : "no",
		   cfg->daemonize ? "yes" : "no");
}
