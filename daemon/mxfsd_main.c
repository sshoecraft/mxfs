/*
 * MXFS — Multinode XFS
 * Daemon entry point
 *
 * mxfsd is the userspace daemon that runs on each node participating in
 * an MXFS cluster. It manages peer connections, runs the DLM protocol,
 * handles lease management, and communicates with the local mxfs.ko
 * kernel module via generic netlink.
 *
 * Usage: mxfsd start --config /etc/mxfs/volumes.conf
 *        mxfsd stop
 *        mxfsd status
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <mxfs/mxfs_common.h>
#include "mxfsd_config.h"
#include "mxfsd_log.h"
#include "mxfsd_peer.h"
#include "mxfsd_dlm.h"
#include "mxfsd_netlink.h"
#include "mxfsd_lease.h"
#include "mxfsd_journal.h"
#include "mxfsd_volume.h"

#define MXFSD_PID_FILE    "/var/run/mxfsd.pid"
#define MXFSD_DLM_BUCKETS 1024
#define MXFSD_DEFAULT_CONF "/etc/mxfs/volumes.conf"

static volatile sig_atomic_t running;
static volatile sig_atomic_t reload;

static struct mxfsd_config      config;
static struct mxfsd_peer_ctx    peer_ctx;
static struct mxfsd_dlm_ctx     dlm_ctx;
static struct mxfsd_netlink_ctx nl_ctx;
static struct mxfsd_lease_ctx   lease_ctx;
static struct mxfsd_journal_ctx journal_ctx;
static struct mxfsd_volume_ctx  volume_ctx;

/* Track which subsystems initialized for orderly shutdown */
enum subsystem {
	SUB_LOG = 0,
	SUB_CONFIG,
	SUB_VOLUME,
	SUB_DLM,
	SUB_NETLINK,
	SUB_PEER,
	SUB_LEASE,
	SUB_JOURNAL,
	SUB_COUNT,
};

static bool sub_init[SUB_COUNT];

static void signal_handler(int sig)
{
	if (sig == SIGHUP)
		reload = 1;
	else
		running = 0;
}

static void setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	/* Ignore SIGPIPE — peer sockets may close unexpectedly */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s start [--config <path>] [--foreground]\n"
		"       %s stop\n"
		"       %s status\n"
		"\n"
		"Options:\n"
		"  --config, -c <path>   Config file (default: %s)\n"
		"  --foreground, -f      Run in foreground (don't daemonize)\n"
		"  --help, -h            Show this help\n",
		prog, prog, prog, MXFSD_DEFAULT_CONF);
}

static int write_pid_file(void)
{
	FILE *fp = fopen(MXFSD_PID_FILE, "w");
	if (!fp) {
		mxfsd_warn("cannot write pid file '%s': %s",
			   MXFSD_PID_FILE, strerror(errno));
		return -1;
	}
	fprintf(fp, "%d\n", getpid());
	fclose(fp);
	return 0;
}

static void remove_pid_file(void)
{
	unlink(MXFSD_PID_FILE);
}

static int daemonize(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "mxfsd: fork failed: %s\n", strerror(errno));
		return -1;
	}
	if (pid > 0)
		_exit(0);  /* parent exits */

	if (setsid() < 0)
		return -1;

	/* Second fork to prevent acquiring a controlling terminal */
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	/* Redirect stdio to /dev/null */
	int devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	return 0;
}

/* Lease expire callback — invoked when a peer's lease expires */
static void on_lease_expire(mxfs_node_id_t node, void *user_data)
{
	(void)user_data;

	mxfsd_notice("node %u lease expired — purging locks and "
		     "initiating journal recovery", node);

	/* Purge all DLM locks held by the dead node */
	mxfsd_dlm_purge_node(&dlm_ctx, node);

	/* Mark journal slot for recovery */
	mxfsd_journal_mark_needs_recovery(&journal_ctx, node);

	/* Attempt to begin recovery (we may not be the one to do it) */
	if (mxfsd_journal_begin_recovery(&journal_ctx, node) == 0) {
		mxfsd_netlink_send_recovery_start(&nl_ctx);
		mxfsd_netlink_send_node_status(&nl_ctx, node, MXFS_NODE_DEAD);

		/* The actual XFS journal replay is triggered by the kernel
		 * module when it receives RECOVERY_START. When it finishes,
		 * it sends a status message back which we handle in the
		 * netlink callback. For now, we finish recovery here since
		 * we don't have the full kernel module loop yet. */
		mxfsd_journal_finish_recovery(&journal_ctx, node);
		mxfsd_netlink_send_recovery_done(&nl_ctx);
	}

	/* Advance epoch to invalidate stale locks */
	mxfsd_dlm_advance_epoch(&dlm_ctx);
}

static void shutdown_subsystems(void)
{
	/* Shutdown in reverse init order */
	if (sub_init[SUB_JOURNAL]) {
		mxfsd_journal_shutdown(&journal_ctx);
		sub_init[SUB_JOURNAL] = false;
	}
	if (sub_init[SUB_LEASE]) {
		mxfsd_lease_shutdown(&lease_ctx);
		sub_init[SUB_LEASE] = false;
	}
	if (sub_init[SUB_PEER]) {
		mxfsd_peer_shutdown(&peer_ctx);
		sub_init[SUB_PEER] = false;
	}
	if (sub_init[SUB_NETLINK]) {
		mxfsd_netlink_shutdown(&nl_ctx);
		sub_init[SUB_NETLINK] = false;
	}
	if (sub_init[SUB_DLM]) {
		mxfsd_dlm_shutdown(&dlm_ctx);
		sub_init[SUB_DLM] = false;
	}
	if (sub_init[SUB_VOLUME]) {
		mxfsd_volume_shutdown(&volume_ctx);
		sub_init[SUB_VOLUME] = false;
	}
	/* LOG stays up until the very end so shutdown messages are captured */
}

static int init_subsystems(void)
{
	int rc;

	/* Volume tracking */
	rc = mxfsd_volume_init(&volume_ctx, config.node_id);
	if (rc) {
		mxfsd_err("volume init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_VOLUME] = true;

	/* Add configured volumes */
	for (int i = 0; i < config.volume_count; i++) {
		mxfsd_volume_add(&volume_ctx,
				 config.volumes[i].name,
				 config.volumes[i].device);
	}

	/* DLM engine */
	rc = mxfsd_dlm_init(&dlm_ctx, config.node_id, MXFSD_DLM_BUCKETS);
	if (rc) {
		mxfsd_err("DLM init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_DLM] = true;

	/* Netlink to kernel module */
	rc = mxfsd_netlink_init(&nl_ctx);
	if (rc) {
		mxfsd_err("netlink init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_NETLINK] = true;

	/* Peer connections */
	rc = mxfsd_peer_init(&peer_ctx, config.node_id,
			     config.bind_addr, config.bind_port);
	if (rc) {
		mxfsd_err("peer init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_PEER] = true;

	/* Add configured peers */
	for (int i = 0; i < config.peer_count; i++) {
		mxfsd_peer_add(&peer_ctx,
			       config.peers[i].node_id,
			       config.peers[i].host,
			       config.peers[i].port);
	}

	/* Connect to peers with lower node IDs.
	 * Higher-ID nodes connect to us — this prevents simultaneous
	 * outbound connections between the same pair of nodes. */
	for (int i = 0; i < config.peer_count; i++) {
		if (config.peers[i].node_id >= config.node_id)
			continue;
		rc = mxfsd_peer_connect(&peer_ctx, config.peers[i].node_id);
		if (rc)
			mxfsd_warn("initial connect to node %u failed (will retry)",
				   config.peers[i].node_id);
	}

	/* Lease management */
	rc = mxfsd_lease_init(&lease_ctx, config.node_id,
			      config.lease_duration_ms,
			      config.lease_renew_ms,
			      config.node_timeout_ms);
	if (rc) {
		mxfsd_err("lease init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_LEASE] = true;

	mxfsd_lease_set_expire_callback(&lease_ctx, on_lease_expire, NULL);

	/* Register peers with the lease monitor */
	for (int i = 0; i < config.peer_count; i++)
		mxfsd_lease_register_node(&lease_ctx, config.peers[i].node_id);

	/* Journal coordination */
	rc = mxfsd_journal_init(&journal_ctx, config.node_id, MXFS_MAX_NODES);
	if (rc) {
		mxfsd_err("journal init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_JOURNAL] = true;

	rc = mxfsd_journal_claim_slot(&journal_ctx);
	if (rc) {
		mxfsd_err("journal slot claim failed: %d", rc);
		return rc;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *config_path = MXFSD_DEFAULT_CONF;
	const char *command = NULL;
	int foreground = 0;
	int rc;

	static struct option long_opts[] = {
		{ "config",     required_argument, NULL, 'c' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "help",       no_argument,       NULL, 'h' },
		{ NULL,         0,                 NULL,  0  },
	};

	/* Parse command */
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];

	/* Parse options (skip command word) */
	optind = 2;
	int opt;
	while ((opt = getopt_long(argc, argv, "c:fh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (strcmp(command, "stop") == 0) {
		/* Read PID file and send SIGTERM */
		FILE *fp = fopen(MXFSD_PID_FILE, "r");
		if (!fp) {
			fprintf(stderr, "mxfsd: not running (no pid file)\n");
			return 1;
		}
		int pid = 0;
		if (fscanf(fp, "%d", &pid) != 1 || pid <= 0) {
			fprintf(stderr, "mxfsd: invalid pid file\n");
			fclose(fp);
			return 1;
		}
		fclose(fp);
		if (kill(pid, SIGTERM) < 0) {
			fprintf(stderr, "mxfsd: kill(%d, SIGTERM): %s\n",
				pid, strerror(errno));
			return 1;
		}
		printf("mxfsd: sent SIGTERM to pid %d\n", pid);
		return 0;
	}

	if (strcmp(command, "status") == 0) {
		FILE *fp = fopen(MXFSD_PID_FILE, "r");
		if (!fp) {
			printf("mxfsd: not running\n");
			return 1;
		}
		int pid = 0;
		if (fscanf(fp, "%d", &pid) != 1 || pid <= 0) {
			printf("mxfsd: invalid pid file\n");
			fclose(fp);
			return 1;
		}
		fclose(fp);
		if (kill(pid, 0) == 0) {
			printf("mxfsd: running (pid %d)\n", pid);
			return 0;
		}
		printf("mxfsd: stale pid file (pid %d not running)\n", pid);
		return 1;
	}

	if (strcmp(command, "start") != 0) {
		fprintf(stderr, "mxfsd: unknown command '%s'\n", command);
		usage(argv[0]);
		return 1;
	}

	/* ── Start command ────────────────────────────────────────── */

	/* Set config defaults, then load config file */
	mxfsd_config_set_defaults(&config);
	sub_init[SUB_CONFIG] = true;

	rc = mxfsd_config_load(&config, config_path);
	if (rc) {
		fprintf(stderr, "mxfsd: failed to load config '%s'\n",
			config_path);
		return 1;
	}

	/* Init logging early so everything else can log */
	rc = mxfsd_log_init(config.log_file, config.log_level,
			    config.log_to_syslog);
	if (rc) {
		fprintf(stderr, "mxfsd: log init failed\n");
		return 1;
	}
	sub_init[SUB_LOG] = true;

	mxfsd_info("mxfsd v%d.%d.%d starting — node %u (%s)",
		   MXFS_VERSION_MAJOR, MXFS_VERSION_MINOR, MXFS_VERSION_PATCH,
		   config.node_id, config.node_name);

	mxfsd_config_dump(&config);

	/* Daemonize unless --foreground */
	if (!foreground && config.daemonize) {
		if (daemonize() < 0) {
			mxfsd_err("daemonize failed");
			return 1;
		}
	}

	setup_signals();
	write_pid_file();

	/* Init all subsystems */
	rc = init_subsystems();
	if (rc) {
		mxfsd_err("subsystem initialization failed");
		shutdown_subsystems();
		mxfsd_log_shutdown();
		remove_pid_file();
		return 1;
	}

	mxfsd_info("mxfsd fully initialized — entering main loop");

	/* ── Main loop ────────────────────────────────────────────── */
	running = 1;
	int reconnect_counter = 0;
	while (running) {
		if (reload) {
			reload = 0;
			mxfsd_notice("SIGHUP received — reloading config");

			struct mxfsd_config new_cfg;
			mxfsd_config_set_defaults(&new_cfg);
			if (mxfsd_config_load(&new_cfg, config_path) == 0) {
				/* Update log level dynamically */
				mxfsd_log_set_level(new_cfg.log_level);
				mxfsd_info("config reloaded successfully");
			} else {
				mxfsd_warn("config reload failed, "
					   "keeping current config");
			}
		}

		/* Periodically retry connections to disconnected peers.
		 * Only connect to peers with lower IDs (convention). */
		reconnect_counter++;
		if (reconnect_counter >= 20) {  /* every ~5 seconds */
			reconnect_counter = 0;
			for (int i = 0; i < config.peer_count; i++) {
				if (config.peers[i].node_id >= config.node_id)
					continue;
				struct mxfsd_peer *p = mxfsd_peer_find(
					&peer_ctx, config.peers[i].node_id);
				if (p && p->state != MXFSD_CONN_ACTIVE)
					mxfsd_peer_connect(&peer_ctx,
						config.peers[i].node_id);
			}
		}

		/* Sleep in small intervals so we respond to signals promptly */
		usleep(250000);  /* 250ms */
	}

	/* ── Shutdown ─────────────────────────────────────────────── */
	mxfsd_notice("mxfsd shutting down");

	/* Release journal slot before shutting down peers */
	mxfsd_journal_release_slot(&journal_ctx);

	shutdown_subsystems();

	remove_pid_file();

	mxfsd_info("mxfsd shutdown complete");
	mxfsd_log_shutdown();

	return 0;
}
