/*
 * MXFS — Multinode XFS
 * DLM test tool
 *
 * Connects to the local mxfsd daemon via its control socket and
 * issues lock/unlock requests. Used to test distributed locking
 * across nodes.
 *
 * Usage:
 *   mxfs_lock lock  <volume_hex> <ino> <mode>
 *   mxfs_lock unlock <volume_hex> <ino>
 *
 * Modes: NL=0, CR=1, CW=2, PR=3, PW=4, EX=5
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

#include <mxfs/mxfs_common.h>

#define MXFSD_CTRL_SOCKET "/var/run/mxfsd.sock"

/* Must match daemon/mxfsd_main.c ctrl_req/ctrl_resp */
struct ctrl_req {
	uint8_t cmd;      /* 1 = lock, 2 = unlock */
	uint8_t mode;
	uint8_t pad[2];
	uint32_t flags;
	struct mxfs_resource_id resource;
};

struct ctrl_resp {
	uint8_t status;   /* 0 = granted, 1 = denied, 2 = error */
	uint8_t mode;
	uint8_t pad[2];
};

static const char *mode_names[] = {
	"NL", "CR", "CW", "PR", "PW", "EX"
};

static int read_full(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t rem = len;
	while (rem > 0) {
		ssize_t n = read(fd, p, rem);
		if (n <= 0) return -1;
		p += n;
		rem -= (size_t)n;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t rem = len;
	while (rem > 0) {
		ssize_t n = write(fd, p, rem);
		if (n <= 0) return -1;
		p += n;
		rem -= (size_t)n;
	}
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s lock  <volume_hex> <ino> <mode>\n"
		"       %s unlock <volume_hex> <ino>\n"
		"\n"
		"Modes: NL=0, CR=1, CW=2, PR=3, PW=4, EX=5\n"
		"\n"
		"Examples:\n"
		"  %s lock 0xB6CD1234 42 5    # EX lock on inode 42\n"
		"  %s unlock 0xB6CD1234 42    # release\n",
		prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];
	uint64_t volume = strtoull(argv[2], NULL, 0);
	uint64_t ino = strtoull(argv[3], NULL, 0);

	struct ctrl_req req;
	memset(&req, 0, sizeof(req));
	req.resource.volume = volume;
	req.resource.ino = ino;
	req.resource.type = 1; /* MXFS_LTYPE_INODE */

	if (strcmp(cmd, "lock") == 0) {
		if (argc < 5) {
			fprintf(stderr, "lock requires a mode argument\n");
			usage(argv[0]);
			return 1;
		}
		req.cmd = 1;
		req.mode = (uint8_t)atoi(argv[4]);
		if (req.mode >= 6) {
			fprintf(stderr, "invalid mode %d (must be 0-5)\n",
				req.mode);
			return 1;
		}
		printf("Requesting %s lock on volume 0x%lx inode %lu...\n",
		       mode_names[req.mode],
		       (unsigned long)volume,
		       (unsigned long)ino);
	} else if (strcmp(cmd, "unlock") == 0) {
		req.cmd = 2;
		printf("Releasing lock on volume 0x%lx inode %lu...\n",
		       (unsigned long)volume,
		       (unsigned long)ino);
	} else {
		fprintf(stderr, "unknown command '%s'\n", cmd);
		usage(argv[0]);
		return 1;
	}

	/* Connect to daemon control socket */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, MXFSD_CTRL_SOCKET,
	        sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "connect(%s): %s\n"
			"Is mxfsd running?\n",
			MXFSD_CTRL_SOCKET, strerror(errno));
		close(fd);
		return 1;
	}

	/* Send request */
	if (write_full(fd, &req, sizeof(req)) < 0) {
		perror("write");
		close(fd);
		return 1;
	}

	/* Read response */
	struct ctrl_resp resp;
	if (read_full(fd, &resp, sizeof(resp)) < 0) {
		perror("read");
		close(fd);
		return 1;
	}

	close(fd);

	if (resp.status == 0) {
		if (req.cmd == 1)
			printf("GRANTED (mode %s)\n",
			       resp.mode < 6 ? mode_names[resp.mode] : "??");
		else
			printf("RELEASED\n");
		return 0;
	} else if (resp.status == 1) {
		printf("DENIED\n");
		return 1;
	} else {
		printf("ERROR\n");
		return 2;
	}
}
