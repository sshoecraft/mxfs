/*
 * MXFS — Multinode XFS
 * DLM overhead benchmark
 *
 * Measures filesystem I/O latency with and without DLM lock
 * acquisition to quantify locking overhead.
 *
 * Usage: mxfs_bench <test_dir> <num_files> <iterations>
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

#include <mxfs/mxfs_common.h>

#define MXFSD_CTRL_SOCKET "/var/run/mxfsd.sock"
#define FILE_SIZE         4096
#define READ_BUF_SIZE     4096

struct ctrl_req {
	uint8_t cmd;
	uint8_t mode;
	uint8_t pad[2];
	uint32_t flags;
	struct mxfs_resource_id resource;
};

struct ctrl_resp {
	uint8_t status;
	uint8_t mode;
	uint8_t pad[2];
};

struct bench_stats {
	double min_us;
	double max_us;
	double total_us;
	int count;
};

static void stats_init(struct bench_stats *s)
{
	s->min_us = 1e12;
	s->max_us = 0;
	s->total_us = 0;
	s->count = 0;
}

static void stats_add(struct bench_stats *s, double us)
{
	if (us < s->min_us) s->min_us = us;
	if (us > s->max_us) s->max_us = us;
	s->total_us += us;
	s->count++;
}

static double stats_avg(struct bench_stats *s)
{
	return s->count > 0 ? s->total_us / s->count : 0;
}

static double now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1000.0;
}

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

/* Connect to mxfsd control socket, send lock/unlock, get response */
static int dlm_op(uint8_t cmd, uint8_t mode, uint64_t volume, uint64_t ino)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, MXFSD_CTRL_SOCKET, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	struct ctrl_req req;
	memset(&req, 0, sizeof(req));
	req.cmd = cmd;
	req.mode = mode;
	req.resource.volume = volume;
	req.resource.ino = ino;
	req.resource.type = 1;

	if (write_full(fd, &req, sizeof(req)) < 0) {
		close(fd);
		return -1;
	}

	struct ctrl_resp resp;
	if (read_full(fd, &resp, sizeof(resp)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return resp.status == 0 ? 0 : -1;
}

static int dlm_lock(uint64_t volume, uint64_t ino, uint8_t mode)
{
	return dlm_op(1, mode, volume, ino);
}

static int dlm_unlock(uint64_t volume, uint64_t ino)
{
	return dlm_op(2, 0, volume, ino);
}

static void print_stats(const char *label, struct bench_stats *s)
{
	printf("  %-28s  %8d ops  %8.1f us avg  %8.1f us min  %8.1f us max  %8.0f ops/sec\n",
	       label, s->count, stats_avg(s), s->min_us, s->max_us,
	       s->count > 0 ? 1e6 / stats_avg(s) : 0);
}

static void print_comparison(const char *label,
                             struct bench_stats *base,
                             struct bench_stats *locked)
{
	double base_avg = stats_avg(base);
	double lock_avg = stats_avg(locked);
	double overhead = lock_avg - base_avg;
	double pct = base_avg > 0 ? (overhead / base_avg) * 100.0 : 0;

	printf("  %-28s  base=%7.1f us  locked=%7.1f us  overhead=%7.1f us  (%.1f%%)\n",
	       label, base_avg, lock_avg, overhead, pct);
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr,
			"Usage: %s <test_dir> <num_files> <iterations>\n"
			"\n"
			"Benchmarks filesystem I/O with and without DLM locking.\n"
			"Creates test files in <test_dir>, runs <iterations> of each\n"
			"operation across <num_files> files.\n"
			"\n"
			"Requires mxfsd running with control socket.\n",
			argv[0]);
		return 1;
	}

	const char *test_dir = argv[1];
	int num_files = atoi(argv[2]);
	int iterations = atoi(argv[3]);

	if (num_files < 1 || num_files > 1000) {
		fprintf(stderr, "num_files must be 1-1000\n");
		return 1;
	}
	if (iterations < 1 || iterations > 100000) {
		fprintf(stderr, "iterations must be 1-100000\n");
		return 1;
	}

	/* Check control socket */
	struct stat sb;
	int have_dlm = (stat(MXFSD_CTRL_SOCKET, &sb) == 0);
	if (!have_dlm) {
		fprintf(stderr, "WARNING: %s not found, skipping locked tests\n",
			MXFSD_CTRL_SOCKET);
	}

	uint64_t volume = 0xBEEF0001;

	printf("=== MXFS DLM Overhead Benchmark ===\n");
	printf("Directory: %s\n", test_dir);
	printf("Files: %d, Iterations: %d\n", num_files, iterations);
	printf("DLM available: %s\n\n", have_dlm ? "yes" : "no");

	/* --- Phase 1: Create test files --- */
	printf("Creating %d test files (%d bytes each)...\n", num_files, FILE_SIZE);
	char **paths = calloc(num_files, sizeof(char *));
	char buf[FILE_SIZE];

	/* Fill buffer with pattern */
	for (int i = 0; i < FILE_SIZE; i++)
		buf[i] = (char)(i & 0xFF);

	for (int i = 0; i < num_files; i++) {
		paths[i] = malloc(512);
		snprintf(paths[i], 512, "%s/bench_%04d.dat", test_dir, i);

		int fd = open(paths[i], O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd < 0) {
			fprintf(stderr, "open(%s): %s\n", paths[i], strerror(errno));
			return 1;
		}
		if (write_full(fd, buf, FILE_SIZE) < 0) {
			fprintf(stderr, "write(%s): %s\n", paths[i], strerror(errno));
			close(fd);
			return 1;
		}
		fsync(fd);
		close(fd);
	}

	/* Drop page cache so we measure actual I/O on first pass */
	sync();
	int drop = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (drop >= 0) {
		ssize_t wr __attribute__((unused)) = write(drop, "3", 1);
		close(drop);
	}

	printf("Test files created.\n\n");

	/* --- Phase 2: Baseline (no locks) --- */
	struct bench_stats base_read, base_write, base_stat, base_open_read;
	stats_init(&base_read);
	stats_init(&base_write);
	stats_init(&base_stat);
	stats_init(&base_open_read);

	printf("--- Baseline (no DLM locks) ---\n");

	/* Sequential read: open, read entire file, close */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			double t0 = now_us();
			int fd = open(paths[i], O_RDONLY);
			if (fd < 0) continue;
			char rbuf[READ_BUF_SIZE];
			ssize_t n;
			while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
				;
			close(fd);
			double elapsed = now_us() - t0;
			stats_add(&base_open_read, elapsed);
		}
	}
	print_stats("open+read+close (seq)", &base_open_read);

	/* Random read: open a random file, read 4K at offset 0 */
	srand(42);
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			int idx = rand() % num_files;
			double t0 = now_us();
			int fd = open(paths[idx], O_RDONLY);
			if (fd < 0) continue;
			char rbuf[READ_BUF_SIZE];
			if (read(fd, rbuf, sizeof(rbuf)) < 0) { /* ignore */ }
			close(fd);
			double elapsed = now_us() - t0;
			stats_add(&base_read, elapsed);
		}
	}
	print_stats("open+read+close (rand)", &base_read);

	/* Write: open, overwrite file, fsync, close */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			double t0 = now_us();
			int fd = open(paths[i], O_WRONLY);
			if (fd < 0) continue;
			(void)write_full(fd, buf, FILE_SIZE);
			fsync(fd);
			close(fd);
			double elapsed = now_us() - t0;
			stats_add(&base_write, elapsed);
		}
	}
	print_stats("open+write+fsync+close", &base_write);

	/* Stat */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			double t0 = now_us();
			struct stat st;
			(void)stat(paths[i], &st);
			double elapsed = now_us() - t0;
			stats_add(&base_stat, elapsed);
		}
	}
	print_stats("stat", &base_stat);

	printf("\n");

	if (!have_dlm) {
		printf("No DLM available — skipping locked tests.\n");
		goto cleanup;
	}

	/* --- Phase 3: With DLM locks (PR for reads, EX for writes) --- */
	struct bench_stats lock_read, lock_write, lock_stat, lock_open_read;
	struct bench_stats lock_only, unlock_only;
	stats_init(&lock_read);
	stats_init(&lock_write);
	stats_init(&lock_stat);
	stats_init(&lock_open_read);
	stats_init(&lock_only);
	stats_init(&unlock_only);

	printf("--- With DLM locks (PR=read, EX=write) ---\n");

	/* Measure pure lock/unlock overhead first */
	printf("  (measuring pure lock/unlock latency first...)\n");
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			uint64_t ino = 10000 + (uint64_t)i;

			double t0 = now_us();
			if (dlm_lock(volume, ino, 3 /* PR */) < 0) {
				fprintf(stderr, "dlm_lock failed for ino %lu\n",
					(unsigned long)ino);
				continue;
			}
			double t1 = now_us();
			stats_add(&lock_only, t1 - t0);

			t0 = now_us();
			dlm_unlock(volume, ino);
			t1 = now_us();
			stats_add(&unlock_only, t1 - t0);
		}
	}
	print_stats("lock only (PR)", &lock_only);
	print_stats("unlock only", &unlock_only);
	printf("\n");

	/* Sequential read with PR lock */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			uint64_t ino = 10000 + (uint64_t)i;
			double t0 = now_us();

			if (dlm_lock(volume, ino, 3 /* PR */) < 0) continue;

			int fd = open(paths[i], O_RDONLY);
			if (fd >= 0) {
				char rbuf[READ_BUF_SIZE];
				ssize_t n;
				while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
					;
				close(fd);
			}

			dlm_unlock(volume, ino);

			double elapsed = now_us() - t0;
			stats_add(&lock_open_read, elapsed);
		}
	}
	print_stats("lock+read+unlock (seq)", &lock_open_read);

	/* Random read with PR lock */
	srand(42);
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			int idx = rand() % num_files;
			uint64_t ino = 10000 + (uint64_t)idx;
			double t0 = now_us();

			if (dlm_lock(volume, ino, 3 /* PR */) < 0) continue;

			int fd = open(paths[idx], O_RDONLY);
			if (fd >= 0) {
				char rbuf[READ_BUF_SIZE];
				if (read(fd, rbuf, sizeof(rbuf)) < 0) { /* ignore */ }
				close(fd);
			}

			dlm_unlock(volume, ino);

			double elapsed = now_us() - t0;
			stats_add(&lock_read, elapsed);
		}
	}
	print_stats("lock+read+unlock (rand)", &lock_read);

	/* Write with EX lock */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			uint64_t ino = 10000 + (uint64_t)i;
			double t0 = now_us();

			if (dlm_lock(volume, ino, 5 /* EX */) < 0) continue;

			int fd = open(paths[i], O_WRONLY);
			if (fd >= 0) {
				(void)write_full(fd, buf, FILE_SIZE);
				fsync(fd);
				close(fd);
			}

			dlm_unlock(volume, ino);

			double elapsed = now_us() - t0;
			stats_add(&lock_write, elapsed);
		}
	}
	print_stats("lock+write+fsync+unlock", &lock_write);

	/* Stat with PR lock */
	for (int iter = 0; iter < iterations; iter++) {
		for (int i = 0; i < num_files; i++) {
			uint64_t ino = 10000 + (uint64_t)i;
			double t0 = now_us();

			if (dlm_lock(volume, ino, 3 /* PR */) < 0) continue;

			struct stat st;
			(void)stat(paths[i], &st);

			dlm_unlock(volume, ino);

			double elapsed = now_us() - t0;
			stats_add(&lock_stat, elapsed);
		}
	}
	print_stats("lock+stat+unlock", &lock_stat);

	printf("\n");

	/* --- Phase 4: Comparison --- */
	printf("--- Overhead Summary ---\n");
	print_comparison("sequential read", &base_open_read, &lock_open_read);
	print_comparison("random read", &base_read, &lock_read);
	print_comparison("write+fsync", &base_write, &lock_write);
	print_comparison("stat", &base_stat, &lock_stat);

	double lock_avg = stats_avg(&lock_only);
	double unlock_avg = stats_avg(&unlock_only);
	printf("\n  Pure lock round-trip:   %.1f us (lock) + %.1f us (unlock) = %.1f us total\n",
	       lock_avg, unlock_avg, lock_avg + unlock_avg);

cleanup:
	/* Clean up test files */
	printf("\nCleaning up test files...\n");
	for (int i = 0; i < num_files; i++) {
		unlink(paths[i]);
		free(paths[i]);
	}
	free(paths);

	return 0;
}
