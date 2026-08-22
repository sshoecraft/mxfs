/*
 * MXFS — Multinode XFS
 * Platform Abstraction Layer — Linux userspace implementation
 *
 * Uses pthreads for threading, POSIX sockets for networking,
 * O_DIRECT file I/O for block device access, and standard C
 * library functions for memory and time.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#define _GNU_SOURCE

#include "pal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>

/* ─── Block device ─── */

struct mxfs_bdev {
    int fd;
    uint64_t base_offset;
    bool is_clone;
    char path[4096];
};

mxfs_bdev_t *mxfs_pal_bdev_open(const char *path)
{
    mxfs_bdev_t *dev;
    int fd;

    if (!path)
        return NULL;

    fd = open(path, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        /* Fall back to non-O_DIRECT if device doesn't support it */
        fd = open(path, O_RDWR | O_SYNC);
        if (fd < 0)
            return NULL;
    }

    dev = calloc(1, sizeof(*dev));
    if (!dev) {
        close(fd);
        return NULL;
    }

    dev->fd = fd;
    strncpy(dev->path, path, sizeof(dev->path) - 1);
    dev->path[sizeof(dev->path) - 1] = '\0';

    return dev;
}

void mxfs_pal_bdev_close(mxfs_bdev_t *dev)
{
    if (!dev)
        return;
    if (dev->fd >= 0 && !dev->is_clone)
        close(dev->fd);
    free(dev);
}

mxfs_bdev_t *mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev,
                                               uint64_t base_offset)
{
    mxfs_bdev_t *clone;

    if (!dev)
        return NULL;

    clone = calloc(1, sizeof(*clone));
    if (!clone)
        return NULL;

    clone->fd = dev->fd;
    clone->base_offset = base_offset;
    clone->is_clone = true;
    /* do NOT copy path — clone doesn't own the fd */

    return clone;
}

void mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev)
{
    if (!dev)
        return;
    /* Don't close the fd — the original owns it */
    free(dev);
}

void mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev,
                                    uint64_t *writes, uint64_t *write_bytes,
                                    uint64_t *writes_fua, uint64_t *write_fua_bytes,
                                    uint64_t *flushes)
{
    (void)dev;
    if (writes) *writes = 0;
    if (write_bytes) *write_bytes = 0;
    if (writes_fua) *writes_fua = 0;
    if (write_fua_bytes) *write_fua_bytes = 0;
    if (flushes) *flushes = 0;
}

int mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset,
                       void *buf, uint32_t len)
{
    ssize_t total = 0;
    ssize_t n;

    if (!dev || dev->fd < 0 || !buf)
        return -EINVAL;

    while ((uint32_t)total < len) {
        n = pread(dev->fd, (char *)buf + total, len - total,
                  (off_t)(offset + dev->base_offset + total));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EIO; /* unexpected EOF */
        total += n;
    }
    return 0;
}

int mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset,
                             void *buf, uint32_t len)
{
    /* Userspace has no I/O priority concept — same as regular read */
    return mxfs_pal_bdev_read(dev, offset, buf, len);
}

int mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset,
                        const void *buf, uint32_t len)
{
    ssize_t total = 0;
    ssize_t n;

    if (!dev || dev->fd < 0 || !buf)
        return -EINVAL;

    while ((uint32_t)total < len) {
        n = pwrite(dev->fd, (const char *)buf + total, len - total,
                   (off_t)(offset + dev->base_offset + total));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EIO;
        total += n;
    }
    return 0;
}

int mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset,
                             const void *buf, uint32_t len)
{
    int ret = mxfs_pal_bdev_write(dev, offset, buf, len);
    if (ret)
        return ret;
    return mxfs_pal_bdev_flush(dev);
}

int mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset,
                               const void *buf, uint32_t len)
{
    /* Userspace: no bio pipelining, delegate to sync write */
    return mxfs_pal_bdev_write(dev, offset, buf, len);
}

int mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev,
                                 const uint64_t *offsets,
                                 void * const *bufs,
                                 const uint32_t *lens,
                                 int count)
{
    int i, ret = 0;
    for (i = 0; i < count; i++) {
        int r = mxfs_pal_bdev_write(dev, offsets[i], bufs[i], lens[i]);
        if (r && !ret) ret = r;
    }
    return ret;
}

int mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset,
                              void *buf, uint32_t len)
{
    /* Userspace: no bio pipelining, delegate to sync read */
    return mxfs_pal_bdev_read(dev, offset, buf, len);
}

int mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset,
                                    void **bufs, int nbufs,
                                    uint32_t blocksize)
{
    int i, ret;

    for (i = 0; i < nbufs; i++) {
        ret = mxfs_pal_bdev_write(dev, offset + (uint64_t)i * blocksize,
                                   bufs[i], blocksize);
        if (ret)
            return ret;
    }
    return mxfs_pal_bdev_flush(dev);
}

int mxfs_pal_bdev_flush(mxfs_bdev_t *dev)
{
    if (!dev || dev->fd < 0)
        return -EINVAL;

    if (fsync(dev->fd) < 0)
        return -errno;
    return 0;
}

int mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out)
{
    struct stat st;

    if (!dev || dev->fd < 0 || !size_out)
        return -EINVAL;

    if (fstat(dev->fd, &st) < 0)
        return -errno;

    if (S_ISBLK(st.st_mode)) {
        if (ioctl(dev->fd, BLKGETSIZE64, size_out) < 0)
            return -errno;
        return 0;
    }

    /* Regular file (for testing with loop devices) */
    *size_out = (uint64_t)st.st_size;
    return 0;
}

/* ─── Memory ─── */

void *mxfs_pal_alloc(size_t size)
{
    if (size == 0)
        return NULL;
    return calloc(1, size);
}

void mxfs_pal_free(void *ptr)
{
    free(ptr);
}

void *mxfs_pal_realloc(void *ptr, size_t new_size)
{
    return realloc(ptr, new_size);
}

/* ─── Threading ─── */

struct mxfs_thread {
    pthread_t tid;
    void (*fn)(void *);
    void *arg;
};

static void *thread_wrapper(void *arg)
{
    struct mxfs_thread *t = arg;

    t->fn(t->arg);
    return NULL;
}

mxfs_thread_t *mxfs_pal_thread_create(void (*fn)(void *), void *arg)
{
    mxfs_thread_t *t;
    int ret;

    if (!fn)
        return NULL;

    t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;

    t->fn = fn;
    t->arg = arg;

    ret = pthread_create(&t->tid, NULL, thread_wrapper, t);
    if (ret != 0) {
        free(t);
        return NULL;
    }

    return t;
}

/*
 * RT-priority thread creation for userspace.
 * Userspace threads are preemptible by default, so RT priority is
 * less critical.  Attempt SCHED_FIFO at lowest priority; fall back
 * silently to normal scheduling if we lack CAP_SYS_NICE.
 */
mxfs_thread_t *mxfs_pal_thread_create_rt(void (*fn)(void *), void *arg)
{
    mxfs_thread_t *t;
    struct sched_param sp;

    t = mxfs_pal_thread_create(fn, arg);
    if (!t)
        return NULL;

    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = sched_get_priority_min(SCHED_FIFO);
    /* Best-effort: don't fail if unprivileged */
    pthread_setschedparam(t->tid, SCHED_FIFO, &sp);

    return t;
}

void mxfs_pal_thread_join(mxfs_thread_t *t)
{
    if (!t)
        return;
    pthread_join(t->tid, NULL);
    free(t);
}

int mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms)
{
    struct timespec ts;
    int ret;

    if (!t)
        return 0;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    ret = pthread_timedjoin_np(t->tid, NULL, &ts);
    if (ret == ETIMEDOUT)
        return -ETIMEDOUT;

    free(t);
    return 0;
}

/* No stable task id for a pthread; callers treat 0 as "unavailable". */
int mxfs_pal_thread_pid(mxfs_thread_t *t)
{
    (void)t;
    return 0;
}

void mxfs_pal_dump_task_stack(int pid)
{
    (void)pid;
}

/* ─── Mutex ─── */

struct mxfs_mutex {
    pthread_mutex_t mtx;
};

mxfs_mutex_t *mxfs_pal_mutex_create(void)
{
    mxfs_mutex_t *m = calloc(1, sizeof(*m));

    if (!m)
        return NULL;

    if (pthread_mutex_init(&m->mtx, NULL) != 0) {
        free(m);
        return NULL;
    }

    return m;
}

void mxfs_pal_mutex_destroy(mxfs_mutex_t *m)
{
    if (!m)
        return;
    pthread_mutex_destroy(&m->mtx);
    free(m);
}

void mxfs_pal_mutex_lock(mxfs_mutex_t *m)
{
    if (m)
        pthread_mutex_lock(&m->mtx);
}

void mxfs_pal_mutex_unlock(mxfs_mutex_t *m)
{
    if (m)
        pthread_mutex_unlock(&m->mtx);
}

/* ─── Spinlock — user-mode has no atomic-context restriction, a plain
 * mutex gives the same mutual-exclusion contract as the kernel spinlock_t
 * without needing pthread_spin_t's stricter (no-recursion-tolerant, busy
 * looping) semantics. ─── */

struct mxfs_spinlock {
    pthread_mutex_t mtx;
};

mxfs_spinlock_t *mxfs_pal_spinlock_create(void)
{
    mxfs_spinlock_t *s = calloc(1, sizeof(*s));

    if (!s)
        return NULL;

    if (pthread_mutex_init(&s->mtx, NULL) != 0) {
        free(s);
        return NULL;
    }

    return s;
}

void mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s)
{
    if (!s)
        return;
    pthread_mutex_destroy(&s->mtx);
    free(s);
}

void mxfs_pal_spinlock_lock(mxfs_spinlock_t *s)
{
    if (s)
        pthread_mutex_lock(&s->mtx);
}

void mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s)
{
    if (s)
        pthread_mutex_unlock(&s->mtx);
}

/* ─── Read-Write Lock ─── */

struct mxfs_rwlock {
    pthread_rwlock_t rwl;
};

mxfs_rwlock_t *mxfs_pal_rwlock_create(void)
{
    mxfs_rwlock_t *rw = calloc(1, sizeof(*rw));

    if (!rw)
        return NULL;

    if (pthread_rwlock_init(&rw->rwl, NULL) != 0) {
        free(rw);
        return NULL;
    }

    return rw;
}

void mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw)
{
    if (!rw)
        return;
    pthread_rwlock_destroy(&rw->rwl);
    free(rw);
}

void mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw)
{
    if (rw)
        pthread_rwlock_rdlock(&rw->rwl);
}

/* ccloop c7ee71c6 sess21 — user mode can always sleep (see pal.h). */
int mxfs_pal_may_sleep(void)
{
    return 1;
}

/* ccloop c7ee71c6 sess21 — non-sleeping read acquire (see pal.h). */
int mxfs_pal_rwlock_tryrdlock(mxfs_rwlock_t *rw)
{
    if (!rw)
        return 0;
    return pthread_rwlock_tryrdlock(&rw->rwl) == 0 ? 1 : 0;
}

void mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw)
{
    if (rw)
        pthread_rwlock_wrlock(&rw->rwl);
}

void mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw)
{
    if (rw)
        pthread_rwlock_unlock(&rw->rwl);
}

/* ─── Condition Variable ─── */

struct mxfs_cond {
    pthread_cond_t cv;
};

mxfs_cond_t *mxfs_pal_cond_create(void)
{
    mxfs_cond_t *c = calloc(1, sizeof(*c));

    if (!c)
        return NULL;

    if (pthread_cond_init(&c->cv, NULL) != 0) {
        free(c);
        return NULL;
    }

    return c;
}

void mxfs_pal_cond_destroy(mxfs_cond_t *c)
{
    if (!c)
        return;
    pthread_cond_destroy(&c->cv);
    free(c);
}

void mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m)
{
    if (c && m)
        pthread_cond_wait(&c->cv, &m->mtx);
}

int mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m,
                            uint64_t timeout_ms)
{
    struct timespec ts;
    int ret;

    if (!c || !m)
        return -EINVAL;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(timeout_ms / 1000);
    ts.tv_nsec += (long)((timeout_ms % 1000) * 1000000);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    ret = pthread_cond_timedwait(&c->cv, &m->mtx, &ts);
    if (ret == ETIMEDOUT)
        return -ETIMEDOUT;
    if (ret != 0)
        return -ret;
    return 0;
}

void mxfs_pal_cond_signal(mxfs_cond_t *c)
{
    if (c)
        pthread_cond_signal(&c->cv);
}

void mxfs_pal_cond_broadcast(mxfs_cond_t *c)
{
    if (c)
        pthread_cond_broadcast(&c->cv);
}

/* ─── TCP Networking ─── */

struct mxfs_sock {
    int fd;
    int is_udp;
};

mxfs_sock_t *mxfs_pal_tcp_connect(const char *host, uint16_t port)
{
    mxfs_sock_t *s;
    struct sockaddr_in addr;
    int fd;
    int ret;

    if (!host)
        return NULL;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return NULL;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    ret = inet_pton(AF_INET, host, &addr.sin_addr);
    if (ret != 1) {
        close(fd);
        return NULL;
    }

    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        return NULL;
    }

    s = calloc(1, sizeof(*s));
    if (!s) {
        close(fd);
        return NULL;
    }

    s->fd = fd;
    s->is_udp = 0;
    return s;
}

mxfs_sock_t *mxfs_pal_tcp_listen(uint16_t port)
{
    mxfs_sock_t *s;
    struct sockaddr_in addr;
    int fd;
    int opt = 1;
    int ret;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return NULL;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        return NULL;
    }

    ret = listen(fd, 16);
    if (ret < 0) {
        close(fd);
        return NULL;
    }

    s = calloc(1, sizeof(*s));
    if (!s) {
        close(fd);
        return NULL;
    }

    s->fd = fd;
    s->is_udp = 0;
    return s;
}

mxfs_sock_t *mxfs_pal_tcp_accept(mxfs_sock_t *listener)
{
    mxfs_sock_t *s;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int fd;

    if (!listener)
        return NULL;

    fd = accept(listener->fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (!s) {
        close(fd);
        return NULL;
    }

    s->fd = fd;
    s->is_udp = 0;
    return s;
}

int mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len)
{
    size_t done = 0;
    ssize_t n;

    if (!s || !buf)
        return -EINVAL;

    while (done < len) {
        n = send(s->fd, (const char *)buf + done, len - done,
                 MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -ECONNRESET;
        done += (size_t)n;
    }
    return 0;
}

int mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len)
{
    size_t done = 0;
    ssize_t n;

    if (!s || !buf)
        return -EINVAL;

    while (done < len) {
        n = recv(s->fd, (char *)buf + done, len - done, MSG_WAITALL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -ECONNRESET;
        done += (size_t)n;
    }
    return 0;
}

void mxfs_pal_tcp_set_opts(mxfs_sock_t *s)
{
    int opt = 1;
    unsigned int timeout = 120000;

    if (!s)
        return;

    /* Increase socket buffers for DLM traffic headroom */
    {
        int bufsize = 4 * 1024 * 1024;
        setsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(s->fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    /* Aggressive keepalive: detect dead peers in ~25 seconds
     * (10s idle + 3 probes * 5s interval) instead of the
     * Linux default of ~2+ hours. */
    opt = 10;
    setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
    opt = 5;
    setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
    opt = 3;
    setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));

    /* TCP_USER_TIMEOUT: abort connection after 120s of unacked data
     * or failed keepalive probes.  Required for reliable dead-peer
     * detection when a node is hard-powered-off (no RST/FIN). */
    setsockopt(s->fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
               &timeout, sizeof(timeout));
}

void mxfs_pal_tcp_shutdown(mxfs_sock_t *s)
{
    if (!s)
        return;
    shutdown(s->fd, SHUT_RDWR);
}

void mxfs_pal_tcp_close(mxfs_sock_t *s)
{
    if (!s)
        return;
    shutdown(s->fd, SHUT_RDWR);
    close(s->fd);
    free(s);
}

int mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if (!s || !buf || buf_len < 16)
        return -EINVAL;

    if (getpeername(s->fd, (struct sockaddr *)&addr, &addrlen) < 0)
        return -errno;

    if (!inet_ntop(AF_INET, &addr.sin_addr, buf, (socklen_t)buf_len))
        return -errno;

    return 0;
}

/* ─── UDP Networking ─── */

mxfs_sock_t *mxfs_pal_udp_open(uint16_t port)
{
    mxfs_sock_t *s;
    struct sockaddr_in addr;
    int fd;
    int opt = 1;
    int ret;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return NULL;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        return NULL;
    }

    s = calloc(1, sizeof(*s));
    if (!s) {
        close(fd);
        return NULL;
    }

    s->fd = fd;
    s->is_udp = 1;
    return s;
}

void mxfs_pal_udp_shutdown(mxfs_sock_t *s)
{
    if (!s)
        return;
    shutdown(s->fd, SHUT_RDWR);
}

void mxfs_pal_udp_close(mxfs_sock_t *s)
{
    if (!s)
        return;
    close(s->fd);
    free(s);
}

int mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len,
                        const char *host, uint16_t port)
{
    struct sockaddr_in dest;
    ssize_t n;

    if (!s || !buf || !host)
        return -EINVAL;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &dest.sin_addr) != 1)
        return -EINVAL;

    n = sendto(s->fd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (n < 0)
        return -errno;
    return 0;
}

int mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len,
                          char *from_host, size_t host_len,
                          uint16_t *from_port)
{
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);
    ssize_t n;

    if (!s || !buf)
        return -EINVAL;

    n = recvfrom(s->fd, buf, len, 0, (struct sockaddr *)&sender, &slen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -ETIMEDOUT;
        return -errno;
    }

    if (from_host && host_len > 0) {
        inet_ntop(AF_INET, &sender.sin_addr, from_host, (socklen_t)host_len);
    }
    if (from_port)
        *from_port = ntohs(sender.sin_port);

    return (int)n;
}

int mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group)
{
    struct ip_mreq mreq;
    uint8_t ttl = 1;
    uint8_t loop = 1;
    int ret;

    if (!s || !group)
        return -EINVAL;

    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) != 1)
        return -EINVAL;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    ret = setsockopt(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                     &mreq, sizeof(mreq));
    if (ret < 0)
        return -errno;

    setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    return 0;
}

int mxfs_pal_udp_set_broadcast(mxfs_sock_t *s)
{
    int opt = 1;

    if (!s)
        return -EINVAL;

    if (setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        return -errno;
    return 0;
}

int mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms)
{
    struct timeval tv;

    if (!s)
        return -EINVAL;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return -errno;
    return 0;
}

/* ─── Time ─── */

uint64_t mxfs_pal_time_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

uint64_t mxfs_pal_time_real_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

void mxfs_pal_sleep_ms(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;

    while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
        ; /* retry on signal */
}

/* User-mode has no TASK_UNINTERRUPTIBLE distinction; the kernel backend's
 * D-state hazard (see pal.h) does not exist here. */
void mxfs_pal_sleep_ms_interruptible(uint32_t ms)
{
    mxfs_pal_sleep_ms(ms);
}

void mxfs_pal_cond_resched(void)
{
    /* Userspace threads are preemptible — no-op */
}

/* ─── Logging ─── */

void mxfs_pal_log(int level, const char *fmt, ...)
{
    va_list ap;
    const char *prefix;
    FILE *out;

    switch (level) {
    case MXFS_LOG_DEBUG: prefix = "DEBUG"; out = stdout; break;
    case MXFS_LOG_INFO:  prefix = "INFO";  out = stdout; break;
    case MXFS_LOG_WARN:  prefix = "WARN";  out = stderr; break;
    case MXFS_LOG_ERR:   prefix = "ERROR"; out = stderr; break;
    default:             prefix = "???";   out = stderr; break;
    }

    fprintf(out, "mxfs [%s]: ", prefix);
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    /* Ensure newline */
    if (fmt[0] != '\0' && fmt[strlen(fmt) - 1] != '\n')
        fprintf(out, "\n");
    fflush(out);
}

/* ─── Fail-stop ─── */

/*
 * sess133: the user-build half of the fail-stop contract (see pal.h).  A tool
 * has no shared-storage state to protect the way a mounted node does, but it
 * must not continue past an invariant it just proved it cannot uphold either —
 * so it aborts, which also leaves a core for the operator.
 */
void mxfs_pal_failstop_fn(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "mxfs FAIL-STOP: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    abort();
}

/* ─── Deferred one-shot call ─── */

struct mxfs_defer_arg {
    void (*fn)(void *);
    void *arg;
};

static void *mxfs_defer_thread(void *p)
{
    struct mxfs_defer_arg *d = p;
    void (*fn)(void *) = d->fn;
    void *arg = d->arg;

    free(d);
    fn(arg);
    return NULL;
}

int mxfs_pal_defer(void (*fn)(void *), void *arg)
{
    struct mxfs_defer_arg *d;
    pthread_attr_t attr;
    pthread_t tid;
    int ret;

    if (!fn)
        return -EINVAL;

    d = calloc(1, sizeof(*d));
    if (!d)
        return -ENOMEM;
    d->fn = fn;
    d->arg = arg;

    /* Detached: nothing joins this, and the caller is told only whether the
     * call was queued — exactly the kernel workqueue semantics. */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&tid, &attr, mxfs_defer_thread, d);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        free(d);
        return -ret;
    }
    return 0;
}

/* ─── Sorting ─── */

void mxfs_pal_sort(void *base, size_t nmemb, size_t size,
                   int (*comp)(const void *, const void *))
{
    qsort(base, nmemb, size, comp);
}

/* ─── SCSI PR ───
 *
 * Linux userspace SCSI PR uses SG_IO ioctl to send SCSI persistent
 * reservation commands directly to the device.
 *
 * PR Service Actions (for PERSISTENT RESERVE OUT, opcode 0x5F):
 *   0x00 = REGISTER
 *   0x01 = RESERVE
 *   0x04 = PREEMPT
 *   0x06 = REGISTER AND IGNORE EXISTING KEY
 *
 * PR Type for RESERVE/PREEMPT:
 *   0x05 = WRITE EXCLUSIVE - REGISTRANTS ONLY
 *
 * PERSISTENT RESERVE IN (opcode 0x5E):
 *   0x00 = READ KEYS
 */

#define PR_OUT_CMD       0x5F
#define PR_IN_CMD        0x5E
#define PR_SA_REGISTER   0x00
#define PR_SA_RESERVE    0x01
#define PR_SA_PREEMPT    0x04
#define PR_SA_PREEMPT_ABORT 0x05
#define PR_SA_REG_IGNORE 0x06
#define PR_SA_READ_KEYS  0x00
#define PR_SA_READ_RESV  0x01
#define PR_SA_READ_FULL_STATUS 0x03
#define PR_TYPE_WR_EX_RO 0x05
#define PR_TYPE_WR_EX_AR 0x07

static int scsi_pr_out(int fd, uint8_t sa, uint64_t key,
                       uint64_t sa_key, uint8_t type)
{
    uint8_t cdb[10];
    uint8_t param[24];
    struct sg_io_hdr io;
    uint8_t sense[32];
    int ret;

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = PR_OUT_CMD;
    cdb[1] = sa;
    /* SPC PROUT CDB byte 2 = SCOPE (bits 7-4) | TYPE (bits 3-0).  LU_SCOPE
     * is 0, so the type belongs in the LOW nibble.  sess381: this backend
     * shifted it into the SCOPE field, which sent scope=<type>, type=0 on
     * every PROUT — the kernel backend and upstream sd_pr_out_command()
     * (`cmd[2] = type`) both put it low. */
    cdb[2] = type & 0x0F;
    /* Parameter list length = 24 */
    cdb[7] = 0;
    cdb[8] = 24;

    memset(param, 0, sizeof(param));
    /* Reservation key (current) at offset 0, big-endian */
    param[0] = (uint8_t)(key >> 56);
    param[1] = (uint8_t)(key >> 48);
    param[2] = (uint8_t)(key >> 40);
    param[3] = (uint8_t)(key >> 32);
    param[4] = (uint8_t)(key >> 24);
    param[5] = (uint8_t)(key >> 16);
    param[6] = (uint8_t)(key >> 8);
    param[7] = (uint8_t)(key);
    /* Service action reservation key at offset 8 */
    param[8]  = (uint8_t)(sa_key >> 56);
    param[9]  = (uint8_t)(sa_key >> 48);
    param[10] = (uint8_t)(sa_key >> 40);
    param[11] = (uint8_t)(sa_key >> 32);
    param[12] = (uint8_t)(sa_key >> 24);
    param[13] = (uint8_t)(sa_key >> 16);
    param[14] = (uint8_t)(sa_key >> 8);
    param[15] = (uint8_t)(sa_key);

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = sizeof(param);
    io.dxferp = param;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000; /* 30 seconds */

    ret = ioctl(fd, SG_IO, &io);
    if (ret < 0)
        return -errno;

    if (io.status != 0) {
        /* Check for RESERVATION CONFLICT (status 0x18) */
        if (io.status == 0x18 || io.masked_status == 0x0C)
            return -EBUSY;
        return -EIO;
    }

    return 0;
}

static int scsi_pr_in_read_keys(int fd, uint64_t *keys, int max_keys,
                                int *count, uint32_t *generation, int *total)
{
    uint8_t cdb[10];
    uint8_t *resp;
    struct sg_io_hdr io;
    uint8_t sense[32];
    uint32_t resp_len;
    uint32_t addl_len;
    int nkeys;
    int i;
    int ret;

    resp_len = 8 + (uint32_t)max_keys * 8;
    resp = calloc(1, resp_len);
    if (!resp)
        return -ENOMEM;

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = PR_IN_CMD;
    cdb[1] = PR_SA_READ_KEYS;
    cdb[7] = (uint8_t)((resp_len >> 8) & 0xFF);
    cdb[8] = (uint8_t)(resp_len & 0xFF);

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = resp_len;
    io.dxferp = resp;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000;

    ret = ioctl(fd, SG_IO, &io);
    if (ret < 0) {
        free(resp);
        return -errno;
    }

    if (io.status != 0) {
        free(resp);
        return -EIO;
    }

    /* Parse response: 4-byte generation, 4-byte additional length, then keys */
    if (generation)
        *generation = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                      ((uint32_t)resp[2] << 8) | (uint32_t)resp[3];

    addl_len = ((uint32_t)resp[4] << 24) | ((uint32_t)resp[5] << 16) |
               ((uint32_t)resp[6] << 8) | (uint32_t)resp[7];

    /* ADDITIONAL LENGTH counts every descriptor the TARGET holds, not the
     * number that fit in our allocation.  Report it so the caller can tell
     * a complete view from a truncated one — see the contract in pal.h. */
    if (total)
        *total = (int)(addl_len / 8);

    nkeys = (int)(addl_len / 8);
    if (nkeys > max_keys)
        nkeys = max_keys;

    for (i = 0; i < nkeys; i++) {
        int off = 8 + i * 8;

        keys[i] = ((uint64_t)resp[off] << 56) |
                  ((uint64_t)resp[off + 1] << 48) |
                  ((uint64_t)resp[off + 2] << 40) |
                  ((uint64_t)resp[off + 3] << 32) |
                  ((uint64_t)resp[off + 4] << 24) |
                  ((uint64_t)resp[off + 5] << 16) |
                  ((uint64_t)resp[off + 6] << 8) |
                  (uint64_t)resp[off + 7];
    }

    *count = nkeys;
    free(resp);
    return 0;
}

int mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key)
{
    if (!dev)
        return -EINVAL;
    /* REGISTER AND IGNORE EXISTING KEY: old_key=0, new_key=key */
    return scsi_pr_out(dev->fd, PR_SA_REG_IGNORE, 0, key, 0);
}

int mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key, uint32_t type)
{
    if (!dev)
        return -EINVAL;
    if (type != PR_TYPE_WR_EX_RO && type != PR_TYPE_WR_EX_AR)
        return -EINVAL;

    /* sess381: RESERVATION CONFLICT is returned VERBATIM as -EBUSY, not
     * folded into 0.  See the contract in pal.h — under an all-registrants
     * type a conflict from a registered requester is abnormal and means the
     * reservation in force has the wrong type/scope, or our registration is
     * gone.  Only the caller can read back and classify that. */
    return scsi_pr_out(dev->fd, PR_SA_RESERVE, key, 0, (uint8_t)type);
}

int mxfs_pal_scsi_pr_report_capabilities(mxfs_bdev_t *dev,
                                         struct mxfs_pal_pr_caps *out)
{
    uint8_t cdb[10];
    uint8_t resp[8];
    struct sg_io_hdr io;
    uint8_t sense[32];
    int ret;

    if (!dev || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    /* User-mode talks to the device node directly, so if we can issue the
     * CDB at all we can issue PREEMPT AND ABORT too. */
    out->abort_capable = true;

    memset(cdb, 0, sizeof(cdb));
    memset(resp, 0, sizeof(resp));
    cdb[0] = PR_IN_CMD;
    cdb[1] = 0x02;                      /* REPORT CAPABILITIES */
    cdb[7] = (uint8_t)((sizeof(resp) >> 8) & 0xFF);
    cdb[8] = (uint8_t)(sizeof(resp) & 0xFF);

    memset(&io, 0, sizeof(io));
    memset(sense, 0, sizeof(sense));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = sizeof(resp);
    io.dxferp = resp;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000;

    if (ioctl(dev->fd, SG_IO, &io) < 0)
        return -errno;
    if (io.status == 0x02 /* CHECK CONDITION */) {
        /* ILLEGAL REQUEST -> the target does not implement SA 0x02. */
        if (io.sb_len_wr > 2 && (sense[2] & 0x0F) == 0x05)
            return -EOPNOTSUPP;
        return -EIO;
    }
    if (io.status != 0)
        return -EIO;

    out->ptpl_c    = !!(resp[2] & 0x01);
    out->atp_c     = !!(resp[2] & 0x04);
    out->sip_c     = !!(resp[2] & 0x08);
    out->crh       = !!(resp[2] & 0x10);
    out->ptpl_a    = !!(resp[3] & 0x01);
    out->tmv       = !!(resp[3] & 0x80);
    out->type_mask = ((uint16_t)resp[4] << 8) | (uint16_t)resp[5];
    out->we_ro     = out->tmv && !!(resp[4] & 0x20);
    /* WR_EX_AR is type 7h == byte 4 bit 7 (sess381). */
    out->we_ar     = out->tmv && !!(resp[4] & 0x80);
    (void)ret;
    return 0;
}

int mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key,
                             uint64_t victim_key, bool abort, uint32_t type)
{
    if (!dev)
        return -EINVAL;
    if (type != PR_TYPE_WR_EX_RO && type != PR_TYPE_WR_EX_AR)
        return -EINVAL;

    /*
     * RESERVATION CONFLICT comes back as -EBUSY and is returned VERBATIM:
     * our command performed nothing, so it is not a fence.  See the
     * contract in pal.h — collapsing it to 0 was the sess71 defect.
     */
    return scsi_pr_out(dev->fd, abort ? PR_SA_PREEMPT_ABORT : PR_SA_PREEMPT,
                       my_key, victim_key, (uint8_t)type);
}

int mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key)
{
    int ret;

    if (!dev)
        return -EINVAL;

    /* Unregister: old_key=key, new_key=0 */
    ret = scsi_pr_out(dev->fd, PR_SA_REGISTER, key, 0, 0);

    /* RESERVATION CONFLICT: key already gone (preempted or
     * previously unregistered). Desired outcome. */
    if (ret == -EBUSY)
        return 0;

    return ret;
}

int mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys,
                               int max_keys, int *count, uint32_t *generation,
                               int *total)
{
    if (!dev || !keys || !count)
        return -EINVAL;
    return scsi_pr_in_read_keys(dev->fd, keys, max_keys, count, generation,
                                total);
}

/*
 * PERSISTENT RESERVE IN / READ RESERVATION (service action 0x01).
 *
 * Response: 4-byte PR GENERATION, 4-byte ADDITIONAL LENGTH, then — only
 * when a reservation is held — a 16-byte descriptor whose bytes 0..7 are
 * the holder key and whose byte 13 low nibble is the SCSI TYPE.  An
 * ADDITIONAL LENGTH of 0 means the LUN is NOT reserved, which is a
 * successful read reporting "none held", not an error.
 */
int mxfs_pal_scsi_pr_read_reservation(mxfs_bdev_t *dev,
                                      struct mxfs_pal_pr_reservation *out)
{
    uint8_t cdb[10];
    uint8_t resp[24];
    struct sg_io_hdr io;
    uint8_t sense[32];
    uint32_t addl_len;
    int ret;

    if (!dev || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    memset(resp, 0, sizeof(resp));

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = PR_IN_CMD;
    cdb[1] = PR_SA_READ_RESV;
    cdb[7] = (uint8_t)((sizeof(resp) >> 8) & 0xFF);
    cdb[8] = (uint8_t)(sizeof(resp) & 0xFF);

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = sizeof(resp);
    io.dxferp = resp;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000;

    ret = ioctl(dev->fd, SG_IO, &io);
    if (ret < 0)
        return -errno;
    if (io.status != 0)
        return -EIO;

    out->generation = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                      ((uint32_t)resp[2] << 8) | (uint32_t)resp[3];

    addl_len = ((uint32_t)resp[4] << 24) | ((uint32_t)resp[5] << 16) |
               ((uint32_t)resp[6] << 8) | (uint32_t)resp[7];
    if (addl_len < 16)
        return 0;                       /* no reservation held */

    out->key = ((uint64_t)resp[8] << 56) | ((uint64_t)resp[9] << 48) |
               ((uint64_t)resp[10] << 40) | ((uint64_t)resp[11] << 32) |
               ((uint64_t)resp[12] << 24) | ((uint64_t)resp[13] << 16) |
               ((uint64_t)resp[14] << 8) | (uint64_t)resp[15];
    /* Response byte 21 low nibble is TYPE — already the SCSI WIRE value,
     * which is the space the PAL contract exposes.  (The kernel backend
     * has to translate; this one does not.) */
    out->type = (uint32_t)(resp[21] & 0x0F);
    out->held = true;

    return 0;
}

/*
 * PERSISTENT RESERVE IN / READ FULL STATUS (service action 0x03).
 * See the contract in pal.h.  Response: 4-byte PR GENERATION, 4-byte
 * ADDITIONAL LENGTH, then full-status descriptors of 24 fixed bytes +
 * ADDITIONAL DESCRIPTOR LENGTH (bytes 20-23) of TransportID each.
 */
int mxfs_pal_scsi_pr_read_full_status(mxfs_bdev_t *dev, uint64_t key,
                                      int *present, uint32_t *generation)
{
    uint8_t cdb[10];
    uint8_t *resp;
    size_t resp_len = 4096;
    struct sg_io_hdr io;
    uint8_t sense[32];
    uint32_t addl_len;
    size_t off, end;
    int resized = 0;
    int ret;

    if (!dev || dev->fd < 0 || !present)
        return -EINVAL;

    *present = 0;
    if (generation)
        *generation = 0;

resize:
    resp = calloc(1, resp_len);
    if (!resp)
        return -ENOMEM;

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = PR_IN_CMD;
    cdb[1] = PR_SA_READ_FULL_STATUS;
    cdb[7] = (uint8_t)((resp_len >> 8) & 0xFF);
    cdb[8] = (uint8_t)(resp_len & 0xFF);

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = (unsigned int)resp_len;
    io.dxferp = resp;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000;

    ret = ioctl(dev->fd, SG_IO, &io);
    if (ret < 0) {
        free(resp);
        return -errno;
    }
    if (io.status != 0) {
        /* ILLEGAL REQUEST sense → target lacks SA 0x03; caller falls
         * back to READ KEYS. */
        free(resp);
        if (io.status == 0x02 && (sense[2] & 0x0F) == 0x05)
            return -EOPNOTSUPP;
        return -EIO;
    }

    if (generation)
        *generation = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                      ((uint32_t)resp[2] << 8) | (uint32_t)resp[3];
    addl_len = ((uint32_t)resp[4] << 24) | ((uint32_t)resp[5] << 16) |
               ((uint32_t)resp[6] << 8) | (uint32_t)resp[7];

    /* Truncated view proves nothing about absence — resize once to the
     * reported length and reissue. */
    if (8 + (size_t)addl_len > resp_len) {
        free(resp);
        if (resized++ || addl_len > (1u << 20))
            return -EPROTO;
        resp_len = ((8 + (size_t)addl_len) + 511) & ~(size_t)511;
        goto resize;
    }

    off = 8;
    end = 8 + (size_t)addl_len;
    while (off + 24 <= end) {
        uint64_t dkey =
            ((uint64_t)resp[off]     << 56) | ((uint64_t)resp[off + 1] << 48) |
            ((uint64_t)resp[off + 2] << 40) | ((uint64_t)resp[off + 3] << 32) |
            ((uint64_t)resp[off + 4] << 24) | ((uint64_t)resp[off + 5] << 16) |
            ((uint64_t)resp[off + 6] << 8)  |  (uint64_t)resp[off + 7];
        uint32_t tid_len =
            ((uint32_t)resp[off + 20] << 24) | ((uint32_t)resp[off + 21] << 16) |
            ((uint32_t)resp[off + 22] << 8)  |  (uint32_t)resp[off + 23];

        if (dkey == key) {
            *present = 1;
            break;
        }
        if (off + 24 + (size_t)tid_len > end) {
            free(resp);
            return -EPROTO;         /* descriptor overruns payload */
        }
        off += 24 + tid_len;
    }

    free(resp);
    return 0;
}

/* ─── SCSI COMPARE AND WRITE ───
 *
 * Atomic compare-and-swap at sector granularity using SG_IO.
 * CDB: 16 bytes, opcode 0x89.
 * Data-out buffer: 1024 bytes (512 compare + 512 write).
 * MISCOMPARE sense key (0x0E) → -EAGAIN for caller retry.
 */

/* User mode issues SG_IO through the device node (the kernel forwards a
 * dm ioctl to an underlying path itself) — nothing cached, nothing to drop. */
void mxfs_pal_sdev_cache_release(void)
{
}

int mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset,
                                     const void *compare_buf,
                                     const void *write_buf)
{
    uint8_t cdb[16];
    uint8_t data[1024];
    struct sg_io_hdr io;
    uint8_t sense[32];
    uint64_t lba;
    int ret;

    if (!dev || dev->fd < 0 || !compare_buf || !write_buf)
        return -EINVAL;

    lba = (offset + dev->base_offset) / 512;

    /* Build COMPARE AND WRITE CDB (16 bytes) */
    memset(cdb, 0, sizeof(cdb));
    cdb[0]  = 0x89;                     /* COMPARE AND WRITE opcode */
    cdb[1]  = 0x08;                     /* FUA bit set */
    cdb[2]  = (uint8_t)(lba >> 56);     /* LBA bytes 2-9 (big-endian) */
    cdb[3]  = (uint8_t)(lba >> 48);
    cdb[4]  = (uint8_t)(lba >> 40);
    cdb[5]  = (uint8_t)(lba >> 32);
    cdb[6]  = (uint8_t)(lba >> 24);
    cdb[7]  = (uint8_t)(lba >> 16);
    cdb[8]  = (uint8_t)(lba >> 8);
    cdb[9]  = (uint8_t)(lba);
    cdb[13] = 0x01;                     /* number of logical blocks = 1 */

    /* Data buffer: compare_buf (512) followed by write_buf (512) */
    memcpy(data, compare_buf, 512);
    memcpy(data + 512, write_buf, 512);

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.dxfer_len = sizeof(data);
    io.dxferp = data;
    io.sbp = sense;
    io.mx_sb_len = sizeof(sense);
    io.timeout = 30000; /* 30 seconds */

    ret = ioctl(dev->fd, SG_IO, &io);
    if (ret < 0)
        return -errno;

    if (io.status != 0) {
        /* Parse sense data for MISCOMPARE */
        if (io.sb_len_wr > 0) {
            uint8_t sense_key = 0;

            if ((sense[0] & 0x7F) == 0x70 || (sense[0] & 0x7F) == 0x71) {
                /* Fixed format sense data */
                sense_key = sense[2] & 0x0F;
            } else if ((sense[0] & 0x7F) == 0x72 ||
                       (sense[0] & 0x7F) == 0x73) {
                /* Descriptor format sense data */
                sense_key = sense[1] & 0x0F;
            }

            if (sense_key == 0x0E) /* MISCOMPARE */
                return -EAGAIN;
        }
        return -EIO;
    }

    return 0;
}

/* ─── Hostname ─── */

int mxfs_pal_get_hostname(char *buf, size_t len)
{
    if (!buf || len == 0)
        return -EINVAL;
    if (gethostname(buf, len) < 0)
        return -errno;
    buf[len - 1] = '\0';
    return 0;
}

int mxfs_pal_read_file(const char *path, void *buf, size_t buf_size)
{
    FILE *f;
    size_t nread;

    if (!path || !buf || buf_size == 0)
        return -EINVAL;

    f = fopen(path, "rb");
    if (!f)
        return -errno;

    nread = fread(buf, 1, buf_size, f);
    fclose(f);

    if (nread == 0)
        return -EIO;

    return (int)nread;
}

/* ─── Random bytes ─── */

void mxfs_pal_get_random_bytes(void *buf, size_t len)
{
    int fd;
    size_t done = 0;
    ssize_t n;

    if (!buf || len == 0)
        return;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Last resort: zero-fill (should never happen on Linux) */
        memset(buf, 0, len);
        return;
    }

    while (done < len) {
        n = read(fd, (char *)buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        done += (size_t)n;
    }

    close(fd);
}

/* ─── CRC32C (Castagnoli) ─── */

/*
 * Must match the kernel PAL exactly: linux crc32c() is the raw
 * reflected-table CRC with poly 0x82F63B78, seed passed as-is, no
 * pre/post inversion (lib/crc/crc32-main.c::crc32c_base).
 */
static uint32_t crc32c_table[256];
static pthread_once_t crc32c_once = PTHREAD_ONCE_INIT;

static void crc32c_table_init(void)
{
    uint32_t i, j, c;

    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
        crc32c_table[i] = c;
    }
}

uint32_t mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;

    pthread_once(&crc32c_once, crc32c_table_init);
    while (len--)
        crc = (crc >> 8) ^ crc32c_table[(crc & 0xFF) ^ *p++];
    return crc;
}
