/*
 * MXFS — Multinode XFS
 * Public API for frontend implementations
 *
 * This is the primary interface that platform-specific frontends
 * (Linux VFS, macOS FSKit, Windows WinFSP) use to interact with
 * the portable MXFS library. All filesystem operations go through
 * this API.
 *
 * Usage:
 *   1. Call mxfs_mount() with device path and options
 *   2. Perform filesystem operations via the API functions
 *   3. Call mxfs_unmount() to cleanly shut down
 *
 * Thread safety: All functions are thread-safe. Multiple threads
 * may call any function concurrently.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_MXFS_H
#define MXFS_LIBMXFS_MXFS_H

#include "../pal/pal.h"

/* Opaque mount handle */
struct mxfs_mount;

/* Forward declaration for range-based block map */
struct mxfs_extent_range;

/* ─── File types ─── */

#define MXFS_FT_UNKNOWN   0
#define MXFS_FT_REG_FILE  1
#define MXFS_FT_DIR       2
#define MXFS_FT_CHRDEV    3
#define MXFS_FT_BLKDEV    4
#define MXFS_FT_FIFO      5
#define MXFS_FT_SOCK      6
#define MXFS_FT_SYMLINK   7

/* ─── Mode bits (POSIX compatible) ─── */

#define MXFS_S_IFMT    0170000
#define MXFS_S_IFSOCK  0140000
#define MXFS_S_IFLNK   0120000
#define MXFS_S_IFREG   0100000
#define MXFS_S_IFBLK   0060000
#define MXFS_S_IFDIR   0040000
#define MXFS_S_IFCHR   0020000
#define MXFS_S_IFIFO   0010000

#define MXFS_S_ISUID   04000
#define MXFS_S_ISGID   02000
#define MXFS_S_ISVTX   01000

#define MXFS_S_IRWXU   00700
#define MXFS_S_IRUSR   00400
#define MXFS_S_IWUSR   00200
#define MXFS_S_IXUSR   00100
#define MXFS_S_IRWXG   00070
#define MXFS_S_IRGRP   00040
#define MXFS_S_IWGRP   00020
#define MXFS_S_IXGRP   00010
#define MXFS_S_IRWXO   00007
#define MXFS_S_IROTH   00004
#define MXFS_S_IWOTH   00002
#define MXFS_S_IXOTH   00001

#define MXFS_S_ISDIR(m)  (((m) & MXFS_S_IFMT) == MXFS_S_IFDIR)
#define MXFS_S_ISREG(m)  (((m) & MXFS_S_IFMT) == MXFS_S_IFREG)
#define MXFS_S_ISLNK(m)  (((m) & MXFS_S_IFMT) == MXFS_S_IFLNK)

/* ─── Stat result ─── */

struct mxfs_stat {
    uint64_t    ino;
    uint16_t    mode;
    uint32_t    nlink;
    uint32_t    uid;
    uint32_t    gid;
    uint64_t    size;
    uint32_t    atime_sec;
    uint32_t    atime_nsec;
    uint32_t    mtime_sec;
    uint32_t    mtime_nsec;
    uint32_t    ctime_sec;
    uint32_t    ctime_nsec;
    uint32_t    blksize;
    uint64_t    blocks;
    uint32_t    rdev;           /* device number for block/char special files */
};

/* ─── Readdir callback ─── */

typedef int (*mxfs_readdir_fn)(void *ctx, const char *name,
                                uint8_t namelen, uint64_t ino,
                                uint8_t ftype);

/* ─── DLM transport selection ─── */

enum mxfs_dlm_transport {
    MXFS_DLM_TRANSPORT_CAW = 0,     /* compare-and-write (disk-based) */
    MXFS_DLM_TRANSPORT_TCP = 1,     /* TCP (network-based) */
    MXFS_DLM_TRANSPORT_AUTO = 2,    /* auto-detect from peers or device capability */
};

/* ─── Mount options ─── */

struct mxfs_mount_opts {
    const char  *device;            /* block device path (required) */
    const char  *node_uuid_path;    /* path to /etc/mxfs/node.uuid */
    uint16_t    dlm_port;           /* TCP port for DLM (default 7600) */
    uint16_t    discovery_port;     /* UDP port for discovery (default 7601) */
    const char  *multicast_addr;    /* multicast group (default 239.66.83.1) */
    bool        use_broadcast;      /* use broadcast instead of multicast */
    int         max_block_cache;    /* max cached blocks (0 = default 4096) */
    int         max_inode_cache;    /* max cached inodes (0 = default 8192) */
    int         max_dir_cache;      /* max cached dirs (0 = default 2048) */
    int         max_dlm_lock_caw;   /* v5 sess33: max held CAW DLM locks
                                     * (0 = default MXFS_CAW_MAX_HELD).  Each
                                     * cached inode = one held DLM lock, so
                                     * real workloads need much more than the
                                     * legacy 4096.  Cap at MXFS_CAW_MAX_SLOTS. */
    uint32_t    node_slot;          /* node slot for AG affinity */
    uint64_t    disklock_offset;    /* byte offset for disklock region */
    uint64_t    journal_offset;     /* byte offset for journal region (0 = no journal) */
    uint64_t    xfs_data_offset;    /* byte offset where XFS data starts */
    enum mxfs_dlm_transport dlm_transport;  /* DLM transport: CAW (default) or TCP */
};

/* ─── Lifecycle ─── */

/*
 * Mount an MXFS filesystem.
 * Opens the block device, reads the XFS superblock, initializes all
 * subsystems (DLM, peer, discovery, lease, cache, allocation, etc.),
 * and returns a mount handle.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_mount(const struct mxfs_mount_opts *opts,
               struct mxfs_mount **mnt_out);

/*
 * Unmount an MXFS filesystem.
 * Flushes all dirty data, releases all DLM locks, shuts down all
 * subsystems, and closes the block device.
 */
void mxfs_unmount(struct mxfs_mount *mnt);

/*
 * Query the resolved DLM transport after mount.
 * Returns MXFS_DLM_TRANSPORT_CAW or MXFS_DLM_TRANSPORT_TCP.
 */
enum mxfs_dlm_transport mxfs_get_dlm_transport(struct mxfs_mount *mnt);

/* ─── Path-based operations ─── */

/*
 * Look up a path component in a directory.
 * dir_ino is the directory to search in, name is the component.
 * Returns 0 on success with *ino_out set, -ENOENT if not found.
 */
int mxfs_lookup(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen,
                uint64_t *ino_out);

/*
 * Get inode attributes.
 */
int mxfs_stat(struct mxfs_mount *mnt, uint64_t ino,
              struct mxfs_stat *st);

/* ─── File operations ─── */

/*
 * Read data from a file.
 * Returns number of bytes read, or negative errno on error.
 */
int64_t mxfs_read(struct mxfs_mount *mnt, uint64_t ino,
                   void *buf, uint64_t offset, uint32_t len);

/*
 * Bulk read: holds the inode DLM lock for the entire operation.
 *
 * Reads up to total_len bytes starting at offset. Data is delivered
 * via the callback in chunks of up to chunk_size bytes. The callback
 * receives a pointer to the data buffer, the number of bytes in this
 * chunk, and the caller's ctx. The callback should copy the data
 * (e.g. copy_to_iter) and return 0 on success, or negative errno to
 * abort the read.
 *
 * On success, sets *size_out to the file size (so the caller can
 * update the VFS inode size) and returns the total bytes read.
 *
 * This eliminates DLM lock thrashing for large reads by acquiring
 * the inode PR lock once and holding it across all chunks, rather
 * than acquiring/releasing per chunk as mxfs_read() does.
 *
 * Periodically calls mxfs_pal_cond_resched() between chunks to
 * prevent soft lockups during long I/O.
 */
typedef int (*mxfs_read_chunk_fn)(void *ctx, const void *data,
                                   uint32_t len);

int64_t mxfs_read_bulk(struct mxfs_mount *mnt, uint64_t ino,
                        uint64_t offset, uint64_t total_len,
                        uint32_t chunk_size,
                        mxfs_read_chunk_fn cb, void *ctx,
                        uint64_t *size_out);

/*
 * Write data to a file.
 * Returns number of bytes written, or negative errno on error.
 */
int64_t mxfs_write(struct mxfs_mount *mnt, uint64_t ino,
                    const void *buf, uint64_t offset, uint32_t len);

/*
 * Callback for mxfs_write_bulk() — requests the next chunk of data
 * to write. The callback should copy up to @max_len bytes into @buf
 * and return the number of bytes copied, or negative errno on error.
 * Return 0 to indicate no more data.
 */
typedef int (*mxfs_write_chunk_fn)(void *ctx, void *buf, uint32_t max_len);

/*
 * Bulk write to a file.
 *
 * Acquires the DLM EX lock ONCE for the entire write and holds it
 * across all chunks. This eliminates per-chunk DLM lock thrashing
 * that causes D-state hangs on multi-node direct I/O.
 *
 * Calls the write_fn callback repeatedly to get data, writing each
 * chunk at the current offset. Returns total bytes written, or
 * negative errno on error. Sets *size_out to the final file size.
 *
 * Old: N * write(get_ex+put) = N DLM round-trips per chunk
 * New: write_bulk(get_ex ... put) = 1 DLM round-trip total
 */
int64_t mxfs_write_bulk(struct mxfs_mount *mnt, uint64_t ino,
                          uint64_t offset, uint64_t total_len,
                          uint32_t chunk_size,
                          mxfs_write_chunk_fn write_fn, void *ctx,
                          uint64_t *size_out);

/*
 * Truncate a file to the specified size.
 */
int mxfs_truncate(struct mxfs_mount *mnt, uint64_t ino, uint64_t size);

/*
 * Trim speculative preallocation blocks beyond EOF.
 * Called on file close to reclaim blocks allocated speculatively
 * by mxfs_alloc_file_block() but never written.
 */
int mxfs_trim_eof_blocks(struct mxfs_mount *mnt, uint64_t ino);

/*
 * Sync file data and metadata to disk.
 */
int mxfs_fsync(struct mxfs_mount *mnt, uint64_t ino);

/* ─── Fallocate mode flags ─── */

#define MXFS_FALLOC_FL_KEEP_SIZE    0x01
#define MXFS_FALLOC_FL_PUNCH_HOLE   0x02
#define MXFS_FALLOC_FL_ZERO_RANGE   0x04

/*
 * Preallocate or deallocate file space.
 *
 * mode=0: Allocate blocks covering [offset, offset+len). Update file
 *         size if offset+len > current size. Tries to allocate one
 *         large contiguous extent for the whole range.
 *
 * mode=MXFS_FALLOC_FL_KEEP_SIZE: Same as above but do not change
 *         file size (preallocation beyond EOF).
 *
 * mode=MXFS_FALLOC_FL_PUNCH_HOLE | MXFS_FALLOC_FL_KEEP_SIZE:
 *         Deallocate blocks in [offset, offset+len). Punch a hole.
 *         Does not change file size.
 *
 * mode=MXFS_FALLOC_FL_ZERO_RANGE [| MXFS_FALLOC_FL_KEEP_SIZE]:
 *         Zero data in [offset, offset+len) without freeing extents.
 *         If KEEP_SIZE is not set, extends file size if needed.
 *
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_fallocate(struct mxfs_mount *mnt, uint64_t ino,
                    int mode, uint64_t offset, uint64_t len);

/*
 * Sync all dirty data and metadata to disk.
 * Flushes all dirty inodes, dirty blocks, and issues a device flush.
 * Called by the VFS sync_fs superblock operation.
 */
int mxfs_sync_fs(struct mxfs_mount *mnt);

/* ─── Directory operations ─── */

/*
 * Read all entries in a directory.
 * Calls cb() for each entry.
 */
int mxfs_readdir(struct mxfs_mount *mnt, uint64_t dir_ino,
                 mxfs_readdir_fn cb, void *ctx);

/*
 * Create a new file in a directory.
 * Returns 0 on success with *ino_out set to the new inode number.
 */
int mxfs_create(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen,
                uint16_t mode, uint32_t uid, uint32_t gid,
                uint64_t *ino_out);

/*
 * Create a new directory.
 */
int mxfs_mkdir(struct mxfs_mount *mnt,
               uint64_t parent_ino,
               const char *name, uint8_t namelen,
               uint16_t mode, uint32_t uid, uint32_t gid,
               uint64_t *ino_out);

/*
 * Remove a directory (must be empty).
 */
int mxfs_rmdir(struct mxfs_mount *mnt,
               uint64_t parent_ino,
               const char *name, uint8_t namelen);

/*
 * Unlink (delete) a file.
 */
int mxfs_unlink(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen);

/*
 * Rename flags (matches Linux RENAME_* values).
 */
#define MXFS_RENAME_NOREPLACE  (1 << 0) /* fail if dest exists */
#define MXFS_RENAME_EXCHANGE   (1 << 1) /* exchange source and dest */

/*
 * Rename a file or directory.
 *
 * flags:
 *   0                    — classic rename (overwrite dest if exists)
 *   MXFS_RENAME_NOREPLACE — fail with -EEXIST if dest exists
 *   MXFS_RENAME_EXCHANGE  — atomically swap source and dest entries
 */
int mxfs_rename(struct mxfs_mount *mnt,
                uint64_t old_dir_ino, const char *old_name, uint8_t old_namelen,
                uint64_t new_dir_ino, const char *new_name, uint8_t new_namelen,
                unsigned int flags);

/*
 * Create a hard link.
 */
int mxfs_link(struct mxfs_mount *mnt,
              uint64_t dir_ino,
              const char *name, uint8_t namelen,
              uint64_t target_ino);

/*
 * Create a special file (device node, FIFO, or socket).
 * mode must include S_IFBLK, S_IFCHR, S_IFIFO, or S_IFSOCK.
 * For block/char devices, rdev is the device major/minor number.
 * For FIFOs/sockets, rdev is ignored.
 */
int mxfs_mknod(struct mxfs_mount *mnt,
               uint64_t dir_ino,
               const char *name, uint8_t namelen,
               uint16_t mode, uint32_t uid, uint32_t gid,
               uint32_t rdev,
               uint64_t *ino_out);

/*
 * Create a symbolic link.
 */
int mxfs_symlink(struct mxfs_mount *mnt,
                 uint64_t dir_ino,
                 const char *name, uint8_t namelen,
                 const char *target, uint16_t target_len,
                 uint32_t uid, uint32_t gid,
                 uint64_t *ino_out);

/*
 * Read a symbolic link target.
 * Returns bytes copied into buf, or negative errno.
 */
int mxfs_readlink(struct mxfs_mount *mnt, uint64_t ino,
                  char *buf, uint32_t buflen);

/* ─── Attribute operations ─── */

/*
 * Change file permissions.
 */
int mxfs_chmod(struct mxfs_mount *mnt, uint64_t ino, uint16_t mode);

/*
 * Change file ownership.
 */
int mxfs_chown(struct mxfs_mount *mnt, uint64_t ino,
               uint32_t uid, uint32_t gid);

/*
 * Set file timestamps (atime and mtime). ctime is updated automatically.
 */
int mxfs_utimes(struct mxfs_mount *mnt, uint64_t ino,
                uint32_t atime_sec, uint32_t atime_nsec,
                uint32_t mtime_sec, uint32_t mtime_nsec);

/* ─── Query ─── */

/*
 * Get the root inode number.
 */
uint64_t mxfs_root_ino(struct mxfs_mount *mnt);

/*
 * Get filesystem geometry info.
 */
int mxfs_statfs(struct mxfs_mount *mnt,
                uint32_t *blocksize,
                uint64_t *total_blocks,
                uint64_t *free_blocks,
                uint64_t *total_inodes,
                uint64_t *free_inodes);

/* ─── Page cache support ─── */

/*
 * Map a logical file block to a physical disk block.
 * Uses the cached inode's extent map (DLM lock must be held via
 * mxfs_inode_lock_shared/exclusive).
 *
 * Sets *phys_block_out to the physical block number relative to the
 * XFS data area start, or UINT64_MAX for holes.
 * Sets *flags_out to 0, MXFS_PGCACHE_F_HOLE, or MXFS_PGCACHE_F_UNWRITTEN.
 * Returns 0 on success, negative errno on failure.
 */
#define MXFS_PGCACHE_F_HOLE       0x01
#define MXFS_PGCACHE_F_UNWRITTEN  0x02

int mxfs_get_block_map(struct mxfs_mount *mnt, uint64_t ino,
                       uint64_t logical_block,
                       uint64_t *phys_block_out, uint32_t *flags_out);

/*
 * Range-based block map lookup.
 * Returns the full contiguous extent (or hole) at logical_block via range.
 * DLM lock must be held via mxfs_inode_lock_shared/exclusive.
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_get_block_map_range(struct mxfs_mount *mnt, uint64_t ino,
                              uint64_t logical_block,
                              struct mxfs_extent_range *range);

/*
 * Acquire a shared (PR) DLM lock on an inode for page cache reads.
 * The lock is held via lock caching — it persists until BAST, eviction,
 * or unmount. Returns 0 on success with *size_out set to the current
 * file size. Caller must call mxfs_inode_unlock() when done.
 */
int mxfs_inode_lock_shared(struct mxfs_mount *mnt, uint64_t ino,
                           uint64_t *size_out);

/*
 * Acquire an exclusive (EX) DLM lock on an inode for page cache writes.
 * Returns 0 on success with *size_out set to the current file size.
 * Caller must call mxfs_inode_unlock() when done.
 */
int mxfs_inode_lock_exclusive(struct mxfs_mount *mnt, uint64_t ino,
                              uint64_t *size_out);

/*
 * Release the reference on an inode lock.
 * The DLM lock stays cached (held until BAST).
 */
void mxfs_inode_unlock(struct mxfs_mount *mnt, uint64_t ino);

/*
 * Downgrade an inode's cached DLM lock from EX to PR.
 * Call after a write completes and dirty pages are flushed to allow
 * other nodes to acquire PR (read) without triggering a full BAST.
 * Returns 0 on success, negative errno on failure. On failure the
 * lock remains at its current mode (no data loss).
 */
int mxfs_inode_lock_downgrade(struct mxfs_mount *mnt, uint64_t ino);

/*
 * Update the inode size after a write extended the file.
 * Acquires EX lock if not already held, updates ci->size,
 * marks inode dirty, and serializes the new size to the raw buffer.
 */
int mxfs_update_inode_size(struct mxfs_mount *mnt, uint64_t ino,
                           uint64_t new_size);

/*
 * Allocate a disk block for a file at the given logical offset.
 * Used by the page cache write path when writing to a hole.
 * The inode must already be EX-locked via mxfs_inode_lock_exclusive().
 * Returns 0 on success with *phys_block_out set.
 */
int mxfs_alloc_file_block(struct mxfs_mount *mnt, uint64_t ino,
                          uint64_t logical_block,
                          uint64_t *phys_block_out);

/*
 * Convert an unwritten (fallocate-preallocated) extent to written.
 *
 * Called from the write path when writing into a block that was
 * preallocated by fallocate(mode=0). Splits the unwritten extent
 * into up to 3 parts: unwritten prefix, single written block,
 * unwritten suffix.
 *
 * Returns 0 on success.
 */
int mxfs_convert_unwritten(struct mxfs_mount *mnt, uint64_t ino,
                            uint64_t logical_block);

/*
 * Set the page cache invalidation callback.
 * Called by the kernel frontend at mount time. The callback is invoked
 * from complete_bast() to flush dirty pages and invalidate page cache
 * before releasing the DLM lock.
 */
void mxfs_set_page_invalidate_cb(struct mxfs_mount *mnt,
                                 void (*fn)(void *, uint64_t), void *ctx);

/* ─── Sparse file seek support ─── */

/*
 * Seek to the next data region at or after offset.
 *
 * POSIX SEEK_DATA semantics:
 *   - If offset is within a data extent, return offset unchanged.
 *   - If offset is in a hole, return the start of the next data extent.
 *   - If no data exists at or after offset, return -ENXIO.
 *   - If offset >= file size, return -ENXIO.
 *
 * Acquires a shared (PR) DLM lock on the inode.
 */
int64_t mxfs_seek_data(struct mxfs_mount *mnt, uint64_t ino, int64_t offset);

/*
 * Seek to the next hole at or after offset.
 *
 * POSIX SEEK_HOLE semantics:
 *   - If offset is in a hole (gap between extents), return offset.
 *   - If offset is within a data extent, return the end of that extent
 *     (start of the next hole or gap before EOF).
 *   - If offset is past all extents but before EOF, return offset
 *     (virtual hole at EOF).
 *   - If offset >= file size, return -ENXIO.
 *
 * Acquires a shared (PR) DLM lock on the inode.
 */
int64_t mxfs_seek_hole(struct mxfs_mount *mnt, uint64_t ino, int64_t offset);

/* ─── Extended attribute operations ─── */

/*
 * Get an extended attribute value.
 * name includes namespace prefix (e.g. "user.foo", "trusted.bar").
 * value may be NULL to query size only.
 * Returns attribute value length on success, negative errno on error.
 */
int mxfs_getxattr(struct mxfs_mount *mnt, uint64_t ino,
                  const char *name, void *value, int size);

/*
 * Set an extended attribute.
 * name includes namespace prefix. value=NULL means remove.
 * flags: XATTR_CREATE (0x01) or XATTR_REPLACE (0x02).
 * Returns 0 on success, negative errno on error.
 */
int mxfs_setxattr(struct mxfs_mount *mnt, uint64_t ino,
                  const char *name, const void *value, int size,
                  int flags);

/*
 * List all extended attribute names (NUL-separated).
 * list may be NULL to query total size.
 * Returns total bytes for the list, negative errno on error.
 */
int mxfs_listxattr(struct mxfs_mount *mnt, uint64_t ino,
                   char *list, int size);

/*
 * Remove an extended attribute by name.
 * Returns 0 on success, -ENODATA if not found.
 */
int mxfs_removexattr(struct mxfs_mount *mnt, uint64_t ino,
                     const char *name);

#endif /* MXFS_LIBMXFS_MXFS_H */
