# SEEK_HOLE / SEEK_DATA Support

## Overview

MXFS implements POSIX `SEEK_HOLE` and `SEEK_DATA` via custom `llseek` file
operations. This enables sparse-aware tools to efficiently copy, convert, and
back up files without reading through hole regions:

- `cp --sparse=auto`
- `qemu-img convert` (VM disk images)
- `rsync --sparse`
- Backup utilities (tar, borgbackup, restic)

## Architecture

### Three layers

1. **Public API** (`libmxfs/mxfs.h`):
   - `mxfs_seek_data(mnt, ino, offset)` -- find next data at or after offset
   - `mxfs_seek_hole(mnt, ino, offset)` -- find next hole at or after offset
   - Returns byte offset on success, `-ENXIO` when past EOF or no data found

2. **Implementation** (`libmxfs/mount.c`):
   - Acquires a PR (shared) DLM lock via `mxfs_inode_cache_get()`
   - Walks the inode's sorted extent map (`struct mxfs_extent_map`)
   - Converts between byte offsets and logical block offsets using `sb.blocksize`
   - Holes are implicit gaps between extents

3. **VFS frontend** (`frontend/linux/mxfs_file.c`):
   - `mxfs_kern_llseek()` dispatches `SEEK_DATA`/`SEEK_HOLE` to libmxfs
   - `SEEK_SET`/`SEEK_CUR`/`SEEK_END` delegated to `generic_file_llseek_size()`
   - Result passed through `vfs_setpos()` to update file position

### POSIX semantics

**SEEK_DATA(offset)**:
- offset within an extent: return offset (already in data)
- offset in a hole: return start of next extent
- offset >= file_size or no more data: return -ENXIO
- FMT_LOCAL (inline): entire file is data, return offset

**SEEK_HOLE(offset)**:
- offset in a hole: return offset (already in hole)
- offset within an extent: return end of that extent
- offset past all extents but < file_size: return offset (trailing hole)
- offset >= file_size: return -ENXIO
- FMT_LOCAL (inline): return file_size (virtual hole at EOF)

### DLM locking

Both functions acquire a shared (PR) lock via the inode cache, ensuring the
extent map is up-to-date with respect to remote writers. The lock is held
only for the duration of the extent walk and released via
`mxfs_inode_cache_put()`.

## Files changed

- `/src/mxfs/libmxfs/mxfs.h` -- API declarations
- `/src/mxfs/libmxfs/mount.c` -- seek implementation
- `/src/mxfs/frontend/linux/mxfs_file.c` -- VFS llseek handler

## Testing

Verify with:
```bash
# Create a sparse file
dd if=/dev/zero of=/mnt/shared/sparse bs=4k count=1 seek=1000
# Check that cp preserves sparseness
cp --sparse=always /mnt/shared/sparse /mnt/shared/sparse2
ls -ls /mnt/shared/sparse /mnt/shared/sparse2
# Both should show only 4k allocated blocks, not 4MB apparent size
```
