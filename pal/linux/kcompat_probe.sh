#!/bin/sh
#
# kcompat_probe.sh — which kernel APIs the kernel being built for provides
#
# Usage: pal/linux/kcompat_probe.sh <cc> [kernel compiler flags ...]
#   Prints a C header on stdout defining MXFS_HAVE_<NAME> 1 for each API the
#   kernel's own headers provide, and leaving it undefined otherwise.  Kbuild
#   runs it from the kernel build directory with the flags every module object
#   is compiled with, so a probe answers exactly what an MXFS object would see.
#
# Why probes and not LINUX_VERSION_CODE: a distribution kernel's version names
# the base it forked from, not what it carries.  RHEL 9 reports 5.14 for every
# minor release while Red Hat backports newer block and super APIs into it
# (9.8 has super_set_uuid, the bdev file API, bio_add_vmalloc and the atomic
# write helpers) and keeps older VFS and iomap ones (update_time with a
# timespec64, an int filldir_t, iomap_page_ops).  Ubuntu backports inside a
# point series (6.8.0-101 has FALLOC_FL_MODE_MASK, 6.8.0-53 does not).  A
# version gate is wrong in one direction or the other on each of them; a probe
# of the kernel's own declarations is not.
#
# A probe is one small translation unit compiled syntax-only.  It passes only
# if the API exists with the shape MXFS uses: a missing function, member or
# type, a wrong argument count, or an incompatible pointer type fails it.  It
# never fails the build: a probe that cannot compile leaves its define unset,
# and the shim in xfs/xfs_platform.h (or the older call in pal/linux) is used.
#
cc="$1"
shift

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

# probe NAME 'includes' 'body' [exported-symbol]
#   With a fourth argument the API also has to be exported to modules: a
#   declaration proves nothing about the export (RHEL 9.8 declares
#   bio_add_folio and does not export it).  Kbuild passes the kernel's
#   Module.symvers in MXFS_SYMVERS: from 6.13 an M= build runs from the module
#   directory, where a relative path finds nothing and every export reads
#   absent.  A kernel without one answers "not provided", which selects
#   MXFS's own fallback.
symvers="${MXFS_SYMVERS:-Module.symvers}"
if [ -n "${MXFS_KCOMPAT_DEBUG:-}" ] && [ ! -r "$symvers" ]; then
    echo "kcompat_probe: no $symvers: every export-checked probe reads absent" >&2
fi
probe() {
    if [ -n "$4" ] && ! grep -q "$(printf '\t%s\t' "$4")" "$symvers" 2>/dev/null; then
        echo "/* MXFS_HAVE_$1 not provided (not exported) */" > "$tmp/$1.res"
        return
    fi
    printf '%s\n%s\n' "$2" "$3" > "$tmp/$1.c"
    (
        # -Wno-error first: a kernel built with CONFIG_WERROR would otherwise
        # fail a probe on its own harmless warnings (an unused static, a
        # missing prototype) and report a present API as absent.
        if $cc -fsyntax-only -Wno-error -Werror=implicit-function-declaration \
               -Werror=incompatible-pointer-types -Werror=int-conversion \
               -Werror=return-type "$tmp/$1.c" >"$tmp/$1.err" 2>&1; then
            echo "#define MXFS_HAVE_$1 1" > "$tmp/$1.res"
        else
            echo "/* MXFS_HAVE_$1 not provided */" > "$tmp/$1.res"
            # MXFS_KCOMPAT_DEBUG=1 in the build's environment prints why a
            # probe did not compile: a probe written wrong answers "absent"
            # exactly as a missing API does, and nothing else tells them apart
            [ -n "${MXFS_KCOMPAT_DEBUG:-}" ] && sed "s/^/kcompat_probe $1: /" "$tmp/$1.err" >&2
        fi
    ) &
}
# Inside probe(), "$@" is probe's own arguments, so the kernel flags travel in
# $cc, split at spaces when it is expanded: the form Kbuild passes them in.
cc="$cc $*"

# --- block and super APIs Red Hat backports into older bases -------------
probe SUPER_SET_UUID '#include <linux/fs.h>' \
    'void p(struct super_block *s, const u8 *u) { super_set_uuid(s, u, 16); }'
probe SUPER_SET_SYSFS_NAME_ID '#include <linux/fs.h>' \
    'void p(struct super_block *s) { super_set_sysfs_name_id(s); }'
probe BDEV_FILE_OPEN '#include <linux/blkdev.h>
#include <linux/fs.h>' \
    'struct block_device *p(void) { struct file *f = bdev_file_open_by_path("x", BLK_OPEN_READ, NULL, NULL); struct block_device *b = file_bdev(f); bdev_fput(f); return b; }'
probe SB_BDEV_FILE '#include <linux/fs.h>' \
    'struct file *p(struct super_block *s) { return s->s_bdev_file; }'
probe BIO_ADD_VMALLOC_CHUNK '#include <linux/bio.h>' \
    'unsigned int p(struct bio *b, void *v) { return bio_add_vmalloc_chunk(b, v, 1); }'
probe BIO_ADD_VMALLOC '#include <linux/bio.h>' \
    'bool p(struct bio *b, void *v) { return bio_add_vmalloc(b, v, 1); }'
probe BIO_ADD_VIRT_NOFAIL '#include <linux/bio.h>' \
    'void p(struct bio *b, void *v) { bio_add_virt_nofail(b, v, 1); }'
probe BIO_ADD_MAX_VECS '#include <linux/bio.h>' \
    'unsigned int p(void *d) { return bio_add_max_vecs(d, 1); }'
probe BDEV_RW_VIRT '#include <linux/bio.h>
#include <linux/blkdev.h>' \
    'int p(struct block_device *b, void *d) { return bdev_rw_virt(b, 0, d, 512, REQ_OP_READ); }'
probe BDEV_CAN_ATOMIC_WRITE '#include <linux/blkdev.h>' \
    'bool p(struct block_device *b) { return bdev_can_atomic_write(b); }'
probe BDEV_ATOMIC_WRITE_UNIT_MIN_BYTES '#include <linux/blkdev.h>' \
    'unsigned int p(struct block_device *b) { return bdev_atomic_write_unit_min_bytes(b); }'
probe BDEV_ATOMIC_WRITE_UNIT_MAX_BYTES '#include <linux/blkdev.h>' \
    'unsigned int p(struct block_device *b) { return bdev_atomic_write_unit_max_bytes(b); }'
probe BDEV_VALIDATE_BLOCKSIZE '#include <linux/blkdev.h>' \
    'int p(struct block_device *b) { return bdev_validate_blocksize(b, 4096); }'

# --- atomic write reporting: present, and with which signature ------------
probe GENERIC_FILL_STATX_ATOMIC_WRITES_4 '#include <linux/fs.h>
#include <linux/stat.h>' \
    'void p(struct kstat *s) { generic_fill_statx_atomic_writes(s, 1, 1, 1); }'
probe GENERIC_FILL_STATX_ATOMIC_WRITES_3 '#include <linux/fs.h>
#include <linux/stat.h>' \
    'void p(struct kstat *s) { generic_fill_statx_atomic_writes(s, 1, 1); }'
probe GENERIC_ATOMIC_WRITE_VALID '#include <linux/fs.h>
#include <linux/uio.h>' \
    'int p(struct kiocb *k, struct iov_iter *i) { return generic_atomic_write_valid(k, i); }'

# --- iomap ----------------------------------------------------------------
probe IOMAP_LAST_WRITTEN_BLOCK '#include <linux/iomap.h>' \
    'loff_t p(struct inode *i) { return iomap_last_written_block(i, 0, 1); }'
probe IOMAP_WRITE_DELALLOC_RELEASE '#include <linux/iomap.h>' \
    'static void pu(struct inode *i, loff_t o, loff_t l, struct iomap *m) { }
void p(struct inode *i, struct iomap *m) { iomap_write_delalloc_release(i, 0, 1, 0, m, pu); }' \
    iomap_write_delalloc_release
probe IOMAP_FOLIO_OPS '#include <linux/iomap.h>' \
    'const struct iomap_folio_ops *p(struct iomap *m) { return m->folio_ops; }'
probe IOMAP_ITER_PRIVATE '#include <linux/iomap.h>' \
    'void *p(struct iomap_iter *i) { return i->private; }'
probe IOMAP_DIO_BIO_SET '#include <linux/iomap.h>' \
    'struct bio_set *p(const struct iomap_dio_ops *o) { return o->bio_set; }'
# iomap's own ioend bio_set: declared AND exported, because a dio bio_set that
# names a set nobody initialized crashes the first bio_alloc_bioset from it.
probe IOMAP_IOEND_BIOSET '#include <linux/iomap.h>' \
    'struct bio_set *p(void) { return &iomap_ioend_bioset; }' \
    iomap_ioend_bioset
# Probed before xfs_platform.h defines it to 0: set only where this kernel's
# iomap bounces a direct I/O itself.
probe IOMAP_DIO_BOUNCE '#include <linux/iomap.h>' \
    'unsigned int p(void) { return IOMAP_DIO_BOUNCE; }'
probe IOMAP_DIO_RW_PRIVATE '#include <linux/iomap.h>' \
    'ssize_t p(struct kiocb *k, struct iov_iter *i, const struct iomap_ops *o) { return iomap_dio_rw(k, i, o, NULL, 0, NULL, 0); }'

# --- VFS operation signatures ---------------------------------------------
probe UPDATE_TIME_TIMESPEC '#include <linux/fs.h>' \
    'static int u(struct inode *i, struct timespec64 *t, int f) { return 0; }
const struct inode_operations p = { .update_time = u };'
probe FILLDIR_BOOL '#include <linux/fs.h>' \
    'static bool a(struct dir_context *c, const char *n, int l, loff_t o, u64 i, unsigned int t) { return true; }
struct dir_context p = { .actor = a };'
probe ERROR_REMOVE_FOLIO '#include <linux/fs.h>
#include <linux/mm.h>' \
    'const struct address_space_operations p = { .error_remove_folio = generic_error_remove_folio };'

# --- SCSI -----------------------------------------------------------------
probe SCSI_CMND_SENSE_LEN '#include <scsi/scsi_cmnd.h>' \
    'unsigned int p(struct scsi_cmnd *c) { return c->sense_len + c->resid_len; }'

wait

echo "/* generated by pal/linux/kcompat_probe.sh: which APIs this kernel provides */"
cat $(ls "$tmp"/*.res | sort)
