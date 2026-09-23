#include <stdio.h>
#include <mxfs/mxfs_dirshard.h>
int main(void){ struct mxfs_dirshard_view v; unsigned char b[4096]={0};
 struct mxfs_dirshard_blk *blk=(void*)b; struct mxfs_dirshard_manifest *m=(void*)(b+88);
 blk->magic=mxfs_dirshard_be32(MXFS_DIRSHARD_BLK_MAGIC); blk->bytes=mxfs_dirshard_be32(MXFS_DIRSHARD_MANIFEST_LEN(16));
 blk->owner=mxfs_dirshard_be64(200); blk->holder_gen=mxfs_dirshard_be32(7); blk->parent_ino=mxfs_dirshard_be64(100); blk->parent_gen=mxfs_dirshard_be32(5);
 m->magic=mxfs_dirshard_be32(MXFS_DIRSHARD_MANIFEST_MAGIC); m->version=mxfs_dirshard_be16(1); m->hash_id=mxfs_dirshard_be16(1);
 m->length=mxfs_dirshard_be32(MXFS_DIRSHARD_MANIFEST_LEN(16)); m->mgen=mxfs_dirshard_be32(1); m->nshards=mxfs_dirshard_be16(16);
 m->state=mxfs_dirshard_be16(MXFS_DIRSHARD_ST_ALLOCATING); m->name_canon_version=mxfs_dirshard_be16(1); m->nentries=0;
 m->hash_key[0]=1; m->set_uuid[0]=1; m->parent_ino=mxfs_dirshard_be64(100); m->parent_gen=mxfs_dirshard_be32(5); m->valid_mask=0;
 enum mxfs_dirshard_check c=mxfs_dirshard_blk_check(blk,4096,200,7,100,5,1,&v);
 printf("alloc0: %s n=%u\n", mxfs_dirshard_check_name(c), v.nshards);
 m->nentries=mxfs_dirshard_be16(2); m->valid_mask=mxfs_dirshard_be64(3); m->entries[0].ino=mxfs_dirshard_be64(300); m->entries[0].gen=mxfs_dirshard_be32(1);
 m->entries[1].ino=mxfs_dirshard_be64(300); m->entries[1].gen=mxfs_dirshard_be32(2);
 printf("dup: %s\n", mxfs_dirshard_check_name(mxfs_dirshard_blk_check(blk,4096,200,7,100,5,1,&v)));
 m->entries[1].ino=mxfs_dirshard_be64(301);
 printf("ok2: %s mgen=%u\n", mxfs_dirshard_check_name(mxfs_dirshard_blk_check(blk,4096,200,7,100,5,1,&v)), v.mgen);
 printf("badcrc: %s\n", mxfs_dirshard_check_name(mxfs_dirshard_blk_check(blk,4096,200,7,100,5,0,&v)));
 printf("cookie eof slot=%u malformed(1<<63)=%d\n", mxfs_dirshard_cookie_slot(mxfs_dirshard_cookie(65,0)), mxfs_dirshard_cookie_malformed(1ULL<<63));
 return 0; }
