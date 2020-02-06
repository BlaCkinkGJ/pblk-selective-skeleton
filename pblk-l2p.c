#include "pblk.h"

int pblk_get_map_nr_entries(const size_t map_size)
{
	return (int)(map_size / sizeof(struct ppa_addr));
}

struct pblk_l2p_cache *pblk_l2p_cache_create(const size_t cache_size)
{
	struct pblk_l2p_cache *cache = NULL;
	struct pblk_l2p_centry *centry = NULL;
	int nr_centries = 0, i = 0, blk_idx = 0;

	nr_centries = (cache_size / PBLK_CENTRY_SIZE) + 1;

	cache = vmalloc(sizeof(struct pblk_l2p_cache) +
			sizeof(struct pblk_l2p_centry) * nr_centries);
	if (!cache) {
		printk(KERN_ERR "cache creation failed\n");
		goto fail_to_create_cache;
	}

	for (i = 0; i < nr_centries; i++) {
		centry = &cache->centries[i];
		memset(centry->owner_sig, 0, PBLK_SHA1_BLK_SIZE);
		for (blk_idx = 0; blk_idx < PBLK_CENTRY_NR_BLK; blk_idx++) {
			centry->cache_blk[blk_idx] =
				kmalloc(PBLK_CENTRY_BLK_SIZE, GFP_ATOMIC);
			if (!centry->cache_blk[blk_idx]) {
				printk(KERN_ERR
				       "cache block creation failed\n");
				goto fail_to_create_cache_blk;
			}
		}
	}

	cache->free_bitmap = vmalloc(nr_centries);
	if (!cache->free_bitmap) {
		printk(KERN_ERR "cache bitmap creation failed\n");
		goto fail_to_create_bitmap;
	}
	bitmap_zero(cache->free_bitmap, nr_centries);

	cache->nr_centries = nr_centries;

	trace_printk("ALLOCATE THE CACHE\n");
	return cache;

fail_to_create_bitmap:
fail_to_create_cache_blk:
	for (blk_idx = blk_idx - 1; blk_idx >= 0; blk_idx--) {
		vfree(centry->cache_blk[blk_idx]);
	}
	vfree(cache);
fail_to_create_cache:
	return ERR_PTR(-ENOMEM);
}

void pblk_l2p_cache_free(struct pblk_l2p_cache *cache)
{
	struct pblk_l2p_centry *centry = NULL;
	int i = 0, blk_idx = 0;

	trace_printk("FREE CACHE\n");
	vfree(cache->free_bitmap);
	for (i = 0; i < PBLK_CENTRY_NR_BLK; i++) {
		centry = &cache->centries[i];
		for (blk_idx = 0; blk_idx < PBLK_CENTRY_NR_BLK; blk_idx++) {
			kfree(centry->cache_blk[blk_idx]);
		}
	}
	vfree(cache);
}

struct pblk_l2p_dir *pblk_l2p_dir_create(const size_t map_size)
{
	struct pblk_l2p_dir *dir = NULL;
	struct pblk_l2p_dentry *dentry = NULL;
	int nr_dentries = 0, i = 0;

	nr_dentries = (map_size / PBLK_CENTRY_SIZE) + 1;

	dir = vmalloc(sizeof(struct pblk_l2p_dir) +
		      sizeof(struct pblk_l2p_dentry) * nr_dentries);
	if (!dir) {
		printk(KERN_ERR "dir creation failed\n");
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < nr_dentries; i++) {
		dentry = &dir->dentries[i];
		atomic64_set(&dentry->hotness, 0);

		dentry->line = 0;
		dentry->ppa.ppa = 0;

		memset(dentry->sig, 0, PBLK_SHA1_BLK_SIZE);

		dentry->centry = NULL;
	}

	dir->nr_dentries = nr_dentries;

	trace_printk("ALLOCATE THE DIR\n");
	return dir;
}

void pblk_l2p_dir_free(struct pblk_l2p_dir *dir)
{
	trace_printk("FREE DIR\n");
	vfree(dir);
}

void pblk_l2p_construct_trans_map(unsigned char *trans_map, const size_t size)
{
	int i = 0;

	for (i = 0; i < pblk_get_map_nr_entries(size); i++) {
		u32 rnd_num;

		get_random_bytes(&rnd_num, sizeof(u32));

		((struct ppa_addr *)trans_map)[i].a.ch = i;
		((struct ppa_addr *)trans_map)[i].a.lun = i + 10;
		((struct ppa_addr *)trans_map)[i].a.blk = rnd_num;
	}
}

int pblk_l2p_copy_map_to_centry(const unsigned char *map,
				struct pblk_l2p_centry *centry,
				const size_t size)
{
	unsigned char *cache_blk_ptr = NULL;
	size_t rem = size;
	int i = 0;

	struct pblk_l2p_sha1_ctx ctx_trans_map;
	struct pblk_l2p_sha1_ctx ctx_dftl_map;

	unsigned char trans_map_sha[PBLK_SHA1_BLK_SIZE];

	sha1_init(&ctx_trans_map);
	sha1_init(&ctx_dftl_map);

	for (i = 0; i < PBLK_CENTRY_NR_BLK; i++) {
		if (rem <= 0) {
			break;
		}

		cache_blk_ptr = centry->cache_blk[i];

		memcpy(centry->cache_blk[i], map, PBLK_CENTRY_BLK_SIZE);

		sha1_update(&ctx_trans_map, map, PBLK_CENTRY_BLK_SIZE);
		sha1_update(&ctx_dftl_map, centry->cache_blk[i],
			    PBLK_CENTRY_BLK_SIZE);

		rem -= PBLK_CENTRY_BLK_SIZE;
		map += PBLK_CENTRY_BLK_SIZE;
	}

	if (rem > 0) { // remain size check
		printk(KERN_ERR
		       "[%s(%s):%d] unaligned map size: %lu(rem:%lu)\n",
		       __FILE__, __func__, __LINE__, size, rem);
		return -EINVAL;
	}

	sha1_final(&ctx_trans_map, trans_map_sha);
	sha1_final(&ctx_dftl_map, centry->owner_sig);

	if (!strcmp(trans_map_sha, centry->owner_sig)) { // SHA1 signiture check
		printk(KERN_ERR
		       "[%s(%s):%d] SHA1 signature unmatched (original/cache): %s/%s\n",
		       __FILE__, __func__, __LINE__, trans_map_sha,
		       centry->owner_sig);
		return -EINVAL;
	}

	return 0;
}

int pblk_l2p_trans_map_to_dir(struct pblk *pblk, const size_t trans_map_size)
{
	struct pblk_l2p_dir *dir = pblk->dir;
	struct pblk_l2p_dentry *dentry = NULL;

	const unsigned char *trans_map = pblk->trans_map;

	struct pblk_l2p_cache *helper_cache = NULL;

	int i = 0, err;

	helper_cache = pblk_l2p_cache_create(trans_map_size);
	if (IS_ERR(helper_cache)) {
		printk(KERN_ERR "[%s(%s):%d] fail to consist the cache....\n",
		       __FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	for (i = 0; i < dir->nr_dentries; i++) {
		dentry = &dir->dentries[i];
		dentry->centry = &helper_cache->centries[i];
		err = pblk_l2p_copy_map_to_centry(trans_map, dentry->centry,
						  PBLK_CENTRY_SIZE);
		if (err) {
			printk(KERN_ERR
			       "[%s(%s):%d] exception occurred(errno: %d)\n",
			       __FILE__, __func__, __LINE__, err);
			return err;
		}
		memcpy(dentry->sig, dentry->centry->owner_sig,
		       PBLK_SHA1_BLK_SIZE);
		trace_printk(
			"[%s(%s):%d] No.%d signature(dentry/centry): %s/%s\n",
			__FILE__, __func__, __LINE__, i, dentry->sig,
			dentry->centry->owner_sig);
		trans_map += PBLK_CENTRY_SIZE;
	}

	trace_printk("[%s(%s):%d] entry size(d/c) ==> %d/%d\n", __FILE__,
		     __func__, __LINE__, dir->nr_dentries,
		     helper_cache->nr_centries);

	pblk_l2p_cache_free(helper_cache);
	return 0;
}

/* MODULE MAIN */
static int __init init_pblk_l2p(void)
{
	const size_t trans_map_size = 10 * 4096 * PBLK_CENTRY_BLK_SIZE;
	const size_t cache_size = 4096 * PBLK_CENTRY_BLK_SIZE;

	pblk_test(trans_map_size, cache_size);

	return 0;
}

static void __exit cleanup_pblk_l2p(void)
{
	trace_printk("GOOD BYE!!!\n");
}

module_init(init_pblk_l2p); // TODO: MUST DELETE
module_exit(cleanup_pblk_l2p); // TODO: MUST DELETE
