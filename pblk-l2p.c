#include "pblk.h"

struct pblk_l2p_cache *pblk_l2p_cache_create(const size_t cache_size)
{
	struct pblk_l2p_cache *cache = NULL;
	struct pblk_l2p_centry *centry = NULL;
	int nr_centries = 0, i = 0, blk_idx = 0;

	nr_centries = (cache_size / PBLK_CENTRY_SIZE) + 1;

	cache = vmalloc(sizeof(struct pblk_l2p_cache) + \
			sizeof(struct pblk_l2p_centry) * nr_centries);
	if (!cache) {
		printk(KERN_ERR"cache creation failed\n");
		goto fail_to_create_cache;
	}

	for (i = 0; i < nr_centries; i++) {
		centry = &cache->centries[i];
		memset(centry->owner_sig, 0, PBLK_SHA1_BLK_SIZE);
		for (blk_idx = 0; blk_idx < PBLK_CENTRY_NR_BLK; blk_idx++) {
			centry->cache_blk[blk_idx] = kmalloc(PAGE_SIZE, GFP_ATOMIC);
			if (!centry->cache_blk[blk_idx]) {
				printk(KERN_ERR"cache block creation failed\n");
				goto fail_to_create_cache_blk;
			}
		}
	}

	cache->free_bitmap = vmalloc(nr_centries);
	if (!cache->free_bitmap) {
		printk(KERN_ERR"cache bitmap creation failed\n");
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

	dir = vmalloc(sizeof(struct pblk_l2p_dir) + \
			sizeof(struct pblk_l2p_dentry)*nr_dentries);
	if (!dir) {
		printk(KERN_ERR"dir creation failed\n");
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
	vfree(dir);
}

/* MODULE MAIN */
static int __init init_pblk_l2p(void)
{
	struct pblk *pblk;
	struct pblk_l2p_dir *dir = NULL;
	struct pblk_l2p_cache *cache = NULL;

	const size_t trans_map_size = 10*4096*PAGE_SIZE;
	const size_t cache_size = 4096*PAGE_SIZE;

	pblk = vmalloc(sizeof(struct pblk));

	dir = pblk->dir;
	cache = pblk->cache;

	cache = pblk_l2p_cache_create(cache_size);
	dir = pblk_l2p_dir_create(trans_map_size); /* 160MB */
	if (IS_ERR(dir)) {
		printk(KERN_ERR"fail to consist the directory....\n");
		return -1;
	}

	pblk_l2p_dir_free(dir);
	pblk_l2p_cache_free(cache);
	pblk_sha_test(pblk, trans_map_size);

	vfree(pblk);
	return 0;
}

static void __exit cleanup_pblk_l2p(void)
{
	trace_printk("GOOD BYE!!!\n");
}

module_init(init_pblk_l2p); // TODO: MUST DELETE
module_exit(cleanup_pblk_l2p); // TODO: MUST DELETE 
