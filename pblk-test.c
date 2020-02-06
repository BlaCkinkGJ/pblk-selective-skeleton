#include "pblk.h"

static void pblk_sha_test(struct pblk *pblk, const size_t trans_map_size)
{
	struct pblk_l2p_sha1_ctx *ctx = &pblk->ctx;

	unsigned char sha_result[PBLK_SHA1_BLK_SIZE];
	unsigned char *trans_map = pblk->trans_map;

	int corrupt_target = 0, original_value = 0;
	int i = 0;

	sha1_init(ctx);
	sha1_update(ctx, trans_map, trans_map_size);
	sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] before corrupt the table\n", __FILE__,
		     __func__, __LINE__);
	for (i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[%s(%s):%d] index %d ==> 0x%x\n", __FILE__,
			     __func__, __LINE__, i, sha_result[i]);
	}

	corrupt_target = pblk_get_map_nr_entries(trans_map_size) - 1;
	original_value = ((struct ppa_addr *)trans_map)[corrupt_target].a.blk;
	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = 0;

	sha1_init(ctx);
	sha1_update(ctx, trans_map, trans_map_size);
	sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] after corrupt the table (target->%d)\n",
		     __FILE__, __func__, __LINE__, corrupt_target);
	for (i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[%s(%s):%d] index %d ==> 0x%x\n", __FILE__,
			     __func__, __LINE__, i, sha_result[i]);
	}

	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = original_value;

	sha1_init(ctx);
	sha1_update(ctx, trans_map, trans_map_size);
	sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] restore corrupt the table (target->%d)\n",
		     __FILE__, __func__, __LINE__, corrupt_target);
	for (i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[%s(%s):%d] index %d ==> 0x%x\n", __FILE__,
			     __func__, __LINE__, i, sha_result[i]);
	}
}

int pblk_test(const size_t trans_map_size, const size_t cache_size)
{
	struct pblk *pblk;

	pblk = vmalloc(sizeof(struct pblk));

	pblk->cache = pblk_l2p_cache_create(cache_size);
	if (IS_ERR(pblk->cache)) {
		printk(KERN_ERR "[%s(%s):%d] fail to consist the cache....\n",
		       __FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	pblk->dir = pblk_l2p_dir_create(trans_map_size);
	if (IS_ERR(pblk->dir)) {
		printk(KERN_ERR "[%s(%s):%d] fail to consist the dir....\n",
		       __FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	pblk->trans_map = vmalloc(trans_map_size);
	if (!pblk->trans_map) {
		printk(KERN_ERR "[%s(%s):%d] fail to consist the map....\n",
		       __FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	pblk_l2p_construct_trans_map(pblk->trans_map, trans_map_size);
	pblk_l2p_trans_map_to_dir(pblk, trans_map_size);

	pblk_sha_test(pblk, trans_map_size);

	pblk_l2p_cache_free(pblk->cache);
	pblk_l2p_dir_free(pblk->dir);

	vfree(pblk->trans_map);

	vfree(pblk);
	return 0;
}
