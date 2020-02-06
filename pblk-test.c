#include "pblk.h"

static void pblk_l2p_construct_trans_map(struct pblk *pblk,
					 unsigned char *trans_map,
					 const size_t size)
{
	sector_t i = 0;

	for (i = 0; i < pblk_get_map_nr_entries(pblk, size); i++) {
		u32 rnd_num;
		sector_t centry_idx = i;
		sector_t cache_blk_idx = 0;
		sector_t cache_blk_offset = 0;

		cache_blk_idx = do_div(centry_idx, PBLK_CENTRY_SIZE);
		cache_blk_offset = do_div(cache_blk_idx, PBLK_CENTRY_BLK_SIZE);

		get_random_bytes(&rnd_num, sizeof(u32));

		((struct ppa_addr *)trans_map)[i].a.ch = centry_idx;
		((struct ppa_addr *)trans_map)[i].a.lun = cache_blk_idx;
		((struct ppa_addr *)trans_map)[i].a.blk = cache_blk_offset;
	}
}

static void pblk_sha_test(struct pblk *pblk, const size_t trans_map_size)
{
	struct pblk_l2p_sha1_ctx *ctx = &pblk->ctx;

	unsigned char sha_result[PBLK_SHA1_BLK_SIZE];
	unsigned char *trans_map = pblk->trans_map;

	int corrupt_target = 0, original_value = 0;

	pblk_l2p_sha1_init(ctx);
	pblk_l2p_sha1_update(ctx, trans_map, trans_map_size);
	pblk_l2p_sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] before corrupt the table: %s\n", __FILE__,
		     __func__, __LINE__, pblk_l2p_sha1_str(sha_result));

	corrupt_target = pblk_get_map_nr_entries(pblk, trans_map_size) - 1;
	original_value = ((struct ppa_addr *)trans_map)[corrupt_target].a.blk;
	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = 0;

	pblk_l2p_sha1_init(ctx);
	pblk_l2p_sha1_update(ctx, trans_map, trans_map_size);
	pblk_l2p_sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] after corrupt the table (target->%d): %s\n",
		     __FILE__, __func__, __LINE__, corrupt_target,
		     pblk_l2p_sha1_str(sha_result));

	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = original_value;

	pblk_l2p_sha1_init(ctx);
	pblk_l2p_sha1_update(ctx, trans_map, trans_map_size);
	pblk_l2p_sha1_final(ctx, sha_result);

	trace_printk("[%s(%s):%d] restore corrupt the table (target->%d): %s\n",
		     __FILE__, __func__, __LINE__, corrupt_target,
		     pblk_l2p_sha1_str(sha_result));
}

int pblk_test(const size_t trans_map_size, const size_t cache_size)
{
	struct pblk *pblk;
	struct ppa_addr *trans_map_ptr;

	sector_t nr_lba = 0, lba = 0;

	pblk = vmalloc(sizeof(struct pblk));
	pblk->addrf_len = 64; // OCSSD 20 SPEC

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

	pblk_l2p_construct_trans_map(pblk, pblk->trans_map, trans_map_size);
	pblk_l2p_trans_map_to_dir(pblk, trans_map_size);

	nr_lba = pblk_get_map_nr_entries(pblk, trans_map_size);
	trans_map_ptr = (struct ppa_addr *)pblk->trans_map;

	for (lba = 0; lba < nr_lba; lba++) {
		struct ppa_addr c_ppa =
			pblk_l2p_get_ppa(pblk, lba); // cache map ppa
		struct ppa_addr m_ppa = trans_map_ptr[lba]; // trans map ppa
		if (m_ppa.ppa != c_ppa.ppa)
			trace_printk("%u %u %u <==> %u %u %u\n", m_ppa.a.ch,
				     m_ppa.a.lun, m_ppa.a.blk, c_ppa.a.ch,
				     c_ppa.a.lun, c_ppa.a.blk);
	}

	pblk_sha_test(pblk, trans_map_size);

	pblk_l2p_cache_free(pblk->cache);
	pblk_l2p_dir_free(pblk->dir);

	vfree(pblk->trans_map);

	vfree(pblk);
	return 0;
}
