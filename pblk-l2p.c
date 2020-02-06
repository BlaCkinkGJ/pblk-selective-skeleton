/**
 * @file	pblk-l2p.c
 * @author	오기준
 * @date	2019-02-06
 * @version 0.1
 * @brief	선택적 매핑 테이블의 동작을 설명한다.
 * @details	전역 디렉터리와 캐시 매핑 테이블의 생성 및 사용에 대해 정의가 되어있다.
 * @see		KSC 2019, KCS 2020
 */

#include "pblk.h"

/**
 * @brief	매핑 테이블에 들어갈 수 있는 L2P 엔트리 수를 반환한다.
 * @details	사용자가 준 매핑 테이블 크기를 OCSSD의 L2P 주소 형식(u32 or struct ppa_addr)에 해당하는 크기로 나누어 그 값을 사용자에게 준다. 주 목적은 매핑 테이블에 들어갈 수 있는 최대 L2P 엔트리의 갯수를 알기 위함이다.
 * @param	pblk	pblk 구조체
 * @param	map_size	매핑 테이블 크기(byte 단위)
 * @return	매핑 테이블에 들어 갈 수 있는 L2P 매핑 테이블 갯수
 */
sector_t pblk_get_map_nr_entries(struct pblk *pblk, const size_t map_size)
{
	return (sector_t)(map_size / pblk_l2p_ppa_size(pblk));
}

/**
 * @brief	캐시 매핑 테이블을 구성한다.
 * @details	캐시의 크기(byte)를 받아서 캐시 매핑 테이블의 엔트린인 centry를 구축하고, 각 centry의 캐시 블록을 만들어 주도록 한다. 이때, 캐시 블록이 여러개인 이유는 kmalloc의 경우 크기가 일반적으로 PAGE_SIZE를 넘지 않기 때문이다. 이는 논문과 혼동할 수 있는 부분으로, 논문에서 이야기하는 캐시 블록은 캐시 엔트리(centry) 하나가 가지는 캐시 블록의 전체 갯수를 의미하고 여기서 캐시 블록은 PAGE_SIZE의 단일 메모리 블록을 의미한다.
 * @param	cache_size	캐시의 크기(byte)
 * @return	캐시 매핑 테이블의 포인터
 */
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
		centry->free_bitmap_idx = i;
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

/**
 * @brief	캐시 매핑 테이블의 동적 할당 내역을 해제한다.
 * @details	캐시 매핑 테이블에서 동적 할당되는 내용으로는 bitmap, cache_blk, cache가 있다. 따라서 이들을 순서대로 해제를 해주어야 한다.
 * @param	cache	캐시 매핑 테이블의 포인터
 * @see		pblk_l2p_cache_create
 */
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

/**
 * @brief	전역 디렉터리를 생성하도록 한다.
 * @details	매핑 테이블의 크기(byte)를 받아서 전역 디렉터리의 엔트린인 dentry를 구축하고, 각 dentry의 구성 요소를 초기화해주도록 한다.
 * @param	map_size	매핑 테이블 크기(byte)
 * @return	전역 디렉터리 포인터
 */
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
		dentry->paddr = 0;

		memset(dentry->sig, 0, PBLK_SHA1_BLK_SIZE);

		dentry->centry = NULL;
	}

	dir->nr_dentries = nr_dentries;

	return dir;
}

/**
 * @brief	전역 디렉터리의 동적 할당 내역을 해제한다.
 * @param	dir	전역 디렉터리 포인터
 * @see		pblk_l2p_dir_create
 */
void pblk_l2p_dir_free(struct pblk_l2p_dir *dir)
{
	vfree(dir);
}

/**
 * @brief	매핑 테이블의 내용을 캐시 블록으로 복제한다.
 * @details	매핑 테이블의 시작점에서 매개 변수에서 명시된 size의 크기(byte)만큼 centry가 가리키는 캐시 블록으로 복사를 하도록 한다. 이때, 복사 시에 발생하는 무결성 위반 문제를 확인하기 위해서 SHA1 서명을 수행한다.
 * @param	map	매핑 테이블의 포인터를 지칭한다.
 * @param	centry	복사의 대상이 되는 캐시 블록을 포함하는 캐시 매핑 테이블의 엔트리 포인터를 지칭한다.
 * @param	size	매핑 테이블에서 복사하고자하는 크기(byte)를 의미한다.
 * @return	반환 값이 0이면 정상 종료, 이외는 오류로 처리된다. 각 오류 번호는 커널에서 정의된 오류 정의를 따른다.
 * @todo	SHA1 서명의 부하가 크다. 160MB의 매핑 테이블의 경우에 이 과정에만 10초 이상 걸리게 된다.
 * @exception 매핑 테이블을 size 만큼 캐시 블록들에 붙였음에도 나머지 값인 rem이 남은 경우
 * @exception 매핑 테이블의 서명과 캐시 블록의 서명이 다른 경우
 * @see	pblk_l2p_sha1_init();
 * @see	pblk_l2p_sha1_update();
 * @see memcpy();
 */
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

	pblk_l2p_sha1_init(&ctx_trans_map);
	pblk_l2p_sha1_init(&ctx_dftl_map);

	for (i = 0; i < PBLK_CENTRY_NR_BLK; i++) {
		if (rem <= 0) {
			break;
		}

		cache_blk_ptr = centry->cache_blk[i];

		memcpy(centry->cache_blk[i], map, PBLK_CENTRY_BLK_SIZE);

		pblk_l2p_sha1_update(&ctx_trans_map, map, PBLK_CENTRY_BLK_SIZE);
		pblk_l2p_sha1_update(&ctx_dftl_map, centry->cache_blk[i],
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

	pblk_l2p_sha1_final(&ctx_trans_map, trans_map_sha);
	pblk_l2p_sha1_final(&ctx_dftl_map, centry->owner_sig);

	if (pblk_l2p_sha1_cmp(trans_map_sha,
			      centry->owner_sig)) { // SHA1 signiture check
		printk(KERN_ERR
		       "[%s(%s):%d] SHA1 signature unmatched (original/cache): %s/%s\n",
		       __FILE__, __func__, __LINE__,
		       pblk_l2p_sha1_str(trans_map_sha),
		       pblk_l2p_sha1_str(centry->owner_sig));
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief	매핑 테이블의 내용을 전역 디렉터리로 복제한다.
 * @details	pblk에 있는 매핑 테이블(pblk->trans_map) 내용을 전역 디렉터리의 캐시 매핑 테이블 엔트리 포인터로 옮기고 OCSSD에 해당 내용을 넣은 후에 line, paddr 값을 설정하고 centry를 NULL로 해제하여 초기화한다. 유의점으로는 이는 초기화 작업을 하는 데 한정해서 사용되며, helper_cache라고 이 함수에서만 사용하는 임시 캐시 매핑 테이블이 있다.
 * @param	pblk	pblk 구조체
 * @param	trans_map_size	매핑 테이블의 크기를 지칭한다.
 * @return	반환 값이 0이면 정상 종료, 이외는 오류로 처리된다. 각 오류 번호는 커널에서 정의된 오류 정의를 따른다.
 * @todo	SSD에 쓰고 line 및 paddr 값을 받는 것을 구현해야 하며, helper_cache를 좀 더 최적화해야 한다.
 * @exception	helper_cache 포인터가 유효하지 않으면 임시 캐시를 못 만든 것이므로 오류를 발생시킨다.
 * @exception	helper_cache의 엔트리 갯수와 전역 디렉터리의 엔트리 갯수가 맞지 않으면 오류로 처리한다. 동일해야 하는 이유는 매핑 테이블 전체를 1:1로 넣을 것이기 때문이다.
 * @exception	pblk_l2p_copy_map_to_centry 함수 수행 후에 반환 값으로 오류 값을 받은 경우
 * @see	pblk_l2p_cache_create();
 * @see	pblk_l2p_copy_map_to_centry();
 * @see	pblk_l2p_cache_free();
 */
int pblk_l2p_trans_map_to_dir(struct pblk *pblk, const size_t trans_map_size)
{
	struct pblk_l2p_dir *dir = pblk->dir;
	struct pblk_l2p_dentry *dentry = NULL;

	const unsigned char *trans_map = pblk->trans_map;

	struct pblk_l2p_cache *helper_cache = NULL;
	struct pblk_l2p_centry *centry = NULL;

	sector_t i = 0, sz = 0;
	int err;

	helper_cache = pblk_l2p_cache_create(trans_map_size);
	if (IS_ERR(helper_cache)) {
		printk(KERN_ERR "[%s(%s):%d] fail to consist the cache....\n",
		       __FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	if (dir->nr_dentries != helper_cache->nr_centries) {
		printk(KERN_ERR
		       "[%s(%s):%d] unaligned cache size(dir/cache): %lu/%lu\n",
		       __FILE__, __func__, __LINE__, dir->nr_dentries,
		       helper_cache->nr_centries);
		return -EINVAL;
	}

	for (i = 0; i < dir->nr_dentries; i++) {
		if (sz >= trans_map_size) {
			printk(KERN_WARNING
			       "[%s(%s):%d] copy size overflow warning(cur/total): %lu/%lu\n",
			       __FILE__, __func__, __LINE__, sz,
			       trans_map_size);
			break;
		}
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
		centry = dentry->centry;
		memcpy(dentry->sig, centry->owner_sig, PBLK_SHA1_BLK_SIZE);
		set_bit(centry->free_bitmap_idx, helper_cache->free_bitmap);

		trans_map += PBLK_CENTRY_SIZE;
		sz += PBLK_CENTRY_SIZE;
	}

#ifndef PBLK_L2P_TEST
	pblk_l2p_cache_free(helper_cache);
#endif
	return 0;
}

/**
 * @brief	dentry가 가리키는 centry에서 캐시 블록을 통해 PPA 값을 받아오도록 한다.
 * @details	dentry가 가리키는 centry에서 cloc(centry 안 캐시 블록들에서의 LBA의 위치)을 바탕으로 centry 안에서의 캐시 블록 번호랑 해당 캐시 블록에서의 위치를 구해서 PPA 값을 가져오도록 한다.
 * @param	pblk	pblk 구조체
 * @param	dentry	전역 디렉터리 엔트리 구조체
 * @param	centry	centry가 가리키는 캐시 블록 집합에서의 LBA 위치
 * @return	PPA 값
 * @see	pblk_get_map_nr_entries();
 */
static struct ppa_addr
pblk_l2p_get_ppa_from_cache(struct pblk *pblk, struct pblk_l2p_dentry *dentry,
			    sector_t cloc)
{
	const struct pblk_l2p_centry *centry = dentry->centry;

	sector_t offset = -1, idx = cloc; /* cloc ==> cache location */
	const sector_t nr_ppa_in_cache_blk =
		pblk_get_map_nr_entries(pblk, PBLK_CENTRY_BLK_SIZE);
	const unsigned char *addr;

	offset = do_div(idx, nr_ppa_in_cache_blk);
	addr = centry->cache_blk[idx] + offset * pblk_l2p_ppa_size(pblk);

	if (pblk->addrf_len < 32) {
		return pblk_ppa32_to_ppa64(pblk, *addr);
	}
	return *((struct ppa_addr *)addr);
}

/**
 * @brief	SSD에서 캐시 블록으로 매핑 블록을 가져온다.
 * @details	dentry의 line과 paddr을 확인하여 SSD의 매핑 블록을 가져와서 캐시 블록에 넣도록한다.
 * @param	pblk	pblk 구조체
 * @param	dentry	전역 디렉터리 엔트리 구조체
 * @return	PPA 값을 반환
 */
static struct ppa_addr pblk_l2p_get_ppa_from_ssd(struct pblk *pblk,
						 struct pblk_l2p_dentry *dentry)
{
	struct ppa_addr ppa;

	pblk_ppa_set_empty(&ppa);

	/* EVICTION AND READ/WRITE OPERATION IMPLEMENTED IN THIS PLACE */

	return ppa;
}

/**
 * @brief	LBA 값을 받아 PPA 값을 획득한다.
 * @details	LBA 값을 바탕으로 전역 디렉터리에서의 LBA를 포함하는 전역 디렉터리 엔트리의 위치를 찾는다. 그리고 엔트리가 가리키는 캐시 매핑 테이블의 엔트리 포인터 값어 NULL인지를 확인하고 NULL이면 캐시 미스에 해당하는 동작을 하고 아닌 경우 캐시 히트에 해당하는 동작을 하도록 한다.
 * @param	pblk	pblk 구조체
 * @param	lba	LBA 값
 * @return	PPA 값
 * @exception	lba 값으로 계산한 idx 값이 디렉터리가 가지는 엔트리의 갯수보다 큰 경우
 * @exception	lba 값으로 계산한 offset이 0보다 작거나 centry 안에 들어갈 수 있는 ppa 갯수보다 많거나 같은 경우
 * @see	pblk_get_map_nr_entries();
 * @see	pblk_l2p_get_ppa_from_cache();
 * @see	pblk_l2p_get_ppa_from_ssd();
 */
struct ppa_addr pblk_l2p_get_ppa(struct pblk *pblk, sector_t lba)
{
	struct pblk_l2p_dir *dir = pblk->dir;
	struct pblk_l2p_dentry *dentry = NULL;

	struct ppa_addr ppa;

	sector_t offset = -1, idx = lba;
	const sector_t nr_ppa_in_centry =
		pblk_get_map_nr_entries(pblk, PBLK_CENTRY_SIZE);

	pblk_ppa_set_empty(&ppa);
	offset = do_div(idx, nr_ppa_in_centry);

	if (idx >= dir->nr_dentries) {
		printk(KERN_ERR
		       "[%s(%s):%d] Invalid directory entry index: %ld/%ld\n",
		       __FILE__, __func__, __LINE__, idx, dir->nr_dentries);
		return ppa;
	}

	if (offset >= nr_ppa_in_centry || (int)offset < 0) {
		printk(KERN_ERR
		       "[%s(%s):%d] Invalid directory entry offset: %lu/%lu\n",
		       __FILE__, __func__, __LINE__, offset, nr_ppa_in_centry);
		return ppa;
	}

	dentry = &dir->dentries[idx];
	if (IS_PBLK_CACHE_MISS(dentry)) {
		ppa = pblk_l2p_get_ppa_from_ssd(pblk, dentry);
	} else {
		ppa = pblk_l2p_get_ppa_from_cache(pblk, dentry, offset);
	}

	return ppa;
}

/* MODULE MAIN */
#ifdef PBLK_L2P_TEST
static int __init init_pblk_l2p(void)
{
	const size_t trans_map_size = 10 * 4096 * PBLK_CENTRY_BLK_SIZE;
	const size_t cache_size = 4096 * PBLK_CENTRY_BLK_SIZE;

	pblk_test(trans_map_size, cache_size);

	return 0;
}

static void __exit cleanup_pblk_l2p(void)
{
	trace_printk("~~~~~~~~~~~~~~~~~~~GOOD BYE!!!~~~~~~~~~~~~~~~~~~~\n");
}

module_init(init_pblk_l2p); // TODO: MUST DELETE
module_exit(cleanup_pblk_l2p); // TODO: MUST DELETE
#endif /* PBLK_L2P_TEST */
