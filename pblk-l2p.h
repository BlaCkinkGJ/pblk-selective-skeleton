/**
 * @file	pblk-l2p.h
 * @author	오기준
 * @date	2019-02-07
 * @version	0.1
 * @brief	선택적 매핑 테이블 구성에 필요한 도구를 선언
 * @detail	선택적 매핑 테이블에 관련한 구조체 및 빠른 연산을 요하여 인라인으로 처리할 필요가 있는 함수를 정의
 * @see	KSC 2019, KCS 2020
 */

#ifndef PBLK_L2P_H
#define PBLK_L2P_H

/* LINUX KERNEL HEADER */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

/* PBLK_H INCLUDED HEADER(TODO: REMOVE) */
#include <linux/lightnvm.h>

/* USER DEFINE HEADER */
#include "pblk.h"
#include "pblk-sha1.h"

/* PRE-DEFINED MACRO */
#define PBLK_L2P_TEST /* 테스트를 하는 경우에만 사용 */
#define PBLK_CENTRY_BLK_SIZE (PAGE_SIZE) /* 캐시 블록의 크기를 정의(byte) */
#define PBLK_CENTRY_NR_BLK (4) /* centry에 들어가는 캐시 블록의 갯수 */
#define PBLK_CENTRY_SIZE                                                       \
	(PBLK_CENTRY_NR_BLK *                                                  \
	 PBLK_CENTRY_BLK_SIZE) /* centry의 캐시 블록들의 총합 */
#define IS_PBLK_CACHE_MISS(dentry) (dentry->centry == NULL)

/* STRUCT DEFINE */

/**
 * @brief	캐시 매핑 테이블 엔트리 구조체
 * @details	free_bitmap_idx는 상위 구조체인 cache의 free_bitmap에서의 위치를 가지고 있다. owner_sig의 경우 cache_blk 전체에 대한 SHA1 서명 값이 들어간다. cache_blk는 캐시 블록의 포인터를 가리킨다.
 */
struct pblk_l2p_centry {
	sector_t free_bitmap_idx;
	unsigned char owner_sig[PBLK_SHA1_BLK_SIZE];
	unsigned char *cache_blk[PBLK_CENTRY_NR_BLK];
};

/**
 * @brief	캐시 매핑 테이블 구조체
 * @details	이 구조체는 가변 구조체로 구조체의 크기와 캐시 매핑 테이블에서 현재 사용하지 않는 캐시 매핑 테이블 엔트리에 대한 정보를 가지는 부분(free_bitmap)과 캐시 매핑 테이블 엔트리(centries)로 구성된다.
 */
struct pblk_l2p_cache {
	sector_t nr_centries;
	unsigned long *free_bitmap;
	struct pblk_l2p_centry centries[0]; // For dynamic alloc
};

/**
 * @brief	전역 디렉터리 엔트리 구조체
 * @details	축출 대상을 판별하는 데 이용하는 인기도(hotness)와 매핑 블록의 위치를 담는 line, paddr 멤버 변수 및 해당 디렉터리가 가리키는 매핑 블록에 대한 SHA1 서명 값과 캐시 매핑 테이블 엔트리를 가리키는 centry 포인터로 구성된다. 유의사항으로 sig는 pblk_l2p_trans_map_to_dir을 수행하고 이후로 그 값이 절대 변경되면 안되는 특징이 있다.
 */
struct pblk_l2p_dentry {
	atomic64_t hotness;

	struct pblk_line *line;
	u64 paddr;

	unsigned char sig[PBLK_SHA1_BLK_SIZE];
	struct pblk_l2p_centry *centry;
};

/**
 * @brief	전역 디렉터리 구조체
 * @details	가변 구조체로 전역 디렉터리의 엔트리 갯수(nr_entries)와 엔트리 정보를 가진다.
 */
struct pblk_l2p_dir {
	sector_t nr_dentries;
	struct pblk_l2p_dentry dentries[0]; // For dynamic alloc
};

/* DECLARE FUNCION */
struct ppa_addr pblk_l2p_get_ppa(struct pblk *pblk, sector_t lba);

sector_t pblk_get_map_nr_entries(struct pblk *pblk, const size_t map_size);
struct pblk_l2p_cache *pblk_l2p_cache_create(size_t cache_size);
struct pblk_l2p_dir *pblk_l2p_dir_create(size_t map_size);
void pblk_l2p_cache_free(struct pblk_l2p_cache *cache);
void pblk_l2p_dir_free(struct pblk_l2p_dir *dir);
int pblk_l2p_copy_map_to_centry(const unsigned char *map,
				struct pblk_l2p_centry *centry,
				const size_t size);
int pblk_l2p_trans_map_to_dir(struct pblk *pblk, const size_t trans_map_size);

/* DEFINITION FUNCTION */

/**
 * @brief	OCSSD 버전에 따른 ppa의 크기 값을 반환한다.
 * @details	pblk->addrf_len의 값이 32 미만이면 OCSSD 1.2 스펙을 따르는 것으로 판단하고, 아닌 경우 2.0을 따르는 것으로 판단한다.
 * @param	pblk	pblk 구조체
 * @return	ppa의 크기
 * @see	pblk_trans_map_size();
 */
static inline size_t pblk_l2p_ppa_size(struct pblk *pblk)
{
	if (pblk->addrf_len < 32)
		return sizeof(u32);
	else
		return sizeof(struct ppa_addr);
}

#ifdef PBLK_L2P_TEST

int pblk_test(const size_t trans_map_size,
	      const size_t cache_size); // TEST FUNCTION
#define DRIVER_AUTHOR "Gijun O <kijunking@pusan.ac.kr>"
#define DRIVER_DESC "pblk-l2p sample driver"

MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("pblk_test_device");
#endif /* PBLK_L2P_TEST */

#endif /* PBLK_L2P_H */
