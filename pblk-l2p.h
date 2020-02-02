#ifndef PBLK_L2P_H
#define PBLK_L2P_H

/* LINUX KERNEL HEADER */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/random.h>

/* PBLK_H INCLUDED HEADER(TODO: REMOVE) */
#include <linux/lightnvm.h>

/* USER DEFINE HEADER */
#include "pblk-sha1.h"

/* PRE-DEFINED MACRO */
#define PBLK_TEST
#define PBLK_CENTRY_BLK_SIZE (PAGE_SIZE)
#define PBLK_CENTRY_NR_BLK (4)
#define PBLK_CENTRY_SIZE (PBLK_CENTRY_NR_BLK * PBLK_CENTRY_BLK_SIZE)

/* STRUCT DEFINE */
struct pblk_l2p_centry {
	unsigned char owner_sig[PBLK_SHA1_BLK_SIZE];
	unsigned char *cache_blk[PBLK_CENTRY_NR_BLK];
};

struct pblk_l2p_cache {
	int nr_centries;
	unsigned long *free_bitmap;
	struct pblk_l2p_centry centries[0]; // For dynamic alloc
};

struct pblk_l2p_dentry {
	atomic64_t hotness;

	/* translation block location info */
	struct pblk_line *line;
	struct ppa_addr ppa;

	unsigned char sig[PBLK_SHA1_BLK_SIZE];
	struct pblk_l2p_centry *centry;
};

struct pblk_l2p_dir {
	int nr_dentries; 
	struct pblk_l2p_dentry dentries[0]; // For dynamic alloc
};

/* DECLARE FUNCION */
struct pblk_l2p_cache *pblk_l2p_cache_create(size_t cache_size);
struct pblk_l2p_dir *pblk_l2p_dir_create(size_t map_size);
void pblk_l2p_cache_free(struct pblk_l2p_cache *cache);
void pblk_l2p_dir_free(struct pblk_l2p_dir *dir);

int pblk_sha_test(void); // TEST FUNCTION

#define DRIVER_AUTHOR "Gijun O <kijunking@pusan.ac.kr>"
#define DRIVER_DESC "pblk-l2p sample driver"

MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("pblk_test_device");

#endif /* PBLK_L2P_H */
