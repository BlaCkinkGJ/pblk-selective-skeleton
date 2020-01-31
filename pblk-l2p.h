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
#define PBLK_NR_CENTRY_MAP 1000 /* PAGE_SIZE * 1000 */
#define PBLK_NR_CACHE 5 /* TOTAL CACHE = PBLK_NR_CACHE * PBLK_NR_CENTRY_MAP*/

/* STRUCT DEFINE */
struct pblk_l2p_centry {
	unsigned char *trans_map[PBLK_NR_CENTRY_MAP];
};

struct pblk_l2p_dentry {
	atomic64_t hotness;

	/* translation block location info */
	struct pblk_line *line;
	struct ppa_addr ppa;

	unsigned char sig[PBLK_SHA1_BLK_SIZE];
	struct pblk_l2p_centry *ptr;
};

struct pblk_l2p_dir {
	int nr_dentry; 
	mempool_t *centry_pool; 
	struct pblk_l2p_dentry dentry[0]; // For dynamic allocate
};

/* DECLARE FUNCION */
int pblk_sha_test(void); // TEST FUNCTION

#define DRIVER_AUTHOR "Gijun O <kijunking@pusan.ac.kr>"
#define DRIVER_DESC "pblk-l2p sample driver"

MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("pblk_test_device");

#endif /* PBLK_L2P_H */
