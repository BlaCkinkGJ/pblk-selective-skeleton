#include "pblk-l2p.h"

static void *pblk_alloc_centry(gfp_t gfp_mask, void *pool_data)
{
	struct pblk_l2p_centry *centry = NULL;
	int i = 0;

	centry = kmalloc(sizeof(struct pblk_l2p_centry), gfp_mask);
	if (centry == NULL) {
		printk(KERN_ERR"centry allocation failed\n");
		goto fail_to_alloc_centry;
	}

	for (i = 0; i < PBLK_NR_CENTRY_MAP; i++) {
		centry->trans_map[i] = kmalloc(PAGE_SIZE, gfp_mask);
		if (centry->trans_map == NULL) {
			printk(KERN_ERR"centry->trans_map allocation failed\n");
			goto fail_to_alloc_trans_map;
		}
	}

	trace_printk("SUCCESSFUL ALLOCATE THE CENTRY\n");

	return centry;
	
fail_to_alloc_trans_map:
	for (; i >= 0; i--) {
		kfree(centry->trans_map[i]);
	}
fail_to_alloc_centry:
	kfree(centry);

	return ERR_PTR(-ENOMEM);
}

static void pblk_free_centry(void *element, void *pool_data)
{
	struct pblk_l2p_centry *centry = NULL;
	int i = 0;

	centry = (struct pblk_l2p_centry *)element;

	for (i = 0; i < PBLK_NR_CENTRY_MAP; i++) {
		kfree(centry->trans_map[i]);
	}

	kfree(centry);

	trace_printk("DELETE THE CENTRY\n");
}

static struct pblk_l2p_dir *pblk_l2p_dir_alloc(size_t nr_dentry)
{
	struct pblk_l2p_dir *dir = NULL;
	struct pblk_l2p_dentry *dentry = NULL;
	int i = 0;

	dir = vmalloc(sizeof(struct pblk_l2p_dir)+sizeof(struct pblk_l2p_dentry)*nr_dentry);
	if (dir == NULL) {
		printk(KERN_ERR"dir allocation failed\n");
		return ERR_PTR(-ENOMEM);
	}

	for(i = 0; i < nr_dentry; i++) {
		dentry = &dir->dentry[i];
		atomic64_set(&dentry->hotness, 0);

		dentry->line = 0;
		dentry->ppa.ppa = 0;

		memset(dentry->sig, 0, PBLK_SHA1_BLK_SIZE);

		dentry->ptr = NULL;
	}

	dir->centry_pool = mempool_create(PBLK_NR_CACHE, pblk_alloc_centry, pblk_free_centry, NULL);
	dir->nr_dentry = nr_dentry;

	trace_printk("ALLOCATE THE DIR\n");
	return dir;
}

static void pblk_l2p_dir_free(struct pblk_l2p_dir *dir)
{
	mempool_destroy(dir->centry_pool);
}

static int __init init_pblk_l2p(void) {
	struct pblk_l2p_dir *dir = NULL;
	dir = pblk_l2p_dir_alloc(10);
	if (IS_ERR(dir)) {
		printk(KERN_ERR"fail to consist the directory....\n");
		return -1;
	}
	pblk_l2p_dir_free(dir);
	pblk_sha_test();
	return 0;
}

static void __exit cleanup_pblk_l2p(void) {
	trace_printk("GOOD BYE!!!\n");
}

module_init(init_pblk_l2p); // TODO: MUST DELETE
module_exit(cleanup_pblk_l2p); // TODO: MUST DELETE 
