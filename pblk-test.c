#include "pblk-l2p.h"

int pblk_sha_test(void) {
	char *trans_map = NULL;
	int nr_entries = 0, i = 0;

	int corrupt_target = 0, original_value = 0;

	struct pblk_l2p_sha1_ctx ctx;

	unsigned char sha_result[PBLK_SHA1_BLK_SIZE];

	trans_map = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if (!trans_map) {
		return -ENOMEM;
	}

	nr_entries = PAGE_SIZE / sizeof(struct ppa_addr);
	corrupt_target = nr_entries - 1;

	trace_printk("[INFO] # of entries ==> %d\n", nr_entries);

	for(i = 0; i < nr_entries; i++) {
		u32 rnd_num;

		get_random_bytes(&rnd_num, sizeof(u32));
		((struct ppa_addr *)trans_map)[i].a.ch = i;
		((struct ppa_addr *)trans_map)[i].a.lun = i+10;
		((struct ppa_addr *)trans_map)[i].a.blk = rnd_num;
	}
	sha1_init(&ctx);
	sha1_update(&ctx, trans_map, PAGE_SIZE);
	sha1_final(&ctx, sha_result);

	trace_printk("[SHA1] before corrupt the table\n");
	for(i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[SHA1] index %d ==> 0x%x\n", i, sha_result[i]);
	}

	original_value = ((struct ppa_addr *)trans_map)[corrupt_target].a.blk;
	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = 0;

	sha1_init(&ctx);
	sha1_update(&ctx, trans_map, PAGE_SIZE);
	sha1_final(&ctx, sha_result);

	trace_printk("[SHA1] after corrupt the table (target->%d)\n", corrupt_target);
	for(i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[SHA1] index %d ==> 0x%x\n", i, sha_result[i]);
	}

	((struct ppa_addr *)trans_map)[corrupt_target].a.blk = original_value;
	
	sha1_init(&ctx);
	sha1_update(&ctx, trans_map, PAGE_SIZE);
	sha1_final(&ctx, sha_result);

	trace_printk("[SHA1] restore corrupt the table (target->%d)\n", corrupt_target);
	for(i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		trace_printk("[SHA1] index %d ==> 0x%x\n", i, sha_result[i]);
	}

	kfree(trans_map);
	return 0;
}
