/**
 * @file	pblk-sha1.h
 * @author	오기준
 * @date	2019-02-07
 * @version	0.1
 * @brief	SHA1 수행
 * @detail	SHA1 수행을 하는 역할을 한다.
 * @see	https://github.com/B-Con/crypto-algorithms
 */

#ifndef PBLK_SHA1_H
#define PBLK_SHA1_H

#include <linux/string.h>
#include <linux/types.h>

#define PBLK_SHA1_BLK_SIZE 20 // SHA1 outputs a 20 byte digest

struct pblk_l2p_sha1_ctx {
	unsigned char data[64];
	unsigned int datalen;
	u64 bitlen;
	unsigned int state[5];
	unsigned int k[4];
};

static char *buf;

#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

static inline void pblk_l2p_sha1_transform(struct pblk_l2p_sha1_ctx *ctx,
					   const unsigned char data[])
{
	unsigned int a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) +
		       (data[j + 2] << 8) + (data[j + 3]);
	for (; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e +
		    ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

static inline void pblk_l2p_sha1_init(struct pblk_l2p_sha1_ctx *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

static inline void pblk_l2p_sha1_update(struct pblk_l2p_sha1_ctx *ctx,
					const unsigned char data[], size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			pblk_l2p_sha1_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

static inline void pblk_l2p_sha1_final(struct pblk_l2p_sha1_ctx *ctx,
				       unsigned char hash[])
{
	unsigned int i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		pblk_l2p_sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	pblk_l2p_sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big
	// endian, reverse all the bytes when copying the final state to the output
	// hash.
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

static inline int pblk_l2p_sha1_cmp(const unsigned char hash1[],
				    const unsigned char hash2[])
{
	int i = 0;
	for (i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		if (hash1[i] != hash2[i]) {
			return i + 1;
		}
	}
	return 0;
}

static inline const char *pblk_l2p_sha1_str(const unsigned char hash[])
{
	int i = 0, sz = 0;
	unsigned char *ptr = NULL;

	if (buf == NULL)
		buf = vmalloc(PAGE_SIZE);

	memset(buf, 0, PAGE_SIZE);
	for (i = 0; i < PBLK_SHA1_BLK_SIZE; i++) {
		ptr = buf + sz;
		sz += snprintf(ptr, PAGE_SIZE, "%x", hash[i]);
		if (sz >= PAGE_SIZE) {
			printk(KERN_ERR "SHA result over PAGE_SIZE: %d/%lu\n",
			       sz, PAGE_SIZE);
			return ERR_PTR(-EACCES);
		}
	}
	return buf;
}

#endif // PBLK_SHA1_H
