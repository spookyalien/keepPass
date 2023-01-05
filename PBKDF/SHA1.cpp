#include "SHA1.h"

static uint32_t add_temp;
#define SHA1_add_length(context, length)                                   \
					 (add_temp = (context)->len_low,                     \
					 (context)->corrupted =                              \
				     (((context)->len_low += (length)) < add_temp) &&    \
					 (++(context)->len_high == 0) ? 1 : 0)

unsigned int sha_h[5] = {
	 0x67452301,
	 0xEFCDAB89,
	 0x98BADCFE,
	 0x10325476,
	 0xC3D2E1F0
};

unsigned int sha_k[4] = {
	0x5A827999,
	0x6ED9EBA1,
	0x8F1BBCDC,
	0xCA62C1D6
};

int SHA_reset(SHA1_CTX* ctx)
{
	if (!ctx)
		return SHA1_NULL;

	ctx->len_low = 0;
	ctx->len_high = 0;
	ctx->msg_block_index = 0;
	memcpy(ctx->h, sha_h, 5 * sizeof(unsigned int));
	ctx->computed = 0;
	ctx->corrupted = 0;

	return SHA1_SUCCESS;
}

int SHA_input(SHA1_CTX* ctx, const uint8_t* octets, unsigned int byte_count)
{
	if (!byte_count)
		return SHA1_SUCCESS;

	if (!ctx || !octets)
		return SHA1_NULL;

	if (ctx->computed) {
		ctx->corrupted = SHA1_ERROR;
		return SHA1_ERROR;
	}

	if (ctx->corrupted)
		return ctx->corrupted;

	while (byte_count-- && !ctx->corrupted) {
		ctx->msg_block[ctx->msg_block_index++] = (*octets & 0xFF);

		if (!SHA1_add_length(ctx, 8) && (ctx->msg_block_index == SHA1_MSG_BLOCK_SIZE)) 
			SHA1_proc_msg(ctx);

		octets++;
	}

	return SHA1_SUCCESS;
}

int SHA_final(SHA1_CTX* ctx, const uint8_t octet, unsigned int bit_count)
{
	uint8_t masks[8] = {
		/* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
		/* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
		/* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
		/* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
	};

	uint8_t markbit[8] = {
		/* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
		/* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
		/* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
		/* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
	};

	if (!bit_count)
		return SHA1_SUCCESS;

	if (!ctx)
		return SHA1_NULL;

	if (ctx->computed || (bit_count >= 8) || (bit_count == 0)) {
		ctx->corrupted = SHA1_ERROR;
	}

	if (ctx->corrupted)
		return ctx->corrupted;

	SHA1_add_length(ctx, bit_count);
	SHA1_finalize(ctx, (uint8_t)((octet & masks[bit_count]) | markbit[bit_count]));

	return SHA1_SUCCESS;
}

int SHA_result(SHA1_CTX* ctx, uint8_t digest[SHA1_HASH_SIZE])
{
	if (!ctx || !digest)
		return SHA1_NULL;

	if (ctx->corrupted)
		return ctx->corrupted;

	if (!ctx->computed)
		SHA1_finalize(ctx, 0x80);

	for (int i = 0; i < SHA1_HASH_SIZE; i++) {
		digest[i] = (uint8_t)(sha_h[i >> 2] >> 8 * (3 - (i & 0x03) ));
	}

	return SHA1_SUCCESS;
}

void SHA1_finalize(SHA1_CTX* ctx, uint8_t pad_byte)
{
	SHA1_pad_msg(ctx, pad_byte);

	for (int i = 0; i < SHA1_MSG_BLOCK_SIZE; i++) {
		ctx->msg_block[i] = 0;
	}
	ctx->len_low = 0;
	ctx->len_high = 0;
	ctx->computed = 1;
}

void SHA1_pad_msg(SHA1_CTX* ctx, uint8_t pad_byte)
{
	if (ctx->msg_block_index >= (SHA1_MSG_BLOCK_SIZE - 8)) {
		ctx->msg_block[ctx->msg_block_index++] = pad_byte;
		
		while (ctx->msg_block_index < SHA1_MSG_BLOCK_SIZE) {
			ctx->msg_block[ctx->msg_block_index++] = 0;
		}
		SHA1_proc_msg(ctx);
	}
	else {
		ctx->msg_block[ctx->msg_block_index++] = pad_byte;
	}

	while (ctx->msg_block_index < (SHA1_MSG_BLOCK_SIZE - 8)) {
		ctx->msg_block[ctx->msg_block_index++] = 0;
	}

	ctx->msg_block[56] = (uint8_t)(ctx->len_high >> 24);
	ctx->msg_block[57] = (uint8_t)(ctx->len_high >> 16);
	ctx->msg_block[58] = (uint8_t)(ctx->len_high >> 8);
	ctx->msg_block[59] = (uint8_t)(ctx->len_high);
	ctx->msg_block[60] = (uint8_t)(ctx->len_low >> 24);
	ctx->msg_block[61] = (uint8_t)(ctx->len_low >> 16);
	ctx->msg_block[62] = (uint8_t)(ctx->len_low >> 8);
	ctx->msg_block[63] = (uint8_t)(ctx->len_low);

	SHA1_proc_msg(ctx);
}

void SHA1_proc_msg(SHA1_CTX* ctx)
{
	int t;
	uint32_t temp;
	uint32_t w[80];
	uint32_t A, B, C, D, E;

	for (t = 0; t < 16; t++) {
		w[t] = ((uint32_t)ctx->msg_block[t * 4]) << 24;
		w[t] |= ((uint32_t)ctx->msg_block[t * 4 + 1]) << 16;
		w[t] |= ((uint32_t)ctx->msg_block[t * 4 + 2]) << 8;
		w[t] |= ((uint32_t)ctx->msg_block[t * 4 + 3]);
	}

	for (t = 16; t < 80; t++) {
		w[t] = SHA1_ROTL(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
	}

	A = ctx->h[0];
	B = ctx->h[1];
	C = ctx->h[2];
	D = ctx->h[3];
	E = ctx->h[4];

	for (t = 0; t < 20; t++) {
		temp = SHA1_ROTL(5, A) + SHA_ch(B, C, D) + E + w[t] + sha_k[0];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++) {
		temp = SHA1_ROTL(5, A) + SHA_parity(B, C, D) + E + w[t] + sha_k[1];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++) {
		temp = SHA1_ROTL(5, A) + SHA_maj(B, C, D) + E + w[t] + sha_k[2];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++) {
		temp = SHA1_ROTL(5, A) + SHA_parity(B, C, D) + E + w[t] + sha_k[3];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	ctx->h[0] += A;
	ctx->h[1] += B;
	ctx->h[2] += C;
	ctx->h[3] += D;
	ctx->h[4] += E;

	ctx->msg_block_index = 0;
}