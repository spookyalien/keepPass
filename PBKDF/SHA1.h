#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <stdint.h>

#define SHA1_HASH_SIZE 20
#define SHA1_HASH_SIZE_BITS 160
#define SHA1_MSG_BLOCK_SIZE 64
#define SHA1_SUCCESS 0
#define SHA1_NULL -1
#define SHA1_ERROR -1
#define SHA1_LONG_INPUT -1

// SHA1 circular left shift macro
#define SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32-(bits))))

typedef struct SHA1_CTX {

	uint32_t len_low;
	uint32_t len_high;

	int_least16_t msg_block_index;
	unsigned char msg_block[SHA1_MSG_BLOCK_SIZE];
	uint32_t h[SHA1_HASH_SIZE / 4];

	int computed;
	int corrupted;
} SHA1_CTX;


int SHA1_reset(SHA1_CTX* ctx);
int SHA1_input(SHA1_CTX* ctx, const unsigned char* octets, unsigned int byte_count);
int SHA1_final(SHA1_CTX* ctx, const unsigned char octet, unsigned int bit_count);
int SHA1_result(SHA1_CTX* ctx, unsigned char digest[SHA1_HASH_SIZE]);

void SHA1_finalize(SHA1_CTX* ctx, unsigned char pad_byte);
void SHA1_pad_msg(SHA1_CTX* ctx, unsigned char pad_byte);
void SHA1_proc_msg(SHA1_CTX* ctx);

#endif