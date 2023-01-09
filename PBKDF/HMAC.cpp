#include "HMAC.h"
#include "../Utility/utility.h"


int HMAC(unsigned char* key, unsigned char* msg)
{
	SHA1_CTX ctx;
	uint8_t msg_digest[SHA1_HASH_SIZE];
	uint8_t msg_digest_final[SHA1_HASH_SIZE];
	unsigned char i_pad[SHA1_MSG_BLOCK_SIZE];
	unsigned char o_pad[SHA1_MSG_BLOCK_SIZE];
	int i = 0;
	int key_len = strlen((char*)key);

	key = compute_block_size_key(key, &key_len);

	for (; i < key_len; i++) {
		i_pad[i] = key[i] ^ 0x36;
		o_pad[i] = key[i] ^ 0x5c;
	}
	for (; i < SHA1_MSG_BLOCK_SIZE; i++) {
		i_pad[i] = 0x36;
		o_pad[i] = 0x5c;
	}

	// HMAC uses hash(o_key_pad || hash(i_key_pad || message)) to hash where || is concatenation
	SHA1_reset(&ctx);
	SHA1_input(&ctx, i_pad, SHA1_MSG_BLOCK_SIZE);
	SHA1_input(&ctx, msg, strlen((char*)msg));
	SHA1_result(&ctx, msg_digest);

	SHA1_reset(&ctx);
	SHA1_input(&ctx, o_pad, SHA1_MSG_BLOCK_SIZE);
	SHA1_input(&ctx, msg_digest, SHA1_HASH_SIZE);
	SHA1_result(&ctx, msg_digest_final);

	for (int i = 0; i < 20; ++i)
	{
		printf("%02X", msg_digest_final[i]);
	}
	printf("\n");
	return 1;
}

unsigned char* compute_block_size_key(unsigned char* key, int* key_len)
{
	uint8_t tmp_msg_digest[SHA1_HASH_SIZE];

	if (*key_len > SHA1_MSG_BLOCK_SIZE) {
		SHA1_CTX ctx1;

		int err = SHA1_reset(&ctx1) || SHA1_input(&ctx1, key, *key_len) || SHA1_result(&ctx1, tmp_msg_digest);
		if (err != SHA1_SUCCESS)
			return NULL;

		key = tmp_msg_digest;
		*key_len = SHA1_HASH_SIZE;
	}

	return key;
}
