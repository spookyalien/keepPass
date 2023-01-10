#include "HMAC.h"
#include "../Utility/cpputility.h"

/*
	@param key: chosen password
	@param msg: message to be encrypted

	returns: SHA1_SUCCESS (0) if successful, and -1 otherwise
*/
int HMAC(unsigned char* key, unsigned char* msg, unsigned char msg_digest_final[SHA1_HASH_SIZE])
{
	SHA1_CTX ctx;
	unsigned char msg_digest[SHA1_HASH_SIZE] = {};
	unsigned char i_pad[SHA1_MSG_BLOCK_SIZE] = {};
	unsigned char o_pad[SHA1_MSG_BLOCK_SIZE] = {};
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
	
	return SHA1_result(&ctx, msg_digest_final);
}

/*
	@param key: chosen password
	@param key_len: length of key to be passed which will be changed if key size is too large

	returns: key to be used for HMAC
*/
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
