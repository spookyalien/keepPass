#include "pbkdf2.h"

/*
	@param c: number of iterations desired
	@param salt: sequence of random bits for better cryptography
	@param dk_len: desired bit length of derived key
	@param pass: chosen password
	@param prf: pseudorandom function to be used (in this case a keyed HMAC)
    @param out: hashed key

	returns: size of key
*/
int PBKDF2(unsigned char* pass, int pass_len, unsigned char* salt, int salt_len, int c, int dk_len, unsigned char** out)
{
	*out = (unsigned char*) malloc(dk_len);
	memset(*out, 0, dk_len);

	int num_blocks = dk_len / h_len;
	int cursor = 0;

	if (dk_len % h_len)
		num_blocks++;

	unsigned char* concat_salt = (unsigned char*) malloc(salt_len + 4);
	memcpy(concat_salt, salt, salt_len);

	for (int i = 0; i < num_blocks; i++) {
		int block_len = MIN(h_len, dk_len - cursor);
		unsigned char block[SHA1_HASH_SIZE];

		unsigned int salt_counter = i + 1;
		for (int j = 0; j < 4; j++) {
			concat_salt[salt_len + 4 - j - 1] = (unsigned char) salt_counter;
			salt_counter >>= 8;
		}

		unsigned char *prev_salt = concat_salt;
		int prev_salt_len = salt_len + 4;
		for (int j = 0; j < c; j++) {
			int len = HMAC(pass, pass_len, prev_salt, prev_salt_len, block);
            
			for (int k = 0; k < block_len; k++) {
				(*out) [cursor + k] ^= block[k];
			}
         
			prev_salt = block;
			prev_salt_len = len;
		}

		cursor += h_len;
	}
	return strlen((const char*)(*out));
}

