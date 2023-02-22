#include "pbkdf2.h"

/*
	@param c: number of iterations desired
	@param salt: sequence of random bits for better cryptography
	@param dk_len: desired bit length of derived key
	@param pass: chosen password
	@param prf: pseudorandom function to be used (in this case a keyed HMAC)

	returns: derived key to be used for hashing
*/
unsigned char* PBKDF2(unsigned char* pass, unsigned char* salt, int c, int dk_len)
{
	unsigned char digest[SHA1_HASH_SIZE];

	int32_t INT32 = 0;
	//unsigned char* U = salt || INT32;

	for (int i = 0; i < c; i++) {
		//HMAC(pass, U, digest);
	}

	return NULL;
}
