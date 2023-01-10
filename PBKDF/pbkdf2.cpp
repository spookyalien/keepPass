#include "pkbdf2.h"

/*
	@param c: number of iterations desired
	@param salt: sequence of random bits for better cryptography
	@param dk_len: desired bit length of derived key
	@param pass: chosen password
	@param prf: pseudorandom function to be used (in this case a keyed HMAC)

	returns: derived key to be used for hashing
*/
unsigned char* PKBDF2(char* pass, char* salt, char* prf, int c, int dk_len)
{
	return NULL;
}