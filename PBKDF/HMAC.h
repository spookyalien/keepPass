#ifndef HMAC_H
#define HMAC_H

#include "SHA1.h"

int HMAC(unsigned char* key, unsigned char* msg, unsigned char msg_digest_final[SHA1_HASH_SIZE]);
unsigned char* compute_block_size_key(unsigned char* key, int* key_len);

#endif