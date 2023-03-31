#ifndef HMAC_H
#define HMAC_H

#include "SHA1.h"
#define h_len 20

int HMAC(unsigned char* key, int key_len, unsigned char* msg, int msg_len, unsigned char msg_digest_final[SHA1_HASH_SIZE]);
unsigned char* compute_block_size_key(unsigned char* key, int* key_len);

#endif