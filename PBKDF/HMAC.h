#ifndef HMAC_H
#define HMAC_H

#include "SHA1.h"

#define SHA1 1

int HMAC(unsigned char* key, unsigned char* msg);
unsigned char* compute_block_size_key(unsigned char* key, int* key_len);
#endif