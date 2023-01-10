#ifndef MY_SHA_H
#define MY_SHA_H

#include <string>
#include <stdint.h>

#define SHA1_HASH_SIZE 20
#define SHA1_BLOCK_SIZE 64

#define circular_shift(value, count) ((value << count) | (value >> (32 - count)))

unsigned int sha_h[5] = 
{
	0x67452301,
	0xEFCDAB89,
	0x98BADCFE,
	0x10325476,
	0xC3D2E1F0
};

unsigned int sha_k[5] =
{
	0x5A827999,
	0x6ED9EBA1,
	0x8F1BBCDC,
	0xCA62C1D6
};


#endif
