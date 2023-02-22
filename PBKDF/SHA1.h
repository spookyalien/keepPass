#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <stdint.h>

#define SHA_SUCCESS 1
#define SHA1_HASH_SIZE 20
#define SHA1_BLOCK_SIZE 64

#define CIRCULAR_SHIFT(value, count) (((count) << (value)) | ((count) >> (32 - (value))))
#define SHA_CH(x, y, z) ((x & y) | (~x & z))
#define SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA_TRI(x, y, z) ((x & y) | (x & z) | (y & z))
#define SHA_PARITY(x, y, z) (x ^ y ^ z)

class SHA1
{
    private:
        unsigned int class_h[5];
        unsigned int message_index;
        int len_low, len_high;
        bool corrupted, computed;
        unsigned char msg_block[SHA1_BLOCK_SIZE];
        
        // Constants used in SHA1 algorithm
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

    public:
        SHA1();
        void pad();
        void process();
        void update(unsigned char* key, int len);
        int result(unsigned char digest[SHA1_HASH_SIZE]);
};

#endif
