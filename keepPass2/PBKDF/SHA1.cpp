#include "SHA1.h"
/*
	Constructor, initializes all variables, copies constants to user changable
    values, sets length limits.
*/
SHA1::SHA1()
{
    class_h[0] = sha_h[0];
    class_h[1] = sha_h[1];
    class_h[2] = sha_h[2];
    class_h[3] = sha_h[3];
    class_h[4] = sha_h[4];

    len_low = 0;
    len_high = 0;
    corrupted = false;
    computed = false;

    message_index = 0;
}

void SHA1::pad()
{

    if (this->message_index > 55) {
        this->msg_block[this->message_index++] = 0x80;

        while (this->message_index < SHA1_BLOCK_SIZE) {
            this->msg_block[this->message_index++] = 0;
        }

        this->process();

        while (this->message_index < 56) {
            this->msg_block[this->message_index++] = 0;
        }
    }
    else {
        this->msg_block[this->message_index++] = 0x80;

        while (this->message_index < 56) {
            this->msg_block[this->message_index++] = 0;
        }
    }

    this->msg_block[56] = this->len_high >> 24;
    this->msg_block[57] = this->len_high >> 16;
    this->msg_block[58] = this->len_high >> 8;
    this->msg_block[59] = this->len_high;
    this->msg_block[60] = this->len_low >> 24;
    this->msg_block[61] = this->len_low >> 16;
    this->msg_block[62] = this->len_low >> 8;
    this->msg_block[63] = this->len_low;


    this->process();
}


void SHA1::process()
{
    int i = 0;
	uint32_t temp;
	uint32_t w[80] = {};
	uint32_t A, B, C, D, E;

    for ( ; i < 16; i++) {
        w[i] = this->msg_block[i * 4] << 24;
        w[i] |= this->msg_block[i * 4 + 1] << 16;
        w[i] |= this->msg_block[i * 4 + 2] << 8;
        w[i] |= this->msg_block[i * 4 + 3];
    }



    for (i = 16 ; i < 80; i++) {
        w[i] = CIRCULAR_SHIFT(1, w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);

    }

    A = this->class_h[0];
    B = this->class_h[1];
    C = this->class_h[2];
    D = this->class_h[3];
    E = this->class_h[4];

    for (i = 0; i < 20; i++) {
        temp = CIRCULAR_SHIFT(5,A) + ((B & C) | ((~B) & D)) + E + w[i] + sha_k[0];
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    //printf("mine1: %02X %02X %02X %02X %02X\n", A, B, C, D, E);
    for (i = 20; i < 40; i++) {
        temp = CIRCULAR_SHIFT(5,A) + SHA_PARITY(B, C, D) + E + w[i] + sha_k[1];
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }


    //printf("mine2: %02X %02X %02X %02X %02X\n", A, B, C, D, E);
    for (i = 40; i < 60; i++) {
        temp = CIRCULAR_SHIFT(5,A) + SHA_TRI(B, C, D) + E + w[i] + sha_k[2];
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }


    //printf("mine3: %02X %02X %02X %02X %02X\n", A, B, C, D, E);
    for (i = 60; i < 80; i++) {
        temp = CIRCULAR_SHIFT(5,A) + SHA_PARITY(B, C, D) + E + w[i] + sha_k[3];
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }



    this->class_h[0] += A;
    this->class_h[1] += B;
    this->class_h[2] += C;
    this->class_h[3] += D;
    this->class_h[4] += E;

    //printf("mine h: %02X %02X %02X %02X %02X\n", class_h[0], class_h[1], class_h[2], class_h[3], class_h[4]);

    this->message_index = 0;
}

void SHA1::update(unsigned char* key, int len)
{
    if (!key || this->corrupted)
        return;

    if (computed) {
        this->corrupted = true;
        return;
    }
    

    for (int i = 0; i < len; i++) {
        if (corrupted)
            break;

        this->msg_block[this->message_index++] = *key & 0xFF;
        this->len_low += 8;
        if (this->len_low == 0) {
            this->len_high++;
            if (this->len_high == 0) {
                this->corrupted = true;
            }
        }

        if (this->message_index == SHA1_BLOCK_SIZE) {
            this->process();
        }

        key++;
    }


    return;
}

int SHA1::result(unsigned char digest[SHA1_HASH_SIZE])
{
    int i = 0;

    if (this->corrupted)
        return 0;

    if (!this->computed) {
        this->pad();

        for ( ; i < 64; i++) {
            this->msg_block[i] = 0;
        }
        this->len_low = 0;
        this->len_high = 0;
        this->computed = true;
    }
    for (i = 0; i < SHA1_HASH_SIZE; i++) {
        digest[i] = this->class_h[i>>2] >> 8 * ( 3 - ( i & 0x03));
    }

    return SHA1_HASH_SIZE;
}
