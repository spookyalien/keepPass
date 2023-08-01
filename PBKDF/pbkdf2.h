#ifndef PBKDF2_H
#define PBKDF2_H

#include <cmath>
#include <cstring>
#include "HMAC.h"

#define DK_LEN 20
#define MIN(i1, i2) (i1 < i2 ? i1 : i2)

int PBKDF2(unsigned char* pass, int pass_len, unsigned char* salt, int salt_len, int c, int dk_len, unsigned char** out);

#endif
