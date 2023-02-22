#ifndef PBKDF2_H
#define PBKDF2_H

#include "HMAC.h"

unsigned char* PBKDF2(char* pass, char* salt, char* prf, int c, int dk_len);

#endif