#ifndef PKBDF2_H
#define PKBDF2_H

#include "HMAC.h"

unsigned char* PKBDF2(char* pass, char* salt, char* prf, int c, int dk_len);

#endif