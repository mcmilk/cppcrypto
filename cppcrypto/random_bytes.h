/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef RANDOM_BYTES_H
#define RANDOM_BYTES_H

#include <string.h>

namespace cppcrypto
{

void gen_random_bytes(unsigned char* buffer, size_t buflen);

void gen_random_bytes(char* buffer, size_t buflen);

}

#endif
