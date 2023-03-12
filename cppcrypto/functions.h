/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_FUNCTIONS_H
#define CPPCRYPTO_FUNCTIONS_H

namespace cppcrypto
{

static inline bool tag_matches(const unsigned char* tag1, const unsigned char* tag2, size_t len)
{
	int cnt = 0;
	for (size_t i = 0; i < len; i++)
		cnt |= (tag1[i] ^ tag2[i]);
	return !cnt;
}

}

#endif

