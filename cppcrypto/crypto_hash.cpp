/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#include "crypto_hash.h"

namespace cppcrypto
{

	void crypto_hash::hash_string(const char* data, size_t len, uint8_t* hash)
	{
		hash_string((const uint8_t*)data, len, hash);
	}

	void crypto_hash::hash_string(const uint8_t* data, size_t len, uint8_t* hash)
	{
		init();
		update((const uint8_t*)data, len);
		final(hash);
	}

	void crypto_hash::hash_string(const std::string& data, uint8_t* hash)
	{
		hash_string((const uint8_t*)data.c_str(), data.length(), hash);
	}

}