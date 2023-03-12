/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "crypto_mac.h"
#include <vector>
#include <stdexcept>
#include "portability.h"
#include <string.h>

namespace cppcrypto
{
	crypto_mac::~crypto_mac()
	{
	}

	void crypto_mac::init(const std::string& key)
	{
		init(reinterpret_cast<const unsigned char*>(key.c_str()), key.length());
	}

	void crypto_mac::final(unsigned char* hash)
	{
		if (tagsize_in_bits == SIZE_MAX || tagsize_in_bits == hashsize())
			return do_final(hash);

		std::vector<unsigned char> buf(hashsize() / 8);
		do_final(&buf[0]);
		memcpy(hash, buf.data(), tagsize_in_bits / 8);
		zero_memory(&buf[0], buf.size());
	}

	void crypto_mac::set_tagsize_in_bits(size_t tagsize)
	{
		if (!tagsize || (tagsize != SIZE_MAX && tagsize > hashsize()) || tagsize % 8 != 0)
			throw std::runtime_error("invalid tag size for mac");
		tagsize_in_bits = tagsize;
	}

	void crypto_mac::mac_string(const char* key, size_t key_len, const char* data, size_t data_len, unsigned char* mac, size_t truncate_to_bytes)
	{
		mac_string(reinterpret_cast<const unsigned char*>(key), key_len, reinterpret_cast<const unsigned char*>(data), data_len, mac);
	}

	void crypto_mac::mac_string(const char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* mac, size_t truncate_to_bytes)
	{
		mac_string(reinterpret_cast<const unsigned char*>(key), key_len, data, data_len, mac);
	}

	void crypto_mac::mac_string(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* mac, size_t truncate_to_bytes)
	{
		if (truncate_to_bytes != SIZE_MAX && truncate_to_bytes > hashsize() / 8)
			throw std::runtime_error("invalid output size for hmac");

		init(key, key_len);
		if (truncate_to_bytes != SIZE_MAX)
			set_tagsize_in_bits(truncate_to_bytes * 8);
		else
			set_tagsize_in_bits(hashsize());
		update((const unsigned char*)data, data_len);
		final(mac);
	}

	void crypto_mac::mac_string(const std::string& key, const std::string& data, unsigned char* mac, size_t truncate_to_bytes)
	{
		mac_string(reinterpret_cast<const unsigned char*>(key.c_str()), key.length(), reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), mac);
	}


}

