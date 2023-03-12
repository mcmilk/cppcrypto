/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_MAC_H
#define CPPCRYPTO_MAC_H

#include <stdint.h>
#include <string>
#include <initializer_list>

namespace cppcrypto
{

class crypto_mac
{
public:
	crypto_mac() {}
	virtual ~crypto_mac();

	virtual void init(const unsigned char* key, size_t keylen) = 0;
	virtual void init(const std::string& key);

	virtual void update(const unsigned char* data, size_t len) = 0;

	void final(unsigned char* hash);

	virtual size_t hashsize() const = 0;
	virtual size_t blocksize() const = 0;
	virtual size_t keysize() const = 0;
	virtual crypto_mac* clone() const = 0;
	virtual void clear() = 0;

	void set_tagsize_in_bits(size_t tagsize_in_bits);

	void mac_string(const unsigned char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char* hash, size_t truncate_to_bytes = SIZE_MAX);
	void mac_string(const char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char* hash, size_t truncate_to_bytes = SIZE_MAX);
	void mac_string(const char* key, size_t key_len, const char* data, size_t len, unsigned char* hash, size_t truncate_to_bytes = SIZE_MAX);
	void mac_string(const std::string& key, const std::string& data, unsigned char* hash, size_t truncate_to_bytes = SIZE_MAX);

protected:
	virtual void do_final(unsigned char* hash) = 0;

private:
	crypto_mac(const crypto_mac&) = delete;
	void operator=(const crypto_mac&) = delete;
	size_t tagsize_in_bits = SIZE_MAX;
};

}

#endif
