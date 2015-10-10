/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_HASH_H
#define CPPCRYPTO_HASH_H

#include <stdint.h>
#include <string>

namespace cppcrypto
{

class crypto_hash
{
public:
	crypto_hash() {}
	virtual ~crypto_hash() {}

	virtual void init() = 0;
	virtual void update(const uint8_t* data, size_t len) = 0;
	virtual void final(uint8_t* hash) = 0;

	virtual int hashbitlen() const = 0;
	virtual int blockbitlen() const = 0;
	virtual crypto_hash* clone() const = 0;

	void hash_string(const uint8_t* data, size_t len, uint8_t* hash);
	void hash_string(const char* data, size_t len, uint8_t* hash);
	void hash_string(const std::string& data, uint8_t* hash);

private:
	crypto_hash(const crypto_hash&);
};

}

#endif
