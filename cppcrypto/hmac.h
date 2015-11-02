/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_HMAC_H
#define CPPCRYPTO_HMAC_H

#include <stdint.h>
#include <string>
#include <memory>
#include "crypto_hash.h"

namespace cppcrypto
{

	class hmac : public crypto_hash
	{
	public:
		hmac(const crypto_hash& hash, const uint8_t* key, size_t keylen);
		hmac(const crypto_hash& hash, const std::string& key);
		virtual ~hmac();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return hash_->hashbitlen(); }
		int blockbitlen() const { return hash_->blockbitlen(); }
		crypto_hash* clone() const;

	private:
		hmac(const hmac&);
		void construct(const uint8_t* key, size_t keylen);

		uint8_t* ipad_;
		uint8_t* opad_;
		std::unique_ptr<crypto_hash> hash_;
	};

}

#endif
