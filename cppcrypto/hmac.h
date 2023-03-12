/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_HMAC_H
#define CPPCRYPTO_HMAC_H

#include <stdint.h>
#include <string>
#include <memory>
#include "crypto_mac.h"
#include "crypto_hash.h"

namespace cppcrypto
{

	class hmac : public crypto_mac
	{
	public:
		hmac(const crypto_hash& hash);
		virtual ~hmac();

		void init(const unsigned char* key, size_t keylen) override;
		void update(const unsigned char* data, size_t len) override;
		void do_final(unsigned char* hash) override;

		size_t hashsize() const override { return hash_->hashsize(); }
		size_t keysize() const override { return keylen_ * 8; }
		size_t blocksize() const override;
		hmac* clone() const override;
		void clear() override;

	private:
		hmac(const hmac&) = delete;
		void operator=(const hmac&) = delete;
		void construct(const unsigned char* key, size_t keylen);

		std::unique_ptr<crypto_hash> hash_;
		std::basic_string<unsigned char> ipad_;
		std::basic_string<unsigned char> opad_;
		size_t keylen_;
	};
}

#endif
