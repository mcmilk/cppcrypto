/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_BLAKE256_H
#define CPPCRYPTO_BLAKE256_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <array>

namespace cppcrypto
{

	class blake : public crypto_hash
	{
	public:
		blake(size_t hashsize, const unsigned char* salt = nullptr, size_t saltlen = 0);
		~blake();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return hs > 256 ? 1024 : 512; }
		blake* clone() const override;
		void clear() override;

	protected:
		void transform512(bool padding);
		void transform256(bool padding);
		void validate_salt_length(size_t saltlen) const;

		std::function<void(bool)> transfunc;
		union { uint64_t* H512; uint32_t* H256; } u;
		aligned_pod_array<unsigned char, 128, 64> m;
		size_t hs;
		size_t pos;
		uint64_t total;
	};

}

#endif
