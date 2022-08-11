/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SHA3_512_H
#define CPPCRYPTO_SHA3_512_H

#include "crypto_hash.h"
#include <functional>
#include "sha3-impl.h"
#include "alignedarray.h"

namespace cppcrypto
{
	class sha3 : public crypto_hash
	{
	public:
		sha3(size_t hashsize);
		~sha3();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return rate; }
		sha3* clone() const override { return new sha3(hs); }
		void clear() override;

	protected:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		unsigned char* m;
		size_t pos;
		size_t hs;
		size_t rate;
		aligned_impl_ptr<detail::sha3_impl, 32> impl_;
	};

	class shake256 : public sha3
	{
	public:
		shake256(size_t hashsize = 512, const std::string& function_name = "", const std::string& customization = "");
		void init() override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return size; }
		shake256* clone() const override { return new shake256(size, N, S); }
	private:
		size_t size;
		std::string N;
		std::string S;
	};

	class shake128 : public shake256
	{
	public:
		shake128(size_t hashsize = 256, const std::string& function_name = "", const std::string& customization = "");
	};

}

#endif
