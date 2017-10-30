/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SKEIN1024_H
#define CPPCRYPTO_SKEIN1024_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>

namespace cppcrypto
{
	class skein1024 : public crypto_hash
	{
	public:
		skein1024(size_t hashsize);
		~skein1024();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return 1024; }
		skein1024* clone() const override { return new skein1024(hs); }
		void clear() override;

	protected:
		void transform(void* m, uint64_t num_blks, size_t reallen);
#if defined(_MSC_VER) && defined(_M_X64)
		void transform_rorx(void* m, uint64_t num_blks, size_t reallen);
#endif
		std::function<void(void*, uint64_t, size_t)> transfunc;

		aligned_pod_array<uint64_t, 16, 32> h;
		uint64_t* H;
		unsigned char m[128];
		size_t pos;
		uint64_t total;
		uint64_t tweak[2];
		size_t hs;
	};

}

#endif

