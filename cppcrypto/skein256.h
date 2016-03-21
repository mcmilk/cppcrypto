/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SKEIN256_H
#define CPPCRYPTO_SKEIN256_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>

namespace cppcrypto
{
	namespace detail
	{
		class skein256 : public crypto_hash
		{
		public:
			skein256(size_t hashsize);
			~skein256();

			void init() override;
			void update(const uint8_t* data, size_t len) override;
			void final(uint8_t* hash) override;

			size_t hashsize() const override { return hs; }
			size_t blocksize() const override { return 256; }
			skein256* clone() const override { return new skein256(hs); }
			void clear() override;

		protected:
			void transform(void* m, uint64_t num_blks, size_t reallen);

			std::function<void(void*, uint64_t, size_t)> transfunc;
			aligned_pod_array<uint64_t, 4, 32> h;
			uint64_t* H;
			uint8_t m[32];
			size_t pos;
			uint64_t total;
			uint64_t tweak[2];
			size_t hs;
		};
	}

	class skein256_256 : public detail::skein256
	{
	public:
		skein256_256() : skein256(256) {}
		void init() override;
		skein256_256* clone() const override { return new skein256_256; }
	};

	class skein256_224 : public detail::skein256
	{
	public:
		skein256_224() : skein256(224) {}
		void init() override;
		skein256_224* clone() const override { return new skein256_224; }
	};

	class skein256_160 : public detail::skein256
	{
	public:
		skein256_160() : skein256(160) {}
		void init() override;
		skein256_160* clone() const override { return new skein256_160; }
	};

	class skein256_128 : public detail::skein256
	{
	public:
		skein256_128() : skein256(128) {}
		void init() override;
		skein256_128* clone() const override { return new skein256_128; }
	};

}

#endif
