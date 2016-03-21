/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SKEIN512_H
#define CPPCRYPTO_SKEIN512_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>

namespace cppcrypto
{

	namespace detail
	{
		class skein512 : public crypto_hash
		{
		public:
			skein512(size_t hashsize);
			~skein512();

			void init() override;
			void update(const uint8_t* data, size_t len) override;
			void final(uint8_t* hash) override;

			size_t hashsize() const override { return hs; }
			size_t blocksize() const override { return 512; }
			skein512* clone() const override { return new skein512(hs); }
			void clear() override;

		protected:
			void transform(void* m, uint64_t num_blks, size_t reallen);
			std::function<void(void*, uint64_t, size_t)> transfunc;

			aligned_pod_array<uint64_t, 8, 32> h;
			uint64_t* H;
			uint8_t m[64];
			size_t pos;
			uint64_t total;
			uint64_t tweak[2];
			size_t hs;
		};
	}

	class skein512_512 : public detail::skein512
	{
	public:
		skein512_512() : skein512(512) {}
		void init() override;
		skein512_512* clone() const override { return new skein512_512; }
	};

	class skein512_256 : public detail::skein512
	{
	public:
		skein512_256() : skein512(256) {}
		void init() override;
		skein512_256* clone() const override { return new skein512_256; }
	};

	class skein512_384 : public detail::skein512
	{
	public:
		skein512_384() : skein512(384) {}
		void init() override;
		skein512_384* clone() const override { return new skein512_384; }
	};

	class skein512_224 : public detail::skein512
	{
	public:
		skein512_224() : skein512(224) {}
		void init() override;
		skein512_224* clone() const override { return new skein512_224; }
	};

	class skein512_128 : public detail::skein512
	{
	public:
		skein512_128() : skein512(128) {}
		void init() override;
		skein512_128* clone() const override { return new skein512_128; }
	};

	class skein512_160 : public detail::skein512
	{
	public:
		skein512_160() : skein512(160) {}
		void init() override;
		skein512_160* clone() const override { return new skein512_160; }
	};


}

#endif
