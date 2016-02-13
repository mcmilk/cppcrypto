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
	namespace detail
	{
		class skein1024 : public crypto_hash
		{
		public:
			skein1024(size_t hashsize);
			~skein1024();

			void init();
			void update(const uint8_t* data, size_t len);
			void final(uint8_t* hash);

			size_t hashsize() const { return hs; }
			size_t blocksize() const { return 1024; }
			crypto_hash* clone() const { return new skein1024(hs); }
			void clear();

		protected:
			void transform(void* m, uint64_t num_blks, size_t reallen);
#if defined(_MSC_VER) && defined(_M_X64)
			void transform_rorx(void* m, uint64_t num_blks, size_t reallen);
#endif
			std::function<void(void*, uint64_t, size_t)> transfunc;

			aligned_pod_array<uint64_t, 16, 32> h;
			uint64_t* H;
			uint8_t m[128];
			size_t pos;
			uint64_t total;
			uint64_t tweak[2];
			size_t hs;
		};
	}

	class skein1024_1024 : public detail::skein1024
	{
	public:
		skein1024_1024() : skein1024(1024) {}
		void init();
		crypto_hash* clone() const { return new skein1024_1024; }
	};

	class skein1024_512 : public detail::skein1024
	{
	public:
		skein1024_512() : skein1024(512) {}
		void init();
		crypto_hash* clone() const { return new skein1024_512; }
	};

	class skein1024_384 : public detail::skein1024
	{
	public:
		void init();
		skein1024_384() : skein1024(384) {}
		crypto_hash* clone() const { return new skein1024_384; }
	};

	class skein1024_256 : public detail::skein1024
	{
	public:
		void init();
		skein1024_256() : skein1024(256) {}
		crypto_hash* clone() const { return new skein1024_256; }
	};

}

#endif
