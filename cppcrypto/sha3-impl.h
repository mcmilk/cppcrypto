/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SHA3_IMPL_H
#define CPPCRYPTO_SHA3_IMPL_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{
	namespace detail
	{
		class sha3_impl
		{
		public:
			virtual ~sha3_impl() {}
			virtual void init(unsigned int rate, unsigned int capacity) = 0;
			virtual void update(const unsigned char* data, size_t len) = 0;
			virtual void final(unsigned char* hash, unsigned long long hashsize) = 0;
			virtual void set_padding_byte(unsigned char byte) = 0;
		};

		class sha3_impl_ssse3 : public sha3_impl
		{
		public:
			sha3_impl_ssse3();
			~sha3_impl_ssse3();
			void init(unsigned int rate, unsigned int capacity) override;
			void update(const unsigned char* data, size_t len) override;
			void final(unsigned char* hash, unsigned long long hashsize) override;
			void set_padding_byte(unsigned char byte) override;

			sha3_impl_ssse3(sha3_impl_ssse3&& other);
			sha3_impl_ssse3& operator=(sha3_impl_ssse3&& other);
		private:
			void* state;
		};

		class sha3_impl_avx2 : public sha3_impl
		{
		public:
			sha3_impl_avx2();
			~sha3_impl_avx2();
			void init(unsigned int rate, unsigned int capacity) override;
			void update(const unsigned char* data, size_t len) override;
			void final(unsigned char* hash, unsigned long long hashsize) override;
			void set_padding_byte(unsigned char byte) override;

			sha3_impl_avx2(sha3_impl_avx2&& other);
			sha3_impl_avx2& operator=(sha3_impl_avx2&& other);
		private:
			void* state;
		};
	}


}

#endif

