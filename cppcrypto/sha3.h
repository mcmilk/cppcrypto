/******************************************************************************
This file is part of cppcrypto library (http://cppcrypto.sourceforge.net/).
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_SHA3_512_H
#define CPPCRYPTO_SHA3_512_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{
	namespace detail
	{
		class sha3_impl_ssse3
		{
		public:
			sha3_impl_ssse3();
			~sha3_impl_ssse3();
			void init(unsigned int rate, unsigned int capacity);
			void update(const uint8_t* data, size_t len);
			void final(uint8_t* hash, unsigned long long hashsize);
		private:
			void* state;
		};
	}

	class sha3_512 : public crypto_hash
	{
	public:
		sha3_512();
		~sha3_512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashsize() const { return 512; }
		int blocksize() const { return 576; }
		crypto_hash* clone() const { return new sha3_512; }

	private:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		uint8_t m[72];
		size_t pos;
		detail::sha3_impl_ssse3* impl_;
	};

	class sha3_256 : public crypto_hash
	{
	public:
		sha3_256();
		~sha3_256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashsize() const { return 256; }
		int blocksize() const { return 1088; }
		crypto_hash* clone() const { return new sha3_256; }

	private:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		uint8_t m[136];
		size_t pos;
		detail::sha3_impl_ssse3* impl_;
	};

	class sha3_224 : public crypto_hash
	{
	public:
		sha3_224();
		~sha3_224();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashsize() const { return 224; }
		int blocksize() const { return 1152; }
		crypto_hash* clone() const { return new sha3_224; }

	private:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		uint8_t m[144];
		size_t pos;
		detail::sha3_impl_ssse3* impl_;
	};

	class sha3_384 : public crypto_hash
	{
	public:
		sha3_384();
		~sha3_384();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashsize() const { return 384; }
		int blocksize() const { return 832; }
		crypto_hash* clone() const { return new sha3_384; }

	private:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		uint8_t m[104];
		size_t pos;
		detail::sha3_impl_ssse3* impl_;
	};

}

#endif
