/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

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

			sha3_impl_ssse3(sha3_impl_ssse3&& other);
			sha3_impl_ssse3& operator=(sha3_impl_ssse3&& other);
		private:
			void* state;
		};
	}

	class sha3_512 : public crypto_hash
	{
	public:
		sha3_512();
		~sha3_512();

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 512; }
		size_t blocksize() const override { return 576; }
		sha3_512* clone() const override { return new sha3_512; }
		void clear() override;

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

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;
		void clear() override;

		size_t hashsize() const override { return 256; }
		size_t blocksize() const override { return 1088; }
		sha3_256* clone() const override { return new sha3_256; }

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

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 224; }
		size_t blocksize() const override { return 1152; }
		sha3_224* clone() const override { return new sha3_224; }
		void clear() override;

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

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 384; }
		size_t blocksize() const override { return 832; }
		sha3_384* clone() const override { return new sha3_384; }
		void clear() override;

	private:
		void transform(void* m, uint64_t num_blks);

		uint64_t A[25];
		uint8_t m[104];
		size_t pos;
		detail::sha3_impl_ssse3* impl_;
	};

}

#endif
