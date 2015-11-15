/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_RIJNDAELIMPL_H
#define CPPCRYPTO_RIJNDAELIMPL_H

#include <tmmintrin.h>
#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
	namespace detail
	{
		class rijndael_impl
		{
		public:
			virtual ~rijndael_impl() {}
			virtual bool init(const uint8_t* key, block_cipher::direction direction) = 0;
			virtual void encrypt_block(const uint8_t* in, uint8_t* out) = 0;
			virtual void decrypt_block(const uint8_t* in, uint8_t* out) = 0;
		};

		class rijndael128_128_impl_aesni : public rijndael_impl
		{
		private:
			__m128i rk[11];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael128_160_impl_aesni : public rijndael_impl
		{
		private:
			__m128i rk[12];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael128_192_impl_aesni : public rijndael_impl
		{
		private:
			__m128i rk[13];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael128_224_impl_aesni : public rijndael_impl
		{
		private:
			__m128i rk[14];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael128_256_impl_aesni : public rijndael_impl
		{
		private:
			__m128i rk[15];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael256_256_impl_aesni : public rijndael_impl
		{
		protected:
			__m128i rk[30];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael256_128_impl_aesni : public rijndael256_256_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael256_224_impl_aesni : public rijndael256_256_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael256_160_impl_aesni : public rijndael256_256_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael256_192_impl_aesni : public rijndael256_256_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael192_128_impl_aesni : public rijndael_impl
		{
		protected:
			__m128i rk[20];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael192_160_impl_aesni : public rijndael192_128_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael192_192_impl_aesni : public rijndael192_128_impl_aesni
		{
		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
		};

		class rijndael192_224_impl_aesni : public rijndael_impl
		{
		protected:
			__m128i rk[21];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

		class rijndael192_256_impl_aesni : public rijndael_impl
		{
		protected:
			__m128i rk[23];

		public:
			bool init(const uint8_t* key, block_cipher::direction direction);
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
		};

	}
}
#endif
