/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_MARS_H
#define CPPCRYPTO_MARS_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
	namespace detail
	{
		class mars : public block_cipher
		{
		public:
			~mars();

			size_t blocksize() const { return 128; }
			void clear();

			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);

		protected:
			uint32_t rk[40];
		};
	}

	class mars448 : public detail::mars
	{
	public:
		size_t keysize() const { return 448; }
		block_cipher* clone() const { return new mars448; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars320 : public detail::mars
	{
	public:
		size_t keysize() const { return 320; }
		block_cipher* clone() const { return new mars320; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars256 : public detail::mars
	{
	public:
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new mars256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars224 : public detail::mars
	{
	public:
		size_t keysize() const { return 224; }
		block_cipher* clone() const { return new mars224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars192 : public detail::mars
	{
	public:
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new mars192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars160 : public detail::mars
	{
	public:
		size_t keysize() const { return 160; }
		block_cipher* clone() const { return new mars160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars128 : public detail::mars
	{
	public:
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new mars128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars288 : public detail::mars
	{
	public:
		size_t keysize() const { return 288; }
		block_cipher* clone() const { return new mars288; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars352 : public detail::mars
	{
	public:
		size_t keysize() const { return 352; }
		block_cipher* clone() const { return new mars352; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars384 : public detail::mars
	{
	public:
		size_t keysize() const { return 384; }
		block_cipher* clone() const { return new mars384; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class mars416 : public detail::mars
	{
	public:
		size_t keysize() const { return 416; }
		block_cipher* clone() const { return new mars416; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

}

#endif

