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

			size_t blocksize() const override { return 128; }
			void clear() override;

			void encrypt_block(const unsigned char* in, unsigned char* out) override;
			void decrypt_block(const unsigned char* in, unsigned char* out) override;

		protected:
			uint32_t rk[40];
		};
	}

	class mars448 : public detail::mars
	{
	public:
		size_t keysize() const override { return 448; }
		mars448* clone() const override { return new mars448; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars320 : public detail::mars
	{
	public:
		size_t keysize() const override { return 320; }
		mars320* clone() const override { return new mars320; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars256 : public detail::mars
	{
	public:
		size_t keysize() const override { return 256; }
		mars256* clone() const override { return new mars256; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars224 : public detail::mars
	{
	public:
		size_t keysize() const override { return 224; }
		mars224* clone() const override { return new mars224; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars192 : public detail::mars
	{
	public:
		size_t keysize() const override { return 192; }
		mars192* clone() const override { return new mars192; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars160 : public detail::mars
	{
	public:
		size_t keysize() const override { return 160; }
		mars160* clone() const override { return new mars160; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars128 : public detail::mars
	{
	public:
		size_t keysize() const override { return 128; }
		mars128* clone() const override { return new mars128; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars288 : public detail::mars
	{
	public:
		size_t keysize() const override { return 288; }
		mars288* clone() const override { return new mars288; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars352 : public detail::mars
	{
	public:
		size_t keysize() const override { return 352; }
		mars352* clone() const override { return new mars352; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars384 : public detail::mars
	{
	public:
		size_t keysize() const override { return 384; }
		mars384* clone() const override { return new mars384; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class mars416 : public detail::mars
	{
	public:
		size_t keysize() const override { return 416; }
		mars416* clone() const override { return new mars416; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

}

#endif

