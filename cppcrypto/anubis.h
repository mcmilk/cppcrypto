/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_ANUBIS_H
#define CPPCRYPTO_ANUBIS_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class anubis128 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 128; }
		block_cipher* clone() const { return new anubis128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[8 + 4 + 1][4];
	};

	class anubis160 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 160; }
		block_cipher* clone() const { return new anubis160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[9 + 4 + 1][4];
	};

	class anubis192 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 192; }
		block_cipher* clone() const { return new anubis192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[10 + 4 + 1][4];
	};

	class anubis224 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 224; }
		block_cipher* clone() const { return new anubis224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[11 + 4 + 1][4];
	};

	class anubis256 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new anubis256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[12 + 4 + 1][4];
	};

	class anubis288 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 288; }
		block_cipher* clone() const { return new anubis288; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[13 + 4 + 1][4];
	};

	class anubis320 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 320; }
		block_cipher* clone() const { return new anubis320; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t W_[14 + 4 + 1][4];
	};

}

#endif

