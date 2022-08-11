/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ANUBIS_H
#define CPPCRYPTO_ANUBIS_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class anubis128 : public block_cipher
	{
	public:
		~anubis128();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		anubis128* clone() const override { return new anubis128; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[8 + 4 + 1][4];
	};

	class anubis160 : public block_cipher
	{
	public:
		~anubis160();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 160; }
		anubis160* clone() const override { return new anubis160; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[9 + 4 + 1][4];
	};

	class anubis192 : public block_cipher
	{
	public:
		~anubis192();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 192; }
		anubis192* clone() const override { return new anubis192; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[10 + 4 + 1][4];
	};

	class anubis224 : public block_cipher
	{
	public:
		~anubis224();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 224; }
		anubis224* clone() const override { return new anubis224; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[11 + 4 + 1][4];
	};

	class anubis256 : public block_cipher
	{
	public:
		~anubis256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		anubis256* clone() const override { return new anubis256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[12 + 4 + 1][4];
	};

	class anubis288 : public block_cipher
	{
	public:
		~anubis288();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 288; }
		anubis288* clone() const override { return new anubis288; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[13 + 4 + 1][4];
	};

	class anubis320 : public block_cipher
	{
	public:
		~anubis320();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 320; }
		anubis320* clone() const override { return new anubis320; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t W_[14 + 4 + 1][4];
	};

}

#endif

