/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CHACHA_H
#define CPPCRYPTO_CHACHA_H

#include <stdint.h>
#include <memory>
#include <vector>
#include <ostream>
#include "stream_cipher.h"
#include "seekable.h"

namespace cppcrypto
{
	class chacha20_256 : public stream_cipher, public seekable
	{
	public:
		chacha20_256();
		virtual ~chacha20_256();

		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;
		void encrypt(const unsigned char* in, size_t len, unsigned char* out) override;
		void decrypt(const unsigned char* in, size_t len, unsigned char* out) override;

		void clear() override;
		chacha20_256* clone() const override { return new chacha20_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 64; }

	protected:
		virtual size_t max_nonce_bytes_for_aead() const override { return 12; }

		void seek(uint64_t pos) override;

		void do_seek(uint64_t pos, int r);

		uint32_t block_[16];
		uint32_t input_[16];
		size_t pos;
		uint32_t input13_;
	};

	class chacha20_128 : public chacha20_256
	{
	public:
		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;

		chacha20_128* clone() const override { return new chacha20_128; }
		size_t keysize() const override { return 128; }
	};

	class xchacha20_256 : public chacha20_256
	{
	public:
		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;

		xchacha20_256* clone() const override { return new xchacha20_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 192; }

	protected:
		virtual size_t max_nonce_bytes_for_aead() const override { return ivsize() / 8; }
	};

	class xchacha20_128 : public xchacha20_256
	{
	public:
		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;

		xchacha20_128* clone() const override { return new xchacha20_128; }
		size_t keysize() const override { return 128; }
	};

	class chacha12_256 : public chacha20_256
	{
	public:
		void encrypt(const unsigned char* in, size_t len, unsigned char* out) override;

		chacha12_256* clone() const override { return new chacha12_256; }

	protected:
		void seek(uint64_t pos) override;
	};

	class chacha12_128 : public chacha20_128
	{
	public:
		void encrypt(const unsigned char* in, size_t len, unsigned char* out) override;

		chacha12_128* clone() const override { return new chacha12_128; }

	protected:
		void seek(uint64_t pos) override;
	};

	class xchacha12_256 : public chacha12_256
	{
	public:
		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;

		xchacha12_256* clone() const override { return new xchacha12_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 192; }
	protected:
		virtual size_t max_nonce_bytes_for_aead() const override { return ivsize() / 8; }
	};

	class xchacha12_128 : public xchacha12_256
	{
	public:
		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) override;

		xchacha12_128* clone() const override { return new xchacha12_128; }
		size_t keysize() const override { return 128; }
	};

}

#endif

