/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SALSA20_H
#define CPPCRYPTO_SALSA20_H

#include <stdint.h>
#include <memory>
#include <vector>
#include <ostream>
#include "stream_cipher.h"

namespace cppcrypto
{
	class salsa20_256 : public stream_cipher
	{
	public:
		salsa20_256();
		virtual ~salsa20_256();

		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;
		void encrypt(const uint8_t* in, size_t len, uint8_t* out) override;
		void decrypt(const uint8_t* in, size_t len, uint8_t* out) override;

		void clear() override;
		salsa20_256* clone() const override { return new salsa20_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 64; }

	protected:
		uint32_t block_[16];
		uint32_t input_[16];
		size_t pos;
	};

	class salsa20_128 : public salsa20_256
	{
	public:
		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;

		salsa20_128* clone() const override { return new salsa20_128; }
		size_t keysize() const override { return 128; }
	};

	class xsalsa20_256 : public salsa20_256
	{
	public:
		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;

		xsalsa20_256* clone() const override { return new xsalsa20_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 192; }
	};

	class xsalsa20_128 : public xsalsa20_256
	{
	public:
		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;

		xsalsa20_128* clone() const override { return new xsalsa20_128; }
		size_t keysize() const override { return 128; }
	};

	class salsa20_12_256 : public salsa20_256
	{
	public:
		void encrypt(const uint8_t* in, size_t len, uint8_t* out) override;

		salsa20_12_256* clone() const override { return new salsa20_12_256; }
	};

	class salsa20_12_128 : public salsa20_128
	{
	public:
		void encrypt(const uint8_t* in, size_t len, uint8_t* out) override;

		salsa20_12_128* clone() const override { return new salsa20_12_128; }
	};

	class xsalsa20_12_256 : public salsa20_12_256
	{
	public:
		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;

		xsalsa20_12_256* clone() const override { return new xsalsa20_12_256; }
		size_t keysize() const override { return 256; }
		size_t ivsize() const override { return 192; }
	};

	class xsalsa20_12_128 : public xsalsa20_12_256
	{
	public:
		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) override;

		xsalsa20_12_128* clone() const override { return new xsalsa20_12_128; }
		size_t keysize() const override { return 128; }
	};

}

#endif
