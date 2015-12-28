/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_HC_H
#define CPPCRYPTO_HC_H

#include <stdint.h>
#include <memory>
#include <vector>
#include <ostream>
#include "stream_cipher.h"

namespace cppcrypto
{
	class hc256 : public stream_cipher
	{
	public:
		hc256();
		virtual ~hc256();

		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen);
		void encrypt(const uint8_t* in, size_t len, uint8_t* out);
		void decrypt(const uint8_t* in, size_t len, uint8_t* out);

		void clear();
		stream_cipher* clone() const { return new hc256; }
		size_t keysize() const { return 256; }
		size_t ivsize() const { return 256; }

	protected:
		uint32_t block_[16];
		uint32_t P[1024];
		uint32_t Q[1024];
		uint32_t X[16];
		uint32_t Y[16];
		uint32_t words;
		size_t pos;
	};

	class hc128 : public stream_cipher
	{
	public:
		hc128();
		virtual ~hc128();

		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen);
		void encrypt(const uint8_t* in, size_t len, uint8_t* out);
		void decrypt(const uint8_t* in, size_t len, uint8_t* out);

		void clear();
		stream_cipher* clone() const { return new hc128; }
		size_t keysize() const { return 128; }
		size_t ivsize() const { return 128; }

	protected:
		uint32_t block_[16];
		uint32_t P[512];
		uint32_t Q[512];
		uint32_t X[16];
		uint32_t Y[16];
		uint32_t words;
		size_t pos;
	};

}

#endif
