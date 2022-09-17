/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CTR_H
#define CPPCRYPTO_CTR_H

#include <stdint.h>
#include "block_cipher.h"
#include "stream_cipher.h"
#include <memory>
#include <vector>
#include <ostream>

namespace cppcrypto
{
	class ctr : public stream_cipher
	{
	public:
		ctr(const block_cipher& cipher);
		virtual ~ctr();

		void clear();

		void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen);
		void encrypt(const unsigned char* in, size_t len, unsigned char* out);
		void decrypt(const unsigned char* in, size_t len, unsigned char* out);

		size_t keysize() const { return cipher_->keysize(); }
		size_t ivsize() const { return cipher_->blocksize(); }
		stream_cipher* clone() const { return new ctr(*cipher_); }
	private:
		ctr(const ctr&) = delete;
		void operator=(const ctr&) = delete;

		unsigned char* block_;
		unsigned char* iv_;
		size_t pos;
		size_t nb_;
		uint32_t* ctrs[8];
		uint32_t counter;
		std::unique_ptr<block_cipher> cipher_;
	};
}

#endif
