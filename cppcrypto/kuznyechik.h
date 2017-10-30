/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KUZNYECHIK_H
#define CPPCRYPTO_KUZNYECHIK_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class kuznyechik : public block_cipher
	{
	public:
		~kuznyechik();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		kuznyechik* clone() const override { return new kuznyechik; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t rk[10][2];
	};

}

#endif
