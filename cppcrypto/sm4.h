/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SM4_H
#define CPPCRYPTO_SM4_H

#include <stdint.h>
#include "sm4-impl.h"
#include "alignedarray.h"
#include <memory>

namespace cppcrypto
{
	class sm4 : public block_cipher
	{
	public:
		sm4();
		~sm4();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		sm4* clone() const override { return new sm4; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;
		void encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) override;
		void decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) override;

	private:
		uint32_t rk[32];
		aligned_impl_ptr<detail::sm4_impl, 16> impl_;
	};

}

#endif
