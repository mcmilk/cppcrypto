/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#include "block_cipher.h"

namespace cppcrypto
{

	void block_cipher::encrypt_blocks(const uint8_t* in, uint8_t* out, size_t n)
	{
		int bs = blocksize();
		for (size_t i = 0; i < n; i++)
		{
			encrypt_block(in, out);
			in += bs;
			out += bs;
		}
	}

	void block_cipher::decrypt_blocks(const uint8_t* in, uint8_t* out, size_t n)
	{
		int bs = blocksize();
		for (size_t i = 0; i < n; i++)
		{
			decrypt_block(in, out);
			in += bs;
			out += bs;
		}
	}

}