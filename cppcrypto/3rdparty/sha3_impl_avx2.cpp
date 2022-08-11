/******************************************************************************
This file is part of cppcrypto library (http://cppcrypto.sourceforge.net/).
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "../sha3.h"
#include <algorithm>
#include "../portability.h"

extern "C" {
#include "KeccakHash.h"
}

namespace cppcrypto
{
	namespace detail
	{
		sha3_impl_avx2::sha3_impl_avx2()
		{
			state = aligned_allocate(sizeof(Keccak_HashInstance), 64);
		}
		sha3_impl_avx2::~sha3_impl_avx2()
		{
			aligned_deallocate(state);
		}
		
		void sha3_impl_avx2::init(unsigned int rate, unsigned int capacity)
		{
			Keccak_HashInitialize(static_cast<Keccak_HashInstance*>(state), rate, capacity, 0, 0x06);
		}
		void sha3_impl_avx2::update(const uint8_t* data, size_t len)
		{
			Keccak_HashUpdate(static_cast<Keccak_HashInstance*>(state), data, len * 8);
		}
		void sha3_impl_avx2::final(uint8_t* hash, unsigned long long hashbitlen)
		{
			static_cast<Keccak_HashInstance*>(state)->fixedOutputLength = static_cast<unsigned int>(hashbitlen);
			Keccak_HashFinal(static_cast<Keccak_HashInstance*>(state), hash);
		}
		void sha3_impl_avx2::set_padding_byte(unsigned char byte)
		{
			static_cast<Keccak_HashInstance*>(state)->delimitedSuffix = byte;
		}

		sha3_impl_avx2::sha3_impl_avx2(sha3_impl_avx2&& other)
		{
			state = other.state;
			other.state = nullptr;
		}
		sha3_impl_avx2& sha3_impl_avx2::operator=(sha3_impl_avx2&& other)
		{
			std::swap(state, other.state);
			return *this;
		}

	}
}
