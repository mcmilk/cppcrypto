/******************************************************************************
This file is part of cppcrypto library (http://cppcrypto.sourceforge.net/).
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "../sha3.h"
#include <algorithm>
#include "../portability.h"
extern "C"
{
#include "KeccakSponge.h"
}

namespace cppcrypto
{
	namespace detail
	{
		sha3_impl_ssse3::sha3_impl_ssse3()
		{
			state = aligned_allocate(sizeof(spongeState), 64);
		}
		sha3_impl_ssse3::~sha3_impl_ssse3()
		{
			aligned_deallocate(state);
		}
		
		void sha3_impl_ssse3::init(unsigned int rate, unsigned int capacity)
		{
			InitSponge(static_cast<spongeState*>(state), rate, capacity);
		}
		void sha3_impl_ssse3::update(const uint8_t* data, size_t len)
		{
			Absorb(static_cast<spongeState*>(state), data, len * 8);
		}
		void sha3_impl_ssse3::final(uint8_t* hash, unsigned long long hashbitlen)
		{
			Squeeze(static_cast<spongeState*>(state), hash, hashbitlen);
		}
		void sha3_impl_ssse3::set_padding_byte(unsigned char byte)
		{
			static_cast<spongeState*>(state)->paddingByte = byte;
		}

		sha3_impl_ssse3::sha3_impl_ssse3(sha3_impl_ssse3&& other)
		{
			state = other.state;
			other.state = nullptr;
		}
		sha3_impl_ssse3& sha3_impl_ssse3::operator=(sha3_impl_ssse3&& other)
		{
			std::swap(state, other.state);
			return *this;
		}
	}
}
