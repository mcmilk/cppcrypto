/******************************************************************************
This file is part of cppcrypto library (http://cppcrypto.sourceforge.net/).
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "../sha3.h"
#include <algorithm>
extern "C"
{
#include "KeccakSponge.h"
}

#ifndef _MSC_VER
#define _aligned_malloc(a, b) aligned_alloc(b, a)
#define _aligned_free free
#endif

namespace cppcrypto
{
	namespace detail
	{
		sha3_impl_ssse3::sha3_impl_ssse3()
		{
			state = _aligned_malloc(sizeof(spongeState), 64);
		}
		sha3_impl_ssse3::~sha3_impl_ssse3()
		{
			_aligned_free(state);
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
