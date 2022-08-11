/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "../poly1305-impl.h"
#include <stdint.h>

extern "C"
{
	void poly1305_init_ext_sse2(void *state, const uint8_t* key, size_t bytes_hint);
	void poly1305_blocks_sse2(void *state, const unsigned char *in, size_t inlen);
	void poly1305_finish_ext_sse2(void *state, const unsigned char *in, size_t remaining, unsigned char *mac);
}

namespace cppcrypto
{
	namespace detail
	{
		void poly1305_impl_sse2::init(const uint8_t* key)
		{
			poly1305_init_ext_sse2(state_, key, 0);
		}
		void poly1305_impl_sse2::transform(const unsigned char *in, size_t inlen)
		{
			poly1305_blocks_sse2(state_, in, inlen);
		}
		void poly1305_impl_sse2::finish(const unsigned char *in, size_t remaining, unsigned char *mac)
		{
			poly1305_finish_ext_sse2(state_, in, remaining, mac);
		}
		void poly1305_impl_sse2::clear()
		{
			zero_memory(state_, state_.bytes());
		}

	}
}
