/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_PORTABILITY_H
#define CPPCRYPTO_PORTABILITY_H

#include <stdint.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define swap_uint64 _byteswap_uint64
#define swap_uint32 _byteswap_ulong
#define aligned_allocate(a, b) _aligned_malloc(a, b)
#define aligned_deallocate _aligned_free
#define rotater32 _rotr
#define rotatel32 _rotl
#define rotater64 _rotr64
#define rotatel64 _rotl64
#define FASTCALL __fastcall
#else
#define swap_uint64 __builtin_bswap64
#define swap_uint32 __builtin_bswap32
#define FASTCALL

#ifdef __clang__
static inline uint32_t rotater32(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}
static inline uint32_t rotatel32(uint32_t x, unsigned n)
{
	return (x << n) | (x >> (32 - n));
}
#else
#define rotater32 _rotr
#define rotatel32 _rotl
#endif

static inline uint64_t rotater64(uint64_t x, unsigned n)
{
	return (x >> n) | (x << (64 - n));
}

static inline uint64_t rotatel64(uint64_t x, unsigned n)
{
	return (x << n) | (x >> (64 - n));
}

#ifdef __linux__
#define aligned_allocate(a, b) aligned_alloc(b, a)
#define aligned_deallocate free
#else
static inline void* aligned_allocate(size_t a, size_t b)
{
	void* aPtr;
	if (posix_memalign (&aPtr, b, a))
		aPtr = NULL;
	return aPtr;
}
#define aligned_deallocate free
#endif

#endif

#endif

