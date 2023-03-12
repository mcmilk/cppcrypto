/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_PORTABILITY_H
#define CPPCRYPTO_PORTABILITY_H

#include <stdint.h>
#include <stdlib.h>

#ifdef _MSC_VER
#include <Windows.h>
#include <intrin.h>
#define swap_uint64 _byteswap_uint64
#define swap_uint32 _byteswap_ulong
#define swap_uint16 _byteswap_ushort
#define aligned_allocate(a, b) _aligned_malloc(a, b)
#define aligned_deallocate _aligned_free
#define rotater32 _rotr
#define rotatel32 _rotl
#define rotater64 _rotr64
#define rotatel64 _rotl64
#define FASTCALL __fastcall
#define CPPCRYPTO_STATIC_ALIGN(x) __declspec(align(x))
#define zero_memory(a, b) SecureZeroMemory(a, b)

#ifdef _M_X64
static inline uint32_t count_trailing_zeroes(uint64_t value)
{
	unsigned long trailing_zero = 0;
    _BitScanForward64(&trailing_zero, value);
	return static_cast<uint32_t>(trailing_zero);
}
#else
#define NO_COUNT_TRAILING_ZEROES 1
static inline __m128i _mm_insert_epi64(__m128i a, int64_t b, const int ndx)
{
	if (!ndx)
	{
		a = _mm_insert_epi32(a, static_cast<int>(b), 0);
		a = _mm_insert_epi32(a, static_cast<int>(b >> 32), 1);
	}
	else
	{
		a = _mm_insert_epi32(a, static_cast<int>(b), 2);
		a = _mm_insert_epi32(a, static_cast<int>(b >> 32), 3);
	}
	return a;
}
#endif

#ifdef CPPCRYPTODLL_EXPORT
#define CPPCRYPTOAPI __declspec(dllexport) 
#elif defined(CPPCRYPTODLL)
#define CPPCRYPTOAPI __declspec(dllimport) 
#else
#define CPPCRYPTOAPI
#endif
#else
#define CPPCRYPTO_STATIC_ALIGN(x) __attribute__((aligned(x)))
#ifdef __SUNPRO_CC
#define NO_BIND_TO_FUNCTION
#define NO_CPP11_THREADS
static inline uint16_t swap_uint16(uint16_t val)
{
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8);
}
static inline uint32_t swap_uint32(uint32_t val)
{
    return (((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) | ((val & 0x0000ff00) << 8) | ((val & 0x000000ff) << 24));
}
static inline uint64_t swap_uint64(uint64_t val)
{
    return (((val & 0xff00000000000000ull) >> 56) |
	((val & 0x00ff000000000000ull) >> 40) |
	((val & 0x0000ff0000000000ull) >> 24) |
	((val & 0x000000ff00000000ull) >> 8) |
	((val & 0x00000000ff000000ull) << 8) |
	((val & 0x0000000000ff0000ull) << 24) |
	((val & 0x000000000000ff00ull) << 40) |
	((val & 0x00000000000000ffull) << 56));
}
#define NO_COUNT_TRAILING_ZEROES 1
#else
#define swap_uint64 __builtin_bswap64
#define swap_uint32 __builtin_bswap32
#define swap_uint16 __builtin_bswap16
#define count_trailing_zeroes __builtin_ctzll
#endif
#define FASTCALL
#define CPPCRYPTOAPI

#if defined(__clang__) || defined(__SUNPRO_CC)
static inline uint32_t rotater32(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}
static inline uint32_t rotatel32(uint32_t x, unsigned n)
{
	return (x << n) | (x >> (32 - n));
}
#else
#include <x86intrin.h>
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
#ifdef __MINGW32__
#define NO_CPP11_THREADS
#define aligned_allocate(a, b) _aligned_malloc(a, b)
#define aligned_deallocate _aligned_free
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


#if defined(__APPLE__) && defined(__MACH__)
#define zero_memory(a, b) memset_s(a, b, 0, b)
//#elif defined(__linux__)
//#define zero_memory(a, b) memzero_explicit(a, b)
#else
static inline void zero_memory(void *v, size_t n) {
	volatile unsigned char *p = (volatile unsigned char *)v;
	while (n--) {
		*p++ = 0;
	}
}
#endif

#endif

#ifdef NO_COUNT_TRAILING_ZEROES
static inline uint32_t count_trailing_zeroes(uint64_t v)
{
	if (v & 0x1)
		return 0;
	uint32_t res = 1;
	if ((v & 0xffffffff) == 0)
	{
		v >>= 32;
		res += 32;
	}
	if ((v & 0xffff) == 0)
	{
		v >>= 16;
		res += 16;
	}
	if ((v & 0xff) == 0)
	{
		v >>= 8;
		res += 8;
	}
	if ((v & 0xf) == 0)
	{
		v >>= 4;
		res += 4;
	}
	if ((v & 0x3) == 0)
	{
		v >>= 2;
		res += 2;
	}
	res -= v & 0x1;
	return res;
}
#endif

namespace cppcrypto
{
    static inline uint16_t byteswap(uint16_t val)
    {
        return swap_uint16(val);
    }

    static inline uint32_t byteswap(uint32_t val)
    {
        return swap_uint32(val);
    }

    static inline uint64_t byteswap(uint64_t val)
    {
        return swap_uint64(val);
    }
}

#endif

