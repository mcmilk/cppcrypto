/*
salsa20-xmm6int.c version 20140715
D. J. Bernstein
Romain Dolbeau
Public domain.
*/

// Modified by kerukuro for use in cppcrypto.

#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifndef _M_X64
#ifdef _MSC_VER
#if _MSC_VER < 1900
#pragma warning(disable:4799)
__inline __m128i _mm_set1_epi64x(int64_t a)
{
	union {
		__m64 m;
		long long ii;
	} u;
	u.ii = a;
	return _mm_set1_epi64(u.m);
}
#pragma warning(default:4799)
#endif
#endif
#endif


#define crypto_stream_salsa20_e_dolbeau_amd64_xmm6int_KEYBYTES 32
#define crypto_stream_salsa20_e_dolbeau_amd64_xmm6int_NONCEBYTES 8

#define U32V(v) (v)
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = (v))

#ifndef _M_X64
#ifdef _MSC_VER
#if _MSC_VER < 1900
__inline __m128i _mm_set_epi64x(int64_t i0, int64_t i1) {
	union {
		int64_t q[2];
		int32_t r[4];
	} u;
	u.q[0] = i1;  u.q[1] = i0;
	// this is inefficient, but other solutions are worse
	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
}
#define _mm_cvtsi64_si128(a) _mm_set_epi64x(0, a)
#endif
#endif
#endif


/* Compatibility layer. This array help translates
   to the storage format in the SIMD code. */
static const int tr[16] = {  0,  5, 10, 15,
                            12,  1,  6, 11,
                             8, 13,  2,  7,
                             4,  9, 14,  3 };

/* SIMD format-compatible scalar code. This should be replaced by
   more efficient code, but so far this is a proof of concept. */
static void salsa20_wordtobyte_tr(uint8_t output[64],const uint32_t input[16], unsigned int r)
{
  uint32_t x[16];
  int i;

  for (i = 0;i < 16;++i) x[tr[i]] = input[tr[i]];
  for (i = r;i > 0; --i) {
    x[tr[ 4]] = XOR(x[tr[ 4]],ROTATE(PLUS(x[tr[ 0]],x[tr[12]]), 7));
    x[tr[ 8]] = XOR(x[tr[ 8]],ROTATE(PLUS(x[tr[ 4]],x[tr[ 0]]), 9));
    x[tr[12]] = XOR(x[tr[12]],ROTATE(PLUS(x[tr[ 8]],x[tr[ 4]]),13));
    x[tr[ 0]] = XOR(x[tr[ 0]],ROTATE(PLUS(x[tr[12]],x[tr[ 8]]),18));
    x[tr[ 9]] = XOR(x[tr[ 9]],ROTATE(PLUS(x[tr[ 5]],x[tr[ 1]]), 7));
    x[tr[13]] = XOR(x[tr[13]],ROTATE(PLUS(x[tr[ 9]],x[tr[ 5]]), 9));
    x[tr[ 1]] = XOR(x[tr[ 1]],ROTATE(PLUS(x[tr[13]],x[tr[ 9]]),13));
    x[tr[ 5]] = XOR(x[tr[ 5]],ROTATE(PLUS(x[tr[ 1]],x[tr[13]]),18));
    x[tr[14]] = XOR(x[tr[14]],ROTATE(PLUS(x[tr[10]],x[tr[ 6]]), 7));
    x[tr[ 2]] = XOR(x[tr[ 2]],ROTATE(PLUS(x[tr[14]],x[tr[10]]), 9));
    x[tr[ 6]] = XOR(x[tr[ 6]],ROTATE(PLUS(x[tr[ 2]],x[tr[14]]),13));
    x[tr[10]] = XOR(x[tr[10]],ROTATE(PLUS(x[tr[ 6]],x[tr[ 2]]),18));
    x[tr[ 3]] = XOR(x[tr[ 3]],ROTATE(PLUS(x[tr[15]],x[tr[11]]), 7));
    x[tr[ 7]] = XOR(x[tr[ 7]],ROTATE(PLUS(x[tr[ 3]],x[tr[15]]), 9));
    x[tr[11]] = XOR(x[tr[11]],ROTATE(PLUS(x[tr[ 7]],x[tr[ 3]]),13));
    x[tr[15]] = XOR(x[tr[15]],ROTATE(PLUS(x[tr[11]],x[tr[ 7]]),18));
    x[tr[ 1]] = XOR(x[tr[ 1]],ROTATE(PLUS(x[tr[ 0]],x[tr[ 3]]), 7));
    x[tr[ 2]] = XOR(x[tr[ 2]],ROTATE(PLUS(x[tr[ 1]],x[tr[ 0]]), 9));
    x[tr[ 3]] = XOR(x[tr[ 3]],ROTATE(PLUS(x[tr[ 2]],x[tr[ 1]]),13));
    x[tr[ 0]] = XOR(x[tr[ 0]],ROTATE(PLUS(x[tr[ 3]],x[tr[ 2]]),18));
    x[tr[ 6]] = XOR(x[tr[ 6]],ROTATE(PLUS(x[tr[ 5]],x[tr[ 4]]), 7));
    x[tr[ 7]] = XOR(x[tr[ 7]],ROTATE(PLUS(x[tr[ 6]],x[tr[ 5]]), 9));
    x[tr[ 4]] = XOR(x[tr[ 4]],ROTATE(PLUS(x[tr[ 7]],x[tr[ 6]]),13));
    x[tr[ 5]] = XOR(x[tr[ 5]],ROTATE(PLUS(x[tr[ 4]],x[tr[ 7]]),18));
    x[tr[11]] = XOR(x[tr[11]],ROTATE(PLUS(x[tr[10]],x[tr[ 9]]), 7));
    x[tr[ 8]] = XOR(x[tr[ 8]],ROTATE(PLUS(x[tr[11]],x[tr[10]]), 9));
    x[tr[ 9]] = XOR(x[tr[ 9]],ROTATE(PLUS(x[tr[ 8]],x[tr[11]]),13));
    x[tr[10]] = XOR(x[tr[10]],ROTATE(PLUS(x[tr[ 9]],x[tr[ 8]]),18));
    x[tr[12]] = XOR(x[tr[12]],ROTATE(PLUS(x[tr[15]],x[tr[14]]), 7));
    x[tr[13]] = XOR(x[tr[13]],ROTATE(PLUS(x[tr[12]],x[tr[15]]), 9));
    x[tr[14]] = XOR(x[tr[14]],ROTATE(PLUS(x[tr[13]],x[tr[12]]),13));
    x[tr[15]] = XOR(x[tr[15]],ROTATE(PLUS(x[tr[14]],x[tr[13]]),18));
  }
  for (i = 0;i < 16;++i) x[tr[i]] = PLUS(x[tr[i]],input[tr[i]]);
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[tr[i]]);
}

void salsa20_ECRYPT_encrypt_bytes(size_t bytes, uint32_t* x, const uint8_t* m, uint8_t* out, uint8_t* output, unsigned int r)
{
  size_t i;

#if 0
#if defined(__AVX512F__)
#include "u16.h"
#endif

#if defined(__AVX2__)
#include "u8.h"
#endif
#endif

#if 1
#include "salsa20_u4.h"
#endif

#if 1
#include "salsa20_u1.h"
#endif

#ifndef _M_X64
#ifdef _MSC_VER
#if _MSC_VER < 1900
  _mm_empty();
#endif
#endif
#endif

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte_tr(output,x, r);
    x[tr[8]] = PLUSONE(x[tr[8]]);
    if (!x[tr[8]]) {
      x[tr[9]] = PLUSONE(x[tr[9]]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) out[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) out[i] = m[i] ^ output[i];
    bytes -= 64;
    out += 64;
    m += 64;
  }

}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

#define U8TO32_LITTLE(v) *((uint32_t*)(v))

/* This initializes in SIMD format */
void salsa20_ECRYPT_keysetup(uint32_t* input, const uint8_t *k, uint32_t kbits, uint32_t ivbits)
{
  const char *constants;

  input[tr[1]] = U8TO32_LITTLE(k + 0);
  input[tr[2]] = U8TO32_LITTLE(k + 4);
  input[tr[3]] = U8TO32_LITTLE(k + 8);
  input[tr[4]] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  input[tr[11]] = U8TO32_LITTLE(k + 0);
  input[tr[12]] = U8TO32_LITTLE(k + 4);
  input[tr[13]] = U8TO32_LITTLE(k + 8);
  input[tr[14]] = U8TO32_LITTLE(k + 12);
  input[tr[0]] = U8TO32_LITTLE(constants + 0);
  input[tr[5]] = U8TO32_LITTLE(constants + 4);
  input[tr[10]] = U8TO32_LITTLE(constants + 8);
  input[tr[15]] = U8TO32_LITTLE(constants + 12);
}

/* This initializes in SIMD format */
void salsa20_ECRYPT_ivsetup(uint32_t* input, const uint8_t *iv)
{
  input[tr[6]] = U8TO32_LITTLE(iv + 0);
  input[tr[7]] = U8TO32_LITTLE(iv + 4);
  input[tr[8]] = 0;
  input[tr[9]] = 0;
}

