/*
chacha.c version $Date: 2014/09/08 17:38:05 $
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
__inline __m128i _mm_set_epi64x(int64_t i0, int64_t i1) {
	union {
		int64_t q[2];
		int32_t r[4];
	} u;
	u.q[0] = i1;  u.q[1] = i0;
	// this is inefficient, but other solutions are worse
	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
}
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


#define U32V(v) (v)
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = (v))
#define U8TO32_LITTLE(v) *((uint32_t*)(v))


#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void salsa20_wordtobyte(uint8_t output[64],const uint32_t input[16], unsigned int r)
{
  uint32_t x[16];
  int i;

  for (i = 0;i < 16;++i) x[i] = input[i];
  for (i = r;i > 0;--i) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }
  for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

void chacha_ECRYPT_init(void)
{
  return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void chacha_ECRYPT_keysetup(uint32_t* input,const uint8_t *k,uint32_t kbits,uint32_t ivbits)
{
  const char *constants;

  input[4] = U8TO32_LITTLE(k + 0);
  input[5] = U8TO32_LITTLE(k + 4);
  input[6] = U8TO32_LITTLE(k + 8);
  input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  input[8] = U8TO32_LITTLE(k + 0);
  input[9] = U8TO32_LITTLE(k + 4);
  input[10] = U8TO32_LITTLE(k + 8);
  input[11] = U8TO32_LITTLE(k + 12);
  input[0] = U8TO32_LITTLE(constants + 0);
  input[1] = U8TO32_LITTLE(constants + 4);
  input[2] = U8TO32_LITTLE(constants + 8);
  input[3] = U8TO32_LITTLE(constants + 12);
}

void chacha_ECRYPT_ivsetup(uint32_t* input,const uint8_t *iv)
{
  input[12] = 0;
  input[13] = 0;
  input[14] = U8TO32_LITTLE(iv + 0);
  input[15] = U8TO32_LITTLE(iv + 4);
}

void chacha_ECRYPT_encrypt_bytes(size_t bytes, uint32_t* x, const uint8_t* m, uint8_t* out, uint8_t* output, unsigned int r)
{
  unsigned int i;

#if 0
#if defined(__AVX512F__)
#include "u16.h"
#endif

#if defined(__AVX2__)
#include "uint8_t.h"
#endif
#endif

#if 1
#include "chacha_u4.h"
#endif

#if 1
#include "chacha_u1.h"
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
    salsa20_wordtobyte(output,x, r);
    x[12] = PLUSONE(x[12]);
    if (!x[12]) {
      x[13] = PLUSONE(x[13]);
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

