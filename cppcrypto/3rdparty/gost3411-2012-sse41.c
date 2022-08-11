/*
 * Copyright (c) 2013, Alexey Degtyarev. 
 * All rights reserved.
 *
 * GOST R 34.11-2012 core and API functions.
 *
 * $Id: gost3411-2012-core.c 526 2013-05-26 18:24:29Z alexey $
 */

// Modified by kerukuro for use in cppcrypto.


#include <smmintrin.h>
#include "gost3411-2012-sse2.h"
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifndef _M_X64
#define EXTRACT EXTRACT32SSE4
#else
#define EXTRACT EXTRACT64SSE4
#endif

void streebog_gN_sse41(uint64_t* h, uint64_t N, const unsigned char *m, const uint64_t Ax[][256], const uint64_t RC[][8])
{
    __m128i xmm0, xmm2, xmm4, xmm6; /* XMMR0-quadruple */
    __m128i xmm1, xmm3, xmm5, xmm7; /* XMMR1-quadruple */
    unsigned int i;

	xmm0 = _mm_cvtsi64_si128(N);
	xmm2 = _mm_setzero_si128();
	xmm4 = _mm_setzero_si128();
	xmm6 = _mm_setzero_si128();

    XLPS128M(h, xmm0, xmm2, xmm4, xmm6);

    LOAD(m, xmm1, xmm3, xmm5, xmm7);
    XLPS128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    for (i = 0; i < 11; i++)
        ROUND128(i, xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    XLPS128M((&RC[11][0]), xmm0, xmm2, xmm4, xmm6);
    X128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    X128M(h, xmm0, xmm2, xmm4, xmm6);
    X128M(m, xmm0, xmm2, xmm4, xmm6);

    UNLOAD(h, xmm0, xmm2, xmm4, xmm6);

#ifndef _M_X64
    /* Restore the Floating-point status on the CPU */
    _mm_empty();
#endif

}
