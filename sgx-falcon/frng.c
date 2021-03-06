/*
 * Interface to the system RNG.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.trust>
 */

// TODO: can we include assert in an SGX?
#ifndef USE_SGX
#include <assert.h>
#endif

#include "internal.h"

/*
 * PRNG
 * ----
 *
 * The Falcon implementation uses an architecture-specific PRNG for the
 * sampling (the PRNG is seeded from a SHAKE-256 instance, itself seeded
 * with hardware/OS bytes and/or user-provided seeds). This file contains
 * a single, portable PRNG based on ChaCha20. Other PRNG implementations,
 * e.g. using SSE2 or AES-NI intrinsics, could provide a speed-up.
 *
 * (NIST_API_REMOVE_BEGIN)
 *
 * Seeding
 * -------
 *
 * Three sources of seeding are used:
 *
 *  - The /dev/urandom file, on Unix-like systems.
 *
 *  - CryptGenRandom(), on Windows systems (Win32).
 *
 *  - sgx_read_rand, in an SGX Enclave.
 *
 *
 * Configuration
 * -------------
 *
 * Normally everything is auto-detected. To override detection, define
 * macros explicitly, with a value of 1 (to enable) or 0 (to disable).
 * Available macros are:
 *
 *  USE_URANDOM      /dev/urandom seeding
 *  USE_WIN32_RAND   CryptGenRandom() seeding
 *  USE_SGX          SGX sgx_read_rand seeding
 *
 * (NIST_API_REMOVE_END)
 */

/* NIST_API_REMOVE_BEGIN */
/*
 * /dev/urandom is accessible on a variety of Unix-like systems.
 */
#ifndef USE_URANDOM
#if defined _AIX \
	|| defined __ANDROID__ \
	|| defined __FreeBSD__ \
	|| defined __NetBSD__ \
	|| defined __OpenBSD__ \
	|| defined __DragonFly__ \
	|| defined __linux__ \
	|| (defined __sun && (defined __SVR4 || defined __svr4__)) \
	|| (defined __APPLE__ && defined __MACH__)
#define USE_URANDOM   1
#endif
#endif

/*
 * CryptGenRandom() exists on Windows.
 */
#ifndef USE_WIN32_RAND
#if defined _WIN32 || defined _WIN64 && !defined USE_SGX
#define USE_WIN32_RAND   1
#endif
#endif

/*
 * Accessing /dev/urandom requires using some file descriptors.
 */
#if USE_URANDOM
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

/*
 * CryptGenRandom() is defined in specific headers and requires linking
 * with advapi32.lib (to use advapi32.dll).
 */
#if USE_WIN32_RAND
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32")
#endif

/* 
 * SGX headers.
 */
#if USE_SGX
#include "sgx_trts.h"
#endif

#if USE_URANDOM
static int
urandom_get_seed(void *seed, size_t len)
{
	int f;

	if (len == 0) {
		return 1;
	}
	f = open("/dev/urandom", O_RDONLY);
	if (f >= 0) {
		while (len > 0) {
			ssize_t rlen;

			rlen = read(f, seed, len);
			if (rlen < 0) {
				if (errno == EINTR) {
					continue;
				}
				break;
			}
			seed = (unsigned char *)seed + rlen;
			len -= (size_t)rlen;
		}
		close(f);
		return len == 0;
	} else {
		return 0;
	}
}
#endif

#if USE_WIN32_RAND
static int
win32_get_seed(void *seed, size_t len)
{
	HCRYPTPROV hp;

	if (CryptAcquireContext(&hp, 0, 0, PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		BOOL r;

		r = CryptGenRandom(hp, len, seed);
		CryptReleaseContext(hp, 0);
		return r != 0;
	}
	return 0;
}
#endif

#if USE_SGX
static int
sgx_get_seed(void *seed, size_t len)
{
  sgx_status_t r = sgx_read_rand(seed, len);
  return (r == SGX_SUCCESS);
}
#endif
/* NIST_API_REMOVE_END */

/* see internal.h */
int
falcon_get_seed(void *seed, size_t len)
{
	/* (NIST_API_REMOVE_BEGIN) */
#if USE_URANDOM
	if (urandom_get_seed(seed, len)) {
		return 1;
	}
#endif
#if USE_WIN32_RAND
	if (win32_get_seed(seed, len)) {
		return 1;
	}
#endif
	/* (NIST_API_REMOVE_END) */
#if USE_SGX
  if (sgx_get_seed(seed, len)) {
    return 1;
  }
#endif
	return 0;
}

/*
 * PRNG based on ChaCha20.
 *
 * State consists in key (32 bytes) then IV (16 bytes) and block
 * counter (8 bytes). Normally, we should not care about local endianness
 * (this is for a PRNG), but for the NIST competition we need reproducible
 * KAT vectors that work across architectures, so we enforce little-endian
 * interpretation where applicable.
 *
 * The block counter is XORed into the first 8 bytes of the IV.
 */
static void
refill_chacha20(prng *p)
{
	static const uint32_t CW[] = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	};

	uint64_t cc;
	size_t u;

	/*
	 * State uses local endianness. Only the output bytes must be
	 * converted to little endian (if used on a big-endian machine).
	 */
	cc = *(uint64_t *)(p->state.d + 48);
	for (u = 0; u < sizeof p->buf.d; u += 64) {
		uint32_t state[16];
		size_t v;
		int i;

		memcpy(&state[0], CW, sizeof CW);
		memcpy(&state[4], p->state.d, 48);
		state[14] ^= (uint32_t)cc;
		state[15] ^= (uint32_t)(cc >> 32);
		for (i = 0; i < 10; i ++) {

#define QROUND(a, b, c, d)   do { \
		state[a] += state[b]; \
		state[d] ^= state[a]; \
		state[d] = (state[d] << 16) | (state[d] >> 16); \
		state[c] += state[d]; \
		state[b] ^= state[c]; \
		state[b] = (state[b] << 12) | (state[b] >> 20); \
		state[a] += state[b]; \
		state[d] ^= state[a]; \
		state[d] = (state[d] <<  8) | (state[d] >> 24); \
		state[c] += state[d]; \
		state[b] ^= state[c]; \
		state[b] = (state[b] <<  7) | (state[b] >> 25); \
	} while (0)

			QROUND( 0,  4,  8, 12);
			QROUND( 1,  5,  9, 13);
			QROUND( 2,  6, 10, 14);
			QROUND( 3,  7, 11, 15);
			QROUND( 0,  5, 10, 15);
			QROUND( 1,  6, 11, 12);
			QROUND( 2,  7,  8, 13);
			QROUND( 3,  4,  9, 14);

#undef QROUND

		}

		for (v = 0; v < 4; v ++) {
			state[v] += CW[v];
		}
		for (v = 4; v < 14; v ++) {
			state[v] += ((uint32_t *)p->state.d)[v - 4];
		}
		state[14] += ((uint32_t *)p->state.d)[10]
			^ (uint32_t)cc;
		state[15] += ((uint32_t *)p->state.d)[11]
			^ (uint32_t)(cc >> 32);
		cc ++;

#if FALCON_LE_U
		memcpy(p->buf.d + u, state, sizeof state);
#else
		for (v = 0; v < 16; v ++) {
			p->buf.d[u + (v << 2) + 0] = state[v];
			p->buf.d[u + (v << 2) + 1] = (state[v] >> 8);
			p->buf.d[u + (v << 2) + 2] = (state[v] >> 16);
			p->buf.d[u + (v << 2) + 3] = (state[v] >> 24);
		}
#endif
	}
	*(uint64_t *)(p->state.d + 48) = cc;
}

/* see internal.h */
int
falcon_prng_init(prng *p, shake_context *src, int type)
{
	if (type == 0) {
		type = PRNG_CHACHA20;
	}
	switch (type) {
	case PRNG_CHACHA20:
#if FALCON_LE_U
		shake_extract(src, p->state.d, 56);
#else
		{
			/*
			 * To ensure reproducibility for a given seed, we
			 * must enforce little-endian interpretation of
			 * the state words.
			 */
			unsigned char tmp[56];
			uint64_t th, tl;
			int i;

			shake_extract(src, tmp, 56);
			for (i = 0; i < 14; i ++) {
				uint32_t w;

				w = (uint32_t)tmp[(i << 2) + 0]
					| ((uint32_t)tmp[(i << 2) + 1] << 8)
					| ((uint32_t)tmp[(i << 2) + 2] << 16)
					| ((uint32_t)tmp[(i << 2) + 3] << 24);
				*(uint32_t *)(p->state.d + (i << 2)) = w;
			}
			tl = *(uint32_t *)(p->state.d + 48);
			th = *(uint32_t *)(p->state.d + 52);
			*(uint64_t *)(p->state.d + 48) = tl + (th << 32);
		}
#endif
		break;
	default:
		return 0;
	}
	p->type = type;
	falcon_prng_refill(p);
	return type;
}

/* see internal.h */
void
falcon_prng_refill(prng *p)
{
	switch (p->type) {
	case PRNG_CHACHA20:
		refill_chacha20(p);
		break;
	default:
#ifndef USE_SGX
		assert(0);
#endif
		break;
	}
	p->ptr = 0;
}

/* see internal.h */
void
falcon_prng_get_bytes(prng *p, void *dst, size_t len)
{
	unsigned char *buf;

	buf = dst;
	while (len > 0) {
		size_t clen;

		clen = (sizeof p->buf.d) - p->ptr;
		if (clen > len) {
			clen = len;
		}
		memcpy(buf, p->buf.d, clen);
		buf += clen;
		len -= clen;
		p->ptr += clen;
		if (p->ptr == sizeof p->buf.d) {
			falcon_prng_refill(p);
		}
	}
}
