#include "sha512256d.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../common/sha3/sph_sha2.h"

#ifndef bswap_16
#define	bswap_16(value)  \
 	((((value) & 0xff) << 8) | ((value) >> 8))

#define	bswap_32(value)	\
 	(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
 	(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define	bswap_64(value)	\
 	(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
 	    << 32) | \
 	(uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif

static inline uint32_t swab32(uint32_t v)
{
	return bswap_32(v);
}

static inline void swap32yes(void*out, const void*in, size_t sz) {
	size_t swapcounter = 0;
	for (swapcounter = 0; swapcounter < sz; ++swapcounter)
		(((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}

void sha512256d_hash(const char* input, char* output, uint32_t nonce)
{

	sph_sha512_context ctx;
	sph_sha512_256_init(&ctx);
	sph_sha512(&ctx, input, 80);
	uint32_t hash1[16];
	sph_sha512_close(&ctx, hash1);

	uint32_t hash2[16];
	sph_sha512_256_init(&ctx);
	sph_sha512(&ctx, hash1, 32);
	sph_sha512_close(&ctx, hash2);

	memcpy(output, hash2, 32);

}
