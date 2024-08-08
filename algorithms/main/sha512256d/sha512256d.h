#ifndef SHA512256D_H
#define SHA512256D_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
    void sha512256d_hash(const char* input, char* output, uint32_t nonce);
#ifdef __cplusplus
}
#endif

#endif
