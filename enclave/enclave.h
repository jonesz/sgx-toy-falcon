#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include <stddef.h>
#include <stdint.h>
#include "sgx_error.h"

#if defined(__cplusplus)
extern "C" {
#endif

sgx_status_t trust_falcon_keygen();
sgx_status_t trust_falcon_sign(uint8_t *sig, size_t *sig_len, uint8_t *pt,
    size_t pt_len);

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H

