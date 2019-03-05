#include "enclave.h"
#include "enclave_t.h"
#include "../include/boundary_types.h"
#include "../sgx-falcon/falcon.h"

#if defined(__cplusplus)
extern "C" {
#endif

uint8_t pkey[3000];
uint8_t skey[6000];
static size_t pkey_len = 3000;
static size_t skey_len = 6000;

sgx_status_t trust_falcon_keygen(void)
{
  // TODO: Should probably have preprocessor defines for the key settings.
  falcon_keygen *fk = falcon_keygen_new(9, 0);
  if (fk == NULL) {
    ocall_print_string("Failed to allocate keygen context.\n");
    return SGX_ERROR_UNEXPECTED;
  }

  int r = falcon_keygen_make(fk, FALCON_COMP_STATIC, &skey, &skey_len,
      &pkey, &pkey_len);
  if (r != 1) {
    ocall_print_string("Failed to generate keys.\n");
    return SGX_ERROR_UNEXPECTED;
  }

  falcon_keygen_free(fk);
  return SGX_SUCCESS;
}

sgx_status_t trust_falcon_sign(uint8_t *sig, size_t *sig_len, uint8_t *pt,
    size_t pt_len)
{
  if ((sig == NULL) || (sig_len == NULL) || (pt == NULL) || (pt_len <= 0)) {
    ocall_print_string("Failed: invalid parameter.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }
  if (skey_len <= 0) {
    ocall_print_string("Failed: invalid state.\n");
    return SGX_ERROR_INVALID_STATE;
  }

  ocall_print_string("Copied plaintext:\n");
  ocall_print((char *) pt, pt_len);
  ocall_print_string("\n");

  falcon_sign *fs = falcon_sign_new();
  falcon_sign_set_private_key(fs, &skey, skey_len);

  uint8_t r_nonce[40];
  falcon_sign_start(fs, &r_nonce);
  falcon_sign_update(fs, pt, pt_len);
  size_t size = falcon_sign_generate(fs, sig, MAX_SIG_LEN, FALCON_COMP_STATIC);
  *sig_len = size;
  falcon_sign_free(fs);

  // Go ahead and print the pubkey from this context.
  ocall_print_string("Public key:\n");
  ocall_print((char *) pkey, pkey_len);
  ocall_print_string("\n");
  return SGX_SUCCESS;
}

#if defined(__cplusplus)
}
#endif

