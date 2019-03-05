#include <stdio.h>

#include "enclave_u.h"
#include "sgx_urts.h"
#include "randombytes.h"
#include "../include/boundary_types.h"

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define PLAINTEXT_LEN 32

static sgx_enclave_id_t global_eid = 0;

void ocall_print(char *str, size_t str_len)
{
  for (int i = 0; i < str_len; ++i)
    printf("%x", (uint8_t) str[i]);
  printf("\n");
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

int initialize_enclave(void)
{
  sgx_status_t r = SGX_ERROR_UNEXPECTED;
  r = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL,
      &global_eid, NULL);
  if (r != SGX_SUCCESS)
    return -1;
  return 0;
}

int main(int argc, char **argv)
{
  printf("Initializing enclave.\n");
  if (initialize_enclave() < 0)
    return -1;

  uint8_t plaintext[PLAINTEXT_LEN];
  randombytes(plaintext, PLAINTEXT_LEN);
  printf("Plaintext to sign:\n");
  ocall_print((char *) plaintext, PLAINTEXT_LEN);
  printf("\n");

  sgx_status_t retval;
  trust_falcon_keygen(global_eid, &retval);

  uint8_t signature[MAX_SIG_LEN];
  size_t sig_size;
  printf("Signature before signing:\n");
  ocall_print((char *) signature, MAX_SIG_LEN);
  printf("\n");

  trust_falcon_sign(global_eid, &retval, (uint8_t *) &signature, &sig_size,
      (uint8_t *) &plaintext, PLAINTEXT_LEN);

  printf("Signature after signing:\n");
  ocall_print((char *) signature, sig_size);
  printf("\n");

  sgx_destroy_enclave(global_eid);
}
