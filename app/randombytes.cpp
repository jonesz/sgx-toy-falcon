// TODO: placeholder, not random.
#include "randombytes.h"
#include <stdint.h>
#include <string.h>

static uint32_t state = 1337;
static uint32_t xorshift32(uint32_t *state);

static uint32_t xorshift32(uint32_t *state)
{
  uint32_t x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

void randombytes(void *s, size_t len)
{
  uint8_t *buf = (uint8_t *) s;
  for (int i = 0; i < len; i++) {
    buf[i] = (uint8_t) xorshift32(&state);
  }
}

