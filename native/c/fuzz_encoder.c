#include "encoder.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t state = 0xB451115u;

static uint32_t next_random(void) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}

int main(void) {
  for (int round = 0; round < 10000; round++) {
    int input_len = (int)(next_random() % 1024);
    unsigned char *input = malloc((size_t)input_len + 1);
    assert(input != NULL);
    for (int i = 0; i < input_len; i++)
      input[i] = (unsigned char)(next_random() & 0xff);
    input[input_len] = '\0';

    char *encoded = basilisk_base64_encode(input, input_len);
    assert(encoded != NULL);
    int decoded_len = -1;
    unsigned char *decoded = basilisk_base64_decode(encoded, &decoded_len);
    assert(decoded != NULL);
    assert(decoded_len == input_len);
    assert(memcmp(input, decoded, (size_t)input_len) == 0);
    basilisk_free(encoded);
    basilisk_free(decoded);

    char *hex = basilisk_hex_encode(input, input_len);
    assert(hex != NULL);
    unsigned char *unhex = basilisk_hex_decode(hex, &decoded_len);
    assert(unhex != NULL);
    assert(decoded_len == input_len);
    assert(memcmp(input, unhex, (size_t)input_len) == 0);
    basilisk_free(hex);
    basilisk_free(unhex);
    free(input);
  }
  return 0;
}
