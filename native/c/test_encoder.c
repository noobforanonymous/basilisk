#include "encoder.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
  int length = -1;
  unsigned char *empty = basilisk_base64_decode("", &length);
  assert(empty != NULL);
  assert(length == 0);
  free(empty);

  unsigned char *decoded = basilisk_base64_decode("TQ==", &length);
  assert(decoded != NULL);
  assert(length == 1);
  assert(decoded[0] == 'M');
  free(decoded);

  assert(basilisk_base64_decode("AA=A", &length) == NULL);
  assert(basilisk_base64_decode("invalid!", &length) == NULL);
  assert(basilisk_base64_decode(NULL, &length) == NULL);
  assert(basilisk_base64_decode("TQ==", NULL) == NULL);
  assert(basilisk_base64_encode(NULL, 1) == NULL);
  assert(basilisk_base64_encode((const unsigned char *)"x", -1) == NULL);

  unsigned char *hex = basilisk_hex_decode("00ff10", &length);
  assert(hex != NULL);
  assert(length == 3);
  assert(hex[0] == 0x00 && hex[1] == 0xff && hex[2] == 0x10);
  free(hex);
  assert(basilisk_hex_decode("0", &length) == NULL);
  assert(basilisk_hex_decode("zz", &length) == NULL);
  assert(basilisk_hex_decode(NULL, &length) == NULL);
  assert(basilisk_hex_decode("00", NULL) == NULL);

  char *rotated = basilisk_rot13("Abc-Nop");
  assert(rotated != NULL && strcmp(rotated, "Nop-Abc") == 0);
  free(rotated);
  assert(basilisk_rot13(NULL) == NULL);
  assert(basilisk_url_encode(NULL) == NULL);
  assert(basilisk_unicode_escape(NULL) == NULL);
  assert(basilisk_reverse(NULL) == NULL);
  return 0;
}
