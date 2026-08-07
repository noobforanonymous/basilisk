/*
 * Basilisk Payload Encoder — C implementation for fast encoding
 * transformations used by the evolution engine.
 *
 * Provides:
 *   - Base64 encode/decode
 *   - Hex encode/decode
 *   - ROT13 transform
 *   - URL encoding
 *   - Unicode escape generation
 *
 * Build: gcc -shared -fPIC -O3 -o libbasilisk_encoder.so encoder.c
 */

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Base64 Encode / Decode
 * ============================================================ */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *basilisk_base64_encode(const unsigned char *data, int len) {
  if (len < 0 || (len > 0 && data == NULL))
    return NULL;
  size_t input_len = (size_t)len;
  if (input_len > (SIZE_MAX - 2) / 4 * 3)
    return NULL;
  size_t out_len = 4 * ((input_len + 2) / 3);
  if (out_len > (size_t)INT_MAX || out_len == SIZE_MAX)
    return NULL;
  char *output = (char *)malloc(out_len + 1);
  if (!output)
    return NULL;

  int i;
  size_t j;
  for (i = 0, j = 0; i < len; i += 3, j += 4) {
    uint32_t n = ((uint32_t)data[i]) << 16;
    if (i + 1 < len)
      n |= ((uint32_t)data[i + 1]) << 8;
    if (i + 2 < len)
      n |= (uint32_t)data[i + 2];

    output[j] = B64_TABLE[(n >> 18) & 0x3F];
    output[j + 1] = B64_TABLE[(n >> 12) & 0x3F];
    output[j + 2] = (i + 1 < len) ? B64_TABLE[(n >> 6) & 0x3F] : '=';
    output[j + 3] = (i + 2 < len) ? B64_TABLE[n & 0x3F] : '=';
  }
  output[out_len] = '\0';
  return output;
}

static int b64_decode_char(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

unsigned char *basilisk_base64_decode(const char *input, int *out_len) {
  if (!input || !out_len)
    return NULL;
  size_t raw_len = strlen(input);
  if (raw_len > (size_t)INT_MAX)
    return NULL;
  int in_len = (int)raw_len;
  if (in_len % 4 != 0)
    return NULL;

  if (in_len == 0) {
    unsigned char *empty = (unsigned char *)malloc(1);
    if (!empty)
      return NULL;
    empty[0] = '\0';
    *out_len = 0;
    return empty;
  }

  int padding = 0;
  for (int i = 0; i < in_len; i++) {
    if (input[i] == '=') {
      padding++;
      if (i < in_len - 2 || padding > 2)
        return NULL;
    } else if (padding > 0) {
      return NULL;
    } else if (b64_decode_char(input[i]) < 0) {
      return NULL;
    }
  }

  *out_len = in_len / 4 * 3;
  if (input[in_len - 1] == '=')
    (*out_len)--;
  if (input[in_len - 2] == '=')
    (*out_len)--;

  unsigned char *output = (unsigned char *)malloc(*out_len + 1);
  if (!output)
    return NULL;

  int i, j;
  for (i = 0, j = 0; i < in_len; i += 4) {
    uint32_t n = 0;
    for (int k = 0; k < 4; k++) {
      int v = b64_decode_char(input[i + k]);
      if (v >= 0)
        n = (n << 6) | v;
      else
        n <<= 6;
    }
    if (j < *out_len)
      output[j++] = (n >> 16) & 0xFF;
    if (j < *out_len)
      output[j++] = (n >> 8) & 0xFF;
    if (j < *out_len)
      output[j++] = n & 0xFF;
  }
  output[*out_len] = '\0';
  return output;
}

/* ============================================================
 * Hex Encode / Decode
 * ============================================================ */

char *basilisk_hex_encode(const unsigned char *data, int len) {
  if (len < 0 || (len > 0 && data == NULL) || (size_t)len > (SIZE_MAX - 1) / 2)
    return NULL;
  size_t out_len = (size_t)len * 2;
  char *output = (char *)malloc(out_len + 1);
  if (!output)
    return NULL;

  for (int i = 0; i < len; i++) {
    snprintf(output + i * 2, 3, "%02x", data[i]);
  }
  output[len * 2] = '\0';
  return output;
}

unsigned char *basilisk_hex_decode(const char *input, int *out_len) {
  if (!input || !out_len)
    return NULL;
  size_t raw_len = strlen(input);
  if (raw_len > (size_t)INT_MAX || raw_len % 2 != 0)
    return NULL;
  int in_len = (int)raw_len;
  *out_len = in_len / 2;
  unsigned char *output = (unsigned char *)malloc(*out_len + 1);
  if (!output)
    return NULL;

  for (int i = 0; i < *out_len; i++) {
    int high = isdigit((unsigned char)input[i * 2])
                   ? input[i * 2] - '0'
                   : tolower((unsigned char)input[i * 2]) - 'a' + 10;
    int low = isdigit((unsigned char)input[i * 2 + 1])
                  ? input[i * 2 + 1] - '0'
                  : tolower((unsigned char)input[i * 2 + 1]) - 'a' + 10;
    if (!isxdigit((unsigned char)input[i * 2]) ||
        !isxdigit((unsigned char)input[i * 2 + 1])) {
      free(output);
      return NULL;
    }
    output[i] = (unsigned char)((high << 4) | low);
  }
  output[*out_len] = '\0';
  return output;
}

/* ============================================================
 * ROT13
 * ============================================================ */

char *basilisk_rot13(const char *input) {
  if (!input)
    return NULL;
  int len = strlen(input);
  char *output = (char *)malloc(len + 1);
  if (!output)
    return NULL;

  for (int i = 0; i < len; i++) {
    char c = input[i];
    if (c >= 'a' && c <= 'z')
      output[i] = 'a' + (c - 'a' + 13) % 26;
    else if (c >= 'A' && c <= 'Z')
      output[i] = 'A' + (c - 'A' + 13) % 26;
    else
      output[i] = c;
  }
  output[len] = '\0';
  return output;
}

/* ============================================================
 * URL Encoding
 * ============================================================ */

char *basilisk_url_encode(const char *input) {
  if (!input)
    return NULL;
  int len = strlen(input);
  if ((size_t)len > (SIZE_MAX - 1) / 3)
    return NULL;
  // Worst case: every char needs %XX encoding
  char *output = (char *)malloc(len * 3 + 1);
  if (!output)
    return NULL;

  int j = 0;
  for (int i = 0; i < len; i++) {
    unsigned char c = (unsigned char)input[i];
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      output[j++] = c;
    } else if (c == ' ') {
      output[j++] = '+';
    } else {
      snprintf(output + j, 4, "%%%02X", c);
      j += 3;
    }
  }
  output[j] = '\0';
  return output;
}

/* ============================================================
 * Unicode Escape Generation
 * ============================================================ */

char *basilisk_unicode_escape(const char *input) {
  if (!input)
    return NULL;
  int len = strlen(input);
  if ((size_t)len > (SIZE_MAX - 1) / 6)
    return NULL;
  // Each char becomes \uXXXX (6 chars)
  char *output = (char *)malloc(len * 6 + 1);
  if (!output)
    return NULL;

  int j = 0;
  for (int i = 0; i < len; i++) {
    j += snprintf(output + j, 7, "\\u%04x", (unsigned char)input[i]);
  }
  output[j] = '\0';
  return output;
}

/* ============================================================
 * String Reversal (UTF-8 aware)
 * ============================================================ */

char *basilisk_reverse(const char *input) {
  if (!input)
    return NULL;
  int len = strlen(input);
  char *output = (char *)malloc(len + 1);
  if (!output)
    return NULL;

  int in_ptr = 0;
  int out_ptr = len;

  while (in_ptr < len) {
    int char_len = 1;
    // Identify UTF-8 sequence length (search for continuation bytes)
    while (in_ptr + char_len < len &&
           ((unsigned char)input[in_ptr + char_len] & 0xC0) == 0x80) {
      char_len++;
    }

    // Copy the whole character sequence to the end of the output buffer
    out_ptr -= char_len;
    memcpy(output + out_ptr, input + in_ptr, char_len);
    in_ptr += char_len;
  }

  output[len] = '\0';
  return output;
}

/* ============================================================
 * Memory Management
 * ============================================================ */

void basilisk_free(void *ptr) { free(ptr); }
