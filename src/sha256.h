/* Sha256.h -- SHA-256 Hash
2013-11-27 : Unknown : Public domain
2010-06-11 : Igor Pavlov : Public domain */

#ifndef _SHA256_H
#define _SHA256_H

#include <stdint.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct
{
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
} sha256;

void sha256_init(sha256* context);

void sha256_update(sha256* context, const uint8_t* data, size_t size);
void sha256_finalize(sha256* context, uint8_t* digest);

void sha256_hash(const uint8_t* data, size_t size, uint8_t* result);
void sha256_hmac(const uint8_t* key, size_t keySize, const uint8_t* message, size_t messageSize, uint8_t* result);

#endif
