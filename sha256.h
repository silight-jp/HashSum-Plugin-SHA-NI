#pragma once

#include <stdint.h>
#include <emmintrin.h>

struct __declspec(align(16)) sha256_state {
    constexpr static rsize_t BLOCK_SIZE = 64;
    __declspec(align(16)) __m128i hash_value[2]; // H0_H1_H4_H5, H2_H3_H6_H7
    __declspec(align(16)) uint8_t buffer[BLOCK_SIZE];
    __declspec(align(8)) uint64_t total;
    rsize_t buffer_usage;
};

void sha256_init(sha256_state* state);
void sha256_update(sha256_state* state, const uint8_t* message, rsize_t length);
void sha256_finalize(sha256_state* state, void* digest, rsize_t size);

void sha224_init(sha256_state* state);
void sha224_finalize(sha256_state* state, void* digest, rsize_t size);
