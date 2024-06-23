#pragma

#include <stdint.h>
#include <emmintrin.h>

struct __declspec(align(16)) sha1_state {
    constexpr static rsize_t BLOCK_SIZE = 64;
    __declspec(align(16)) __m128i hash_value[2]; // H0_H1_H2_H3, H4_0_0_0
    __declspec(align(16)) uint8_t buffer[BLOCK_SIZE];
    __declspec(align(8)) uint64_t total;
    rsize_t buffer_usage;
};

void sha1_init(sha1_state* state);
void sha1_update(sha1_state* state, const uint8_t* message, rsize_t length);
void sha1_finalize(sha1_state* state, void* digest, rsize_t size);
