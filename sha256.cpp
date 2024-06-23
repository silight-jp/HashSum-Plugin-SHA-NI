#include "sha256.h"
#include <bit>
#include <memory.h>
#include <immintrin.h>
#include "inline_loop.h"

static constexpr __m128i K[16] = {
    {.m128i_u32 = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5 } },
    {.m128i_u32 = { 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5 } },
    {.m128i_u32 = { 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3 } },
    {.m128i_u32 = { 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174 } },
    {.m128i_u32 = { 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc } },
    {.m128i_u32 = { 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da } },
    {.m128i_u32 = { 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7 } },
    {.m128i_u32 = { 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967 } },
    {.m128i_u32 = { 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13 } },
    {.m128i_u32 = { 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85 } },
    {.m128i_u32 = { 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3 } },
    {.m128i_u32 = { 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070 } },
    {.m128i_u32 = { 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5 } },
    {.m128i_u32 = { 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3 } },
    {.m128i_u32 = { 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208 } },
    {.m128i_u32 = { 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 } },
};

static constexpr rsize_t BLOCK_SIZE = sha256_state::BLOCK_SIZE;

static __forceinline void sha256_compute(__m128i hash_value[2], const uint8_t* message, rsize_t blocks) {
    const __m128i u8x16_to_u32x4 = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

    const __m128i* messageBlocks = (const __m128i*)message;

    __m128i H0_H1_H4_H5 = _mm_loadu_si128(hash_value + 0);
    __m128i H2_H3_H6_H7 = _mm_loadu_si128(hash_value + 1);

    for (rsize_t i = 0; i < blocks; i++) {
        // 1. Prepare the message schedule, {Wt}

        __m128i W_W_W_W[16];

        inline_loop<0, 16>([&](rsize_t t) {
            if (t < 4) {
                auto tmp1 = _mm_loadu_si128(messageBlocks++);
                W_W_W_W[t] = _mm_shuffle_epi8(tmp1, u8x16_to_u32x4);
            } else {
                auto tmp1 = _mm_sha256msg1_epu32(W_W_W_W[t - 4], W_W_W_W[t - 3]);
                auto tmp2 = _mm_alignr_epi8(W_W_W_W[t - 1], W_W_W_W[t - 2], 4);
                auto tmp3 = _mm_add_epi32(tmp1, tmp2);
                W_W_W_W[t] = _mm_sha256msg2_epu32(tmp3, W_W_W_W[t - 1]);
            }
        });

        // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st hash value

        __m128i a_b_e_f = H0_H1_H4_H5;
        __m128i c_d_g_h = H2_H3_H6_H7;

        // 3. For t=0 to 63

        inline_loop<0, 16>([&](rsize_t t) {
            auto k = _mm_loadu_si128((const __m128i*)K + t);
            auto tmp1 = _mm_add_epi32(W_W_W_W[t], k);
            c_d_g_h = _mm_sha256rnds2_epu32(c_d_g_h, a_b_e_f, tmp1);
            auto tmp2 = _mm_shuffle_epi32(tmp1, 0x0E);
            a_b_e_f = _mm_sha256rnds2_epu32(a_b_e_f, c_d_g_h, tmp2);
        });

        // 4. Compute the (i)th intermediate hash value H(i)

        H0_H1_H4_H5 = _mm_add_epi32(H0_H1_H4_H5, a_b_e_f);
        H2_H3_H6_H7 = _mm_add_epi32(H2_H3_H6_H7, c_d_g_h);
    }

    _mm_storeu_si128(hash_value + 0, H0_H1_H4_H5);
    _mm_storeu_si128(hash_value + 1, H2_H3_H6_H7);
}

void sha256_init(sha256_state* state) {
    auto& [hash_value, buffer, total, usage] = *state;
    hash_value[0] = {
        .m128i_u32 = {
            0x9b05688c, // H5
            0x510e527f, // H4
            0xbb67ae85, // H1
            0x6a09e667, // H0
        }
    };
    hash_value[1] = {
        .m128i_u32 = {
            0x5be0cd19, // H7
            0x1f83d9ab, // H6
            0xa54ff53a, // H3
            0x3c6ef372, // H2
        }
    };
    total = 0;
    usage = 0;
}

void sha256_update(sha256_state* state, const uint8_t* message, rsize_t length) {
    auto& [hash_value, buffer, total, usage] = *state;

    total += length;

    if (usage + length >= BLOCK_SIZE) {
        if (usage > 0) {
            auto rem = BLOCK_SIZE - usage;
            memcpy_s(buffer + usage, rem, message, rem);
            sha256_compute(hash_value, buffer, 1);
            message += rem;
            length -= rem;
            usage = 0;
        }

        rsize_t count = length / BLOCK_SIZE;
        if (count > 0) {
            sha256_compute(hash_value, message, count);
            auto progressed = BLOCK_SIZE * count;
            message += progressed;
            length -= progressed;
        }
    }

    if (length > 0) {
        memcpy_s(buffer + usage, BLOCK_SIZE - usage, message, length);
        usage += length;
    }
}

void sha256_finalize(sha256_state* state, void* digest, rsize_t size) {
    auto& [hash_value, buffer, total, usage ] = *state;

    buffer[usage++] = 0x80;

    if (usage + 8 > BLOCK_SIZE) {
        memset(buffer + usage, 0, BLOCK_SIZE - usage);
        sha256_compute(hash_value, buffer, 1);
        usage = 0;
    }

    memset(buffer + usage, 0, BLOCK_SIZE - usage - 8);
    uint64_t length = std::byteswap(total * 8);
    memcpy_s(buffer + BLOCK_SIZE - 8, 8, &length, sizeof(length));
    sha256_compute(hash_value, buffer, 1);
    usage = 0;

    uint64_t final_hash_value[4] = {
        std::byteswap(hash_value[0].m128i_u64[1]), // H0_H1
        std::byteswap(hash_value[1].m128i_u64[1]), // H2_H3
        std::byteswap(hash_value[0].m128i_u64[0]), // H4_H5
        std::byteswap(hash_value[1].m128i_u64[0]), // H6_H7
    };
    memcpy_s(digest, size, final_hash_value, sizeof(final_hash_value));
}

void sha224_init(sha256_state* state) {
    auto& [hash_value, buffer, total, usage] = *state;
    hash_value[0] = {
        .m128i_u32 = {
            0x68581511, // H5
            0xffc00b31, // H4
            0x367cd507, // H1
            0xc1059ed8, // H0
        }
    };
    hash_value[1] = {
        .m128i_u32 = {
            0xbefa4fa4, // H7
            0x64f98fa7, // H6
            0xf70e5939, // H3
            0x3070dd17, // H2
        }
    };
    total = 0;
    usage = 0;
}

void sha224_finalize(sha256_state* state, void* digest, rsize_t size) {
    uint32_t final_hash_value[8];
    sha256_finalize(state, final_hash_value, sizeof(final_hash_value));
    memcpy_s(digest, size, final_hash_value, sizeof(uint32_t) * 7);
}
