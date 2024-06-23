#include "sha1.h"
#include <bit>
#include <memory.h>
#include <immintrin.h>
#include "inline_loop.h"

static constexpr rsize_t BLOCK_SIZE = sha1_state::BLOCK_SIZE;

static __forceinline void sha1_compute(__m128i hash_value[2], const uint8_t* message, rsize_t blocks) {
    const __m128i REVERSE = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    const __m128i* messageBlocks = (const __m128i*)message;

    __m128i H0_H1_H2_H3 = _mm_loadu_si128(hash_value + 0);
    __m128i H4_0_0_0 = _mm_loadu_si128(hash_value + 1);

    for (rsize_t i = 0; i < blocks; i++) {
        // 1. Prepare the message schedule, {Wt}

        __m128i W_W_W_W[20];

        inline_loop<0, 20>([&](rsize_t t) {
            if (t < 4) {
                auto tmp1 = _mm_loadu_si128(messageBlocks++);
                W_W_W_W[t] = _mm_shuffle_epi8(tmp1, REVERSE);
            } else {
                auto tmp1 = _mm_sha1msg1_epu32(W_W_W_W[t - 4], W_W_W_W[t - 3]);
                auto tmp2 = _mm_xor_si128(tmp1, W_W_W_W[t - 2]);
                W_W_W_W[t] = _mm_sha1msg2_epu32(tmp2, W_W_W_W[t - 1]);
            }
        });

        // 2. Initialize the five working variables, a, b, c, d, and e, with the (i-1)st hash value

        __m128i a_b_c_d = H0_H1_H2_H3;
        __m128i e_0_0_0 = H4_0_0_0;

        // 3. For t=0 to 79

        __m128i prev_a_b_c_d;

        inline_loop<0, 20>([&](rsize_t t) {
            __m128i WE_W0_W0_W0;
            if (t == 0) {
                WE_W0_W0_W0 = _mm_add_epi32(e_0_0_0, W_W_W_W[t]);
            } else {
                // e_0_0_0 can be calculated from previous a_b_c_d
                WE_W0_W0_W0 = _mm_sha1nexte_epu32(prev_a_b_c_d, W_W_W_W[t]);
            }
            prev_a_b_c_d = a_b_c_d;
            if (t / 5 == 0) a_b_c_d = _mm_sha1rnds4_epu32(a_b_c_d, WE_W0_W0_W0, 0);
            if (t / 5 == 1) a_b_c_d = _mm_sha1rnds4_epu32(a_b_c_d, WE_W0_W0_W0, 1);
            if (t / 5 == 2) a_b_c_d = _mm_sha1rnds4_epu32(a_b_c_d, WE_W0_W0_W0, 2);
            if (t / 5 == 3) a_b_c_d = _mm_sha1rnds4_epu32(a_b_c_d, WE_W0_W0_W0, 3);
        });

        // 4. Compute the (i)th intermediate hash value H(i)

        H0_H1_H2_H3 = _mm_add_epi32(a_b_c_d, H0_H1_H2_H3);
        // e_0_0_0 can be calculated from previous a_b_c_d
        H4_0_0_0 = _mm_sha1nexte_epu32(prev_a_b_c_d, H4_0_0_0);
    }

    _mm_storeu_si128(hash_value + 0, H0_H1_H2_H3);
    _mm_storeu_si128(hash_value + 1, H4_0_0_0);
}

void sha1_init(sha1_state* state) {
    auto& [hash_value, buffer, total, usage] = *state;
    hash_value[0] = {
        .m128i_u32 = {
            0x10325476, // H3
            0x98badcfe, // H2
            0xefcdab89, // H1
            0x67452301, // H0
        }
    };
    hash_value[1] = {
        .m128i_u32 = {
            0, // 0
            0, // 0
            0, // 0
            0xc3d2e1f0, // H4
        }
    };
    total = 0;
    usage = 0;
}

void sha1_update(sha1_state* state, const uint8_t* message, rsize_t length) {
    auto& [hash_value, buffer, total, usage] = *state;

    total += length;

    if (usage + length >= BLOCK_SIZE) {
        if (usage > 0) {
            auto rem = BLOCK_SIZE - usage;
            memcpy_s(buffer + usage, rem, message, rem);
            sha1_compute(hash_value, buffer, 1);
            message += rem;
            length -= rem;
            usage = 0;
        }

        rsize_t count = length / BLOCK_SIZE;
        if (count > 0) {
            sha1_compute(hash_value, message, count);
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

void sha1_finalize(sha1_state* state, void* digest, rsize_t size) {
    auto& [hash_value, buffer, total, usage] = *state;

    buffer[usage++] = 0x80;

    if (usage + 8 > BLOCK_SIZE) {
        memset(buffer + usage, 0, BLOCK_SIZE - usage);
        sha1_compute(hash_value, buffer, 1);
        usage = 0;
    }

    memset(buffer + usage, 0, BLOCK_SIZE - usage - 8);
    uint64_t length = std::byteswap(total * 8);
    memcpy_s(buffer + BLOCK_SIZE - 8, 8, &length, sizeof(length));
    sha1_compute(hash_value, buffer, 1);
    usage = 0;

    uint64_t final_hash_value[3] = {
        std::byteswap(hash_value[0].m128i_u64[1]), // H1_H2
        std::byteswap(hash_value[0].m128i_u64[0]), // H3_H4
        std::byteswap(hash_value[1].m128i_u64[1]), // H5_0
    };
    memcpy_s(digest, size, final_hash_value, sizeof(uint32_t) * 5);
}
