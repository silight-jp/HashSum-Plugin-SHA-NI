#pragma once

#include <stddef.h>

template<rsize_t i, rsize_t n, typename F>
__forceinline void inline_loop(const F& f) {
    if constexpr (i < n) {
        f(i);
        inline_loop<i + 1, n>(f);
    }
}
