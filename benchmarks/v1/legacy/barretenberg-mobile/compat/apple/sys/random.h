#pragma once

#include <stddef.h>
#include <stdlib.h>

/*
 * Barretenberg v0.87 includes Linux's <sys/random.h> unconditionally and uses
 * getentropy on __APPLE__. The iOS SDK exposes neither that header nor the
 * libc declaration. arc4random_buf is the platform CSPRNG, has no failure
 * mode, and accepts the same output buffer contract.
 */
static inline int getentropy(void* buffer, size_t length)
{
    arc4random_buf(buffer, length);
    return 0;
}
