//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#ifndef MURMURHASH3_H
#define MURMURHASH3_H

//-----------------------------------------------------------------------------
// Platform-specific functions and macros
#ifdef __Nautilus__
#include <nautilus/naut_types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

//-----------------------------------------------------------------------------

uint32_t MurmurHash3_x86_32(const void *key, size_t length);

//-----------------------------------------------------------------------------

#endif // MURMURHASH3_H
