/*
 * Copyright Erik Dubbelboer. and other contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _POOL_H_
#define _POOL_H_


#include <stdbool.h>  /* bool   */
#include <stdlib.h>   /* size_t */


#if __GNUC_MINOR__ >= 4
#define _NO_UNUSED_ __attribute__((warn_unused_result))
#endif


typedef struct pool_entry_s pool_entry_t;

typedef struct pool_s {
  pool_entry_t* rbh_root;
} pool_t;

typedef void (*pool_free_cb)(void* ptr);


void pool_init(pool_t* pool);

/**
 * Free all memory belonging to this pool.
 */
void pool_reset(pool_t* pool);

/**
 * Allocates a block size bytes of memory.
 */
void* _NO_UNUSED_ pool_malloc(pool_t* pool, size_t size);

/**
 * Allocates a block size bytes of memory, and initializes all
 * its bits to zero.
 */
void* _NO_UNUSED_ pool_calloc(pool_t* pool, size_t size);

/**
 * Changes the size of the memory block pointed to by ptr.
 *
 * Return a new pointer on success, or a null-pointer when
 * the memory pointed to be ptr was not part of the pool or
 * when realloc() failed.
 * It is not possible to realloc memory added by pool_add(). Doing
 * this will throw an assertion in debug mode. In release mode it
 * will remove the memory from the pool and return a null-pointer.
 */
void* _NO_UNUSED_ pool_realloc(pool_t* pool, void* ptr, size_t size);

/**
 * Free memory belonging to a pool.
 * When this is externally allocated memory the free callback
 * provided to pool_add() will be called.
 *
 * Return true on success, false when the memory pointed to be ptr
 * was not part of the pool.
 */
bool pool_free(pool_t* pool, void* ptr);

/**
 * Remove the memory pointed to by ptr from the pool. This will prevent
 * the memory from being freed when the pool is reset.
 *
 * After removing ptr can be freed using the normal free() call.
 *
 * Return true on success, false when the memory pointed to be ptr
 * was not part of the pool.
 */
bool pool_remove(pool_t* pool, void* ptr);

/**
 * Add externally allocated memory to the pool.
 */
void pool_add(pool_t* pool, void* ptr, pool_free_cb free_cb);


#undef _NO_UNUSED_


#endif /* _POOL_H_ */

