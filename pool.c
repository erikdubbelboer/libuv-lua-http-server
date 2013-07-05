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

#include <stdbool.h>
#include <assert.h>

#include "tree.h"

#include "pool.h"


struct pool_entry_s {
  RB_ENTRY(pool_entry_s) entry;

  void* ptr;

  /* Free callback for externally allocated memory. */
  pool_free_cb free_cb;
};

static int compare_pool_entries(const pool_entry_t* a, const pool_entry_t* b);

RB_GENERATE_STATIC(pool_s, pool_entry_s, entry, compare_pool_entries)


static int compare_pool_entries(const pool_entry_t* a, const pool_entry_t* b) {
  if (a->ptr == b->ptr) {
    return 1;
  }

  return (a->ptr < b->ptr) ? -1 : 1;
}


void pool_init(pool_t* pool) {
  RB_INIT(pool);
}


/**
 * Free all memory belonging to this pool.
 */
void pool_reset(pool_t* pool) {
  for (pool_entry_t* entry = RB_MIN(pool_s, pool); entry != 0;) {
    pool_entry_t* next = RB_NEXT(pool_s, pool, entry);

    if (entry->free_cb) {
      entry->free_cb(entry->ptr);
      free(entry);
    } else {
      /* This will also free the entry seeing as it is appened to ptr. */
      free(entry->ptr);
    }

    entry = next;
  }
}


/**
 * Allocates a block size bytes of memory.
 */
void* pool_malloc(pool_t* pool, size_t size) {
  void* ptr = malloc(size + sizeof(pool_entry_t));

  if (!ptr) {
    return 0;
  }

  pool_entry_t* entry = (pool_entry_t*)((char*)ptr + size);
  entry->ptr          = ptr;
  entry->free_cb      = 0;

  RB_INSERT(pool_s, pool, entry);

  return ptr;
}


/**
 * Allocates a block size bytes of memory, and initializes all
 * its bits to zero.
 */
void* pool_calloc(pool_t* pool, size_t size) {
  void* ptr = calloc(1, size + sizeof(pool_entry_t));

  if (!ptr) {
    return 0;
  }

  pool_entry_t* entry = (pool_entry_t*)((char*)ptr + size);
  entry->ptr          = ptr;

  RB_INSERT(pool_s, pool, entry);

  return ptr;
}


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
void* pool_realloc(pool_t* pool, void* ptr, size_t size) {
  pool_entry_t* entry = 0;

  if (ptr) {
    pool_entry_t  f;
    f.ptr = ptr;
    entry = RB_REMOVE(pool_s, pool, &f);

    if (!entry) {
      return 0;
    }

    /* If the entry has a free callback it means it was allocated
     * externally. We can't resize these allocations.
     */
    assert(!entry->free_cb);
    if (entry->free_cb) {
      return 0;
    }
  }

  ptr = realloc(ptr, size + sizeof(pool_entry_t));

  if (!ptr) {
    /* realloc() doesn't modify the memory pointed to by ptr
     * when it fails. So we do the same.
     */
    if (entry) {
      RB_INSERT(pool_s, pool, entry);
    }

    return 0;
  }

  entry          = (pool_entry_t*)((char*)ptr + size);
  entry->ptr     = ptr;
  entry->free_cb = 0;

  RB_INSERT(pool_s, pool, entry);
  
  return ptr;
}


/**
 * Free memory belonging to a pool.
 * When this is externally allocated memory the free callback
 * provided to pool_add() will be called.
 *
 * Return true on success, false when the memory pointed to be ptr
 * was not part of the pool.
 */
bool pool_free(pool_t* pool, void* ptr) {
  assert(ptr);
  if (!ptr) {
    return false;
  }

  pool_entry_t  f;
  f.ptr               = ptr;
  pool_entry_t* entry = RB_FIND(pool_s, pool, &f);

  if (!entry) {
    return false;
  }

  RB_REMOVE(pool_s, pool, entry);

  if (entry->free_cb) {
    entry->free_cb(ptr);
    free(entry);
  } else {
    /* This will also free the entry seeing as it is appened to ptr. */
    free(entry->ptr);
  }

  return true;
}


/**
 * Remove the memory pointed to by ptr from the pool. This will prevent
 * the memory from being freed when the pool is reset.
 *
 * After removing, ptr can be freed using the normal free() call.
 *
 * Return true on success, false when the memory pointed to be ptr
 * was not part of the pool.
 */
bool pool_remove(pool_t* pool, void* ptr) {
  assert(ptr);
  if (!ptr) {
    return false;
  }

  pool_entry_t  f;
  f.ptr               = ptr;
  pool_entry_t* entry = RB_REMOVE(pool_s, pool, &f);

  if (!entry) {
    return false;
  }

  /* If the memory was allocated externally we can free
   * the entry structure.
   */
  if (entry->free_cb) {
    free(entry);
  }

  return true;
}


/**
 * Add externally allocated memory to the pool.
 */
void pool_add(pool_t* pool, void* ptr, pool_free_cb free_cb) {
  assert(ptr);
  if (!ptr) {
    return;
  }

  pool_entry_t* entry = (pool_entry_t*)malloc(sizeof(pool_entry_t));
  entry->ptr          = ptr;
  entry->free_cb      = free_cb;

  if (RB_INSERT(pool_s, pool, entry) != 0) {
    /* The memory was already added to the pool. */
    free(entry);
  }
}

