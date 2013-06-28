//
// Copyright Erik Dubbelboer. and other contributors. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

#ifndef _LRU_H_
#define _LRU_H_


#include <string.h>  /* memset() */
#include <assert.h>  /* assert() */

#include "tree.h"


#if __GNUC__
#define LRU_UNUSED __attribute__((unused))
#else
#define LRU_UNUSED
#endif


#define LRU_INSERT(type, lru, entry) type##_lru_insert(lru, entry)
#define LRU_REMOVE(type, lru, entry) type##_lru_remove(lru, entry)
#define LRU_FIND(  type, lru, entry) type##_lru_find(  lru, entry)

#define LRU_HEAD(lru) (lru)->list

#define LRU_ENTRY(type) \
struct {                \
  RB_ENTRY(type) rb;    \
  struct type*   next;  \
  struct type*   prev;  \
}

#define LRU_TYPE(type) struct type##_lru

#define LRU_INIT(lru, size) (lru)->rbh_root = 0; (lru)->list = 0; (lru)->available = size


#define LRU_GENERATE(type, cmp, release, field) \
  LRU_GENERATE_INTERNAL(type, cmp, release, field, )

#define LRU_GENERATE_STATIC(type, cmp, release, field) \
  LRU_GENERATE_INTERNAL(type, cmp, release, field, LRU_UNUSED static)

#define LRU_GENERATE_INTERNAL(type, cmp, release, field, attr)   \
struct type##_lru {                                              \
  struct type* rbh_root;                                         \
  struct type* list;                                             \
  int          available;                                        \
};                                                               \
                                                                 \
/* Generate the red-black tree code. */                          \
RB_GENERATE_STATIC(type##_lru, type, field.rb, cmp)              \
                                                                 \
attr void type##_lru_evict(struct type##_lru* lru) {             \
  struct type* i = lru->list->field.prev;                        \
                                                                 \
  RB_REMOVE(type##_lru, lru, i);                                 \
                                                                 \
  if (i == lru->list) {                                          \
    lru->list = 0;                                               \
  } else {                                                       \
    i->field.next->field.prev = i->field.prev;                   \
    i->field.prev->field.next = i->field.next;                   \
  }                                                              \
                                                                 \
  release(i);                                                    \
                                                                 \
  ++lru->available;                                              \
}                                                                \
                                                                 \
attr void type##_lru_move_head(                                  \
  struct type##_lru* lru,                                        \
  struct type*       entry                                       \
) {                                                              \
  assert(entry);                                                 \
                                                                 \
  if (entry != lru->list) {                                      \
    if (entry != lru->list->field.prev) {                        \
      entry->field.next->field.prev = entry->field.prev;         \
      entry->field.prev->field.next = entry->field.next;         \
                                                                 \
      entry->field.prev = lru->list->field.prev;                 \
      entry->field.next = lru->list;                             \
                                                                 \
      entry->field.next->field.prev = entry;                     \
      entry->field.prev->field.next = entry;                     \
    }                                                            \
                                                                 \
    lru->list = entry;                                           \
  }                                                              \
}                                                                \
                                                                 \
attr struct type* type##_lru_find(                               \
  struct type##_lru* lru,                                        \
  struct type*       entry                                       \
) {                                                              \
  struct type* i = RB_FIND(type##_lru, lru, entry);              \
                                                                 \
  if (!i) {                                                      \
    return 0;                                                    \
  }                                                              \
                                                                 \
  type##_lru_move_head(lru, i);                                  \
                                                                 \
  return i;                                                      \
}                                                                \
                                                                 \
attr void type##_lru_insert(                                     \
  struct type##_lru* lru,                                        \
  struct type*       entry                                       \
) {                                                              \
  struct type* i = RB_FIND(type##_lru, lru, entry);              \
                                                                 \
  if (i) {                                                       \
    if (i == entry) {                                            \
      type##_lru_move_head(lru, i);                              \
      return;                                                    \
    }                                                            \
                                                                 \
    RB_REMOVE(type##_lru, lru, i);                               \
                                                                 \
    if (i == lru->list) {                                        \
      /* If this is the only item in the lru. */                 \
      if (lru->list->field.next == i) {                          \
        lru->list = 0;                                           \
      } else {                                                   \
        lru->list = lru->list->field.next;                       \
      }                                                          \
    }                                                            \
                                                                 \
    i->field.next->field.prev = i->field.prev;                   \
    i->field.prev->field.next = i->field.next;                   \
                                                                 \
    release(i);                                                  \
  } else {                                                       \
    if (lru->available-- == 0) {                                 \
      type##_lru_evict(lru);                                     \
    }                                                            \
  }                                                              \
  if (lru->list) {                                               \
    entry->field.prev                 = lru->list->field.prev;   \
    lru->list->field.prev->field.next = entry;                   \
    lru->list->field.prev             = entry;                   \
    entry->field.next                 = lru->list;               \
    lru->list                         = entry;                   \
  } else {                                                       \
    entry->field.next     = entry;                               \
    entry->field.prev     = entry;                               \
    lru->list = entry;                                           \
  }                                                              \
                                                                 \
  RB_INSERT(type##_lru, lru, entry);                             \
}                                                                \
                                                                 \
attr void type##_lru_remove(                                     \
  struct type##_lru* lru,                                        \
  struct type*       entry                                       \
) {                                                              \
  struct type* i = RB_FIND(type##_lru, lru, entry);              \
                                                                 \
  if (!i) {                                                      \
    return;                                                      \
  }                                                              \
                                                                 \
  RB_REMOVE(type##_lru, lru, i);                                 \
                                                                 \
  if (i == lru->list) {                                          \
    /* If this is the only item in the lru. */                   \
    if (lru->list->field.next == i) {                            \
      lru->list = 0;                                             \
    } else {                                                     \
      lru->list = lru->list->field.next;                         \
    }                                                            \
  }                                                              \
                                                                 \
  i->field.next->field.prev = i->field.prev;                     \
  i->field.prev->field.next = i->field.next;                     \
                                                                 \
  release(i);                                                    \
                                                                 \
  ++lru->available;                                              \
}


#endif /* _LRU_H_ */

