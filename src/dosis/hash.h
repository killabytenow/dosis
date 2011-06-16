/*****************************************************************************
 * hash.h
 *
 * Hash tables.
 *
 * ---------------------------------------------------------------------------
 * DioNiSio - DNS scanner
 *   (C) 2006-2008 Gerardo García Peña
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the Free
 *   Software Foundation; either version 2 of the License, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful, but WITHOUT
 *   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *   more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc., 51
 *   Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *****************************************************************************/

#ifndef __HASH_H__
#define __HASH_H__

typedef struct _tag_HASH_NODE {
  char                  *key;
  void                  *entry;
  struct _tag_HASH_NODE *next;
} HASH_NODE;

typedef struct _tag_HASH {
  int         nentries;
  int         bits;
  HASH_NODE   **htable;
} HASH;

HASH_NODE *hash_node_get(HASH *h, char *key);
HASH_NODE *hash_node_new(char *key, void *value);

#define hash_key_exists(h, k)   (hash_node_get(h, k) != (void *) 0)

int   hash_entry_add(HASH *h, char *key, void *value);
int   hash_entry_set(HASH *h, char *key, void *value);
void *hash_entry_add_or_set(HASH *h, char *key, void *value);
void  hash_entry_remove(HASH *h, char *key);
void *hash_entry_get(HASH *h, char *key);
HASH *hash_new(void);
void  hash_destroy(HASH *h, void (*freefunc)(char *k, void *e, va_list fp), ...);
HASH *hash_copy(HASH *h);
HASH *hash_join(HASH *h1, HASH *h2, void *(*conflict_handler)(char *k, void *va, void *vb));
HASH *hash_merge(HASH *hout, HASH *hin, void *(*conflict_handler)(char *k, void *va, void *vb));

void hash_print(HASH *h, FILE *f);
void  hash_entry_foreach(HASH *h, void (*func)(char *k, void *e, va_list fp), ...);
void  hash_entry_foreach_free(HASH *h);

typedef struct _tag_HASH_ITER {
  HASH        *h;
  int         ci;
  HASH_NODE   *cn;
} HASH_ITER;

void       hash_iter_init(HASH_ITER *i, HASH *h);
HASH_NODE *hash_iter_first(HASH_ITER *i, HASH *h);
HASH_NODE *hash_iter_next(HASH_ITER *i);
int        hash_iter_finished(HASH_ITER *i);

#endif
