/*****************************************************************************
 * hash.c
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

#include <config.h>
#include "hash.h"
#include "log.h"

#define HASH_INITIAL_BITS        7
#define HASH_SIZE(x)             (1 << (x))
#define HASH_MASK(x)             ((unsigned long) (~(~0l << (x))))
#define HASH_INDEX(x,y)          (sdbm(x) & HASH_MASK(y))

/* sdbm
 *
 *   this algorithm was created for sdbm (a public-domain reimplementation of
 *   ndbm) database library. it was found to do well in scrambling bits,
 *   causing better distribution of the keys and fewer splits. it also happens
 *   to be a good general hashing function with good distribution. the actual
 *   function is hash(i) = hash(i - 1) * 65599 + str[i]; what is included below
 *   is the faster version used in gawk. [there is even a faster, duff-device
 *   version] the magic constant 65599 was picked out of thin air while
 *   experimenting with different constants, and turns out to be a prime. this
 *   is one of the algorithms used in berkeley db (see sleepycat) and
 *   elsewhere.
 *
 *     (source: http://www.cs.yorku.ca/~oz/hash.html)
 */

static unsigned long sdbm(char *str)
{
  unsigned long hash = 0;
  int c;

  while((c = *((unsigned char *) str++)) != '\0')
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

static int hash_make_space(HASH *h, int n)
{
  HASH_NODE *l, *hn, *next;
  int i;
  unsigned long hv;

  if(!h->htable)
  {
    if((h->htable = calloc(HASH_SIZE(HASH_INITIAL_BITS), sizeof(HASH_NODE *))) == NULL)
      FAT("No memory for a hash table of %d entries.", HASH_SIZE(HASH_INITIAL_BITS));
    h->bits = HASH_INITIAL_BITS;
  } else {
    if((n >> 1) > HASH_SIZE(h->bits))
    {
      DBG("Extending hash to %d bits.", h->bits+1);
      /* put all nodes in one list */
      l = NULL;
      for(i = 0; i < HASH_SIZE(h->bits); i++)
        for(hn = h->htable[i]; hn; hn = next)
        {
          next = hn->next;
          hn->next = l;
          l = hn;
        }
      /* extend hash table */
      h->bits++;
      if((h->htable = realloc(h->htable, HASH_SIZE(h->bits) * sizeof(HASH_NODE *))) == NULL)
        FAT("No memory for a hash extend of %d entries.", HASH_SIZE(h->bits));
      memset(h->htable, 0, HASH_SIZE(h->bits) * sizeof(HASH_NODE *));
      /* insert entries */
      for(; l; l = next)
      {
        next = l->next;
        hv = HASH_INDEX(l->key, h->bits);
        l->next = h->htable[hv];
        h->htable[hv] = l;
      }
    }
  }

  return 0;
}

HASH_NODE *hash_node_new(char *key, void *value)
{
  HASH_NODE *hn;

  if((hn = calloc(1, sizeof(HASH_NODE))) == NULL
  || (hn->key = strdup(key)) == NULL)
  {
    if(hn)
      free(hn);
    FAT("Cannot alloc a new hash node.");
  }
  hn->entry = value;

  return hn;
}

HASH_NODE *hash_node_get(HASH *h, char *key)
{
  HASH_NODE *hn;

  if(!h->htable)
    return NULL;

  hn = h->htable[HASH_INDEX(key, h->bits)];
  while(hn && strcmp(hn->key, key))
    hn = hn->next;

  return hn;
}

static int __hash_entry_add(HASH *h, char *key, void *value)
{
  HASH_NODE *hn;
  unsigned long hv;

  if(hash_make_space(h, h->nentries + 1))
    FAT("Cannot make space on hash.");
  h->nentries++;

  /* build a new entry */
  hn = hash_node_new(key, value);

  /* insert node */
  hv = HASH_INDEX(key, h->bits);
  hn->next = h->htable[hv];
  h->htable[hv] = hn;

  return 0;
}

int hash_entry_add(HASH *h, char *key, void *value)
{
  /* if this entry exists return it directly! */
  if(hash_node_get(h, key) != NULL)
  {
    ERR("Entry '%s' already exists.", key);
    return -1;
  }

  /* make space (if needed) for a new entry */
  return __hash_entry_add(h, key, value);
}

int hash_entry_set(HASH *h, char *key, void *value, void **old)
{
  HASH_NODE *hn;

  /* if this entry does not exist return error */
  if((hn = hash_node_get(h, key)) == NULL)
  {
    ERR("Entry '%s' does not exist.", key);
    return -1;
  }

  /* set value */
  if(old)
    *old = hn->entry;
  hn->entry = value;

  return 0;
}

int hash_entry_add_or_set(HASH *h, char *key, void *value, void **old)
{
  HASH_NODE *hn;

  if((hn = hash_node_get(h, key)) != NULL)
  {
    /* node exists => set value */
    if(old)
      *old = hn->entry;
    hn->entry = value;
  } else {
    /* add node */
    if(old)
      *old = NULL;
    __hash_entry_add(h, key, value);
  }

  return 0;
}

void *hash_entry_get(HASH *h, char *key)
{
  HASH_NODE *hn = hash_node_get(h, key);
  
  return hn ? hn->entry : NULL;
}

void hash_remove_entry(HASH *h, char *key)
{
  HASH_NODE *e, *n;
  unsigned long hv;

  /* simple protection */
  if(!key || !h->htable)
    return;

  /* calculate entry hash index */
  hv = HASH_INDEX(key, h->bits);

  /* get hash entry */
  e = h->htable[hv];
  while(e && strcmp(e->key, key))
    e = e->next;

  /* remove from hash */
  h->nentries--;

  if(h->htable[hv] == e)
    h->htable[hv] = e->next;
  else
    for(n = h->htable[hv]; n != NULL; n = n->next)
      if(n->next == e)
      {
        n->next = e->next;
        break;
      }

  /* free node */
  free(e->key);
  free(e);
}

HASH *hash_new(void)
{
  HASH *h;

  if((h = calloc(1, sizeof(HASH))) == NULL)
    FAT("Cannot build a new hash.");

  return h;
}

void hash_destroy(HASH *h, void (*freefunc)(char *k, void *e, va_list fp), ...)
{
  HASH_NODE *n, *n2;
  int i;
  va_list fp;

  if(!h)
    return;

  va_start(fp, freefunc);
  if(h->htable)
  {
    for(i = 0; i < HASH_SIZE(h->bits); i++)
    {
      for(n = h->htable[i]; n; n = n2)
      {
        n2 = n->next;
        if(freefunc)
          freefunc(n->key, n->entry, fp);
        free(n->key);
        free(n);
      }
    }
    free(h->htable);
  }
  free(h);
  va_end(fp);
}

HASH *hash_copy(HASH *hi)
{
  HASH *ho;
  HASH_NODE **lp, *n;
  int i;

  if(!hi)
    return NULL;

  ho = hash_new();

  if(hi->htable)
  {
    ho->bits     = hi->bits;
    ho->nentries = hi->nentries;
    if((ho->htable = malloc(sizeof(HASH_NODE *) * HASH_SIZE(hi->bits))) == NULL)
      FAT("No mem for htable copy (%d entries).", HASH_SIZE(hi->bits));

    for(i = 0; i < HASH_SIZE(hi->bits); i++)
    {
      lp = &(ho->htable[i]);
      for(n = hi->htable[i]; n; n = n->next)
      {
        *lp = hash_node_new(n->key, n->entry);
        lp = &((*lp)->next);
      }
      *lp = NULL;
    }
  }

  return ho;
}

static void hash_merge__add(char *k, void *v, va_list ap)
{
  HASH *h;
  HASH_NODE *n;
  void *(*conflict_handler)(char *k, void *va, void *vb);
 
  h                = va_arg(ap, HASH *);
  conflict_handler = va_arg(ap, void *);
 
  if((n = hash_node_get(h, k)) != NULL)
    hash_entry_set(h, k, conflict_handler ? conflict_handler(k, v, n->entry) : v, NULL);
  else
    hash_entry_add(h, k, v);
}

HASH *hash_merge(HASH *hout, HASH *hin, void *(*conflict_handler)(char *k, void *va, void *vb))
{
  hash_entry_foreach(hin, hash_merge__add, hout, conflict_handler);

  return hout;
}

HASH *hash_join(HASH *h1, HASH *h2, void *(*conflict_handler)(char *k, void *va, void *vb))
{
  HASH *ho;

  ho = hash_copy(h1);
  return hash_merge(ho, h2, conflict_handler);
}

void hash_entry_foreach(HASH *h, void (*func)(char *k, void *e, va_list fp), ...)
{
  HASH_NODE *n;
  int i;
  va_list fp, tfp;

  if(!h || !h->htable)
    return;

  va_start(fp, func);
  for(i = 0; i < HASH_SIZE(h->bits); i++)
    if(h->htable[i])
      for(n = h->htable[i]; n; n = n->next)
      {
        va_copy(tfp, fp);
        func(n->key, n->entry, tfp);
        va_end(tfp);
      }
  va_end(fp);
}

static void hash_foreach_free_callback(char *k, void *e, va_list fp)
{
  free(e);
}

void hash_foreach_free(HASH *h)
{
  hash_entry_foreach(h, hash_foreach_free_callback, NULL);
}

static void hash_print_callback(char *k, void *e, va_list fp)
{
  HASH *h = va_arg(fp, HASH *);
  FILE *f = va_arg(fp, FILE *);
  fprintf(f, "  [%ld] '%s' = " STRF_PTR_X "\n", HASH_INDEX(k, h->bits), k, (INT_POINTER) e);
}

void hash_print(HASH *h, FILE *f)
{
  if(h && h->htable)
  {
    fprintf(f, "Hash contents:\n");
    hash_entry_foreach(h, hash_print_callback, h, f);
  } else
    fprintf(f, "Void hash table. No contents.\n");
}

int hash_iter_finished(HASH_ITER *i)
{
  return !i->h->htable || i->ci > HASH_SIZE(i->h->bits);
}

HASH_NODE *hash_iter_next(HASH_ITER *i)
{
  HASH_NODE *r;

  if(!i->h->htable)
    return NULL;

  while(i->ci <= HASH_SIZE(i->h->bits))
  {
    if(i->cn == NULL)
    {
      if(i->ci < HASH_SIZE(i->h->bits))
        i->cn = i->h->htable[i->ci];
      i->ci++;
    } else {
      r = i->cn;
      i->cn = i->cn->next;
      return r;
    }
  }

  return NULL;
}

void hash_iter_init(HASH_ITER *i, HASH *h)
{
  i->h = h;
  i->ci = 0;
  i->cn = NULL;
}

HASH_NODE *hash_iter_first(HASH_ITER *i, HASH *h)
{
  hash_iter_init(i, h);
  return hash_iter_next(i);
}

