/*****************************************************************************
 * pthreadex.h
 *
 * Thread management functions and structures.
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2009 Gerardo García Peña <gerardo@kung-foo.dhs.org>
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

#ifndef __THREADS_H__
#define __THREADS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* following enables flag `_GNU_SOURCE' when compiling, which directs the    */
/* libc header files to provide the standard GNU system interfaces including */
/* all GNU extensions. If this macro is not defined, certain GNU extensions  */
/* may not be available.                                                     */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef __USE_GNU
#define __USE_GNU 1
#endif

/* include pthread header */
#include <pthread.h>

typedef struct _tag_pthreadex_prot_int {
  pthread_mutex_t  mutex;
  int              value;
} pthreadex_prot_int;

typedef pthread_mutex_t                pthreadex_mutex_t;
#define PTHREADEX_MUTEX_INITIALIZER    PTHREAD_MUTEX_INITIALIZER

#define pthreadex_mutex_init(x)          pthread_mutex_init(x, NULL)
#define pthreadex_mutex_begin(x)         pthread_cleanup_push_defer_np(       \
                                           (void *) pthread_mutex_unlock, x); \
                                         pthread_mutex_lock(x)
#define pthreadex_mutex_end()            pthread_cleanup_pop_restore_np(1)
#define pthreadex_mutex_destroy(x)       pthread_mutex_destroy(x)

#define PTHREADEX_PROT_VAR_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }
#define pthreadex_prot_var_init(x)     { pthreadex_mutex_init(&((x).mutex));  \
                                         ((x).value) = 0;                     }
#define pthreadex_prot_var_begin(x)    pthreadex_mutex_begin(&((x).mutex))
#define pthreadex_prot_var_end()       pthreadex_mutex_end()
#define pthreadex_prot_var_get(x)      ((x).value)
#define pthreadex_prot_var_set(x,y)    { pthreadex_mutex_begin(&((x).mutex)); \
                                         ((x).value) = y;                     \
                                         pthreadex_mutex_end();               }
#define pthreadex_prot_var_dec(x)      { pthreadex_mutex_begin(&((x).mutex))  \
                                         ((x).value)--;                       \
                                         pthreadex_mutex_end();               }
#define pthreadex_prot_var_inc(x)      { pthreadex_mutex_begin(&((x).mutex)); \
                                         ((x).value)++;                       \
                                         pthreadex_mutex_end();               }
#define pthreadex_prot_var_destroy(x)  { pthreadex_mutex_destroy(&((x).mutex)); }

#define pthreadex_prot_gen(x,y)        struct pthreadex_protected_##y##_s {   \
                                         pthread_mutex_t  mutex;              \
                                         x                value;              \
                                       } pthreadex_protected_##y =            \
                                         PTHREADEX_PROT_VAR_INITIALIZER
#define pthreadex_prot_ref(x)          (pthreadex_protected_##x.value)
#define pthreadex_prot_begin(x)        pthreadex_mutex_begin(&(pthreadex_protected_##x))
#define pthreadex_prot_end()           pthreadex_mutex_end()

#define PTHREADEX_PROT_INT_INITIALIZER PTHREADEX_PROT_VAR_INITIALIZER
#define pthreadex_prot_int_init(x)     pthreadex_prot_var_init(x)
#define pthreadex_prot_int_get(x)      pthreadex_prot_var_get(x)
#define pthreadex_prot_int_set(x,y)    pthreadex_prot_var_set(x,y)
#define pthreadex_prot_int_dec(x)      pthreadex_prot_var_dec(x)
#define pthreadex_prot_int_inc(x)      pthreadex_prot_var_inc(x)
#define pthreadex_prot_int_destroy(x)  pthreadex_prot_var_destroy(x)

typedef struct _tag_pthreadex_barrier_t {
  int             NNodes;    /* number of threads participating in the barrier     */
  int             Count[2];  /* number of threads that have hit the barrier so far */
  int             EvenOdd;
  pthread_mutex_t Lock;
  pthread_cond_t  CV;
} pthreadex_barrier_t;
#define PTHREADEX_BARRIER_INITIALIZER(x)  { 0, { 0, 0 }, (x), PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }

typedef struct _tag_pthreadex_semaphore_t
{
  unsigned int    count;         /* Current count of the semaphore.          */
  unsigned int    waiters_count; /* Number of threads blocked                */
  pthread_mutex_t lock;          /* Serialize access to struct fields        */
  pthread_cond_t  count_nonzero; /* Cond variable that blocks the <count> 0  */
} pthreadex_semaphore_t;
#define PTHREADEX_SEMAPHORE_INITIALIZER  { 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }

typedef struct _tag_pthreadex_lock_t
{
  int             lock_count;    /* Current count of exclusive/shared locks. */
  pthread_mutex_t lock;          /* Serialize access to struct fields        */
  pthread_cond_t  lock_zero;     /* Cond variable that adverts of zero locks */
} pthreadex_lock_t;
#define PTHREADEX_LOCK_INITIALIZER  { 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }
#define PTHREADEX_LOCK_SHARED       0
#define PTHREADEX_LOCK_EXCLUSIVE    1

typedef struct timespec pthreadex_timer_t;

void pthreadex_barrier_init(pthreadex_barrier_t *barrier, int n);
void pthreadex_barrier_destroy(pthreadex_barrier_t *barrier);
void pthreadex_barrier_wait(pthreadex_barrier_t *barrier);

void pthreadex_semaphore_init(pthreadex_semaphore_t *sema, int initial_count);
void pthreadex_semaphore_destroy(pthreadex_semaphore_t *sema);
void pthreadex_semaphore_wait(pthreadex_semaphore_t *sema);
int  pthreadex_semaphore_post(pthreadex_semaphore_t *sema);
int  pthreadex_semaphore_set(pthreadex_semaphore_t *sema, int new_count);

void pthreadex_lock_init(pthreadex_lock_t *ex);
void pthreadex_lock_get_raw(pthreadex_lock_t *ex, int type);
void pthreadex_lock_release_raw(pthreadex_lock_t *ex);
void pthreadex_lock_fini(pthreadex_lock_t *ex);
#define pthreadex_lock_get(x,y)         pthread_cleanup_push_defer_np(             \
                                          (void *) pthreadex_lock_release_raw, x); \
                                        pthreadex_lock_get_raw(x,y)
#define pthreadex_lock_release()        pthread_cleanup_pop_restore_np(1)

#define pthreadex_lock_get_shared(x)    pthreadex_lock_get(x, PTHREADEX_LOCK_SHARED)
#define pthreadex_lock_get_exclusive(x) pthreadex_lock_get(x, PTHREADEX_LOCK_EXCLUSIVE)

void   pthreadex_timer_init(pthreadex_timer_t *t, double secs);
void   pthreadex_timer_set(pthreadex_timer_t *t, double secs);
void   pthreadex_timer_set_frequency(pthreadex_timer_t *t, double tps);
double pthreadex_timer_get(pthreadex_timer_t *t);
int    pthreadex_timer_wait(pthreadex_timer_t *t);
void   pthreadex_timer_destroy(pthreadex_timer_t *t);

/*****************************************************************************
 * FLAGS
 *
 *   A flag allows to awake only one thread -pthreadex_flag_up()- from all
 *   threads waiting at one point -pthreadex_flag_wait()-.
 *
 * pthreadex_flag_init(flag, initial_state)
 *   Initializes 'flag' with initial state 'initial_state', where
 *   'initial_state' can take values 0 flag down (so any thread will be
 *   blocked), or 1 that means the first thread that arrives to flag will pass.
 * pthreadex_flag_destroy(flag)
 *   Destro the flag freeing memory.
 * pthreadex_flag_wait(flag)
 *   Wait until flag is up -see pthreadex_flag_up()-
 * pthreadex_flag_up(flag)
 *   Allow one thread to pass.
 *
 *****************************************************************************/

typedef struct _tag_pthreadex_flag_t
{
  unsigned int    state;         /* Current flag state (0 = down, 1 = up)    */
  unsigned int    waiters_count; /* Number of threads blocked                */
  pthread_mutex_t lock;          /* Serialize access to struct fields        */
  pthread_cond_t  flag_up;       /* Cond variable that blocks the <state> 0  */
} pthreadex_flag_t;
#define PTHREADEX_FLAG_INITIALIZER  { 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }

void pthreadex_flag_init(pthreadex_flag_t *flag, int initial_state);
void pthreadex_flag_destroy(pthreadex_flag_t *flag);
void pthreadex_flag_wait(pthreadex_flag_t *flag);
int  pthreadex_flag_up(pthreadex_flag_t *flag);

/* signal callback */
int (*pthreadex_set_signal_callback(int (*f)(void)))(void);

#ifdef __cplusplus
}
#endif

#endif
