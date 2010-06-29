/*****************************************************************************
 * pthreadex.h
 *
 * Thread management functions and structures.
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2009 Gerardo García Peña <gerardo@kung-foo.net>
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

#ifndef __PTHREADEX_H__
#define __PTHREADEX_H__

#ifdef __cplusplus
extern "C" {
#endif

/* -- include pthread header -- */
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
#include <pthread.h>

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + DEBUG FACILITY
  +
  +  If you want to debug your pthreads program (i.e. a deadlock) you can
  +  enable the PTHREADEX_DEBUG flag.
  +
  +  Once enabled, pthreadex li will report all lock/unlock operation to
  +  ease the debuging of parallel programs.
  +
  +  The results will be printed with DBG and FAT macros (fprintf by default),
  +  but you can redefine them to whatever you want.
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/* #define PTHREADEX_DEBUG 1 */

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + DEBUG MACROS
 + 
 +   Enabled automatically if not exists a macro before with name FAT or DBG.
 +   Both functions take same parameters as printf(3).
 +
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#if ((!defined FAT) || (!defined DBG))
#  define PTHREADEX_LOG(l, ...) { fputs("pthreadex:" l ":", stderr); \
                                  fprintf(stderr, __VA_ARGS__); }
#  ifndef FAT
#    define FAT(...) { PTHREADEX_LOG("fatal", __VA_ARGS__); exit(1); }
#  endif
#  ifndef DBG
#  define DBG(...) { PTHREADEX_LOG("debug", __VA_ARGS__); }
#  endif
#endif

#if PTHREADEX_DEBUG
#  define __X_FAT(m, f, ...)   FAT("%s: " f, (m)->n,  __VA_ARGS__)
#else
#  define __X_FAT(m, f, ...)   FAT(f, __VA_ARGS__)
#endif

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + MUTEX
 +   On steroids mutex with debugging option. Easier to use than standard
 +   pthread_mutex_t.
 +
 +   We recommend to assign a name in every mutex in your program (using
 +   PTHREADEX_MUTEX_INIT_NAMED() macro or pthreadex_mutex_name() function) to
 +   assign a name to your mutex. In case of problems you'll only need to
 +   debug with PTHREADEX_DEBUG flag enabled.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

typedef struct _tag_pthreadex_mutex_t {
  pthread_mutex_t  m;
#if PTHREADEX_DEBUG
  char            *n;
#endif
} pthreadex_mutex_t;

#define __PTHREADEX_MUTEX_STRUCT_INIT    PTHREAD_MUTEX_INITIALIZER
#if PTHREADEX_DEBUG
#define PTHREADEX_MUTEX_INIT_NAMED(x,n)  { __PTHREADEX_MUTEX_STRUCT_INIT(x), n }
#else
#define PTHREADEX_MUTEX_INIT_NAMED(x,n)  { __PTHREADEX_MUTEX_STRUCT_INIT(x) }
#endif
#define PTHREADEX_MUTEX_INITIALIZER(x)   PTHREADEX_MUTEX_INIT_NAMED(x, "$unnamed:mutex$")

#if PTHREADEX_DEBUG
#define __x_pthreadex_munlock            pthreadex_debug_mutex_unlock
#define __x_pthreadex_mutex_get(x)       &((x)->m)
#else
#define __x_pthreadex_munlock            ((void (*)(void *)) pthread_mutex_unlock)
#define __x_pthreadex_mutex_get(x)       ((pthread_mutex_t *) (x))
#endif
#define __x_pthreadex_mutex_begin(x)     pthread_cleanup_push_defer_np(                          \
                                           __x_pthreadex_munlock,                                \
                                           __x_pthreadex_mutex_get(x));                          \
                                         {                                                       \
                                         int __pthreadex_err_ret =                               \
                                           pthread_mutex_lock(__x_pthreadex_mutex_get(x));       \
                                         if(__pthreadex_err_ret != 0)                            \
                                           __X_FAT((x), "mutex lock error (%d)", __pthreadex_err_ret); \
                                         }
#define __x_pthreadex_mutex_init(x)      pthread_mutex_init(__x_pthreadex_mutex_get(x), NULL);
#if PTHREADEX_DEBUG
#define pthreadex_mutex_name(x,y)        ((x)->n = (y))
#define pthreadex_mutex_begin(x)         DBG("Mutex %s: Entering...", (x)->n);               \
                                         __x_pthreadex_mutex_begin(x);                           \
                                         DBG("Mutex %s: In mutual exclusion zone.", (x)->n);
#define pthreadex_mutex_init(x)          { __x_pthreadex_mutex_init(x); (x)->n = "$unnamed:mutex$"; }
#define pthreadex_mutex_destroy(x)       { DBG("Mutex %s: DESTROY", (x)->n);                  \
                                           pthread_mutex_destroy(__x_pthreadex_mutex_get(x)); }
#else
#define pthreadex_mutex_name(x,y)
#define pthreadex_mutex_begin(x)         __x_pthreadex_mutex_begin(x);
#define pthreadex_mutex_init(x)          { __x_pthreadex_mutex_init(x); }
#define pthreadex_mutex_destroy(x)       { pthread_mutex_destroy(__x_pthreadex_mutex_get(x)); }
#endif
#define pthreadex_mutex_end()            pthread_cleanup_pop_restore_np(1);

#if PTHREADEX_DEBUG
void pthreadex_debug_mutex_unlock(void *d);
#endif

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + EXCLUSIVE/SHARED LOCK
 +   The classical exclusive vs shared lock.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

typedef struct _tag_pthreadex_lock_t
{
  int             lock_count;    /* Current count of exclusive/shared locks. */
  pthread_mutex_t lock;          /* Serialize access to struct fields        */
  pthread_cond_t  lock_zero;     /* Cond variable that adverts of zero locks */
#if PTHREADEX_DEBUG
  char            *n;
#endif
} pthreadex_lock_t;

#define PTHREADEX_LOCK_SHARED        0
#define PTHREADEX_LOCK_EXCLUSIVE     1

#define __PTHREADEX_LOCK_STRUCT_INIT 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER
#if PTHREADEX_DEBUG
#define PTHREADEX_LOCK_INIT_NAMED(n) { __PTHREADEX_LOCK_STRUCT_INIT, n }
#define pthreadex_lock_name(x,y)     ((x)->n = (y))
#else
#define PTHREADEX_LOCK_INIT_NAMED(n) { __PTHREADEX_LOCK_STRUCT_INIT }
#define pthreadex_lock_name(x,y)
#endif
#define PTHREADEX_LOCK_INITIALIZER   PTHREADEX_LOCK_INIT_NAMED("$unnamed:lock$")

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

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + PROTECTED VAR
 +   Macros to protect a var of concurrent access.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#define PTHREADEX_PROT_VAR_TYPE(t)       struct {                                 \
                                           pthreadex_mutex_t  mutex;              \
                                           t                  value;              \
                                         }
#define PTHREADEX_PROT_VAR_INIT_NAMED(n) { PTHREAD_MUTEX_INITIALIZER_NAMED(n) }
#define PTHREADEX_PROT_VAR_INITIALIZER   PTHREADEX_PROT_VAR_INIT_NAMED("$unnamed:protvar$")

#define pthreadex_prot_var_init(x)       { pthreadex_mutex_init(&((x)->mutex)); }
#define pthreadex_prot_var_begin(x)      pthreadex_mutex_begin(&((x)->mutex))
#define pthreadex_prot_var_end()         pthreadex_mutex_end()
#define pthreadex_prot_var_get(x)        ((x)->value)
#define pthreadex_prot_var_get_ptr(x)    &((x)->value)
#define pthreadex_prot_var_set(x,y)      { pthreadex_mutex_begin(&((x)->mutex));   \
                                           (x)->value = y;                         \
                                           pthreadex_mutex_end();                  }
#define pthreadex_prot_var_destroy(x)    { pthreadex_mutex_destroy(&((x)->mutex)); }

#define PTHREADEX_PROT_INT               PTHREADEX_PROT_VAR_TYPE(int)
#define PTHREADEX_PROT_INT_INITIALIZER   PTHREADEX_PROT_VAR_INITIALIZER
#define pthreadex_prot_int_init(x)       pthreadex_prot_var_init(x)
#define pthreadex_prot_int_get(x)        pthreadex_prot_var_get(x)
#define pthreadex_prot_int_set(x,y)      pthreadex_prot_var_set(x,y)
#define pthreadex_prot_int_dec(x)        { pthreadex_mutex_begin(&((x)->mutex))    \
                                           (x)->value--;                           \
                                           pthreadex_mutex_end();                  }
#define pthreadex_prot_int_inc(x)        { pthreadex_mutex_begin(&((x)->mutex));   \
                                           (x)->value++;                           \
                                           pthreadex_mutex_end();                  }
#define pthreadex_prot_int_destroy(x)  pthreadex_prot_var_destroy(x)


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + BARRIER
 +   Classic barrier implementation.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

typedef struct _tag_pthreadex_barrier_t {
  int             NNodes;    /* number of threads participating in the barrier     */
  int             Count[2];  /* number of threads that have hit the barrier so far */
  int             EvenOdd;
  pthread_mutex_t Lock;
  pthread_cond_t  CV;
#if PTHREADEX_DEBUG
  char           *n;
#endif
} pthreadex_barrier_t;

#define __PTHREADEX_BARRIER_STRUCT_INIT(x) 0, { 0, 0 }, (x), PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER
#if PTHREADEX_DEBUG
#define PTHREADEX_BARRIER_INIT_NAMED(x,n)  { __PTHREADEX_BARRIER_STRUCT_INIT(x), n }
#else
#define PTHREADEX_BARRIER_INIT_NAMED(x,n)  { __PTHREADEX_BARRIER_STRUCT_INIT(x) }
#endif
#define PTHREADEX_BARRIER_INITIALIZER(x)   PTHREADEX_BARRIER_INIT_NAMED(x, "$unnamed:barrier$")

void pthreadex_barrier_init(pthreadex_barrier_t *barrier, int n);
void pthreadex_barrier_destroy(pthreadex_barrier_t *barrier);
void pthreadex_barrier_wait(pthreadex_barrier_t *barrier);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + SEMAPHORE
 +   Classic barrier implementation.
 +
 + TODO: Add debug facilities
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

typedef struct _tag_pthreadex_semaphore_t
{
  unsigned int    count;         /* Current count of the semaphore.          */
  unsigned int    waiters_count; /* Number of threads blocked                */
  pthread_mutex_t lock;          /* Serialize access to struct fields        */
  pthread_cond_t  count_nonzero; /* Cond variable that blocks the <count> 0  */
#if PTHREADEX_DEBUG
  char           *n;
#endif
} pthreadex_semaphore_t;

#define __PTHREADEX_SEMAPHORE_STRUCT_INIT 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER
#if PTHREADEX_DEBUG
#define PTHREADEX_SEMAPHORE_INIT_NAMED(n) { __PTHREADEX_SEMAPHORE_STRUCT_INIT, n }
#else
#define PTHREADEX_SEMAPHORE_INIT_NAMED(n) { __PTHREADEX_SEMAPHORE_STRUCT_INIT }
#endif
#define PTHREADEX_SEMAPHORE_INITIALIZER   PTHREADEX_SEMAPHORE_INIT_NAMED("$unnamed:semaphore$")

void pthreadex_semaphore_init(pthreadex_semaphore_t *sema, int initial_count);
void pthreadex_semaphore_destroy(pthreadex_semaphore_t *sema);
void pthreadex_semaphore_wait(pthreadex_semaphore_t *sema);
int  pthreadex_semaphore_post(pthreadex_semaphore_t *sema);
int  pthreadex_semaphore_set(pthreadex_semaphore_t *sema, int new_count);

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
#if PTHREADEX_DEBUG
  char           *n;
#endif
} pthreadex_flag_t;
#define __PTHREADEX_FLAG_STRUCT_INIT 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER
#if PTHREADEX_DEBUG
#define pthreadex_flag_name(x,y)     ((x)->n = (y))
#define PTHREADEX_FLAG_INIT_NAMED(n) { __PTHREADEX_FLAG_STRUCT_INIT, n }
#else
#define pthreadex_flag_name(x,y)
#define PTHREADEX_FLAG_INIT_NAMED(n) { __PTHREADEX_FLAG_STRUCT_INIT }
#endif
#define PTHREADEX_FLAG_INITIALIZER   PTHREADEX_FLAG_INIT_NAMED("$unnamed:flag$")

void pthreadex_flag_init(pthreadex_flag_t *flag, int initial_state);
void pthreadex_flag_destroy(pthreadex_flag_t *flag);
int  pthreadex_flag_wait(pthreadex_flag_t *flag);
int  pthreadex_flag_wait_timeout(pthreadex_flag_t *flag, long long tout);
int  pthreadex_flag_up(pthreadex_flag_t *flag);

/* signal callback */
int (*pthreadex_set_signal_callback(int (*f)(void)))(void);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + TIMER
 +   A timer.. a simply and silly timer. Without portability issues.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

typedef struct _tag_pthreadex_timer_t
{
  struct timespec t;
#if PTHREADEX_DEBUG
  char           *n;
#endif
} pthreadex_timer_t;

#define __PTHREADEX_TIMER_STRUCT_INIT { 0, 0 }
#if PTHREADEX_DEBUG
#define pthreadex_timer_name(x,y)     ((x)->n = (y))
#define PTHREADEX_TIMER_INIT_NAMED(n) { __PTHREADEX_TIMER_STRUCT_INIT, n }
#else
#define pthreadex_timer_name(x,y)
#define PTHREADEX_TIMER_INIT_NAMED(n) { __PTHREADEX_TIMER_STRUCT_INIT }
#endif
#define PTHREADEX_TIMER_INITIALIZER   PTHREADEX_TIMER_INIT_NAMED("$unnamed:timer$")

void   pthreadex_timer_init(pthreadex_timer_t *t, double secs);
void   pthreadex_timer_set(pthreadex_timer_t *t, double secs);
void   pthreadex_timer_set_frequency(pthreadex_timer_t *t, double tps);
double pthreadex_timer_get(pthreadex_timer_t *t);
int    pthreadex_timer_wait(pthreadex_timer_t *t);
void   pthreadex_timer_destroy(pthreadex_timer_t *t);

double pthreadex_time_get(void);

#ifdef __cplusplus
}
#endif

#endif
