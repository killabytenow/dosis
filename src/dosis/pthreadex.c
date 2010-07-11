/*****************************************************************************
 * pthreadex.c
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

#include <config.h>
#include "pthreadex.h"

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + MUTEX
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#if PTHREADEX_DEBUG
void pthreadex_debug_mutex_unlock(void *d)
{
  PTHREADEX_DBG("Mutex %s: Going out...", ((pthreadex_mutex_t *) d)->n);
  pthread_mutex_unlock(&(((pthreadex_mutex_t *) d)->m));
}
#endif

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + SIGNAL CALLBACK
  + 
  +   When a signal is received this callback is executed. If it returns 0,
  +   signal is ignored, elsewhere function is interrupted.
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int (*pthreadex_signal_callback)(void) = NULL;

int (*pthreadex_set_signal_callback(int (*f)(void)))(void)
{
  int (*o)(void) = pthreadex_signal_callback;
  pthreadex_signal_callback = f;
  return o;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + SIGNAL RESISTANT HIGH PRECISION DELAYS
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

void pthreadex_timer_set(pthreadex_timer_t *t, double secs)
{
  t->t.tv_sec  = floor(secs);
  t->t.tv_nsec = (secs - floor(secs)) * 1000000000.0;
}

void pthreadex_timer_set_frequency(pthreadex_timer_t *t, double tps)
{
  pthreadex_timer_set(t, 1 / tps);
}

void pthreadex_timer_init(pthreadex_timer_t *t, double secs)
{
  pthreadex_timer_set(t, secs);
#if PTHREADEX_TIMER_NANOSLEEP
  pthread_mutex_init(&(flag->lock), NULL);
  pthread_cond_init(&(flag->flag_up), NULL);
#endif
}

double pthreadex_timer_get(pthreadex_timer_t *t)
{
  return ((double) t->t.tv_sec) + (((double) t->t.tv_nsec) / 1000000000.0);
}

void pthreadex_timer_destroy(pthreadex_timer_t *t)
{
  PTHREADEX_DBG("Timer %s: DESTROY", t->n);
  pthreadex_timer_set(t, 0.0);
#if PTHREADEX_TIMER_NANOSLEEP
  pthread_mutex_destroy(&flag->lock);
  pthread_cond_destroy(&flag->cond);
#endif
}

int pthreadex_timer_wait(pthreadex_timer_t *t)
{
#if PTHREADEX_TIMER_NANOSLEEP
  struct timespec r, *c;

  if(t->t.tv_nsec || t->t.tv_sec)
  {
    c = &(t->t);
    while(nanosleep(c, &r) < 0)
    {
      if(errno != EINTR)
        return -1;
      if(pthreadex_signal_callback
      && pthreadex_signal_callback())
        return 0;
      c = &r;
    }
  }
#else
  int e;
  struct timespec tt;

  /* get current time & add timeout */
  if(clock_gettime(CLOCK_REALTIME, &tt) < 0)
  {
    PTHREADEX_ERR_ERRNO("Cannot read CLOCK_REALTIME");
    return -1;
  }
  tt.tv_nsec += t->t.tv_nsec;
  while(tt.tv_nsec > 1000000000)
  {
    tt.tv_nsec++;
    tt.tv_nsec -= 1000000000;
  }
  tt.tv_sec += t->t.tv_sec;

  /* lock the lock */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(t->lock));
  pthread_mutex_lock(&(t->lock));

  /* wait! */
  PTHREADEX_DBG("Timer %s: Going to wait %ld.%09ld...", t->n, t->t.tv_sec, t->t.tv_nsec);
  while((e = pthread_cond_timedwait(&t->cond, &t->lock, &tt)) == EINTR)
  {
    if(pthreadex_signal_callback && pthreadex_signal_callback())
      return 0;
  }

  /* check return code */
  switch(e)
  {
    case ETIMEDOUT: /* do nothing really ... */
      PTHREADEX_DBG("Timer %s: Timed out!", t->n);
    case 0:         /* everything ok ... somebody set up the bomb */
      break;
    default:
      PTHREADEX_ERR_ERRNO("pthread_cond_timedwait()");
      return e;
  }
  pthread_cleanup_pop_restore_np(1);
#endif

  return 0;
}

double pthreadex_time_get(void)
{
  struct timespec t;

  /* XXX TODO: we should use gettimeofday(2) if clock_gettime(3) is not available */
  if(clock_gettime(CLOCK_REALTIME, &t) < 0)
    PTHREADEX_FAT("Cannot read CLOCK_REALTIME.");

  return ((double) t.tv_sec) + (((double) t.tv_nsec) / 1000000000.0);
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + BARRIERS
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

void pthreadex_barrier_init(pthreadex_barrier_t *barrier, int num_threads)
{
  memset(barrier, 0, sizeof(pthreadex_barrier_t));
  barrier->NNodes = num_threads;
  pthread_mutex_init(&(barrier->Lock), NULL); /* PTHREAD_MUTEX_INITIALIZER */
  pthread_cond_init(&(barrier->CV), NULL);    /* PTHREAD_COND_INITIALIZER  */
}

void pthreadex_barrier_destroy(pthreadex_barrier_t *barrier)
{
  PTHREADEX_DBG("Barrier %s: DESTROY", barrier->n);
  pthread_mutex_destroy(&(barrier->Lock));
  pthread_cond_destroy(&(barrier->CV));
}

void pthreadex_barrier_wait(pthreadex_barrier_t *barrier)
{
  int Par, OldCount, i;

  /* lock barrier data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(barrier->Lock));
  pthread_mutex_lock(&(barrier->Lock));

  Par = barrier->EvenOdd;
  OldCount = ++(barrier->Count[Par]);
  PTHREADEX_DBG("Barrier %s: entering (%d/%d)...", barrier->n, OldCount, barrier->NNodes);
  if(OldCount < barrier->NNodes)
  {
    pthread_cond_wait(&(barrier->CV), &(barrier->Lock));
  } else {
    barrier->Count[Par] = 0;
    barrier->EvenOdd = 1 - Par;
    /* XXX: ¿¿ should pthread_cond_broadcast be used ?? */
    for(i = 0; i < barrier->NNodes; i++)
      pthread_cond_signal(&(barrier->CV));
  }

  PTHREADEX_DBG("Barrier %s: Exiting!.", barrier->n);

  /* following does unlock */
  pthread_cleanup_pop_restore_np(1);
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + SEMAPHORES
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

void pthreadex_semaphore_init(pthreadex_semaphore_t *sema, int initial_count)
{
  pthread_mutex_init(&(sema->lock), NULL);
  pthread_cond_init(&(sema->count_nonzero), NULL);
  sema->count = initial_count;
  sema->waiters_count = 0;
}

void pthreadex_semaphore_wait(pthreadex_semaphore_t *sema)
{
  /* lock semaphore data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(sema->lock));
  pthread_mutex_lock(&(sema->lock));

  PTHREADEX_DBG("Semaphore %s: entering (waiters=%d, max=%d)", sema->n, sema->waiters_count, sema->count);

  /* (probably) one more thread waiting until semaphore count >0 */
  sema->waiters_count++;
  while(sema->count == 0)
    pthread_cond_wait(&sema->count_nonzero, &(sema->lock));
  sema->waiters_count--;

  /* decrement one semaphore resource */
  sema->count--;

  PTHREADEX_DBG("Semaphore %s: resumed", sema->n);

  /* unlock */
  pthread_cleanup_pop_restore_np(1);
}

int pthreadex_semaphore_post(pthreadex_semaphore_t *sema)
{
  int awake = 0;

  /* lock semaphore data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(sema->lock));
  pthread_mutex_lock(&(sema->lock));

  PTHREADEX_DBG("Semaphore %s: releasing one thread.", sema->n);

  /* Always allow one thread to continue if it is waiting */
  if(sema->waiters_count > 0)
  {
    pthread_cond_signal(&(sema->count_nonzero));
    awake = 1;
  }

  /* Increment the semaphore's count */
  sema->count++;

  /* unlock */
  pthread_cleanup_pop_restore_np(1);

  return awake;
}

int pthreadex_semaphore_set(pthreadex_semaphore_t *sema, int count)
{
  int i, awake = 0;

  /* lock semaphore data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(sema->lock));
  pthread_mutex_lock(&(sema->lock));

  PTHREADEX_DBG("Semaphore %s: setting counter (max) to %d.", sema->n, count);

  if(sema->waiters_count > 0 && sema->count < count)
  {
    awake = 1;
    for(i = sema->waiters_count; i > 0 && sema->count < count; i--)
      pthread_cond_signal(&(sema->count_nonzero));
  }
  sema->count = count;

  /* unlock */
  pthread_cleanup_pop_restore_np(1);

  return awake;
}

void pthreadex_semaphore_destroy(pthreadex_semaphore_t *sema)
{
  PTHREADEX_DBG("Semaphore %s: DESTROY", sema->n);
  pthread_mutex_destroy(&(sema->lock));
  pthread_cond_destroy(&(sema->count_nonzero));
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + FLAGS
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

void pthreadex_flag_init(pthreadex_flag_t *flag, int initial_state)
{
  pthread_mutex_init(&(flag->lock), NULL);
  pthread_cond_init(&(flag->flag_up), NULL);
  flag->state = initial_state;
  flag->waiters_count = 0;
}

int pthreadex_flag_wait_timeout_ts(pthreadex_flag_t *flag, struct timespec *tout)
{
  int e = 0;

  /* lock semaphore data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(flag->lock));
  pthread_mutex_lock(&(flag->lock));
  PTHREADEX_DBG("Flag %s: Going to wait...", flag->n);

  /* (probably) one more thread waiting nnutil flag count >0 */
  flag->waiters_count++;
  while(flag->state == 0)
    if(tout)
    {
      /* wait until somebody flags or time run out */
      while((e = pthread_cond_timedwait(&flag->flag_up, &flag->lock, tout)) == EINTR)
        if(pthreadex_signal_callback && pthreadex_signal_callback())
          return 0;

      /* check return code */
      switch(e)
      {
        case ETIMEDOUT: /* do nothing really ... */
          PTHREADEX_DBG("Flag %s: Timed out!", flag->n);
        case 0:         /* everything ok ... somebody set up the bomb */
          break;
        default:
          PTHREADEX_ERR_ERRNO("Error at pthread_cond_timedwait()");
      }
    } else
      e = pthread_cond_wait(&flag->flag_up, &flag->lock);
  flag->waiters_count--;

  /* decrement one flag resource */
  flag->state = 0;

  PTHREADEX_DBG("Flag %s: Restarted.", flag->n);

  /* unlock */
  pthread_cleanup_pop_restore_np(1);

  return e;
}

int pthreadex_flag_wait_timeout(pthreadex_flag_t *flag, long long tout)
{
  struct timespec t;

  /* get current time */
  if(clock_gettime(CLOCK_REALTIME, &t) < 0)
    PTHREADEX_FAT("Cannot read CLOCK_REALTIME.");

  /* add timeout */
  t.tv_nsec += (tout % 1000) * 1000;
  t.tv_sec  += (tout / 1000) + (t.tv_nsec / 1000000000);
  t.tv_nsec = t.tv_nsec / 1000000000;

  /* call wait op */
  return pthreadex_flag_wait_timeout_ts(flag, &t);
}

int pthreadex_flag_wait(pthreadex_flag_t *flag)
{
  return pthreadex_flag_wait_timeout(flag, 0);
}

int pthreadex_flag_up(pthreadex_flag_t *flag)
{
  int awake = 0;

  /* lock semaphore data */
  pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &(flag->lock));
  pthread_mutex_lock(&(flag->lock));

  PTHREADEX_DBG("Flag %s: Flag is going up!.", flag->n);

  /* Allow one thread to continue if it is waiting */
  if(flag->waiters_count > 0)
  {
    pthread_cond_signal(&(flag->flag_up));
    awake = 1;
  }

  /* flag up! */
  flag->state = 1;

  /* unlock */
  pthread_cleanup_pop_restore_np(1);

  return awake;
}

void pthreadex_flag_destroy(pthreadex_flag_t *flag)
{
  PTHREADEX_DBG("Flag %s: DESTROY", flag->n);
  pthread_mutex_destroy(&(flag->lock));
  pthread_cond_destroy(&(flag->flag_up));
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  + LOCK SHARED/EXCLUSIVE
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#if PTHREADEX_DEBUG
void pthreadex_debug_lock_mutex_unlock(void *d)
{
  PTHREADEX_DBG("Lock %s: Going out...", ((pthreadex_lock_t *) d)->n);
  pthread_mutex_unlock(&(((pthreadex_lock_t *) d)->lock));
}
#define __pthreadex_lock_get_mutex(x)                                                       \
            pthread_cleanup_push_defer_np(pthreadex_debug_lock_mutex_unlock, (void *) (x)); \
            pthread_mutex_lock(&((x)->lock));
#else
#define __pthreadex_lock_get_mutex(x)                                                   \
            pthread_cleanup_push_defer_np((void *) pthread_mutex_unlock, &((x)->lock)); \
            pthread_mutex_lock(&((x)->lock));
#endif
#define __pthreadex_lock_release_mutex() \
            pthread_cleanup_pop_restore_np(1)

void pthreadex_lock_init(pthreadex_lock_t *l)
{
  l->lock_count = 0;
  pthread_mutex_init(&l->lock, NULL);
  pthread_cond_init(&l->lock_zero, NULL);
}

void pthreadex_lock_get_raw(pthreadex_lock_t *l, int type)
{
  /* lock semaphore data */
  __pthreadex_lock_get_mutex(l);

  PTHREADEX_DBG("Lock %s: Going to enter %s lock...",
        l->n,
        type == PTHREADEX_LOCK_SHARED ? "SHARED" : "EXCLUSIVE");
  switch(type)
  {
    case PTHREADEX_LOCK_SHARED:
      while(l->lock_count < 0)
        pthread_cond_wait(&l->lock_zero, &l->lock);
      l->lock_count++;
      break;

    default:
      PTHREADEX_ERR("Unknown type '%d'.", type);

    case PTHREADEX_LOCK_EXCLUSIVE:
      while(l->lock_count != 0)
        pthread_cond_wait(&l->lock_zero, &l->lock);
      l->lock_count--;
  }
  PTHREADEX_DBG("Lock %s: Lock captured with %s mode",
        l->n,
        type == PTHREADEX_LOCK_SHARED ? "SHARED" : "EXCLUSIVE");

  /* unlock */
  __pthreadex_lock_release_mutex();
}

void pthreadex_lock_release_raw(pthreadex_lock_t *l)
{
  /* lock semaphore data */
  PTHREADEX_DBG("Lock %s: Going to be released", l->n);

  __pthreadex_lock_get_mutex(l);

  l->lock_count += (l->lock_count >= 0) ? -1 : 1;
  if(l->lock_count == 0)
    pthread_cond_signal(&l->lock_zero);

  PTHREADEX_DBG("Lock %s: Released", l->n);

  /* unlock */
  __pthreadex_lock_release_mutex();
}

void pthreadex_lock_fini(pthreadex_lock_t *l)
{
  PTHREADEX_DBG("Lock %s: DESTROY", l->n);
  pthread_mutex_destroy(&l->lock);
  pthread_cond_destroy(&l->lock_zero);
}

