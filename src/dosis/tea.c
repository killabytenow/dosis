/*****************************************************************************
 * tea.c
 *
 * Is now the tea time?
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008 Gerardo García Peña <gerardo@kung-foo.dhs.org>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "dosis.h"
#include "log.h"
#include "pthreadex.h"
#include "tea.h"

void tea_timer(tea_attack_go2work go2work,
               tea_attack_thread attack_thread)
{
  int i;
  struct timeval sttime, entime;
  pthreadex_barrier_t start_barrier;
  THREAD_WORK *tin;
  unsigned int mneeded, tneeded;
  pthreadex_timer_t timer;

  /* build a timer to limit petitions to only opts.hits per minute */
  pthreadex_timer_init(&timer, 0.0);
  pthreadex_timer_set_frequency(&timer, opts.hits);
  if(pthreadex_timer_get(&timer) > (double) opts.runtime)
    pthreadex_timer_set(&timer, opts.runtime);

  /* flag that will keep threads waiting for starting */
  pthreadex_barrier_init(&start_barrier, opts.c + 1);

  /* build threads */
  DBG("Alloc'ing memory for %d threads.", opts.c);
  if((tin = (THREAD_WORK *) calloc(opts.c, sizeof(THREAD_WORK))) == NULL)
    FAT("Memory allocation failed.");

  for(i = 0; i < opts.c; i++)
  {
    tin[i].id         = i;
    tin[i].pthread_id = 0;
    tin[i].start      = &start_barrier;

    if(pthread_create(&(tin[i].pthread_id), NULL, (void *) attack_thread, tin+i) != 0)
      FAT("  - Thread creation failed at thread %d: %s", i, strerror(errno));
  }

  /* GO! */
  DBG("Waiting that all threads have been created and ready before start...");
  pthreadex_barrier_wait(&start_barrier);
  DBG("Starting attack of %d seconds.", opts.runtime);
  tneeded = 0;
  mneeded = opts.c;
  for(gettimeofday(&sttime, NULL), gettimeofday(&entime, NULL);
      entime.tv_sec - sttime.tv_sec < opts.runtime && !opts.finalize;
      gettimeofday(&entime, NULL))
  {
    if(!go2work())
      tneeded++;
    else
      tneeded = 0;

    /* wait */
    if(pthreadex_timer_wait(&timer) < 0)
      ERR("Error at pthreadex_timer_wait(): %s", strerror(errno));
  }
  if(opts.finalize)
    WRN("Attack cancelled by user.");
  if(tneeded > mneeded)
    WRN("You should allow at least %d threads for getting optimum performance.", tneeded);

  /* cancel all threads */
  /* NOTE: Only cancelations with 'errno' different from zero are real    */
  /*       errors. A pthread_cancel return value different from zero, but */
  /*       a zero errno only means that thread is already finished.       */
  LOG("[--] Cancelling all threads.");
  for(i = 0; i < opts.c; i++)
    if(pthread_cancel(tin[i].pthread_id) && errno != 0)
      ERR("[--] Cannot cancel thread %02u: %s", i, strerror(errno));

  DBG("[--] Waiting for all to join.");
  for(i = 0; i < opts.c; i++)
    if(pthread_join(tin[i].pthread_id, NULL))
      ERR("[--] Cannot join with thread %02u: %s", i, strerror(errno));

  /* free memory */
  DBG2("[--]   Free memory.");
  pthreadex_timer_destroy(&timer);
  pthreadex_barrier_destroy(&start_barrier);
  free(tin);
}

