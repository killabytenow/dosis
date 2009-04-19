/*****************************************************************************
 * tea.c
 *
 * Is now the tea time?
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008 Gerardo Garc�a Pe�a <gerardo@kung-foo.dhs.org>
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

#include "dosconfig.h"
#include "dosis.h"
#include "log.h"
#include "pthreadex.h"
#include "tea.h"

static THREAD_WORK **ttable;
static TEA_MSG_QUEUE *msg_free;

static TEA_MSG_QUEUE *tea_timer_mqueue_create(void)
{
  TEA_MSG_QUEUE *mq;

  if((mq = calloc(1, sizeof(TEA_MSG_QUEUE))) == NULL)
    D_FAT("No memory for a tea message queue.");
  pthreadex_mutex_init(&(mq->mutex));

  return mq;
}

static void tea_timer_mqueue_destroy(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  /* empty queue */
  while((m = tea_timer_mqueue_shift(mq)) != NULL)
    tea_timer_mqueue_release(m);

  /* free queue */
  free(mq);
}

TEA_MSG *tea_timer_msg_allocate(void)
{
  TEA_MSG *m;

  if((m = tea_timer_mqueue_shift(msg_free)) == NULL)
    if((m = calloc(1, sizeof(TEA_MSG))) == NULL)
      D_FAT("No memory for msg.");

  return m;
}

void tea_timer_mqueue_release(TEA_MSG *m)
{
  tea_timer_mqueue_push(msg_free, m);
}

void tea_timer_mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m)
{
  pthreadex_mutex_begin(&(mq->mutex));
  m->prev = mq->last;
  if(mq->last)
    mq->last->next = m;
  else
    mq->first = m;
  m->next = NULL;
  pthreadex_mutex_end();
}

TEA_MSG *tea_timer_mqueue_shift(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  pthreadex_mutex_begin(&(mq->mutex));
  if(mq->last)
  {
    m = mq->first;
    mq->first = m->next;
    if(!mq->first)
      mq->last = NULL;
    m->prev = NULL;
    m->next = NULL;
  } else
    m = NULL;
  pthreadex_mutex_end();

  return m;
}

static void tea_timer_basic_thread_cleanup(THREAD_WORK *tw)
{
  TEA_MSG_QUEUE *mq;

  tw->methods->cleanup(tw);

  /* disassociate mqueue of tw */
  pthreadex_mutex_begin(&(tw->mqueue->mutex));
  if(tw->mqueue)
    mq = tw->mqueue;
  else
    mq = NULL;
  tw->mqueue = NULL;
  pthreadex_mutex_end();

  /* destroy mqueue */
  if(mq)
    tea_timer_mqueue_destroy(mq);
  pthreadex_flag_destroy(&(tw->mwaiting));
}

static void *tea_timer_thread(void *data)
{
  int r;
  THREAD_WORK *tw = (THREAD_WORK *) data;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) tea_timer_basic_thread_cleanup, tw);

  /* launch thread */
  if(tw->methods->listen)
  {
    while(1)
    {
      pthreadex_flag_wait(&(tw->mwaiting));
      tw->methods->listen(tw);
    }
  } else
    tw->methods->thread(tw);

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);

  return NULL;
}

void tea_timer_new_thread(int tid, TEA_OBJECT *to)
{
  THREAD_WORK *tw;

  /* build threads */
  DBG("Alloc'ing thread %d.", tid);
  if(ttable[tid])
    D_FAT("Cannot alloc thread %d because it is already used.", tid);

  if((tw = calloc(1, sizeof(THREAD_WORK))) == NULL)
    D_FAT("Cannot alloc THREAD_WORK struct for thread %d.", tid);

  tw->id         = tid;
  tw->pthread_id = 0;
  tw->methods    = to;

  /* check methods */
  tw->mqueue = tw->methods->listen
                 ? tea_timer_mqueue_create()
                 : NULL;
  pthreadex_flag_init(&(tw->mwaiting), 0);

  /* configure thread here */
  if(tw->methods->configure)
    tw->methods->configure(tw);

  /* launch thread */
  if(pthread_create(&(tw->pthread_id), NULL, tea_timer_thread, tw) != 0)
    FAT("Error creating thread %d: %s", tid, strerror(errno));
}

static void tea_timer_fini(void)
{
  int i;

  if(ttable)
  {
    for(i = 0; i < cfg.maxthreads; i++)
      if(ttable[i])
        free(ttable[i]);
    free(ttable);
  }
}

void tea_timer_init(void)
{
  if(atexit(tea_timer_fini))
    D_FAT("Cannot set finalization routine.");

  if((ttable = calloc(cfg.maxthreads, sizeof(THREAD_WORK *))) == NULL)
    D_FAT("Cannot allocate memory for managing %d threads.", cfg.maxthreads);

  msg_free = tea_timer_mqueue_create();
}

void tea_timer(SNODE *program)
{
  struct timeval sttime, entime;
  SNODE *cmd;
  int i;

  if(cfg.finalize)
    WRN("[TT] Attack cancelled by user.");

  for(cmd = program; !cmd; cmd = cmd->command.next)
  {
    switch(cmd->type)
    {
      case TYPE_CMD_ON:
      case TYPE_CMD_MOD:
      case TYPE_CMD_OFF:
        break;
      default:
        D_FAT("[TT] Unknown command %d.", cmd->type);
    }
  }

  /* cancel all threads */
  /* NOTE: Only cancelations with 'errno' different from zero are real    */
  /*       errors. A pthread_cancel return value different from zero, but */
  /*       a zero errno only means that thread is already finished.       */
  LOG("[TT] Cancelling all threads.");
  for(i = 0; i < cfg.maxthreads; i++)
    if(ttable[i])
      if(pthread_cancel(ttable[i]->pthread_id) && errno != 0)
        ERR("[TT] Cannot cancel thread %02u: %s", i, strerror(errno));

  DBG("[TT] Waiting for all to join.");
  for(i = 0; i < cfg.maxthreads; i++)
    if(ttable[i])
      if(pthread_join(ttable[i]->pthread_id, NULL))
        ERR("[TT] Cannot join with thread %02u: %s", i, strerror(errno));

  /* free memory */
  DBG2("[TT]   Free memory.");
  //pthreadex_timer_destroy(&timer);
  //free(tw);
}

