/*****************************************************************************
 * tea.c
 *
 * Is now the tea time?
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "dosconfig.h"
#include "dosis.h"
#include "log.h"
#include "pthreadex.h"
#include "tea.h"

#include "tcpraw.h"
#include "listener.h"

static THREAD_WORK **ttable;
static TEA_MSG_QUEUE *msg_free;

typedef struct {
  SNODE *first;
  int    i1, i2, i;
  SNODE *c;
} TEA_ITER;

/*---------------------------------------------------------------------------*
 * MSG AND MQUEUE MANAGAMENT
 *
 *   MQUEUE objects are threadsafe queues for making FIFO queues of raw
 *   network messages. This interface provides a simple message passing
 *   facility to deliver raw packets from the listener threads to other
 *   types of threads that need a raw network input.
 *---------------------------------------------------------------------------*/

static TEA_MSG_QUEUE *tea_mqueue_create(void)
{
  TEA_MSG_QUEUE *mq;

  if((mq = calloc(1, sizeof(TEA_MSG_QUEUE))) == NULL)
    D_FAT("No memory for a tea message queue.");
  pthreadex_mutex_init(&(mq->mutex));

  return mq;
}

static void tea_mqueue_destroy(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  /* empty queue */
  while((m = tea_mqueue_shift(mq)) != NULL)
    tea_mqueue_release(m);

  /* free queue */
  free(mq);
}

TEA_MSG *tea_msg_allocate(void)
{
  TEA_MSG *m;

  if((m = tea_mqueue_shift(msg_free)) == NULL)
    if((m = calloc(1, sizeof(TEA_MSG))) == NULL)
      D_FAT("No memory for msg.");

  return m;
}

void tea_mqueue_release(TEA_MSG *m)
{
  tea_mqueue_push(msg_free, m);
}

void tea_mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m)
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

TEA_MSG *tea_mqueue_shift(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  if(!mq)
    return NULL;

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

/*---------------------------------------------------------------------------*
 * THREAD MANAGAMENT
 *
 *   Following functions start, stop, and manage tea threads.
 *---------------------------------------------------------------------------*/

static void tea_thread_basic_cleanup(THREAD_WORK *tw)
{
  TEA_MSG_QUEUE *mq;

  /* do thread cleanup */
  if(tw->methods->cleanup)
    tw->methods->cleanup(tw);

  /* disassociate mqueue of tw and destroy it */
  if(tw->methods->listen)
  {
    pthreadex_mutex_begin(&(tw->mqueue->mutex));
    if(tw->mqueue)
      mq = tw->mqueue;
    else
      mq = NULL;
    tw->mqueue = NULL;
    pthreadex_mutex_end();

    if(mq)
      tea_mqueue_destroy(mq);
  }

  pthreadex_flag_destroy(&(tw->mwaiting));
}

static void *tea_thread(void *data)
{
  int r;
  THREAD_WORK *tw = (THREAD_WORK *) data;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) tea_thread_basic_cleanup, tw);

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

void tea_thread_new(int tid, TEA_OBJECT *to, SNODE *command)
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
                 ? tea_mqueue_create()
                 : NULL;
  pthreadex_flag_init(&(tw->mwaiting), 0);

  /* configure thread here */
  if(tw->methods->configure)
    tw->methods->configure(tw, command);

  /* add thread to the list */
  ttable[tid] = tw;

  /* launch thread */
  if(pthread_create(&(tw->pthread_id), NULL, tea_thread, tw) != 0)
    FAT("Error creating thread %d: %s", tid, strerror(errno));
}

void tea_thread_stop(int tid)
{
  THREAD_WORK *tw = ttable[tid];

  if(!tw)
  {
    ERR("Thread %u does not exist.", tid);
    return;
  }

  /* consider it dead */
  ttable[tid] = NULL;

  if(pthread_detach(tw->pthread_id))
    ERR("Cannot detach thread %u: %s", tid, strerror(errno));
  if(pthread_cancel(tw->pthread_id) && errno != 0)
    ERR("Cannot cancel thread %u: %s", tid, strerror(errno));
}

char *tea_get_var(SNODE *n)
{
  char *r;

  if(n->type != TYPE_VAR)
    D_FAT("Node of type %d is not a var.", n->type);

  r = getenv(n->varname);
  if(!r)
    D_FAT("Non-existent variable '%s'.", n->varname);

  if((r = strdup(r)) == NULL)
    D_FAT("No memory for var '%s' content.", n->varname);

  return r;
}

char *tea_get_string(SNODE *n)
{
  char *r = NULL;

  switch(n->type)
  {
    case TYPE_STRING:
      if((r = strdup(n->string.value)) == NULL)
        D_FAT("Cannot dup string.");
      break;
    case TYPE_VAR:
      r = tea_get_var(n);
      break;
    default:
      D_FAT("Node of type %d cannot be converted to string.", n->type);
  }

  return r;
}

int tea_get_int(SNODE *n)
{
  int r;
  char *v;

  switch(n->type)
  {
    case TYPE_NINT:
      r = n->nint;
      break;
    case TYPE_VAR:
      v = tea_get_var(n);
      r = atoi(v);
      free(v);
      break;
    default:
      D_FAT("Node of type %d cannot be converted to integer.", n->type);
  }

  return r;
}

double tea_get_float(SNODE *n)
{
  double r;
  char *v;

  switch(n->type)
  {
    case TYPE_NINT:
      r = (double) n->nint;
      break;
    case TYPE_NFLOAT:
      r = n->nfloat;
      break;
    case TYPE_VAR:
      v = tea_get_var(n);
      r = atof(v);
      free(v);
      break;
    default:
      D_FAT("Node of type %d cannot be converted to float.", n->type);
  }

  return r;
}

int tea_iter_get(TEA_ITER *ti)
{
  int i = 0;
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      i = ti->i;
      break;
    case TYPE_LIST_NUM:
      i = tea_get_int(ti->c->list_num.val);
      break;
    default:
      D_FAT("Bad selector node.");
  }
  return i;
}

int tea_iter_start(SNODE *s, TEA_ITER *ti)
{
  ti->first = s;
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      ti->i1 = ti->first->range.min != NULL
                 ? tea_get_int(ti->first->range.min)
                 : 0;
      ti->i2 = ti->first->range.max != NULL
                 ? tea_get_int(ti->first->range.max)
                 : cfg.maxthreads - 1;
      if(ti->i1 < 0)
        D_FAT("Bad range minimum value '%d'.", ti->i1);
      if(ti->i2 >= cfg.maxthreads)
        D_FAT("Bad range maximum value '%d' (maxthreads set to %d).", ti->i2, cfg.maxthreads);
      if(ti->i1 > ti->i2)
        D_FAT("Bad range.");
      ti->i = ti->i1;
      D_DBG("Iterator for range [%d, %d]", ti->i1, ti->i2);
      break;
    case TYPE_LIST_NUM:
      ti->c = ti->first;
      D_DBG("Iterator for list.");
      break;
    default:
      D_FAT("Bad selector node.");
  }

  return tea_iter_get(ti);
}

int tea_iter_finish(TEA_ITER *ti)
{
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      return ti->i > ti->i2;
    case TYPE_LIST_NUM:
      return ti->c == NULL;
    default:
      D_FAT("Bad selector node.");
  }
  return -1;
}

int tea_iter_next(TEA_ITER *ti)
{
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      ti->i++;
      break;
    case TYPE_LIST_NUM:
      ti->c = ti->c->list_num.next;
      break;
    default:
      D_FAT("Bad selector node.");
  }

  return tea_iter_get(ti);
}

/*---------------------------------------------------------------------------*
 * THE TEA CORE
 *
 *   Dump the tea.
 *---------------------------------------------------------------------------*/

static double tea_time_get(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return ((double) tv.tv_sec) + (((double) tv.tv_usec) / 1000000.0);
}

static void tea_fini(void)
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

void tea_init(void)
{
  if(atexit(tea_fini))
    D_FAT("Cannot set finalization routine.");

  if((ttable = calloc(cfg.maxthreads, sizeof(THREAD_WORK *))) == NULL)
    D_FAT("Cannot allocate memory for managing %d threads.", cfg.maxthreads);

  msg_free = tea_mqueue_create();
}

void tea_timer(SNODE *program)
{
  double stime, ctime, ltime, ntime;
  SNODE *cmd;
  int i, tid;
  TEA_OBJECT *to = NULL;
  TEA_ITER ti;
  pthreadex_timer_t teatimer;

  /* get time 0 */
  ltime = stime = tea_time_get();
  pthreadex_timer_init(&teatimer, 0.0);

  for(cmd = program; !cfg.finalize && cmd; cmd = cmd->command.next)
  {
    /* wait until command is prepared to be executed */
    ctime = tea_time_get() - stime;

    if(cmd->command.time)
    {
      ntime = tea_get_float(cmd->command.time->ntime.n);
      if(ntime > 0)
      {
        if(cmd->command.time->ntime.rel)
          ntime += ltime;

        if(ntime > ctime)
        {
          pthreadex_timer_set(&teatimer, ntime - ctime);
          pthreadex_timer_wait(&teatimer);
        } else
          WRN("Command on line %d happened too fast.", cmd->line);
      }

      LOG("Now it is %.2f seconds from the begining of time.", tea_time_get() - stime);
    }
    ltime = ctime;

    /* launch command */
    switch(cmd->type)
    {
      case TYPE_CMD_ON:
      case TYPE_CMD_MOD:
        for(tid = tea_iter_start(cmd->command.thc.selection, &ti);
            !tea_iter_finish(&ti);
            tid = tea_iter_next(&ti))
        {
          switch(cmd->command.thc.to->type)
          {
          /*case TYPE_TO_LISTEN: to = &teaLISTEN; break; */
          /*case TYPE_TO_TCP:    to = &teaTCP;    break; */
            case TYPE_TO_TCPRAW: to = &teaTCPRAW; break;
          /*case TYPE_TO_UDP:    to = &teaUDP;    break; */
            default:
              D_FAT("Unknown thread type %d.", cmd->command.thc.to->type);
          }
          D_DBG("Creating thread of type %s.", to->name);
          tea_thread_new(tid, to, cmd);
        }
        break;
      case TYPE_CMD_OFF:
        for(tid = tea_iter_start(cmd->command.thc.selection, &ti);
            !tea_iter_finish(&ti);
            tid = tea_iter_next(&ti))
          if(ttable[tid])
            tea_thread_stop(tid);
        break;
      case TYPE_CMD_SETVAR:
        D_DBG("TYPE_CMD_SETVAR");
        {
          char *val = tea_get_string(cmd->command.setvar.val);
          if(setenv(cmd->command.setvar.var, val, 1))
            D_FAT("Cannot set var '%s' with value '%s'.",
                  cmd->command.setvar.var, val);
          free(val);
        }
        break;
      default:
        D_FAT("%d: Unknown command %d.", cmd->line, cmd->type);
    }
  }
  if(cfg.finalize)
    WRN("Attack cancelled by user.");

  /* cancel all threads */
  /* NOTE: Only cancelations with 'errno' different from zero are real    */
  /*       errors. A pthread_cancel return value different from zero, but */
  /*       a zero errno only means that thread is already finished.       */
  D_DBG("The begining of the end");
  DBG("  - Cancelling all threads.");
  for(i = 0; i < cfg.maxthreads; i++)
    if(ttable[i])
      if(pthread_cancel(ttable[i]->pthread_id) && errno != 0)
        ERR("  ! Cannot cancel thread %02u: %s", i, strerror(errno));

  DBG("  - Waiting for all to join.");
  for(i = 0; i < cfg.maxthreads; i++)
    if(ttable[i])
      if(pthread_join(ttable[i]->pthread_id, NULL))
        ERR("  ! Cannot join with thread %02u: %s", i, strerror(errno));

  /* free memory */
  D_DBG("Script finished.");
  //pthreadex_timer_destroy(&timer);
  //free(tw);
}

