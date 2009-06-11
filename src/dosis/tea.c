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

#include "listener.h"
#include "udp.h"
#include "tcpopen.h"
#include "tcpraw.h"

static THREAD_WORK     **ttable;
static pthreadex_lock_t  ttable_lock;
static TEA_MSG_QUEUE    *msg_free;

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
    FAT("No memory for a tea message queue.");
  pthreadex_mutex_init(&(mq->mutex));

  return mq;
}

static void tea_mqueue_destroy(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  /* empty queue */
  while((m = tea_mqueue_shift(mq)) != NULL)
    if(mq == msg_free)
      tea_msg_destroy(m);
    else
      tea_msg_release(m);

  /* destroy mutex */
  pthreadex_mutex_destroy(&mq->mutex);

  /* free queue */
  free(mq);
}

void tea_mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m)
{
  pthreadex_mutex_begin(&(mq->mutex));
  m->next = NULL;
  m->prev = mq->last;
  if(mq->last)
    mq->last->next = m;
  else
    mq->first = m;
  mq->last = m;
  pthreadex_mutex_end();
}

TEA_MSG *tea_mqueue_shift(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  if(!mq)
    return NULL;

  pthreadex_mutex_begin(&(mq->mutex));
  m = mq->first;
  if(m)
  {
    mq->first = m->next;
    if(mq->first)
      mq->first->prev = NULL;
    else
      mq->last = NULL;
    m->prev = NULL;
    m->next = NULL;
  }
  pthreadex_mutex_end();

  return m;
}

/*---------------------------------------------------------------------------*
 * MESSAGE MANAGAMENT
 *
 *   Following functions create, get, release and destroy messages.
 *---------------------------------------------------------------------------*/

TEA_MSG *tea_msg_allocate(void)
{
  TEA_MSG *m;

  if((m = tea_mqueue_shift(msg_free)) == NULL)
    if((m = calloc(1, sizeof(TEA_MSG))) == NULL)
      FAT("No memory for msg.");

  m->b  = NULL;
  m->s  = 0;
  m->bs = 0;

  return m;
}

void tea_msg_destroy(TEA_MSG *m)
{
  free(m->b);
  m->b  = NULL;
  m->s  = 0;
  m->bs = 0;
}

TEA_MSG *tea_msg_get(void)
{
  TEA_MSG *m;

  if((m = tea_mqueue_shift(msg_free)) == NULL)
    m = tea_msg_allocate();

  return m;
}

void tea_msg_release(TEA_MSG *m)
{
  tea_mqueue_push(msg_free, m);
}

void tea_msg_fill(TEA_MSG *m, char *b, unsigned int s)
{
  /* get moar mem, if necessary */
  if(s > m->bs)
  {
    if((m->b = realloc(m->b, s)) == NULL)
      FAT("No memory for msg of size %d.", s);
    m->bs = s;
  }

  /* copy msg */
  m->s  = s;
  if(s > 0)
    memcpy(m->b, b, s);
}

/*---------------------------------------------------------------------------*
 * THREAD MANAGAMENT
 *
 *   Following functions start, stop, and manage tea threads.
 *---------------------------------------------------------------------------*/

static void tea_thread_cleanup(THREAD_WORK *tw)
{
  TEA_MSG_QUEUE *mq;

  DBG("Cleanup on thread %d.", tw->id);

  /* do thread cleanup */
  if(tw->methods->cleanup)
    tw->methods->cleanup(tw);

  /* disassociate mqueue of tw and destroy it */
  if(tw->methods->listen)
  {
DBG("cleanup %d: before mutex", tw->id);
    pthreadex_mutex_begin(&(tw->mqueue->mutex));
DBG("cleanup %d: in mutex", tw->id);
    if(tw->mqueue)
      mq = tw->mqueue;
    else
      mq = NULL;
    tw->mqueue = NULL;
    pthreadex_mutex_end();
DBG("cleanup %d: after mutex", tw->id);

    if(mq)
    {
      DBG("SAS");
      tea_mqueue_destroy(mq);
      DBG("SIS");
    }
  }

  pthreadex_flag_destroy(&(tw->mwaiting));

  /* free mem */
  DBG("Thread %d finished.", tw->id);
  free(tw);
}

static void *tea_thread(void *data)
{
  int r;
  THREAD_WORK *tw = (THREAD_WORK *) data;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) tea_thread_cleanup, tw);

  /* launch thread */
  if(tw->methods->listen)
  {
    while(1)
    {
DBG("WAITING FOR INPUT");
      pthreadex_flag_wait(&(tw->mwaiting));
DBG("I HAVE INPUT");
      tw->methods->listen(tw);
DBG("LISTENED");
    }
  } else
    tw->methods->thread(tw);

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);

  return NULL;
}

static void tea_thread_new(int tid, TEA_OBJECT *to, SNODE *command)
{
  THREAD_WORK *tw;

  pthreadex_lock_get_exclusive(&ttable_lock);

  /* build threads */
  DBG("Alloc'ing thread %d.", tid);
  if(ttable[tid])
    FAT("Cannot alloc thread %d because it is already used.", tid);

  if((tw = calloc(1, sizeof(THREAD_WORK))) == NULL)
    FAT("Cannot alloc THREAD_WORK struct for thread %d.", tid);

  tw->id         = tid;
  tw->pthread_id = 0;
  tw->methods    = to;

  /* check methods */
  tw->mqueue = tw->methods->listen
                 ? tea_mqueue_create()
                 : NULL;
  pthreadex_flag_init(&(tw->mwaiting), 0);

  /* global thread initialization here */
  if(tw->methods->global_init && !tw->methods->initialized)
  {
    tw->methods->initialized = -1;
    tw->methods->global_init();
  }

  /* configure thread here */
  if(tw->methods->configure)
    tw->methods->configure(tw, command);

  /* add thread to the list */
  ttable[tid] = tw;

  /* launch thread */
  if(pthread_create(&(tw->pthread_id), NULL, tea_thread, tw) != 0)
    FAT("Error creating thread %d: %s", tid, strerror(errno));

  pthreadex_lock_release();
}

static void tea_thread_stop(int tid)
{
  THREAD_WORK *tw;
  int r;

DBG("Going to kill %d", tid);
  pthreadex_lock_get_exclusive(&ttable_lock);
DBG("Killing %d", tid);

  if((tw = ttable[tid]) != NULL)
  {
    /* consider it dead */
    ttable[tid] = NULL;

    /* kill thread */
    DBG("FUSKY on thread %d (%x)", tw->id, tw);
    while((r = pthread_detach(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("Detach EINTR; repeating pthread_detach() on thread %d", tw->id);
      errno = 0;
    }
    if(r != 0)
      ERR("Cannot detach thread %u:(%d) %s", tid, errno, strerror(errno));
    while((r = pthread_cancel(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("Cancel EINTR; repeating pthread_cancel() on thread %d", tw->id);
      errno = 0;
    }
    if(r != 0)
      ERR("Cannot cancel thread %u: %s", tid, strerror(errno));
  } else {
    ERR("Thread %u does not exist.", tid);
  }

DBG("KILLED %d", tid);
  pthreadex_lock_release();
}

int tea_thread_search_listener(char *b, unsigned int l, int pivot_id)
{
  int tid, prio, stid, sprio;

  stid = -1;
  sprio = 0;

  if(pivot_id < 0 || pivot_id >= cfg.maxthreads)
    pivot_id = 0;

  pthreadex_lock_get_shared(&ttable_lock);

  tid = pivot_id;
  do {
    if(ttable[tid]
    && ttable[tid]->methods->listen_check
    && (prio = ttable[tid]->methods->listen_check(ttable[tid], b, l)) != 0)
    {
      if(prio > 0)
        FAT("Positive priority? Not in my world. Die motherfucker.");
      if(prio == -1)
      {
        stid = tid;
        break;
      }
      if(sprio < prio)
        continue;
      sprio = prio;
      stid  = tid;
    }
    tid++;
    if(tid >= cfg.maxthreads)
      tid = 0;
  } while(tid != pivot_id);

  pthreadex_lock_release();

  return stid;
}

int tea_thread_msg_push(int tid, TEA_MSG *m)
{
  int r = 0;

  pthreadex_lock_get_shared(&ttable_lock);

  if(ttable[tid])
  {
    if(ttable[tid]->mqueue)
    {
      DBG("  - package queued to %d", tid);
      tea_mqueue_push(ttable[tid]->mqueue, m);
      pthreadex_flag_up(&(ttable[tid]->mwaiting));
    } else
      tea_msg_release(m);
  } else
    r = -1;

  pthreadex_lock_release();
  
  return r;
}

char *tea_get_var(SNODE *n)
{
  char *r;

  if(n->type != TYPE_VAR)
    FAT("Node of type %d is not a var.", n->type);

  r = getenv(n->varname);
  if(!r)
    FAT("Non-existent variable '%s'.", n->varname);

  if((r = strdup(r)) == NULL)
    FAT("No memory for var '%s' content.", n->varname);

  return r;
}

char *tea_get_string(SNODE *n)
{
  char *r = NULL;

  switch(n->type)
  {
    case TYPE_STRING:
      if((r = strdup(n->string.value)) == NULL)
        FAT("Cannot dup string.");
      break;
    case TYPE_VAR:
      r = tea_get_var(n);
      break;
    default:
      FAT("Node of type %d cannot be converted to string.", n->type);
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
      FAT("Node of type %d cannot be converted to integer.", n->type);
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
      FAT("Node of type %d cannot be converted to float.", n->type);
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
      i = ti->c
            ? tea_get_int(ti->c->list_num.val)
            : 0;
      break;
    default:
      FAT("Bad selector node.");
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
        FAT("Bad range minimum value '%d'.", ti->i1);
      if(ti->i2 >= cfg.maxthreads)
        FAT("Bad range maximum value '%d' (maxthreads set to %d).", ti->i2, cfg.maxthreads);
      if(ti->i1 > ti->i2)
        FAT("Bad range.");
      ti->i = ti->i1;
      DBG("Iterator for range [%d, %d]", ti->i1, ti->i2);
      break;
    case TYPE_LIST_NUM:
      ti->c = ti->first;
      DBG("Iterator for list.");
      DBG("list: %p", ti->c);
      break;
    default:
      FAT("Bad selector node.");
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
      DBG("list: %p", ti->c);
      return ti->c == NULL;
    default:
      FAT("Bad selector node.");
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
      if(ti->c)
        ti->c = ti->c->list_num.next;
      DBG("list: %p", ti->c);
      break;
    default:
      FAT("Bad selector node.");
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
    /* cancel all threads */
    /* NOTE: Only cancelations with 'errno' different from zero are real    */
    /*       errors. A pthread_cancel return value different from zero, but */
    /*       a zero errno only means that thread is already finished.       */
    DBG("The begining of the end");
    DBG("  - Cancelling all threads.");
    for(i = 0; i < cfg.maxthreads; i++)
      if(ttable[i])
        tea_thread_stop(i);
    DBG("  - All threads cancelled.");

    /* free mem */
    free(ttable);
  }

  pthreadex_lock_fini(&ttable_lock);
  tea_mqueue_destroy(msg_free);

  DBG("tea timer finished.");
}

void tea_init(void)
{
  dosis_atexit("TEA", tea_fini);

  pthreadex_lock_init(&ttable_lock);
  if((ttable = calloc(cfg.maxthreads, sizeof(THREAD_WORK *))) == NULL)
    FAT("Cannot allocate memory for managing %d threads.", cfg.maxthreads);

  msg_free = tea_mqueue_create();
}

void tea_timer(SNODE *program)
{
  double stime, ctime, ltime, ntime;
  SNODE *cmd;
  int tid;
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
            case TYPE_TO_LISTEN:  to = &teaLISTENER; break;
            case TYPE_TO_TCPOPEN: to = &teaTCPOPEN;  break;
          /*case TYPE_TO_TCP:     to = &teaTCP;      break; */
            case TYPE_TO_TCPRAW:  to = &teaTCPRAW;   break;
            case TYPE_TO_UDP:     to = &teaUDP;      break;
            default:
              FAT("Unknown thread type %d.", cmd->command.thc.to->type);
          }
          DBG("Creating thread of type %s.", to->name);
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
        DBG("TYPE_CMD_SETVAR");
        {
          char *val = tea_get_string(cmd->command.setvar.val);
          if(setenv(cmd->command.setvar.var, val, 1))
            FAT("Cannot set var '%s' with value '%s'.",
                  cmd->command.setvar.var, val);
          free(val);
        }
        break;
      default:
        FAT("%d: Unknown command %d.", cmd->line, cmd->type);
    }
  }
  if(cfg.finalize)
    WRN("Attack cancelled by user.");

  /* free memory */
  DBG("Script finished.");
  //pthreadex_timer_destroy(&timer);
}

