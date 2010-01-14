/*****************************************************************************
 * tea.c
 *
 * Is now the tea time?
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

#include "config.h"

#include "dosconfig.h"
#include "dosis.h"
#include "log.h"
#include "pthreadex.h"
#include "tea.h"

#include "pills/listener.h"
#include "pills/slowy.h"
#include "pills/tcp.h"
#include "pills/tcpopen.h"
#include "pills/tcpraw.h"
#include "pills/udp.h"

static THREAD_WORK     **ttable;
static pthreadex_lock_t  ttable_lock;

/*---------------------------------------------------------------------------*
 * THREAD MANAGAMENT
 *
 *   Following functions start, stop, and manage tea threads.
 *---------------------------------------------------------------------------*/

static void tea_thread_cleanup(THREAD_WORK *tw)
{
  TEA_MSG_QUEUE *mq;

  DBG2("Cleanup of thread %d.", tw->id);

  /* do thread cleanup */
  if(tw->methods->cleanup)
    tw->methods->cleanup(tw);

  /* disassociate mqueue of tw and destroy it */
  if(tw->methods->listen)
  {
    pthreadex_mutex_begin(&(tw->mqueue->mutex));
    DBG2("  [cleanup %d] listen cleanup", tw->id);
    if(tw->mqueue)
      mq = tw->mqueue;
    else
      mq = NULL;
    tw->mqueue = NULL;
    pthreadex_mutex_end();

    if(mq)
    {
      DBG2("  [cleanup %d] mqueue cleanup", tw->id);
      mqueue_destroy(mq);
    }
  }

  DBG2("  [cleanup %d] destroy mwaiting flag", tw->id);
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
  tw->methods->thread(tw);

  /*
   *# set timeout/wait condition
   *XXX
   *# do actions
   *if(tw->methods->listen)
   *{
   *  while(1)
   *  {
   *    # XXX TIMEOUT HERE?? XXX
   *    pthreadex_flag_wait(&(tw->mwaiting));
   *    tw->methods->listen(tw);
   *  }
   *} else
   */

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
                 ? mqueue_create()
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

  DBG("Thread %d kill scheduled.", tid);
  pthreadex_lock_get_exclusive(&ttable_lock);

  if((tw = ttable[tid]) != NULL)
  {
    DBG2("[kill %d] detaching thread", tid);

    /* consider it dead */
    ttable[tid] = NULL;

    /* kill thread */
    while((r = pthread_detach(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("[kill %d] Detach EINTR; repeating pthread_detach()", tid);
      errno = 0;
    }
    if(r != 0)
      ERR("[kill %d] Cannot detach thread:(%d) %s", tid, errno, strerror(errno));
    while((r = pthread_cancel(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("[kill %d] Cancel EINTR; repeating pthread_cancel()", tid);
      errno = 0;
    }
    if(r != 0)
      ERR("[kill %d] Cannot cancel thread: %s", tid, strerror(errno));

    DBG("[kill %d] KILLED!", tid);
  } else {
    ERR("Thread %u does not exist.", tid);
  }

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

TEA_MSG *tea_thread_msg_get(THREAD_WORK *tw)
{
  return mqueue_shift(tw->mqueue);
}

TEA_MSG *tea_thread_msg_wait(THREAD_WORK *tw)
{
  TEA_MSG *m;

  do {
    pthreadex_flag_wait(&(tw->mwaiting));
    m = mqueue_shift(tw->mqueue);
  } while(!m);

  return m;
}

int tea_thread_msg_push(int tid, TEA_MSG *m)
{
  int r = 0;

  pthreadex_lock_get_shared(&ttable_lock);

  if(ttable[tid])
  {
    if(ttable[tid]->mqueue)
    {
      mqueue_push(ttable[tid]->mqueue, m);
      pthreadex_flag_up(&(ttable[tid]->mwaiting));
    } else
      msg_release(m);
  } else
    r = -1;

  pthreadex_lock_release();
  
  return r;
}

/*---------------------------------------------------------------------------*
 * THE TEA CORE
 *
 *   Dump the tea (the tea interpreter).
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

  mqueue_fini();

  DBG("tea timer finished.");
}

void tea_init(void)
{
  dosis_atexit("TEA", tea_fini);

  pthreadex_lock_init(&ttable_lock);
  if((ttable = calloc(cfg.maxthreads, sizeof(THREAD_WORK *))) == NULL)
    FAT("Cannot allocate memory for managing %d threads.", cfg.maxthreads);

  mqueue_init();
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
      ntime = tea_snode_get_float(cmd->command.time->ntime.n);
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

    if(cfg.finalize)
      break;

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
            case TYPE_TO_TCP:     to = &teaTCP;      break;
            case TYPE_TO_TCPRAW:  to = &teaTCPRAW;   break;
            case TYPE_TO_UDP:     to = &teaUDP;      break;
            case TYPE_TO_ZWIN:    to = &teaSlowy;    break;
            case TYPE_TO_SLOW:    to = &teaSlowy;    break;
            default:
              FAT("Unknown thread type %d.", cmd->command.thc.to->type);
          }
          LOG("[tea %d] %s thread of type %s.",
              tid, cmd->type == TYPE_CMD_ON ? "Started" : "Modified", to->name);
          tea_thread_new(tid, to, cmd);
        }
        break;

      case TYPE_CMD_OFF:
        for(tid = tea_iter_start(cmd->command.thc.selection, &ti);
            !tea_iter_finish(&ti);
            tid = tea_iter_next(&ti))
          if(ttable[tid])
          {
            LOG("[tea %d] Stopped thread of type %s.", tid, to->name);
            tea_thread_stop(tid);
          }
        break;

      case TYPE_CMD_SETVAR:
        if(!cmd->command.setvar.cond
        || !getenv(cmd->command.setvar.var))
        {
          char *val = tea_snode_get_string(cmd->command.setvar.val);
          LOG("[tea] %s='%s'", cmd->command.setvar.var, val);
          if(setenv(cmd->command.setvar.var, val, 1))
            FAT("Cannot set var '%s' with value '%s'.",
                  cmd->command.setvar.var, val);
          free(val);
        }
        break;

/*
      case TYPE_CMD_INCLUDE:
        break;
*/

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

