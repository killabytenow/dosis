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

  TDBG2("Thread cleanup.");

  /* do thread cleanup */
  if(tw->to->cleanup)
    tw->to->cleanup(tw);

  if(tw->data != NULL)
  {
    free(tw->data);
    tw->data = NULL;
  }

  /* disassociate mqueue of tw and destroy it */
  if(tw->to->listen)
  {
    pthreadex_mutex_begin(&(tw->mqueue->mutex));
    TDBG2("  [cleanup] listen cleanup");
    if(tw->mqueue)
      mq = tw->mqueue;
    else
      mq = NULL;
    tw->mqueue = NULL;
    pthreadex_mutex_end();

    if(mq)
    {
      TDBG2("  [cleanup] mqueue cleanup");
      mqueue_destroy(mq);
    }
  }

  TDBG2("  [cleanup] destroy mwaiting flag");
  pthreadex_flag_destroy(&(tw->mwaiting));

  TDBG("Thread finished.");

  /* free mem */
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
  TDBG("Starting thread.");
  tw->to->thread(tw);
  TDBG("Thread finished.");

  /*
   *# set timeout/wait condition
   *XXX
   *# do actions
   *if(tw->to->listen)
   *{
   *  while(1)
   *  {
   *    # XXX TIMEOUT HERE?? XXX
   *    pthreadex_flag_wait(&(tw->mwaiting));
   *    tw->to->listen(tw);
   *  }
   *} else
   */

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);

  return NULL;
}

/* XXX */
static int tea_thread_param_value_set(THREAD_WORK *tw, TEA_OBJCFG *oc, SNODE *v)
{
  char *s;

  /* check tea object */
  switch(oc->type)
  {
    case TEA_TYPE_ADDR_ID:
      {
        int port;
        TEA_TYPE_ADDR *a = (tw->data + oc->offset);

        s = script_get_string(v);
        if(ip_addr_parse(s, &a->addr, &port))
          TFAT("%d: Cannot parse address '%s'.", v->line, s);
        if(port >= 0)
          a->port = port;
        free(s);
      }
      break;

    case TEA_TYPE_PORT_ID:
      {
        TEA_TYPE_ADDR *a = tw->data + oc->offset;
        a->port = script_get_int(v);
      }
      break;

    case TEA_TYPE_BOOL_ID:
      *((TEA_TYPE_INT *) (tw->data + oc->offset)) = script_get_bool(v);
      break;

    case TEA_TYPE_INT_ID:
      *((TEA_TYPE_INT *) (tw->data + oc->offset)) = script_get_int(v);
      break;

    case TEA_TYPE_FLOAT_ID:
      *((TEA_TYPE_FLOAT *) (tw->data + oc->offset)) = script_get_float(v);
      break;

    case TEA_TYPE_DATA_ID:
      {
        TEA_TYPE_DATA *d = tw->data + oc->offset;
        d->data = script_get_data(v, &d->size);
      }
      break;

    case TEA_TYPE_STRING_ID:
      *((TEA_TYPE_STRING *) (tw->data + oc->offset)) = script_get_string(v);
      break;

    default:
      ERR("Unknown type %d.", oc->type);
      return -1;
  }

  /* call handler (if it is available) */
  if(oc->handler)
    return oc->handler(oc, tw);

  return 0;
}

static SNODE *tea_thread_param_value_get(HASH *opts, char *name)
{
  SNODE *r;

  r = script_get_default(name);
  if(hash_key_exists(opts, name))
    r = hash_entry_get(opts, name);

  return r;
}

static void tea_thread_new(int tid, TEA_OBJECT *to, SNODE *command)
{
  THREAD_WORK *tw = NULL;
  TEA_OBJCFG *ocline;
  HASH_ITER hi;
  HASH_NODE *hn;

  DBG("Going to create thread %d.", tid);
  if((tw = calloc(1, sizeof(THREAD_WORK))) == NULL)
  {
    ERR("Cannot alloc THREAD_WORK struct for thread %d.", tid);
    goto fatal;
  }

  tw->id         = tid;
  tw->pthread_id = 0;
  tw->to         = to;

  /* check methods */
  tw->mqueue = tw->to->listen
                 ? mqueue_create()
                 : NULL;
  pthreadex_flag_init(&(tw->mwaiting), 0);
  pthreadex_flag_name(&(tw->mwaiting), "flag-mwaiting");

  /* global thread initialization here */
  if(tw->to->global_init && !tw->to->initialized)
  {
    tw->to->initialized = -1;
    tw->to->global_init();
  }

  /* make space for thread data */
  if((tw->data = calloc(1, to->datasize)) == NULL)
  {
    ERR("%d:%s: No memory for thread data.", command->line, to->name);
    goto fatal;
  }

  /* check config params */
  if(to->cparams)
  {
    DBG("Checking parameters for object %s", to->name);
    /* check only allowed params are defined */
    for(hn = hash_iter_first(&hi, command->command.thc.to->options);
        !hash_iter_finished(&hi);
        hn = hash_iter_next(&hi))
    {
      DBG("  - checking [%s]", hn->key);
      for(ocline = to->cparams;
          ocline->name && strcasecmp(hn->key, ocline->name);
          ocline++)
        ;
      if(!ocline->name)
      {
        ERR("%d:%s: Parameter %s not allowed here.", command->line, to->name, hn->key);
        goto fatal;
      }
    }

    /* set params (apply configuration) */
    DBG("Reading parameters...");
    for(ocline = to->cparams; ocline->name; ocline++)
    {
      SNODE *val;

      /* get configured value (or set default value if not specified) */
      val = tea_thread_param_value_get(command->command.thc.to->options, ocline->name);
      val = script_get_default(ocline->name);
      if(hash_key_exists(command->command.thc.to->options, ocline->name))
        val = hash_entry_get(command->command.thc.to->options, ocline->name);

      /* check if parameter is optional */
      if(!val)
      {
        if(ocline->needed)
        {
          ERR("%d:%s: Parameter %s is mandatory.", command->line, to->name, ocline->name);
          goto fatal;
        }
        continue;
      }

      /* set value */
      if(tea_thread_param_value_set(tw, ocline, val))
        goto fatal;
    }
  } else {
    if(command->command.thc.to->options
    || command->command.thc.to->options->nentries > 0)
    {
      ERR("%d:%s: Parameters not allowed for this type of thread.", command->line, to->name);
      goto fatal;
    }
  }

  /* once configuration applied, launch thread configuration routine */
  if(tw->to->configure)
    if(tw->to->configure(tw, command, 1))
    {
      ERR("%d:%s: Thread configuration failed.", command->line, to->name);
      goto fatal;
    }

  /* add thread to the list */
  pthreadex_lock_get_exclusive(&ttable_lock);
  DBG("Installing thread %d.", tid);

  /* build threads */
  if(ttable[tid])
  {
    ERR("Cannot alloc thread %d because it is already used.", tid);
    goto fatal;
  }

  ttable[tid] = tw;

  /* launch thread */
  if(pthread_create(&(tw->pthread_id), NULL, tea_thread, tw) != 0)
  {
    ERR("Error creating thread %d: %s", tid, strerror(errno));
    goto fatal;
  }

  pthreadex_lock_release();
  return;

fatal:
  ERR("Fatal error happened. Going to abort...");
  if(tw)
  {
    if(ttable[tid] == tw)
      ttable[tid] = NULL;
    if(tw->mqueue)
      mqueue_destroy(tw->mqueue);
    pthreadex_flag_destroy(&(tw->mwaiting));
    free(tw);
  }
  pthreadex_lock_release_raw(&ttable_lock);
  FAT("Aborting.");
}

static void tea_thread_stop(int tid)
{
  THREAD_WORK *tw;
  int r;

  DBG("Thread %d kill scheduled.", tid);
  pthreadex_lock_get_exclusive(&ttable_lock);
  DBG("  going to kill %d.", tid);
  tw = ttable[tid];
  pthreadex_lock_release();

  if(tw != NULL)
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
}

int tea_thread_search_listener(char *b, unsigned int l, int pivot_id)
{
  int tid, prio, stid, sprio;

  stid = -1;
  sprio = 0;

  if(pivot_id < 0 || pivot_id >= cfg.maxthreads)
    pivot_id = 0;

  DBG("Going to look for a listener.");
  pthreadex_lock_get_shared(&ttable_lock);
  DBG("  looking for a listener.");

  tid = pivot_id;
  do {
    if(ttable[tid]
    && ttable[tid]->to->listen_check
    && (prio = ttable[tid]->to->listen_check(ttable[tid], b, l)) != 0)
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

int tea_thread_msg_push(int tid, void *msg, int msg_size)
{
  TEA_MSG *tmsg;
  int r = 0;

  pthreadex_lock_get_shared(&ttable_lock);

  if(ttable[tid])
  {
    if(ttable[tid]->mqueue)
    {
      tmsg = msg_get();
      msg_fill(tmsg, msg, msg_size);
      mqueue_push(ttable[tid]->mqueue, tmsg);
      DBG("  message pushed to %d.", tid);
      pthreadex_flag_up(&(ttable[tid]->mwaiting));
    } else
      DBG("  message ignored by %d", tid);
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

  DBG("Finalizing ttable_lock.");
  pthreadex_lock_fini(&ttable_lock);

  mqueue_fini();

  DBG("tea timer finished.");
}

void tea_init(void)
{
  dosis_atexit("TEA", tea_fini);

  pthreadex_lock_init(&ttable_lock);
  pthreadex_lock_name(&ttable_lock, "ttable-lock");
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
  pthreadex_timer_name(&teatimer, "teatimer");

  for(cmd = program; !cfg.finalize && cmd; cmd = cmd->command.next)
  {
    /* wait until command is prepared to be executed */
    ctime = tea_time_get() - stime;

    if(cmd->command.time)
    {
      ntime = script_get_float(cmd->command.time->ntime.n);
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
          char *val = script_get_string(cmd->command.setvar.val);
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

