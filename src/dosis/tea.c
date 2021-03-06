/*****************************************************************************
 * tea.c
 *
 * Is now the tea time?
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2009 Gerardo Garc�a Pe�a <gerardo@kung-foo.net>
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

#include "pills/ignorer.h"
#include "pills/listener.h"
#include "pills/sender.h"
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

  /* do thread cleanup */
  TDBG2("[tea-cleanup] Thread final cleanup started.");
  if(tw->to->cleanup)
    tw->to->cleanup(tw);

  if(tw->data != NULL)
  {
    free(tw->data);
    tw->data = NULL;
  }

  /* disassociate mqueue of tw and destroy it */
  if(tw->to->listener || tw->to->sender)
  {
    pthreadex_mutex_begin(&(tw->mqueue->mutex));
    TDBG2("[tea-cleanup] listener/sender cleanup");
    mq = tw->mqueue;
    tw->mqueue = NULL;
    pthreadex_mutex_end();

    if(mq)
    {
      TDBG2("[tea-cleanup] mqueue cleanup");
      mqueue_destroy(mq);
    }
  }

  TDBG("[tea-cleanup] Thread finished.");
  pthreadex_flag_up(&(tw->cleanup_done));
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
  TDBG("[tea-thread] Starting thread main function");
  tw->to->thread(tw);
  TDBG("[tea-thread] Thread main function finished.");

  /* wait until the correct die moment */
  TDBG2("[tea-thread] Waiting for cleanup approval...");
  while( pthreadex_flag_wait_timeout(&(tw->cleanup_do), 1000))
  {
    TDBG2("[tea-thread]  ...");
  }

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);

  return NULL;
}

static int tea_thread_param_value_set(THREAD_WORK *tw, TEA_OBJCFG *oc, SNODE *v)
{
  char *s;
  void *pdata = tw->data + oc->offset;

  /* save into config hash */
  hash_entry_add_or_set(tw->options, oc->name, v ? pdata : NULL, NULL);
  if(!v)
    return 0;

  /* check tea object */
  switch(oc->type)
  {
    case TEA_TYPE_ADDR_PORT_ID:
      {
        int port;
        TEA_TYPE_ADDR_PORT *a = pdata;

        if(v->type != TYPE_ADDR_PORT)
          TFAT("Found node '%d' when TYPE_ADDR_PORT was expected.", v->type);

        s = script_get_string(v->addr_port.addr);
        if(ip_addr_parse(s, &a->addr, &port))
          TFAT("%d: Cannot parse address '%s'.", v->line, s);
        if(port >= 0)
        {
          a->port = port;
          if(v->addr_port.port != NULL)
            TWRN("%d: port defined twice (alo defined in addr:port).", v->line);
        }
        if(v->addr_port.port != NULL)
          a->port = script_get_int(v->addr_port.port);
        free(s);
      }
      break;

    case TEA_TYPE_BOOL_ID:
      *((TEA_TYPE_INT *) pdata) = script_get_bool(v);
      break;

    case TEA_TYPE_INT_ID:
      *((TEA_TYPE_INT *) pdata) = script_get_int(v);
      break;

    case TEA_TYPE_FLOAT_ID:
      *((TEA_TYPE_FLOAT *) pdata) = script_get_float(v);
      break;

    case TEA_TYPE_DATA_ID:
      {
        TEA_TYPE_DATA *d = pdata;
        d->data = script_get_data(v, &d->size);
      }
      break;

    case TEA_TYPE_STRING_ID:
      *((TEA_TYPE_STRING *) pdata) = script_get_string(v);
      break;

    default:
      ERR("Tea object %s, Parameter %s, unknown type %d.",
          tw->to->name, oc->name, oc->type);
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

#define FATAL_ERROR(...)  { ERR(__VA_ARGS__); fatal = 1; goto termination; }
static void tea_thread_new(int tid, TEA_OBJECT *to, SNODE *command)
{
  THREAD_WORK *tw = NULL;
  TEA_OBJCFG *ocline;
  HASH_ITER hi;
  HASH_NODE *hn;
  int fatal = 0;

  DBG("[tea] Creating thread %d.", tid);
  if((tw = calloc(1, sizeof(THREAD_WORK))) == NULL)
    FAT("Cannot alloc THREAD_WORK struct for thread %d.", tid);

  tw->id         = tid;
  tw->pthread_id = 0;
  tw->to         = to;
  tw->options    = hash_copy(command->command.thc.to->options);

  /* check methods */
  if(tw->to->listener || tw->to->sender)
    tw->mqueue = mqueue_create();
  pthreadex_flag_init(&(tw->mwaiting), 0);
  pthreadex_flag_name(&(tw->mwaiting), "mwaiting");
  pthreadex_flag_init(&(tw->cleanup_do), 0);
  pthreadex_flag_name(&(tw->cleanup_do), "cleanup_do");
  pthreadex_flag_init(&(tw->cleanup_done), 0);
  pthreadex_flag_name(&(tw->cleanup_done), "cleanup_done");

  /* global thread initialization here */
  if(tw->to->global_init && !tw->to->initialized)
  {
    tw->to->initialized = -1;
    tw->to->global_init();
  }

  /* make space for thread data */
  if((tw->data = calloc(1, to->datasize)) == NULL)
    FAT("%d:%s: No memory for thread data.", command->line, to->name);

  /* check config params */
  if(to->cparams)
  {
    /* check only allowed params are defined */
    for(hn = hash_iter_first(&hi, command->command.thc.to->options);
        !hash_iter_finished(&hi);
        hn = hash_iter_next(&hi))
    {
      /* iterate all allowed params and stop if (1) declared  */
      /* parameter hn->key is found in allowed paramter list, */
      /* or (2) stop if there is not moar allowed params      */
      for(ocline = to->cparams;
          ocline->name && strcasecmp(hn->key, ocline->name);
          ocline++)
        ;
      if(!ocline->name)
        FAT("%d:%s: Parameter %s not allowed here.", command->line, to->name, hn->key);
    }

    /* set params (apply configuration) */
    for(ocline = to->cparams; ocline->name; ocline++)
    {
      SNODE *val;

      /* get configured value (or set default value if not specified) */
      val = tea_thread_param_value_get(tw->options, ocline->name);

      /* check if parameter is optional */
      if(!val && ocline->needed)
        FAT("%d:%s: Parameter %s is mandatory.", command->line, to->name, ocline->name);

      /* set value */
      if(tea_thread_param_value_set(tw, ocline, val))
        FAT("%d:%s: Cannot set parameter %s.", command->line, to->name, ocline->name);
    }
  } else {
    if(command->command.thc.to->options
    || command->command.thc.to->options->nentries > 0)
      FAT("%d:%s: Parameters not allowed for this type of thread.", command->line, to->name);
  }

  /* once configuration applied, launch thread configuration routine */
  if(tw->to->configure
  && tw->to->configure(tw, command, 1))
      FAT("%d:%s: Thread configuration failed.", command->line, to->name);

  /* add thread to the list */
  pthreadex_lock_get_exclusive_n(&ttable_lock, "install-thread");
  DBG("[tea] Installing thread %d.", tid);

  /* build threads */
  if(ttable[tid])
    FATAL_ERROR("Thread slot %d is used already.", tid);
  ttable[tid] = tw;

  /* launch thread */
  if(pthread_create(&(tw->pthread_id), NULL, tea_thread, tw) != 0)
  {
    ERR_ERRNO("Error creating thread %d", tid);
    FATAL_ERROR("Fatal error happened during thread creation.");
  }

termination:
  if(fatal && tw)
  {
    if(ttable[tid] == tw)
      ttable[tid] = NULL;
    if(tw->mqueue)
      mqueue_destroy(tw->mqueue);
    pthreadex_flag_destroy(&(tw->mwaiting));
    pthreadex_flag_destroy(&(tw->cleanup_do));
    pthreadex_flag_destroy(&(tw->cleanup_done));
    free(tw);
  }

  pthreadex_lock_release();
  
  if(!fatal)
    return;

  FAT("Aborting.");
}

static void tea_thread_stop(int tid)
{
  THREAD_WORK *tw;
  int r;

  /* wait until we have exclusive access right on ttable */
  DBG("[tea] Thread %d killing scheduled.", tid);
  pthreadex_lock_get_exclusive_n(&ttable_lock, "kill-thread");

  /* going to kill thread */
  tw = ttable[tid];
  pthreadex_lock_release();

  if(tw != NULL)
  {
    DBG("[tea] Killing thread %d.", tid);

    /* consider it dead */
    ttable[tid] = NULL;

    /* allow thread to do the cleanup */
    DBG2("[tea] Approve cleanup...");
    pthreadex_flag_up(&(tw->cleanup_do));

    while((r = pthread_cancel(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("[tea] Cancel EINTR; repeating pthread_cancel() on %d", tid);
      errno = 0;
    }
    if(r != 0)
      ERR_ERRNO("[tea] Cannot cancel thread %d", tid);

    /* kill thread */
    while((r = pthread_detach(tw->pthread_id)) != 0 && errno == EINTR)
    {
      DBG("[tea] Detach EINTR; repeating pthread_detach() on  %d", tid);
      errno = 0;
    }
    if(r != 0)
      ERR_ERRNO("[tea] Cannot detach thread %d", tid);

    /* wait cleanup finishes */
    DBG2("[tea] Wait cleanup termination...");
    pthreadex_flag_wait(&(tw->cleanup_done));

    DBG("[tea] THREAD %d KILLED!", tid);

    /* destroy flags && free mem */
    pthreadex_flag_destroy(&(tw->mwaiting));
    pthreadex_flag_destroy(&(tw->cleanup_do));
    pthreadex_flag_destroy(&(tw->cleanup_done));
    free(tw);
  } else
    ERR("[tea] Thread %d does not exist or died voluntarely.", tid);
}

int tea_thread_listener_search(int proto, char *b, unsigned int l, int pivot_id)
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
    && ttable[tid]->to->listen_check
    && (prio = ttable[tid]->to->listen_check(ttable[tid], proto, b, l)) != 0)
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

  while((m = mqueue_shift(tw->mqueue)) == NULL)
    pthreadex_flag_wait(&tw->mwaiting);

  return m;
}

int tea_thread_msg_push(int tid, INET_ADDR *addr, void *msg, int msg_size)
{
  TEA_MSG *tmsg;
  int r = 0;

  pthreadex_lock_get_shared(&ttable_lock);

  if(ttable[tid])
  {
    if(ttable[tid]->mqueue)
    {
      tmsg = msg_get();
      if(addr)
         msg_set_addr(tmsg, addr);
      msg_fill(tmsg, msg, msg_size);
      mqueue_push(ttable[tid]->mqueue, tmsg);
      pthreadex_flag_up(&(ttable[tid]->mwaiting));
    } else
      DBG("[tea] network message ignored by %d", tid);
  } else
    r = -1;

  pthreadex_lock_release();
  
  return r;
}

int tea_thread_msg_send(LN_CONTEXT *lnc, TEA_MSG *m, int delay)
{
  static int pivot_id = 0;
  int tid = 0;

  if(delay > 0 || !lnc)
  {
    if(delay > 0)
    {
      /* calculate when */
      if(clock_gettime(CLOCK_REALTIME, &m->w) < 0)
      {
        ERR_ERRNO("Cannot read CLOCK_REALTIME.");
        return -1;
      }
      DBG2("[tea] Now is %ld.%09ld", m->w.tv_sec, m->w.tv_nsec);
      m->w.tv_nsec += (delay % 1000) * 1000000;;
      m->w.tv_sec  += (delay / 1000) * 1000000;
      if(m->w.tv_nsec > 1000000000)
      {
        m->w.tv_sec  += m->w.tv_nsec / 1000000000;
        m->w.tv_nsec %= 1000000000;
      }
    } else {
      /* normal people send directly */
      m->w.tv_nsec = 0;
      m->w.tv_sec  = 0;
    }
    DBG("[tea] Packet queued and delayed until %ld.%09ld secs", m->w.tv_sec, m->w.tv_nsec);

    /* search sender and insert msg into its queue */
    pthreadex_lock_get_shared(&ttable_lock);
    tid = pivot_id < 0 ? 0 : pivot_id;
    do {
      if(++tid >= cfg.maxthreads)
        tid = 0;
      if(ttable[tid] && ttable[tid]->to->sender)
      {
        /* insert into queue in correct order */
        DBG2("[tea] Selected sender thread %d.", tid);
        mqueue_insert_delayed(ttable[tid]->mqueue, m);
        pthreadex_flag_up(&(ttable[tid]->mwaiting));
        m = NULL;
        break;
      }
    } while(tid != pivot_id);
    pivot_id = tid;
    pthreadex_lock_release();
  }

  /* if msg was not queued, then send it directly */
  if(m)
  {
    if(lnc)
    {
      DBG("[tea] Packet is being sent now");
      ln_send_packet(lnc, m->b, m->s, &m->dest);
    } else
      WRN("[tea] Cannot send message (lnc neither sender thread available).");
  }

  return 0;
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
    DBG("[tea] The begining of the end");
    DBG("[tea]   - Cancelling all threads.");
    for(i = 0; i < cfg.maxthreads; i++)
      if(ttable[i])
        tea_thread_stop(i);
    DBG("[tea]   - All threads cancelled.");

    /* free mem */
    free(ttable);
  }

  DBG("[tea] Finalizing ttable_lock.");
  pthreadex_lock_fini(&ttable_lock);

  mqueue_fini();

  DBG("[tea] tea timer finished.");
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

      LOG("[tea] Now it is %.2f seconds from the begining of time.", tea_time_get() - stime);
    }
    ltime = ctime;

    if(cfg.finalize)
      break;

    /* launch command */
    switch(cmd->type)
    {
      case TYPE_CMD_MOD:
        FAT("Thread modify not implemented yet.");
        break;

      case TYPE_CMD_ON:
        for(tid = tea_iter_start(cmd->command.thc.selection, &ti);
            !tea_iter_finish(&ti);
            tid = tea_iter_next(&ti))
        {
          switch(cmd->command.thc.to->type)
          {
            case TYPE_TO_IGNORE:  to = &teaIGNORER; break;
            case TYPE_TO_LISTEN:  to = &teaLISTENER; break;
            case TYPE_TO_TCPOPEN: to = &teaTCPOPEN;  break;
            case TYPE_TO_TCP:     to = &teaTCP;      break;
            case TYPE_TO_TCPRAW:  to = &teaTCPRAW;   break;
            case TYPE_TO_UDP:     to = &teaUDP;      break;
            case TYPE_TO_ZWIN:    to = &teaSlowy;    break;
            case TYPE_TO_SLOW:    to = &teaSlowy;    break;
            case TYPE_TO_SEND:    to = &teaSENDER;   break;
            default:
              FAT("Unknown thread type %d.", cmd->command.thc.to->type);
          }
          LOG("[tea] %s thread %d of type %s.",
              cmd->type == TYPE_CMD_ON ? "Started" : "Modified",
              tid, to->name);
          tea_thread_new(tid, to, cmd);
        }
        break;

      case TYPE_CMD_OFF:
        for(tid = tea_iter_start(cmd->command.thc.selection, &ti);
            !tea_iter_finish(&ti);
            tid = tea_iter_next(&ti))
          if(ttable[tid])
          {
            LOG("[tea] Stopped thread %d of type %s.", tid, ttable[tid]->to->name);
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
    WRN("[tea] Attack cancelled by user.");

  /* free memory */
  DBG("[tea] Script finished.");
  //pthreadex_timer_destroy(&timer);
}

