/*****************************************************************************
 * listener.c
 *
 * Raw IPQ listener (used by raw listeners like tcpopen).
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

#include <config.h>
#include "dosconfig.h"
#include "ipqex.h"
#include "listener.h"
#include "log.h"
#include "tea.h"

#if 0
#include "dosis.h"
#include "tcpopen.h"
#include "lnet.h"
#include "pthreadex.h"
#include "ip.h"
#endif

#define BUFSIZE 65535

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

static ipqex_info_t      ipq;
static pthreadex_mutex_t ipq_mutex;

/*****************************************************************************
 * GLOBAL INITIALIZATION
 *****************************************************************************/

static void listener__global_fini(void)
{
  ipqex_destroy(&ipq);
  pthreadex_mutex_destroy(&ipq_mutex);
}

static void listener__global_init(void)
{
  /* set the finalization routine */
  if(atexit(listener__global_fini))
    D_FAT("Cannot set finalization routine.");

  /* init mutex */
  pthreadex_mutex_init(&ipq_mutex);

  /* initialize ipq */
  DBG("[%s] Initializing ipq.", teaLISTENER.name);
  if(ipqex_init(&ipq, BUFSIZE))
    FAT("[%s]  !! Cannot initialize IPQ.", teaLISTENER.name);

  DBG("[%s] Initialized.", teaLISTENER.name);
}

/*****************************************************************************
 * LISTENER THREAD
 *****************************************************************************/

static void listener__thread(THREAD_WORK *tw)
{
  ipqex_msg_t imsg;
  TEA_MSG *tmsg;
  int id;
  int r;

  /* get packets and classify */
  while(!cfg.finalize)
  {
    pthreadex_mutex_begin(&ipq_mutex);
    r = ipqex_msg_read(&imsg, 0);
    if(r < 0)
      ERR("Error reading from IPQ: %s (errno %s)", ipq_errstr(), strerror(errno));
    pthreadex_mutex_end();
    if(r <= 0)
      continue;

repeat_search:
    id = tea_thread_search_listener((char *) imsg.m->payload, imsg.m->data_len);
    if(id >= 0)
    {
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
      tmsg = tea_msg_get();
      tea_msg_fill(tmsg, (char *) imsg.m->payload, imsg.m->data_len);
      r = tea_thread_msg_push(id, tmsg);
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
      pthread_testcancel();
      /* if the msg cannot be pushed... repeat this until it is pushed */
      if(r < 0)
      {
        tea_msg_release(tmsg);
        goto repeat_search;
      }
    } else {
#warning "decide here the best policy for not handled packets in IPQ."
      pthreadex_mutex_begin(&ipq_mutex);
      if(ipqex_set_verdict(&imsg, NF_DROP) <= 0)
        ERR("Cannot DROP IPQ packet.");
      pthreadex_mutex_end();
#if 0
      /* policy: accept anything unknown */
      if(ipqex_set_verdict(&tw->msg, NF_ACCEPT) <= 0)
        ERR("[LL_%02u] Cannot ACCEPT IPQ packet.", tw->w->id);
#endif
    }
  }
}

static void listener__cleanup(THREAD_WORK *tw)
{
  DBG("[%02u] Finalized.", tw->id);
}

static int listener__configure(THREAD_WORK *tw, SNODE *command)
{
  return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * LISTENER TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaLISTENER = {
  .name        = "LISTENER",
  .global_init = listener__global_init,
  .configure   = listener__configure,
  .cleanup     = listener__cleanup,
  .thread      = listener__thread,
};

