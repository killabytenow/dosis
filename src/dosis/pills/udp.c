/*****************************************************************************
 * udp.c
 *
 * UDP packet generator.
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
#include "tea.h"

typedef struct _tag_UDP_CFG {
  /* parameters */
  TEA_TYPE_ADDR          dhost;
  TEA_TYPE_INT           pattern;
  TEA_TYPE_DATA          payload;
  TEA_TYPE_FLOAT         hitratio;
  TEA_TYPE_INT           npackets;
  TEA_TYPE_ADDR          shost;

  /* other things */
  pthreadex_timer_t  timer;
  LN_CONTEXT         lnc;
} UDP_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

#if 0
/* the best from performance view is to do nothing */
static int udp__listen_check(THREAD_WORK *tw, int proto, char *msg, unsigned int size)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  switch(proto)
  {
    case INET_FAMILY_IPV4:
      /* check msg size and headers */
      if(size < sizeof(struct iphdr)
      || IP_PROTOCOL(msg) != 17
      || size < sizeof(struct udphdr) + (IP_HEADER(msg)->ihl << 2))
        return 0;

      /* check msg */
TDBG("[%s]   VEREDICT: %d (%x, %d) [%x, %d]",
       tw->methods->name,
       IP_HEADER(msg)->saddr == tu->dhost.addr.in.addr
       && ntohs(UDP_HEADER(msg)->source) == tu->dhost.port,
       IP_HEADER(msg)->saddr, ntohs(UDP_HEADER(msg)->source),
       tu->dhost.addr.in.addr, tu->dhost.port);
        return IP_HEADER(msg)->saddr == tu->dhost.addr.in.addr
            && ntohs(UDP_HEADER(msg)->source) == tu->dhost.port
               ? -255 : 0;

    case INET_FAMILY_IPV6:
#warning "IPv6 not implemented."
      return 0;
  }

  return 0;
}
#endif

static void udp__thread(THREAD_WORK *tw)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;
  int i;
  unsigned sport, dport;

  sport = dport = 1337;

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tu->hitratio > 0)
      if(pthreadex_timer_wait(&(tu->timer)) < 0)
        TERR_ERRNO("Error at pthreadex_timer_wait()");

    /* build UDP packet with payload (if requested) */
    TDBG2("Sending %d packet(s)...", tu->npackets);
    for(i = 0; i < tu->npackets; i++)
    {
      sport = tu->shost.port >= 0
                ? tu->shost.port
                : NEXT_RAND_PORT(sport);
      dport = tu->dhost.port >= 0
                ? tu->dhost.port
                : NEXT_RAND_PORT(dport);
TDBG2(" --1- sport[%d] [next=%d]", sport, NEXT_RAND_PORT(sport));
      ln_send_udp_packet(&tu->lnc,
                         &tu->shost.addr, sport,
                         &tu->dhost.addr, dport,
                         tu->payload.data, tu->payload.size);
TDBG2(" --2- sport[%d]", sport);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int udp__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  /* first initialization (specialized work thread data) */
  if(first_time)
  {
    /* initialize lnet */
    ln_init_context(&tu->lnc);
    pthreadex_timer_init(&(tu->timer), 0.0);
    pthreadex_timer_name(&(tu->timer), "udp-timer");
  }

  /* configure src address (if not defined) */
  if(tu->shost.addr.type == INET_FAMILY_NONE
  && dos_get_source_address(&tu->shost.addr, &tu->dhost.addr))
    return -1;

  /* check params sanity */
  if(tu->pattern != TYPE_PERIODIC)
  {
    TERR("Uknown pattern %d.", tu->pattern);
    return -1;
  }
  if(tu->npackets < 0)
    TWRN("Bad number of packets %d.", tu->npackets);
  if(tu->hitratio < 0)
  {
    TERR("Bad hit ratio '%f'.", tu->hitratio);
    return -1;
  }

  /* configure timer */
  if(tu->hitratio > 0)
    pthreadex_timer_set_frequency(&(tu->timer), tu->hitratio);

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.n     = %d", tu->npackets);
    TDBG2("config.periodic.ratio = %f", tu->hitratio);

    ip_addr_snprintf(&tu->shost.addr, tu->shost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.shost  = %s", buff);
    ip_addr_snprintf(&tu->dhost.addr, tu->dhost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost  = %s", buff);
  }

  return 0;
}

static void udp__cleanup(THREAD_WORK *tw)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  ln_destroy_context(&tu->lnc);
  pthreadex_timer_destroy(&tu->timer);

  if(tu->payload.data)
  {
    free(tu->payload.data);
    tu->payload.data = NULL;
  }

  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * UDP TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(udp_cfg_def)
  TOC("dst_addr",       TEA_TYPE_ADDR,   1, UDP_CFG, dhost,      NULL)
  TOC("dst_port",       TEA_TYPE_PORT,   0, UDP_CFG, dhost,      NULL)
  TOC("pattern",        TEA_TYPE_INT,    1, UDP_CFG, pattern,    NULL)
  TOC("payload",        TEA_TYPE_DATA,   0, UDP_CFG, payload,    NULL)
  TOC("periodic_ratio", TEA_TYPE_FLOAT,  1, UDP_CFG, hitratio,   NULL)
  TOC("periodic_n",     TEA_TYPE_INT,    1, UDP_CFG, npackets,   NULL)
  TOC("src_addr",       TEA_TYPE_ADDR,   0, UDP_CFG, shost,      NULL)
  TOC("src_port",       TEA_TYPE_PORT,   0, UDP_CFG, shost,      NULL)
TOC_END

TEA_OBJECT teaUDP = {
  .name         = "UDP",
  .datasize     = sizeof(UDP_CFG),
  .configure    = udp__configure,
  .cleanup      = udp__cleanup,
/*.listen_check = udp__listen_check,*/
  .thread       = udp__thread,
  .cparams      = udp_cfg_def
};

