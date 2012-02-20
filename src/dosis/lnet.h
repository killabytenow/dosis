/*****************************************************************************
 * libnet.c
 *
 * Libnet funcs.
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

#ifndef __LNET_H__
#define __LNET_H__

#include <config.h>

#include "ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/* protocol headers - inherited from BSD flavors */
typedef struct __tag_LN_HDR_TCP
{
  u_int16_t th_sport;    /* source port */
  u_int16_t th_dport;    /* destination port */
  u_int32_t   th_seq;    /* sequence number */
  u_int32_t   th_ack;     /* acknowledgement number */
  union {
    u_int8_t    th_off_x2;
    struct {
#ifdef WORDS_BIGENDIAN
      u_int8_t  th_off:4;    /* data offset */
      u_int8_t  th_x2:4;     /* (unused) */
#else
      u_int8_t  th_x2:4;    /* (unused) */
      u_int8_t  th_off:4;    /* data offset */
#endif
    };
  };
  union {
    u_int8_t  th_flags;
    struct {
#ifdef WORDS_BIGENDIAN
      u_int8_t res2:2;
      u_int8_t urg:1;
      u_int8_t ack:1;
      u_int8_t psh:1;
      u_int8_t rst:1;
      u_int8_t syn:1;
      u_int8_t fin:1;
#else
      u_int8_t fin:1;
      u_int8_t syn:1;
      u_int8_t rst:1;
      u_int8_t psh:1;
      u_int8_t ack:1;
      u_int8_t urg:1;
      u_int8_t res2:2;
#endif
    };
  };
  u_int16_t th_win;    /* window */
  u_int16_t th_sum;    /* checksum */
  u_int16_t th_urp;    /* urgent pointer */
} LN_HDR_TCP;
#define LN_TH_FIN  0x01
#define LN_TH_SYN  0x02
#define LN_TH_RST  0x04
#define LN_TH_PUSH  0x08
#define LN_TH_ACK  0x10
#define LN_TH_URG  0x20

typedef struct __tag_LN_HDR_UDP
{
  u_int16_t uh_sport;    /* source port */
  u_int16_t uh_dport;    /* destination port */
  u_int16_t uh_ulen;    /* udp length */
  u_int16_t uh_sum;    /* udp checksum */
} LN_HDR_UDP;

typedef struct __tag_LN_HDR_IPV4
{
#ifdef WORDS_BIGENDIAN
  unsigned int version:4;
  unsigned int ihl:4;
#else
  unsigned int ihl:4;
  unsigned int version:4;
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
#define LN_HDR_IPV4_RF 0x8000      /* reserved fragment flag */
#define LN_HDR_IPV4_DF 0x4000      /* dont fragment flag */
#define LN_HDR_IPV4_MF 0x2000      /* more fragments flag */
#define LN_HDR_IPV4_OFFMASK 0x1fff /* mask for fragmenting bits */
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  /*The options start here. */
} __attribute__((__may_alias__)) LN_HDR_IPV4;

typedef struct __tag_LN_HDR_IPV6
{
  union {
    struct ip6_hdrctl {
      uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                  20 bits flow-ID */
      uint16_t ip6_un1_plen;   /* payload length */
      uint8_t  ip6_un1_nxt;    /* next header */
      uint8_t  ip6_un1_hlim;   /* hop limit */
    } ip6_un1;
    uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } ip6_ctlun;
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
} __attribute__((__may_alias__)) LN_HDR_IPV6;

/*****************************************************************************
 * libnet mngmnt and packet forgering
 *****************************************************************************/

typedef struct _tag_LN_CONTEXT {
  /* raw sockets */
  int           rs;
  void         *buff;
  int           buff_size;
} LN_CONTEXT;

#define LN_DEFAULT_BUFF_SIZE    4096

void ln_init_context(LN_CONTEXT *lnc);
void ln_destroy_context(LN_CONTEXT *lnc);

int ln_build_ip_packet(void *buff,
                       INET_ADDR *shost,
                       INET_ADDR *dhost,
                       int proto,
                       int ip_id, int frag_off,
                       char *data, int datasz,
                       int *pdata);
int ln_build_ip_tcp_packet(void *buff,
                           INET_ADDR *shost, int sport,
                           INET_ADDR *dhost, int dport,
                           int ip_id, int frag_off,
                           int flags, int window,
                           int seq, int ack,
                           char *data, int datasz,
                           char *opts, int optssz,
                           char *pdata);
int ln_build_ip_udp_packet(void *buff,
                           INET_ADDR *shost, int sport,
                           INET_ADDR *dhost, int dport,
                           int ip_id, int frag_off,
                           char *data, int datasz,
                           char *pdata);
int ln_send_packet(LN_CONTEXT *lnc, void *buff, int sz, INET_ADDR *sa);

int ln_send_tcp_packet(LN_CONTEXT *lnc,
                       INET_ADDR *shost, int sport,
                       INET_ADDR *dhost, int dport,
                       int ip_id, int frag_off,
                       int flags, int window,
                       int seq, int ack,
                       char *data, int datasz,
                       char *opts, int optssz);
int ln_send_udp_packet(LN_CONTEXT *lnc,
                       INET_ADDR *shost, int sport,
                       INET_ADDR *dhost, int dport,
                       int ip_id, int frag_off,
                       char *data, int datasz);
                    
/*****************************************************************************
 * seq number generators
 *
 *   NEXT_PORT      - Programmable number generator (depends on p)
 *   NEXT_SEQ_PORT  - Totally sequential number generator (0, 1, 2, 3, ...)
 *   NEXT_SSEQ_PORT - The Strange Sequence [TM] (65535, 0, 65534, 1, ...)
 *   NEXT_RAND_PORT - Pseudo-random sequence (totally impredictable x"D)
 *****************************************************************************/

#define NEXT_PORT(n,p)      (((n) + (p)) & 0x0000ffff)
#define NEXT_SEQ_PORT(n)    NEXT_PORT(n,1)
#define NEXT_SSEQ_PORT(n)   NEXT_PORT(n,2147483647)
#define NEXT_RAND_PORT(n)   NEXT_PORT(n,805315183)

unsigned ln_get_next_seq_random_port_number(unsigned *n);
unsigned ln_get_next_random_port_number(unsigned *n);

/*****************************************************************************
 * IP/TCP/UDP helpers
 *****************************************************************************/

/* IP/IPv6 helper macros */
#define IP_VERSION(x)          (((*((unsigned char *) (x))) >> 4) & 0x0f)

/* IPv4 helper macros */
#define IPV4_DATA(x)           ((void *) ((x) + IPV4_HDRSZ(x)))
#define IPV4_HDR(x)            ((LN_HDR_IPV4 *)  (x))
#define IPV4_HDRCK(b,s)        (s >= sizeof(LN_HDR_IPV4) && IP_VERSION(b) == 4)
#define IPV4_HDRSZ(x)          (IPV4_HDR(x)->ihl << 2)
#define IPV4_PROTOCOL(x)       (((LN_HDR_IPV4 *) (x))->protocol)
#define IPV4_SADDR(x)          (IPV4_HDR(x)->saddr)
#define IPV4_TADDR(x)          (IPV4_HDR(x)->daddr)
#define IPV4_SADDR_P(p,x)      INET_ADDR_IPV4_GETP(p, IPV4_SADDR(x))
#define IPV4_TADDR_P(p,x)      INET_ADDR_IPV4_GETP(p, IPV4_TADDR(x))

/* TCPoIPv4 helper macros */
#define IPV4_TCP_DATA(x)       ((void *) (x)                                  \
                                       + IPV4_HDRSZ(x)                        \
                                       + IPV4_TCP_HDRSZ(x))
#define IPV4_TCP_OPTS(x)       ((void *) (x)                                  \
                                       + IPV4_HDRSZ(x)                        \
                                       + sizeof(LN_HDR_TCP))
#define IPV4_TCP_HDR(x)        ((LN_HDR_TCP *) (IPV4_DATA(x)))
#define IPV4_TCP_HDRSZ(x)      (IPV4_TCP_HDR(x)->th_off << 2)
#define IPV4_TCP_HDRCK(b,s)    (IPV4_HDRCK(b,s)                               \
                               && IPV4_PROTOCOL(b) == 6                       \
                               && s >= (sizeof(LN_HDR_TCP) + IPV4_HDRSZ(b))   \
                               && s >= (IPV4_TCP_HDRSZ(b) + IPV4_HDRSZ(b)))
#define IPV4_TCP_DPORT(x)      ntohs(IPV4_TCP_HDR(x)->th_dport)
#define IPV4_TCP_SPORT(x)      ntohs(IPV4_TCP_HDR(x)->th_sport)
#define IPV4_TCP_ACK(x)        ntohl(IPV4_TCP_HDR(x)->th_ack)
#define IPV4_TCP_SEQ(x)        ntohl(IPV4_TCP_HDR(x)->th_seq)

/* UDPoIPv4 helper macros */
#define IPV4_UDP_HDR(x)        ((LN_HDR_UDP *) (IPV4_DATA(x)))
#define IPV4_UDP_HDRCK(b,s)    (IPV4_HDRCK(b,s)                               \
                               && IPV4_PROTOCOL(b) == 17                      \
                               && s >= (sizeof(LN_HDR_UDP) + IPV4_HDRSZ(b)))
#define IPV4_UDP_DPORT(x)      ntohs(IPV4_UDP_HDR(x)->uh_dport)
#define IPV4_UDP_SPORT(x)      ntohs(IPV4_UDP_HDR(x)->uh_sport)

void *ln_tcp_get_opt(void *msg, int sz, int sopt);
int ln_tcp_get_mss(void *msg, int sz);

void ln_dump_msg(int level, char *file, char *func, int line, char *prefix, int proto, void *p, int s);

#ifdef __cplusplus
}
#endif

#endif
