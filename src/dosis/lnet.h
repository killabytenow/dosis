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

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * libnet mngmnt and packet forgering
 *****************************************************************************/

typedef struct _tag_LN_CONTEXT {
  libnet_t     *ln;
  int           ipv4_p;
  int           udp_p;
  int           tcp_p;
  int           ip_id;
} LN_CONTEXT;

void ln_init_context(LN_CONTEXT *ln);
void ln_destroy_context(LN_CONTEXT *lnc);
void ln_send_tcp_packet(LN_CONTEXT *lnc,
                        struct in_addr *shost, int sport,
                        struct in_addr *dhost, int dport,
                        int flags, int window,
                        int seq, int ack,
                        char *data, int data_sz,
                        char *opts, int opts_sz);
void ln_send_udp_packet(LN_CONTEXT *lnc,
                        struct in_addr *shost, int sport,
                        struct in_addr *dhost, int dport,
                        char *data, int data_sz);

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
#define NEXT_SSEQ_PORT(n)   NEXT_PORT(n,805315183)
#define NEXT_RAND_PORT(n)   NEXT_PORT(n,2147483647)

unsigned ln_get_next_seq_random_port_number(unsigned *n);
unsigned ln_get_next_random_port_number(unsigned *n);

/*****************************************************************************
 * IP/TCP/UDP helpers
 *****************************************************************************/

#define IP_PROTOCOL(x)      (((struct iphdr *) (x))->protocol)
#define IP_HEADER(x)        ((struct iphdr *)  (x))
#define IP_HEADER_SIZE(x)   (IP_HEADER(x)->ihl << 2)
#define TCP_HEADER(x)       ((struct tcphdr *) ((x) \
                            + (((struct iphdr *) (x))->ihl << 2)))
#define UDP_HEADER(x)       ((struct udphdr *) ((x) \
                            + (((struct iphdr *) (x))->ihl << 2)))
#define TCP_DATA(x)         ((void *) (x)                \
                            + (IP_HEADER(x)->ihl   << 2) \
                            + (TCP_HEADER(x)->doff << 2))

void *ln_tcp_get_opt(void *msg, int sz, int sopt);
int ln_tcp_get_mss(void *msg, int sz);

#ifdef __cplusplus
}
#endif

#endif
