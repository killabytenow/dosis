/*****************************************************************************
 * ipqex.h
 *
 * ip_queue extended.
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

#ifndef __IPQEX_H__
#define __IPQEX_H__

#include <config.h>

#define ipqex_msg_errstr(x)           ((x)->s < 0 ? (x)->e : 0)
#define ipqex_identify_ip_protocol(x) (((struct iphdr *)                  \
                                        (x)->m->payload)->protocol)
#define ipqex_get_ip_header(x)        ((struct iphdr *) (x)->m->payload)
#define ipqex_get_tcp_header(x)       ((struct tcphdr *) ((x)->m->payload \
                                      + (((struct iphdr *)                \
                                          (x)->m->payload)->ihl << 2)))
#define ipqex_set_verdict(x,y)        ipq_set_verdict((x)->i->ipqh,       \
                                                      (x)->m->packet_id,  \
                                                      (y), 0, NULL)

typedef struct _tag_ipqex_info_t {
  struct ipq_handle *ipqh;    /* ipq handle                  */
  int                bufsize; /* buffer size                 */
} ipqex_info_t;

typedef struct _tag_ipqex_msg_t {
  ipqex_info_t     *i;        /* pointer to IPQ handler info */
  int               s;        /* state (0 w/o data)          */
  unsigned char    *b;        /* packet buffer               */
  union {
    ipq_packet_msg_t *m;      /* (state > 0) packet msg      */
    int               e;      /* (state < 0) error msg       */
  };
} ipqex_msg_t;

int ipqex_init_mode(ipqex_info_t *i, int bufsize, int mode);
int  ipqex_init(ipqex_info_t *i, int bufsize);
int  ipqex_msg_init(ipqex_msg_t *m, ipqex_info_t *i);
int  ipqex_msg_read(ipqex_msg_t *m, int timeout);
void ipqex_msg_destroy(ipqex_msg_t *m);
void ipqex_destroy(ipqex_info_t *i);

#endif
