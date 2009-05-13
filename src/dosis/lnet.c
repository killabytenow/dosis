/*****************************************************************************
 * libnet.c
 *
 * Libnet funcs.
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
#include "lnet.h"
#include "log.h"

void ln_init_context(LN_CONTEXT *lnc)
{
  char lnet_errbuf[LIBNET_ERRBUF_SIZE];

  if((lnc->ln = libnet_init(LIBNET_RAW4, NULL, lnet_errbuf)) == NULL)
    FAT("Cannot initialize libnet: %s", lnet_errbuf);
  lnc->tcp_p = LIBNET_PTAG_INITIALIZER;
  lnc->ipv4_p = LIBNET_PTAG_INITIALIZER;
  lnc->ip_id = libnet_get_prand(LIBNET_PRu32);

  if(libnet_seed_prand(lnc->ln) < 0)
    FAT("Faild to initialize libnet pseudorandom number generator.");
}

void ln_destroy_context(LN_CONTEXT *lnc)
{
  if(lnc->ln)
    libnet_destroy(lnc->ln);
}

void ln_send_packet(LN_CONTEXT *lnc,
                    struct in_addr *shost, int sport,
                    struct in_addr *dhost, int dport,
                    int flags, int window,
                    int seq, int ack,
                    char *data, int data_sz)
{
  int ip_size, tcp_size;

  if(!data_sz)
    data = NULL;
  tcp_size = LIBNET_TCP_H + data_sz;
  ip_size  = LIBNET_IPV4_H + tcp_size;

  /* build TCP packet with payload (if requested) */
  lnc->tcp_p =
    libnet_build_tcp(
      sport,                    /* source port                               */
      dport,                    /* destination port                          */
      seq,                      /* sequence number                           */
      ack,                      /* acknowledgement number                    */
      flags,                    /* control flags                             */
      window,                   /* window size                               */
      0,                        /* sum checksum (0 for libnet to autofill)   */
      0,                        /* urgent pointer                            */
      tcp_size,                 /* len total length of the TCP packet        */
      (unsigned char *) data,   /* payload                                   */
      data_sz,                  /* payload size                              */
      lnc->ln,                  /* libnet context                            */
      lnc->tcp_p);              /* protocol tag to modify an existing header */
  if(lnc->tcp_p == -1)
    FAT("Can't build TCP header: %s", libnet_geterror(lnc->ln));

  /* build container IP packet */
  lnc->ipv4_p =
      libnet_build_ipv4(
        ip_size,             /* total length of packet (including data) */
        0x00,                /* type of service bits                    */
        lnc->ip_id++,        /* IP identification number                */
        0x4000,              /* fragmentation bits and offset           */
        64,                  /* time to live in the network             */
        IPPROTO_TCP,         /* upper layer protocol                    */
        0,                   /* checksum (0 for libnet to autofill)     */
        shost->s_addr,       /* source IPv4 address (little endian)     */
        dhost->s_addr,       /* destination IPv4 address (little endian)*/
        NULL,                /* payload                                 */
        0,                   /* payload length                          */
        lnc->ln,             /* libnet context                          */
        lnc->ipv4_p);        /* tag to modify an existing header        */
  if(lnc->ipv4_p == -1)
    FAT("Can't build IP header: %s", libnet_geterror(lnc->ln));

  /* send! */
  if(libnet_write(lnc->ln) == -1)
    FAT("Error sending packet: %s", libnet_geterror(lnc->ln));
}

