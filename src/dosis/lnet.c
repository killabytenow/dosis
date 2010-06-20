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

#define C1_SUM(s, n) { unsigned long __c1_ts;                    \
                       __c1_ts = ((s) + ((unsigned) (n)));       \
                       s = (__c1_ts + (__c1_ts >> 16)) & 0xffff; \
                     }

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
  char err[1024];
  const int one = 1;

  if((lnc->rs = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
  {
    strerror_r(errno, err, sizeof(err));
    if(errno == EPERM)
    {
      ERR("-------------------------------------------------------------------------");
      ERR("This user doesn't have permission to open raw sockets. Only users with an");
      ERR("effective user ID of 0 (root) or the CAP_NET_RAW attribute may do that.");
      ERR("-------------------------------------------------------------------------");
    }
    FAT("Cannot open a raw socket: %s", err);
  }
  if(setsockopt(lnc->rs, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
  {
    strerror_r(errno, err, sizeof(err));
    FAT("Cannot set HDRINCL: %s", err);
  }
  if((lnc->buff = malloc(LN_DEFAULT_BUFF_SIZE)) == NULL)
    FAT("Cannot make space for local buffer.");
  lnc->buff_size = LN_DEFAULT_BUFF_SIZE;
}

void ln_destroy_context(LN_CONTEXT *lnc)
{
  if(lnc->rs >= 0)
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
  if(IPV4_TCP_HDRCK(msg, sz))
    return NULL;

  /* go to options section and process them */
  for(p = IPV4_TCP_OPTS(msg); p < IPV4_TCP_DATA(msg); )
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
    C1_SUM(sum, *buf++);
  return ~sum;
}

/*****************************************************************************
 * SENDING AND FORGING FUNCTIONS
 *****************************************************************************/

/*****************************************************************************
 * int ln_build_ip_packet(void *buff,
 *                        INET_ADDR *shost,
 *                        INET_ADDR *dhost,
 *                        int proto, int ip_id,
 *                        char *data, int datasz,
 *                        int *pdata)
 *
 * Description:
 *   Build an IP packet in buffer 'buff'. Returns packet size as return value,
 *   and in-packet data offset in parameter 'pdata'.
 *
 * Arguments:
 *   buff   - Pointer to output buffer. If NULL, nothing is written but packet
 *            size and pdata offset are returned.
 *   shost  - Source address (if it is zero, it will be filled with the correct
 *            address by kernel (see raw(7)))
 *   dhost  - Target address.
 *   proto  - Protocol encapsulated in IP packet.
 *   ip_id  - IP packet id (if zero, filled by kernel (see raw(7)).
 *   data   - Pointer to payload (if NULL function leave space, but nothing is
 *            copied)
 *   datasz - Size of payload
 *   pdata  - (output) It returns offset where payload starts. If NULL, nothing
 *            is returned.
 *****************************************************************************/

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
    psize   = sizeof(LN_HDR_IPV4) + datasz;
    poffset = sizeof(LN_HDR_IPV4);
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
      /* fill IPv4 header */
      ip.v4 = (struct ip *) buff;
      ip.v4->ip_hl  = 5;
      ip.v4->ip_v   = 4;
      ip.v4->ip_tos = 0;
      ip.v4->ip_len = htons(psize);
      ip.v4->ip_id  = htonl(ip_id); /* IP identification number                */
      ip.v4->ip_off = 0;
      ip.v4->ip_ttl = 255;
      ip.v4->ip_p   = proto;
      ip.v4->ip_src.s_addr = shost->addr.in.inaddr.s_addr;
      ip.v4->ip_dst.s_addr = dhost->addr.in.inaddr.s_addr;
      ip.v4->ip_sum = 0;

      /* copy data */
      if(data && datasz > 0)
        memcpy(buff + poffset, data, datasz);

      /* do checksum */
      ip.v4->ip_sum = ln_ip_checksum((unsigned short *) buff, 5 << 1);
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
                        INET_ADDR *shost, int sport,
                        INET_ADDR *dhost, int dport,
                        int flags, int window,
                        int seq, int ack,
                        char *data, int datasz,
                        char *opts, int optssz,
                        int *pdata)
{
  LN_HDR_TCP *tcph;
  int psize, poffset, i;
  unsigned long sum;

  /* calculate packet size and payload offset */
  poffset = ((5 + ((optssz + 3) >> 2)) << 2);
  psize   = poffset + datasz;
  if(pdata)
    *pdata = poffset;
  if(!buff)
    return psize;

  /* fill TCP header */
  tcph = (LN_HDR_TCP *) buff;
  tcph->th_sport = htons(sport);
  tcph->th_dport = htons(dport);
  tcph->th_seq   = seq;
  tcph->th_ack   = ack;
  tcph->th_x2    = 0;
  tcph->th_off   = 5 + ((optssz + 3) >> 2);
  tcph->th_flags = flags;
  tcph->th_win   = htons(window);
  tcph->th_sum   = 0;
  tcph->th_urp   = 0;

  /* copy flags and data */
  if(opts && optssz > 0)
    memcpy(buff + 20, opts, optssz);
  if(data && datasz > 0)
    memcpy(buff + poffset, data, datasz);

  /* [calculate cheksum] PSEUDO-HEADER */
  sum = 0;
  C1_SUM(sum, shost->addr.in.addr);
  C1_SUM(sum, dhost->addr.in.addr);
  C1_SUM(sum, 0x0600);
  C1_SUM(sum, htons(psize));
  /* [calculate cheksum] header+segment */
  if(psize & 0x1)
    C1_SUM(sum, ((char *) buff)[psize-1]);
  for(i = 0; i < psize; i += 2)
    C1_SUM(sum, *((unsigned short *) (buff + i)));
  /* [calculate cheksum] complement */
  tcph->th_sum = ~sum;

  return psize;
}

int ln_build_udp_packet(void *buff,
                        int sport, int dport,
                        char *data, int datasz,
                        int *pdata)
{
  LN_HDR_UDP *udph;

  if(pdata)
    *pdata = sizeof(LN_HDR_UDP);
  if(buff)
  {
    udph = (LN_HDR_UDP *) buff;
    udph->uh_sport = htons(sport);
    udph->uh_dport = htons(dport);
    udph->uh_ulen  = htons(sizeof(LN_HDR_UDP) + datasz);
    udph->uh_sum   = 0;
    if(data && datasz > 0)
      memcpy(buff + sizeof(LN_HDR_UDP), data, datasz);
  }

  return sizeof(LN_HDR_UDP) + datasz;
}

int ln_build_ip_tcp_packet(void *buff,
                           INET_ADDR *shost, int sport,
                           INET_ADDR *dhost, int dport,
                           int flags, int window,
                           int seq, int ack,
                           char *data, int datasz,
                           char *opts, int optssz,
                           char *pdata)
{
  int ip_size, tcp_size,
      tcp_offset, data_offset;

  /* calculate size */
  DBG("Calculate size...");
  if((tcp_size = ln_build_tcp_packet(NULL,
                                     shost, sport, dhost, dport,
                                     flags, window, seq, ack,
                                     NULL, datasz, opts, optssz,
                                     &data_offset)) < 0
  || (ip_size = ln_build_ip_packet(NULL, shost, dhost, 6, 0,
                                   NULL, tcp_size, &tcp_offset)) < 0)
    return -1;

  /* check space */
  DBG("Check space...");
  if(pdata)
    *pdata = tcp_offset + data_offset;
  if(!buff)
    return ip_size;

  /* buid packet */
  DBG("Build packet...");
  if(ln_build_tcp_packet(buff + tcp_offset,
                         shost, sport, dhost, dport,
                         flags, window, seq, ack,
                         data, datasz, opts, optssz,
                         NULL) < 0
  || ln_build_ip_packet(buff, shost, dhost, 6, 0, NULL, tcp_size, NULL) < 0)
    return -1;

  return ip_size;
}

int ln_build_ip_udp_packet(void *buff,
                           INET_ADDR *shost, int sport,
                           INET_ADDR *dhost, int dport,
                           char *data, int datasz,
                           char *pdata)
{
  int ip_size, udp_size,
      udp_offset, data_offset;

  /* calculate size */
  DBG("Calculate size...");
  if((udp_size = ln_build_udp_packet(NULL, sport, dport,
                                     NULL, datasz, &data_offset)) < 0
  || (ip_size = ln_build_ip_packet(NULL, shost, dhost, 17, 0,
                                   NULL, udp_size, &udp_offset)) < 0)
    return -1;

  /* check space */
  DBG("Check space...");
  if(pdata)
    *pdata = udp_offset + data_offset;
  if(!buff)
    return ip_size;

  /* buid packet */
  DBG("Build packet...");
  if(ln_build_udp_packet(buff + udp_offset, sport, dport,
                         data, datasz, NULL) < 0
  || ln_build_ip_packet(buff, shost, dhost, 17, 0, NULL, udp_size, NULL) < 0)
    return -1;

  return ip_size;
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

  DBG("Building TCP...");
  if((size = ln_build_ip_tcp_packet(lnc->buff,
                                    shost, sport, dhost, dport,
                                    flags, window, seq, ack,
                                    data, datasz, opts, optssz,
                                    NULL)) < 0)
  {
    ERR("Cannot build TCP/IP package.");
    return -1;
  }

  DBG("%d bytes (0x%04x):", size, size);
  DUMP(LOG_LEVEL_DEBUG2,NULL, lnc->buff, size);

  DBG("Sending TCP...");
  return ln_send_packet(lnc, lnc->buff, size, dhost);
}

int ln_send_udp_packet(LN_CONTEXT *lnc,
                       INET_ADDR *shost, int sport,
                       INET_ADDR *dhost, int dport,
                       char *data, int datasz)
{
  int size;

  DBG("Building UDP...");
  if((size = ln_build_ip_udp_packet(lnc->buff,
                                    shost, sport, dhost, dport,
                                    data, datasz, NULL)) < 0)
  {
    ERR("Cannot build UDP/IP package.");
    return -1;
  }
  DBG("%d bytes (0x%04x):", size, size);
  DUMP(LOG_LEVEL_DEBUG2,NULL, lnc->buff, size);

  DBG("Sending UDP...");
  return ln_send_packet(lnc, lnc->buff, size, dhost);
}

int ln_send_packet(LN_CONTEXT *lnc, void *buff, int sz, INET_ADDR *a)
{
  BIG_SOCKET bs;

  ip_addr_to_socket(a, 0, &bs.sa);

  if(sendto(lnc->rs, buff, sz,
            0, &bs.sa, sizeof(struct sockaddr)) < 0)
  {
    char err[1024];
    strerror_r(errno, err, sizeof(err));
    ERR("Cannot send packet: %s", err);
FAT("XXX");
    return -1;
  }

  return 0;
}

