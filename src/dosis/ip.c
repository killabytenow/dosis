/*****************************************************************************
 * ip.c
 *
 * Build and manipulate IP and networks.
 *
 * ---------------------------------------------------------------------------
 * DioNiSio - DNS scanner
 *   (C) 2006-2008 Gerardo García Peña
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
#include "log.h"

#define IPV4_GETP(p,x)  ((unsigned) ((ntohl((x)->addr) >> ((p)*8)) & 0x000000ffl))
#define IPV6_GETB(p,x)  ((unsigned) ((x)->addr[(p)]))

static int ip_read(char *network, char *s, INET_IPV4_ADDR_T *addr, INET_IPV4_ADDR_T rest)
{
  char *s2;
  int i, num;
  INET_IPV4_ADDR_T netmask = 0xFFFFFFFFl;

  *addr = 0;
  for(i = 0; s && i < 4; i++)
  {
    s2 = strchr(s, '.');
    if(s2)
      *s2++ = '\0';
    sscanf(s, "%d", &num);
    if(num < 0 || num > 255)
    {
      D_ERR("Bad component in address '%s'.", network);
      return -1;
    }
    *addr = (*addr) << 8;
    *addr = (*addr) | num;
    netmask <<= 8;
    s = s2;
  }
  if(i < 4)
  {
    if(!rest)
    {
      D_ERR("Need more components in address '%s'.", network);
      return -1;
    } else
      *addr = (rest & netmask) | *addr;
  } else
    if(s)
    {
      D_ERR("Too much components in address '%s'.", network);
      return -1;
    }

  return 0;
}

static int ip_read_network(char *network, char *s, INET_IPV4_RANGE *range)
{
  char *s2;
  int bits;
  INET_IPV4_ADDR_T netmask, addr;

  s2 = strrchr(s, '/');
  *s2++ = '\0';
  sscanf(s2, "%d", &bits);
  if(bits < 0 || bits > 32)
  {
    D_ERR("Bad network address '%s'.", network);
    return -1;
  }
  netmask = (0xffffffffL << (32 - bits));
  if(ip_read(network, s, &addr, 0))
    return -1;

  range->first_addr = (addr &  netmask);
  range->last_addr  = (addr | ~netmask);

  return 0;
}

static int ip_read_addr_range(char *network, char *s, INET_IPV4_RANGE *range)
{
  char *s2;
  INET_IPV4_ADDR_T addr;

  s2 = strchr(s, '-');
  *s2++ = '\0';
  if(ip_read(network, s,  &(range->first_addr), 0))
    return -1;
  if(ip_read(network, s2, &(range->last_addr), range->first_addr))
    return -1;

  if(range->first_addr > range->last_addr)
  {
    addr = range->first_addr;
    range->first_addr = range->last_addr;
    range->last_addr = addr;
  }

  return 0;
}

int ip_read_range(char *network, INET_IPV4_RANGE *range)
{
  char *s;
  int ret = 0;

  if((s = strdup(network)) == NULL)
    D_FAT("No memory for network.");

  if(strrchr(s, '/') != NULL)
    ret = ip_read_network(network, s, range);
  else if(strchr(s, '-') != NULL)
    ret = ip_read_addr_range(network, s, range);
  else
  {
    ret = ip_read(network, s, &(range->first_addr), 0);
    range->last_addr = range->first_addr;
  }

  free(s);

  return ret;
}

void ip_addr_to_socket(INET_ADDR *addr, struct sockaddr *saddr)
{
  char tmp[INET_ADDR_MAXLEN_STR];

  if(addr->port_defined)
  {
    ip_addr_snprintf(addr, INET_ADDR_MAXLEN, tmp);
    D_WRN("Port not defined for address '%s'.", tmp);
  }
  switch(addr->type)
  {
    case INET_FAMILY_IPV4:
      {
        struct sockaddr_in *sin;

        sin = (struct sockaddr_in *) saddr;
        sin->sin_addr.s_addr = addr->addr.in.addr;
        sin->sin_family = AF_INET;
        sin->sin_port = addr->port;
        memset(&(sin->sin_zero), 0, 8);
      }
      break;

    case INET_FAMILY_IPV6:
#if HAVE_STRUCT_SOCKADDR_IN6
      {
        struct sockaddr_in6 *sin6;

        sin6 = (struct sockaddr_in6 *) saddr;
#ifdef SIN6_LEN
        sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        sin6->sin6_family = AF_INET6;
        sin6->sin6_flowinfo = 0;
        sin6->sin6_port = addr->port;
        memcpy(&sin6->sin6_addr, addr->addr.in6.addr, sizeof(addr->addr.in6));
      }
#else
      D_FAT("This platform does not support IPv6.");
#endif
      break;

    default:
      D_FAT("Unknown internet protocol %d.", addr->type);
  }
}

struct sockaddr *ip_addr_get_socket(INET_ADDR *addr)
{
  struct sockaddr *saddr = NULL;
  int bytes = 0;

  /* calc how many bytes uses this structure */
  switch(addr->type)
  {
    case INET_FAMILY_IPV4:
      bytes = sizeof(struct sockaddr_in);
      break;
    case INET_FAMILY_IPV6:
#if HAVE_STRUCT_SOCKADDR_IN6
      bytes = sizeof(struct sockaddr_in6);
      break;
#else
      D_FAT("This platform does not implement IPv6.");
#endif
    default:
      D_FAT("Unknown internet protocol %d.", addr->type);
  }

  /* get memory */
  if((saddr = malloc(bytes)) == NULL)
    D_FAT("No memory for a sockaddr_in structure.");

  /* fill sockaddr structure */
  ip_addr_to_socket(addr, saddr);

  return saddr;
}

void ip_addr_set_null(INET_ADDR *addr)
{
  memset(&addr, 0, sizeof(INET_ADDR));
}

void ip_addr_set_ipv4(INET_ADDR *addr, INET_IPV4_ADDR *in)
{
  addr->type = INET_FAMILY_IPV4;
  memcpy(&addr->addr.in, in, sizeof(INET_IPV4_ADDR));
}

void ip_addr_set_ipv6(INET_ADDR *addr, INET_IPV6_ADDR *in6)
{
  addr->type = INET_FAMILY_IPV6;
  memcpy(&addr->addr.in6, in6, sizeof(INET_IPV6_ADDR));
}

void ip_addr_set_port(INET_ADDR *addr, int port)
{
  addr->port = htons(port);
  addr->port_defined = 1;
}

void ip_addr_unset_port(INET_ADDR *addr)
{
  addr->port = 0;
  addr->port_defined = 0;
}

void ip_addr_copy(INET_ADDR *to, INET_ADDR *from)
{
  memcpy(to, from, sizeof(INET_ADDR));
}

int ip_addr_snprintf_ipv4(INET_ADDR *addr, int l, char *str)
{
  int r;
  char buff[INET_ADDR_MAXLEN+1];

  if(addr->type != INET_FAMILY_IPV4)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_ERR("Address '%s' is not an IPv4 address.", buff);
    return -1;
  }

  if(addr->port_defined)
  {
    r = snprintf(str, l, "%d.%d.%d.%d:%d",
                    IPV4_GETP(3, &addr->addr.in),
                    IPV4_GETP(2, &addr->addr.in),
                    IPV4_GETP(1, &addr->addr.in),
                    IPV4_GETP(0, &addr->addr.in),
                    ntohs(addr->port));
  } else {
    r = snprintf(str, l, "%d.%d.%d.%d",
                    IPV4_GETP(3, &addr->addr.in),
                    IPV4_GETP(2, &addr->addr.in),
                    IPV4_GETP(1, &addr->addr.in),
                    IPV4_GETP(0, &addr->addr.in));
  }

  return r;
}

int ip_addr_snprintf_ipv6(INET_ADDR *addr, int l, char *str)
{
  char buff[INET_ADDR_MAXLEN+1];

  if(addr->type != INET_FAMILY_IPV6)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_ERR("Address '%s' is not an IPv6 address.", buff);
    return -1;
  }

  return snprintf(str, l, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  IPV6_GETB( 0, &addr->addr.in6),
                  IPV6_GETB( 1, &addr->addr.in6),
                  IPV6_GETB( 2, &addr->addr.in6),
                  IPV6_GETB( 3, &addr->addr.in6),
                  IPV6_GETB( 4, &addr->addr.in6),
                  IPV6_GETB( 5, &addr->addr.in6),
                  IPV6_GETB( 6, &addr->addr.in6),
                  IPV6_GETB( 7, &addr->addr.in6),
                  IPV6_GETB( 8, &addr->addr.in6),
                  IPV6_GETB( 9, &addr->addr.in6),
                  IPV6_GETB(10, &addr->addr.in6),
                  IPV6_GETB(11, &addr->addr.in6),
                  IPV6_GETB(12, &addr->addr.in6),
                  IPV6_GETB(13, &addr->addr.in6),
                  IPV6_GETB(14, &addr->addr.in6),
                  IPV6_GETB(15, &addr->addr.in6));
}

int ip_addr_snprintf(INET_ADDR *addr, int l, char *str)
{
  int r;

  switch(addr->type)
  {
    case INET_FAMILY_IPV4: r = ip_addr_snprintf_ipv4(addr,  l, str); break;
    case INET_FAMILY_IPV6: r = ip_addr_snprintf_ipv6(addr, l, str); break;
    default:
      r = snprintf(str, l, "<NO-ADDRESS>");
  }

  return r;
}

int ip_snprintf_ipv4(INET_IPV4_ADDR *in, int l, char *str)
{
  return snprintf(str, l, "%d.%d.%d.%d",
                  IPV4_GETP(3, in),
                  IPV4_GETP(2, in),
                  IPV4_GETP(1, in),
                  IPV4_GETP(0, in));
}

int ip_snprintf_ipv6(INET_IPV6_ADDR *in6, int l, char *str)
{
  return snprintf(str, l, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  IPV6_GETB( 0, in6),
                  IPV6_GETB( 1, in6),
                  IPV6_GETB( 2, in6),
                  IPV6_GETB( 3, in6),
                  IPV6_GETB( 4, in6),
                  IPV6_GETB( 5, in6),
                  IPV6_GETB( 6, in6),
                  IPV6_GETB( 7, in6),
                  IPV6_GETB( 8, in6),
                  IPV6_GETB( 9, in6),
                  IPV6_GETB(10, in6),
                  IPV6_GETB(11, in6),
                  IPV6_GETB(12, in6),
                  IPV6_GETB(13, in6),
                  IPV6_GETB(14, in6),
                  IPV6_GETB(15, in6));
}

int ip_addr_parse_ipv4(char *saddr, INET_ADDR *addr)
{
  int a, b, c, d, p, r, x, port_defined;

  if((r = sscanf(saddr, "%3u.%3u.%3u.%3u:%5u%n", &a, &b, &c, &d, &p, &x)) != 5)
    if((r = sscanf(saddr, "%3u.%3u.%3u.%3u%n", &a, &b, &c, &d, &x)) != 4)
      return -1;

  if(r == 4)
  {
    p = 0;
    port_defined = 0;
  } else
    port_defined = 1;
  if(saddr[x])
    return -1;

  if(a < 0 || a > 255
  || b < 0 || b > 255
  || c < 0 || c > 255
  || d < 0 || d > 255
  || p < 0 || p > 0x0000ffffl)
    return -1;

  addr->type = INET_FAMILY_IPV4;
  addr->addr.in.addr = htonl(
             ((d & 0x000000ffl) <<  0)
           | ((c & 0x000000ffl) <<  8)
           | ((b & 0x000000ffl) << 16)
           | ((a & 0x000000ffl) << 24));
  addr->port_defined = port_defined;
  addr->port = port_defined ? htons(p) : 0;
  
  return 0;
}

int ip_addr_parse_ipv6(char *saddr, INET_ADDR *addr)
{
#warning "IPv6 address parser not implemented."
  return -1;
}

int ip_addr_parse(char *saddr, INET_ADDR *addr)
{
  if(!ip_addr_parse_ipv4(saddr, addr))
    return 0;
  if(!ip_addr_parse_ipv6(saddr, addr))
    return 0;

  memset(addr, 0, sizeof(INET_ADDR));
  return -1;
}

unsigned int ip_addr_get_part_ipv4(INET_ADDR *addr, int part)
{
  char buff[INET_ADDR_MAXLEN+1];

  if(addr->type != INET_FAMILY_IPV4 || part < 1 || part > 4)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_FAT("Bad IPv4 address '%s' or invalid part number (%d).", buff, part);
  }

  return IPV4_GETP(part-1, &addr->addr.in);
}

unsigned int ip_addr_get_part_ipv6_nibble(INET_ADDR *addr, int part)
{
  char buff[INET_ADDR_MAXLEN + 1];
  int byte, desp;

  if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 32)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_FAT("Bad IPv6 address '%s' or invalid nibble-part number (%d).", buff, part);
  }

  byte = (part - 1) >> 1;
  desp = (part - 1) & 1 ? 0 : 4;

  return (IPV6_GETB(byte, &addr->addr.in6) >> desp) & 0x0f;
}

unsigned int ip_addr_get_part_ipv6_byte(INET_ADDR *addr, int part)
{
  char buff[INET_ADDR_MAXLEN+1];

  if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 16)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_FAT("Bad IPv6 address '%s' or invalid byte-part number (%d).", buff, part);
  }

  return IPV6_GETB(part - 1, &addr->addr.in6);
}

unsigned int ip_addr_get_part_ipv6_word(INET_ADDR *addr, int part)
{
  char buff[INET_ADDR_MAXLEN+1];

  if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 8)
  {
    ip_addr_snprintf(addr, sizeof(buff), buff);
    D_FAT("Bad IPv6 address '%s' or invalid word-part number (%d).", buff, part);
  }

  return IPV6_GETB(((part - 1) * 2) + 0, &addr->addr.in6) << 8
       | IPV6_GETB(((part - 1) * 2) + 1, &addr->addr.in6);
}

