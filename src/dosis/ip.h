/*****************************************************************************
 * ip.h
 *
 * Build and manipulate IP and networks.
 *
 * ---------------------------------------------------------------------------
 * DioNiSio - DNS scanner
 *   (C) 2006-2009 Gerardo García Peña
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

#ifndef __IP_H__
#define __IP_H__

#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INET_FAMILY_NONE   0           /* invalid protocol (not set)   */
#define INET_FAMILY_IPV4   2           /* internetwork: UDP, TCP, etc. */
#define INET_FAMILY_IPV6  30           /* IPv6                         */

typedef UINT32_T INET_IPV4_ADDR_T;
typedef union _tag_INET_IPV4_ADDR {
  INET_IPV4_ADDR_T addr;
  struct in_addr   inaddr;
} INET_IPV4_ADDR;

typedef union _tag_INET_IPV6_ADDR {
  UINT8_T         addr[16];
  struct in6_addr in6addr;
} INET_IPV6_ADDR;

typedef union _tag_BIG_SOCKET {
  struct sockaddr_in  in;
#if HAVE_STRUCT_SOCKADDR_IN6
  struct sockaddr_in6 in6;
#endif
} BIG_SOCKET;

#define BIG_SOCKET_TO_SOCKADDR(x)       ((struct sockaddr *) &(x))

#define INET_ADDR_MAXLEN_IPV6    39
#define INET_ADDR_MAXLEN_IPV4    15
#define INET_ADDR_MAXLEN         INET_ADDR_MAXLEN_IPV6
#define INET_ADDR_MAXLEN_STR     (INET_ADDR_MAXLEN_IPV6 + 1)

#define INET_ADDR_IS_IPV4(x)            ((x).type == INET_FAMILY_IPV4)
#define INET_ADDR_IS_IPV6(x)            ((x).type == INET_FAMILY_IPV6)
#define INET_ADDR_IS_VALID(x)           ((x).type != INET_FAMILY_NONE)

typedef struct _tag_INET_ADDR {
  int               type;     /* address type: INET_FAMILY_IPV4, etc...  */
  union {
    INET_IPV4_ADDR  in;       /* IPv4 address                            */
    INET_IPV6_ADDR  in6;      /* IPv6 address                            */
  } addr;
  int               port;     /* connection port (TCP/UDP)               */
  int               port_defined;
} INET_ADDR;

typedef struct _tag_INET_IPV4_RANGE {
  INET_IPV4_ADDR_T  first_addr;
  INET_IPV4_ADDR_T  last_addr;
} INET_IPV4_RANGE;

int ip_read_range(char *network, INET_IPV4_RANGE *range);

int ip_addr_parse(char *saddr, INET_ADDR *addr);
int ip_addr_snprintf_ipv4(INET_ADDR *addr, int l, char *str);
int ip_addr_snprintf_ipv6(INET_ADDR *addr, int l, char *str);
int ip_addr_snprintf(INET_ADDR *addr, int l, char *str);

void ip_addr_set_null(INET_ADDR *addr);
void ip_addr_set_ipv4(INET_ADDR *addr, INET_IPV4_ADDR *in);
void ip_addr_set_ipv6(INET_ADDR *addr, INET_IPV6_ADDR *in);
void ip_addr_set_port(INET_ADDR *addr, int port);
void ip_addr_unset_port(INET_ADDR *addr);
void ip_addr_copy(INET_ADDR *to, INET_ADDR *from);

void             ip_socket_to_addr(struct sockaddr *saddr, INET_ADDR *addr);
void             ip_addr_to_socket(INET_ADDR *addr, struct sockaddr *saddr);
struct sockaddr *ip_addr_get_socket(INET_ADDR *addr);

int ip_snprintf_ipv4(INET_IPV4_ADDR *in, int l, char *str);
int ip_snprintf_ipv6(INET_IPV6_ADDR *in6, int l, char *str);

unsigned int ip_addr_get_part_ipv4(INET_ADDR *addr, int part);
unsigned int ip_addr_get_part_ipv6_nibble(INET_ADDR *addr, int part);
unsigned int ip_addr_get_part_ipv6_byte(INET_ADDR *addr, int part);
unsigned int ip_addr_get_part_ipv6_word(INET_ADDR *addr, int part);

int ip_addr_check_mask(INET_ADDR *addr, INET_ADDR *net, INET_ADDR *mask);

#ifdef __cplusplus
}
#endif

#endif
