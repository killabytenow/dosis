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

#ifndef __LNET_H__
#define __LNET_H__

#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _tag_LN_CONTEXT {
  libnet_t     *ln;
  int           ipv4_p;
  int           tcp_p;
  int           ip_id;
} LN_CONTEXT;

void ln_init_context(LN_CONTEXT *ln);
void ln_destroy_context(LN_CONTEXT *lnc);
void ln_send_packet(LN_CONTEXT *lnc,
                    struct in_addr *shost, int sport,
                    struct in_addr *dhost, int dport,
                    int flags, int window,
                    int seq, int ack,
                    char *data, int data_sz);

#ifdef __cplusplus
}
#endif

#endif
