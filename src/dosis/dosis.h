/*****************************************************************************
 * dosis.c
 *
 * DoS generator.
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008 Gerardo García Peña <gerardo@kung-foo.dhs.org>
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
 *****************************************************************************/

#ifndef __DOSIS_H__
#define __DOSIS_H__

#include <stdlib.h>
#include <arpa/inet.h>

#include "ip.h"

typedef struct __TAG_config {
  INET_ADDR       shost;        /* source address in packet tests            */
  INET_ADDR       dhost;        /* target address in packet tests            */
  u_int32_t       c;            /* total number of threads                   */
  u_int32_t       l;            /* threads used to read from ip_queue        */
  u_int64_t       packets;      /* packets sent in each packet burst         */
  double          hits;         /* packets per second                        */
  u_int32_t       cwait;
  u_int32_t       rwait;
  u_int32_t       runtime;      /* time to keep simulating real users        */
  char           *req;
  int             verbosity;

  char          **args;
  int             nargs;

  /* configuration data set by application based on user options */
  u_int8_t       *payload;      /* (random) data sent in packet tests        */
  int             req_size;     /* request size                              */
  int             finalize;     /* for request inmediate program termination */
  u_int8_t        rsport;       /* if set source port is randomly choosed    */
  u_int8_t        rdport;       /* if set target port is randomly choosed    */
} CONFIG;

extern CONFIG config;

#endif
