/*****************************************************************************
 * dioconfig.h
 *
 * Dosis configuration structure.
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

#ifndef __DOSCONFIG_H__
#define __DOSCONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <config.h>
#include "ip.h"

#define MAX_INCLUDE_DIRS    10
#define MAX_INTERFACES      10
#define MAX_ROUTES          20

typedef struct _tag_DOS_ADDR_INFO {
  char          *name;
  unsigned char  hwaddr[6];
  INET_ADDR      addr;
  INET_ADDR      mask;

  struct _tag_DOS_ADDR_INFO *next;
} DOS_ADDR_INFO;

typedef struct _tag_DOS_ROUTE_INFO {
  char          *iface;
  INET_ADDR      destination;
  INET_ADDR      gateway;
  INET_ADDR      mask;

  struct _tag_DOS_ROUTE_INFO *next;
} DOS_ROUTE_INFO;

typedef struct _tag_DOS_CONFIG {
  int             verbosity;
  char           *output;
  char           *script;
  int             maxthreads;
  char           *includedir[MAX_INCLUDE_DIRS+1];
  char           *interfaces[MAX_INTERFACES+1];
  DOS_ROUTE_INFO *routes;
  DOS_ADDR_INFO  *addr;

  /* configuration data set by application based on user options */
  FILE           *of;
  int             finalize;     /* for request inmediate program termination */
} DOS_CONFIG;

extern DOS_CONFIG cfg;

void dos_config_init(int argc, char **argv);
int dosis_fork(void);
void dosis_atexit(char *name, void (*func)(void));

DOS_ADDR_INFO *dos_get_interface(INET_ADDR *ta);
int dos_get_source_address(INET_ADDR *s, INET_ADDR *t);
void dosis_add_include_dir(char *p, int dirname);
char *dosis_search_file(char *file);

/*****************************************************************************
 * LOGFILE
 *
 *   This macro returns a pointer to 'stderr' if configuration logfile
 *   parameter is not set.
 */

#define LOGFILE     (cfg.logfile ? cfg.logfile : stderr)

#ifdef __cplusplus
}
#endif

#endif
