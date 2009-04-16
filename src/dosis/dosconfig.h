/*****************************************************************************
 * dioconfig.h
 *
 * Dosis configuration structure.
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

#ifndef __DOSCONFIG_H__
#define __DOSCONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <config.h>

typedef struct __TAG_config {
  int             verbosity;
  char           *output;
  char           *script;
  int             maxthreads;
  int             listenthreads;

  /* configuration data set by application based on user options */
  FILE           *of;
  int             finalize;     /* for request inmediate program termination */
} DOS_CONFIG;

extern DOS_CONFIG cfg;

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
