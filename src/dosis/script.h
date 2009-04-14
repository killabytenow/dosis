/*****************************************************************************
 * script.h
 *
 * Dosis script language.
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

#ifndef __SCRIPT_H__
#define __SCRIPT_H__

#include "ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/* yep! */
enum TYPES {
  TYPE_NULL,
  /* commands */
  TYPE_CMD_ON,
  TYPE_CMD_MOD,
  TYPE_CMD_OFF,
  /* lists and selectors */
  TYPE_LIST_NUM,
  TYPE_SELECTOR,
  /* options */
  TYPE_OPT_TCP,
  TYPE_OPT_UDP,
  TYPE_OPT_SRC,
  TYPE_OPT_DST,
  /* patterns */
  TYPE_PERIODIC,

  TYPE_LAST
};

typedef struct SNODE_tag {
  int     type;
  union {
    struct {
      double            time;
      int               command;
      union {
        struct SNODE_tag *list_num;
        struct SNODE_tag *selector;
      };
      struct SNODE_tag *options;
      struct SNODE_tag *pattern;
      struct SNODE_tag *next;
    } command;
    struct {
      union {
        INET_ADDR addr;
      };
      struct SNODE_tag *next;
    } option;
    struct {
      union {
        struct {
          double   ratio;
          unsigned n;
        } periodic;
      };
    } pattern;
    struct {
      int               val;
      struct SNODE_tag *next;
    } list_num;
    struct {
      int rmin;
      int rmax;
    } selector;
  };
} SNODE;

#define IPADDR      

#ifdef __cplusplus
}
#endif

#endif
