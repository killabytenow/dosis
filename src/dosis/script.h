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
  TYPE_CMD_MOD,
  TYPE_CMD_OFF,
  TYPE_CMD_ON,
  TYPE_CMD_SETVAR,
  TYPE_CMD_LISTEN,
  /* basic types */
  TYPE_NINT,
  TYPE_NFLOAT,
  TYPE_NTIME,
  TYPE_STRING,
  TYPE_VAR,
  /* lists and selectors */
  TYPE_LIST_NUM,
  TYPE_SELECTOR,
  /* thread types */
  TYPE_TO_TCP,
  TYPE_TO_TCPRAW,
  TYPE_TO_UDP,
  TYPE_TO_LISTEN,
  /* options */
  TYPE_OPT_DST,
  TYPE_OPT_FLAGS,
  TYPE_OPT_RAW,
  TYPE_OPT_SRC,
  /* patterns */
  TYPE_PERIODIC,

  TYPE_LAST
};

typedef struct SNODE_tag {
  int     type;
  int     line;

  union {
    /* --------------------------------------------------------------------- */
    /* command snode - A structure defining a command to be executed         */
    struct {
      struct SNODE_tag *time;           /* ntime snode specifying time       */
      union {
        struct {
          struct SNODE_tag *selection;  /* list or range of threads          */
          struct SNODE_tag *to;         /* options snode                     */
        } thc;
        struct {
          char             *var;        /* variable identifier               */
          struct SNODE_tag *val;        /* value to assign                   */
        } setvar;
      };
      struct SNODE_tag *next;
    } command;

    /* --------------------------------------------------------------------- */
    /* to snode - It specifies a thread type and its options                 */
    struct {
      struct SNODE_tag *options;        /* options snode                     */
      struct SNODE_tag *pattern;        /* pattern snode                     */
    } to;

    /* --------------------------------------------------------------------- */
    /* option snode - Options specified for a certain command                */
    struct {
      struct SNODE_tag *addr;         /* target/source address               */
      struct SNODE_tag *port;         /* target/source port                  */
      struct SNODE_tag *flags;        /* flags                               */

      struct SNODE_tag *next;
    } option;

    /* --------------------------------------------------------------------- */
    /* pattern snode - Pattern used by ON command                            */
    union {
      struct {
        struct SNODE_tag *ratio; /* nfloat snode specifying packets/s        */
        struct SNODE_tag *n;     /* nint snode with packet size              */
      } periodic;
    } pattern;

    /* --------------------------------------------------------------------- */
    /* basic types snodes - Float & int numbers, time type and strings       */
    struct {
      int   parse;              /* 1 parse vars, 0 is a literal string       */
      char *value;              /* string or var to be processed             */
    } string;
    struct {
      int rel;                  /* if !=0, then it is a time-relative offset */
      double  n;                /* time                                      */
    } ntime;
    double  nfloat;             /* float                                     */
    int     nint;               /* int                                       */
    char   *varname;            /* var name                                  */

    /* --------------------------------------------------------------------- */
    /* list_num snode - snode used to specify a list of integers             */
    struct {
      struct SNODE_tag *val;    /* a snode specifying a number               */
      struct SNODE_tag *next;
    } list_num;

    /* --------------------------------------------------------------------- */
    /* range snode - snode used to specify a range of integers               */
    struct {
      struct SNODE_tag *min;    /* a snode specifying min range value        */
      struct SNODE_tag *max;    /* a snode specifying max range value        */
    } range;
  };
} SNODE;

extern SNODE *script_parse(void);

#define IPADDR      

#ifdef __cplusplus
}
#endif

#endif
