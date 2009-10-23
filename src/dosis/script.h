/*****************************************************************************
 * script.h
 *
 * Dosis script language.
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

#ifndef __SCRIPT_H__
#define __SCRIPT_H__

#include "ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/* yep! */
enum TYPES {
  /* commands */
  TYPE_CMD_MOD = 0,
  TYPE_CMD_OFF,
  TYPE_CMD_ON,
  TYPE_CMD_SETVAR,
  TYPE_CMD_LISTEN,
  /* basic types */
  TYPE_NINT = 1000,
  TYPE_NFLOAT,
  TYPE_NTIME,
  TYPE_STRING,
  TYPE_VAR,
  /* lists and selectors */
  TYPE_LIST_NUM = 2000,
  TYPE_SELECTOR,
  /* thread types */
  TYPE_TO_LISTEN = 3000,
  TYPE_TO_SLOW,
  TYPE_TO_TCP,
  TYPE_TO_TCPOPEN,
  TYPE_TO_TCPRAW,
  TYPE_TO_UDP,
  TYPE_TO_ZWIN,
  /* options */
  TYPE_OPT_CWAIT = 4000,
  TYPE_OPT_SSL,
  TYPE_OPT_DLL,
  TYPE_OPT_DST,
  TYPE_OPT_FILE,
  TYPE_OPT_FLAGS,
  TYPE_OPT_MSS,
  TYPE_OPT_OPEN,
  TYPE_OPT_RAW,
  TYPE_OPT_RWAIT,
  TYPE_OPT_SRC,
  TYPE_OPT_WINDOW,
  TYPE_OPT_PAYLOAD_DLL,
  TYPE_OPT_PAYLOAD_FILE,
  TYPE_OPT_PAYLOAD_NULL,
  TYPE_OPT_PAYLOAD_RANDOM,
  TYPE_OPT_PAYLOAD_STR,
  /* patterns */
  TYPE_PERIODIC = 5000,
  TYPE_PERIODIC_LIGHT,
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
          int               cond;       /* if true only set var if no exists */
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
      struct SNODE_tag *payload;      /* payload for packets                 */
      struct SNODE_tag *cwait;        /* TCP connection wait                 */
      struct SNODE_tag *rwait;        /* TCP read wait                       */
      struct SNODE_tag *sslcipher;    /* SSL cipher suite                    */
      struct SNODE_tag *mss;          /* TCP Maximum Segment Size            */
      struct SNODE_tag *window;       /* TCP Maximum Segment Size            */

      struct SNODE_tag *next;
    } option;

    /* --------------------------------------------------------------------- */
    /* pattern snode - Pattern used by ON command                            */
    union {
      struct {
        struct SNODE_tag *ratio; /* nfloat snode specifying packets/s        */
        struct SNODE_tag *n;     /* nint snode with packets to send          */
      } periodic;
    } pattern;

    /* --------------------------------------------------------------------- */
    /* basic types snodes - Float & int numbers, time type and strings       */
    struct {
      int   parse;              /* 1 parse vars, 0 is a literal string       */
      char *value;              /* string or var to be processed             */
    } string;
    struct {
      int    rel;               /* if !=0, then it is a time-relative offset */
      struct SNODE_tag *n;      /* time                                      */
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

  /* memory management pointer (lazy free) */
  struct SNODE_tag *next_allocated;
} SNODE;

extern void script_init(void);
extern SNODE *script_parse(void);

#ifdef __cplusplus
}
#endif

#endif
