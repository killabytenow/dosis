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
#include "hash.h"

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
  TYPE_FILE = 1000,
  TYPE_BOOL,
  TYPE_NINT,
  TYPE_NFLOAT,
  TYPE_NTIME,
  TYPE_RANDOM,
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
  /*TYPE_OPT_SSL,
  TYPE_OPT_DLL,
  TYPE_OPT_DST,
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
  TYPE_OPT_PAYLOAD_STR,*/
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
    /* options - Specifies thread options                                    */
    HASH *options;              /* options snode                             */

    /* --------------------------------------------------------------------- */
    /* basic types snodes - Float & int numbers, time type and strings       */
    struct {
      int   parse;              /* 1 parse vars, 0 is a literal string       */
      char *value;              /* string or var to be processed             */
    /*int   len;         XXX TODO: string length (for raw binary data)       */
    } string;
    double  nfloat;             /* float                                     */
    int     nint;               /* int                                       */
    int     nbool;              /* bool                                      */
    char   *varname;            /* var name                                  */
    struct {
      int    rel;               /* if !=0, then it is a time-relative offset */
      struct SNODE_tag *n;      /* time                                      */
    } ntime;
    struct {
      struct SNODE_tag *path;   /* path to input file                        */
      struct SNODE_tag *offset; /* seek offset                               */
      struct SNODE_tag *size;   /* max bytes to read                         */
    } file;
    struct {                    /* random data                               */
      struct SNODE_tag *len;    /* length of random data                     */
    } random;

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

typedef struct {
  SNODE *first;
  int    i1, i2, i;
  SNODE *c;
} TEA_ITER;

typedef struct SCONFIG_PARAMETER_tag {
  char   *param;
  int     type;
  SNODE  *defval;

  struct SCONFIG_PARAMETER_tag *next;
} SCONFIG_PARAMETER;

extern void script_init(void);
extern SNODE *script_parse(void);

int      script_get_bool(SNODE *n);
char    *script_get_data(SNODE *n, unsigned int *size);
double   script_get_float(SNODE *n);
int      script_get_int(SNODE *n);
char    *script_get_string(SNODE *n);
char    *script_get_var(SNODE *n);

SNODE   *script_get_default(char *param);

int tea_iter_get(TEA_ITER *ti);
int tea_iter_start(SNODE *s, TEA_ITER *ti);
int tea_iter_finish(TEA_ITER *ti);
int tea_iter_next(TEA_ITER *ti);

#ifdef __cplusplus
}
#endif

#endif
