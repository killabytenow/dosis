/*****************************************************************************
 * dioconfig.h
 *
 * DioNiSio configuration structure.
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
#include "ip.h"

typedef struct __TAG_config {
  int             verbosity;
  INET_ADDR       shost;        /* source address in packet tests            */
  INET_ADDR       dhost;        /* target address in packet tests            */
  u_int8_t        rsport;       /* if set source port is randomly choosed    */
  u_int8_t        rdport;       /* if set target port is randomly choosed    */
  u_int32_t       c;            /* total number of threads                   */
  u_int32_t       l;            /* threads used to read from ip_queue        */
  u_int64_t       packets;      /* packets sent in each packet burst         */
  double          hits;         /* packets per second                        */
  u_int32_t       cwait;
  u_int32_t       rwait;
  u_int32_t       runtime;      /* time to keep simulating real users        */
  char           *req;
  int             req_size;     /* request size                              */

  /* configuration data set by application based on user options */
  int             finalize;     /* for request inmediate program termination */

  /* parameter reading (dosconfig) */
  char            **params;
  char            nparams;
} DOS_CONFIG;

extern DOS_CONFIG *cfg;

/*****************************************************************************
 * LOGFILE
 *
 *   This macro returns a pointer to 'stderr' if configuration logfile
 *   parameter is not set.
 */

#define LOGFILE     (cfg->logfile ? cfg->logfile : stderr)

typedef struct {
  char      **name;                    /* name and aliases of this command */
  void      (*command)(void);
  int       min_pars;                  /* min pars expected                */
  int       max_pars;                  /* max pars expected (-1 infinite)  */
} DOS_COMMAND;

extern DOS_COMMAND *dio_cmd_list[];

/* program flags and configuration parameters */
typedef struct _tag_DOS_PARAMETER {
  char *name;
  char *defvalue;
  int  cfg_offset;
  /* par_handler
   *
   *   This function handles this parameter. Its behaviour depends on
   *   parameters pased:
   *
   *     READ MODE
   *       Enabled when INT is zero or a positive value.
   *       Passed pointer should point to a buffer with space for INT bytes.
   *       If buffer size is 0 no data will be written to pointer, so it does
   *       not matter if pointer to buffer is NULL. The function will return
   *       the needed buffer size to copy data contained in this parameter.
   *
   *     WRITE MODE
   *       Enabled when INT is a negative value.
   *       Passed pointer to data must be NOT null, a pointer to data to copy
   *       into parameter.
   *
   *     FREE MODE
   *       Enabled when INT is a negative value and passed pointer to data is
   *       NULL.
   */
  int (*par_handler)(struct _tag_DOS_PARAMETER *p, char *b, int s);
} DOS_PARAMETER;

extern DOS_PARAMETER dos_param_list[];

typedef struct _tag_CMD_OPTION {
  char shortopt;
  char *longopt;
  int  has_arg; /* 0 no arg; 1 yes; 2 optional */
  char *param;
  char *set_val;
  int  (*handler)(char *);
} DOS_CMD_OPTION;

extern DOS_CMD_OPTION cmd_options[];

DOS_COMMAND *dos_config_init(int argc, char **argv, int *error);
void dos_param_set(char *param, char *value);
int dos_param_get(char *param, void *b);
int dos_param_get_bool(char *param);
int dos_param_get_int(char *param);
int dos_param_get_str(char *param);

#ifdef __cplusplus
}
#endif

#endif
