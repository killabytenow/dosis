/*****************************************************************************
 * config.c
 *
 * Configuration structure.
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

#include <config.h>
#include <datadir.h>
#include "dosconfig.h"
#include "help.h"
#include "log.h"

#include "tcpopen.h"

/* default config and global configuration pointer */
static DOS_CONFIG cfg_default = {
  /* verbosity                                 */ LOG_LEVEL_LOG,
  /* source address in packet tests            */ { 0 },
  /* target address in packet tests            */ { 0 },
  /* total number of threads                   */ 2,
  /* threads used to read from ip_queue        */ 1,
  /* packets sent in each packet burst         */ 1,
  /* hits per second                           */ 1.0,
  /* cwait                                     */ 3000000,
  /* rwait                                     */ 10000000,
  /* time to keep simulating real users        */ 5,
  /* req                                       */ NULL,
  /* request size                              */ 0,

  /* configuration data set by application based on user options */
};
DOS_CONFIG *cfg = &cfg_default;

/* private object's global variables */
static struct option *long_options = NULL;
static char *short_options = NULL;
static int help_flag;

/* prototypes for object's internal functions */
static int dos_vhandler_addr(DOS_PARAMETER *, char *, int);
static int dos_vhandler_bool(DOS_PARAMETER *, char *, int);
static int dos_vhandler_int(DOS_PARAMETER *, char *, int);
static int dos_vhandler_verbosity(DOS_PARAMETER *, char *, int);
static int dos_vhandler_port(DOS_PARAMETER *, char *, int);
static int dos_vhandler_string(DOS_PARAMETER *, char *, int);

#define CFGOFF(f)         offsetof(DOS_CONFIG,f)
DOS_PARAMETER dos_param_list[] = {
  { "script",         NULL, CFGOFF(script),    dos_vhandler_string        },
  { "verbosity",       "2", CFGOFF(verbosity), dos_vhandler_verbosity     },
  { NULL,                0, 0,                 NULL                       }
};

static int dos_help_opt_trigger(char *optarg)
{
  help_flag = -1;
  return 0;
}

#define CMD_OPTIONS_N (sizeof(cmd_options) / sizeof(DOS_CMD_OPTION))
DOS_CMD_OPTION cmd_options[] = {
  { 'i', "script",        1, "script",         NULL, NULL                  },
  { 'h', "help",          0, NULL,             NULL, dos_help_opt_trigger  },
  { 'q', "quiet",         0, "verbosity",       "0", NULL                  },
  { 'v', "verbosity",     2, "verbosity",       "3", NULL                  },
  {   0, NULL,            0, NULL,             NULL, NULL                  },
};

/* declare commands */
DOS_COMMAND *dos_cmd_list[] = {
  &dos_attack_tcpopen,
  NULL
};


/*****************************************************************************
 * Parameter handlers
 *****************************************************************************/

static int dos_vhandler_bool(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  char *ttable[] = { "yes", "true",  "y", "enable",  "enabled",  "1", NULL };
  char *ftable[] = { "no",  "false", "n", "disable", "disabled", "0", NULL };
  char **values[] = { ftable, ttable };
  int i;
  char **v;
  int *target = ((void *) cfg) + c->cfg_offset;
  int ret;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = snprintf(buff, rbuffsize, "%s", *target ? "yes" : "no");
  else
    if(buff)
    {
      for(i = 0; i < 2; i++)
        for(v = values[i]; *v; v++)
          if(!strcasecmp(buff, *v))
          {
            *target = i * -1;
            ret = 0;
          }

      if(ret < 0)
        D_ERR("%s: Bad syntax, I don't know how to interpret '%s'.", c->name, buff);
    }

  return ret;
}

static int dos_vhandler_int(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  int *target = ((void *) cfg) + c->cfg_offset;
  int ret = 0;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = snprintf(buff, rbuffsize, "%d", *target);
  else
    if(buff)
      *target = atoi(buff);

  return ret;
}

static int dos_vhandler_port(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  INET_ADDR *target = ((void *) cfg) + c->cfg_offset;
  int ret = 0;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = snprintf(buff, rbuffsize, "%d", target->port);
  else
    if(buff)
      ip_addr_set_port(target, atoi(buff));

  return ret;
}

static int dos_vhandler_verbosity(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  int *target = ((void *) cfg) + c->cfg_offset;
  int ret = 0;
  int t;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = snprintf(buff, rbuffsize, "%d", *target);
  else
    if(buff)
    {
      t = atoi(buff);
      if(t >= 0 && t <= LOG_LEVEL_ALL)
      {
        *target = t;
        ret = 0;
      } else {
        D_ERR("Bad verbosity level (%d).", t);
        ret = -1;
      }
    }

  return ret;
}

static int dos_vhandler_string(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  char **target = ((void *) cfg) + c->cfg_offset;
  int ret = 0;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = snprintf(buff, rbuffsize, "%s", *target);
  else {
    if(*target != NULL)
      free(*target);
    D_ERR("Going to free %08x", *target);
    D_ERR("Going to set %08x", buff);
    D_ERR("Going to set %s", buff);
    if(!buff)
      *target = NULL;
    else
      if((*target = strdup(buff)) == NULL)
        D_FAT("Cannot alloc memory for string '%s'.", buff);
    D_DBG("Set to %08x", *target);
  }

  return 0;
}

static int dos_vhandler_addr(DOS_PARAMETER *c, char *buff, int rbuffsize)
{
  INET_ADDR *target = ((void *) cfg) + c->cfg_offset;
  int ret;

  if(!buff)
    rbuffsize = 0;

  if(rbuffsize >= 0)
    ret = ip_addr_snprintf(target, rbuffsize, buff);
  else
    if(buff)
    {
      ret = ip_addr_parse(buff, target);

      if(ret < 0)
        D_ERR("%s: Bad address '%s'.", c->name, buff);
    }

  return ret;
}

/*****************************************************************************
 * Command Line Parser
 *
 *   Following code parses command line input (with getopt(3) help), updating
 *   current configuration (cfg).
 *
 *****************************************************************************/

DOS_PARAMETER *find_param(char *param)
{
  DOS_PARAMETER *p;

  for(p = dos_param_list; p->name && strcmp(p->name, param); p++)
    ;

  return p->name ? p : NULL;
}

void *dos_param_get(char *param)
{
  DOS_PARAMETER *p;

  if((p = find_param(param)) == NULL)
  {
   D_ERR("Parameter '%s' does not exists.", param);
   return NULL;
  }

  return ((void *) cfg) + p->cfg_offset;
}

int dos_param_get_int(char *param)
{
  int *p;

  if((p = (int *) dos_param_get(param)) != NULL)
    return *p;
}

int dos_param_get_bool(char *param)
{
  return dos_param_get_int(param) ? -1 : 0;
}

double dos_param_get_float(char *param)
{
  double *p;

  if((p = (double *) dos_param_get(param)) != NULL)
    return *p;
}

void dos_param_set(char *param, char *value)
{
  DOS_PARAMETER *p;

  if((p = find_param(param)) == NULL)
  {
   D_ERR("Parameter configuration '%s' does not exists.", param);
   return;
  }

  if(p->par_handler(p, value, -1))
    D_ERR("Cannot configure parameter '%s'.", param);
}

void dos_param_set_int(char *param, int value)
{
  int *p;

  if((p = (int *) dos_param_get(param)) != NULL)
    *p = value;
}

void dos_param_set_bool(char *param, int value)
{
  dos_param_set_int(param, value ? -1 : 0);
}

static DOS_COMMAND *find_cmd(char *s)
{
  DOS_COMMAND *r;
  int i, j;

  r = NULL;
  for(i = 0; !r && dos_cmd_list[i]; i++)
    for(j = 0; !r && dos_cmd_list[i]->name[j]; j++)
      if(!strcasecmp(dos_cmd_list[i]->name[j], s))
        r = dos_cmd_list[i];

  return r;
}

static DOS_COMMAND *dos_config_parse_command(int argc, char **argv, int *error)
{
  int c, fin, i,
      option_index = 0;
  char *s;
  DOS_CMD_OPTION *opt;
  DOS_COMMAND *cmd;
  int cmd_index, par_index;

  /* configure and reset getopt */
  *error = 0;
  opterr = 0;
  optind = 1;

  /* get options */
  fin = 0;
  while(!fin)
  {
    c = getopt_long(argc, argv, short_options, long_options, &option_index);

    if(c > 0)
    {
      if((opt = find_cmd_option(c)) == NULL)
      {
        D_ERR("Invalid option '%s'.", argv[optind-1]);
        goto error;
      }
      if(!optarg)
        s = NULL;
      else
        if((s = strdup(optarg)) == NULL)
          D_FAT("Cannot duplicate string memory.");
      if(!opt->handler || !opt->handler(optarg))
        if(opt->param && (s || opt->set_val))
          dos_param_set(opt->param, s ? s : opt->set_val);
      if(s)
        free(s);
    } else
      fin = -1;
  }

  /* get command */
  cmd_index = optind;
  par_index = optind +1;

  /* search command */
  cmd = cmd_index < argc
          ? find_cmd(argv[cmd_index])
          : NULL;

  /* if help flag enabled then use 'help' command */
  if(help_flag)
  {
    help_flag = 0;
    if(cmd)
    {
      par_index = cmd_index;
      cfg->nparams = 1;
    } else
      cfg->nparams = 0;
    cmd = find_cmd("help");
  } else
    cfg->nparams = argc - par_index;

  if(!cmd && cmd_index < argc)
  {
    if(cfg->verbosity < LOG_LEVEL_DEBUG)
      D_ERR("Command not found.");
    else
      D_ERR("Bad bad boy ... you are inventing the stupid command '%s'. DIE DIE DIE MTF!!!!", argv[cmd_index]);
    goto error;
  }

  /* check num of parameters and copy them if they are ok */
  if(cmd)
  {
    if(cmd->min_pars > cfg->nparams)
    {
      D_ERR("Command needs at least %d parameters.", cmd->min_pars);
      goto error;
    }

    if(cmd->max_pars > 0 && cmd->max_pars < cfg->nparams)
    {
      D_ERR("Too much parameters for command.");
      goto error;
    }

    if(cfg->nparams == 0)
      cfg->params = NULL;
    else
      if((cfg->params = calloc(cfg->nparams, sizeof(char *))) == NULL)
        D_FAT("No memory for parameters.");

    for(i = 0; i < cfg->nparams; i++)
      if((cfg->params[i] = strdup(argv[i + par_index])) == NULL)
        D_FAT("Cannot copy parameter %d (%s).", i + par_index, argv[i + par_index]);
  }

  return cmd;

error:
  *error = 1;
  return NULL;
}

/*****************************************************************************
 * Initialization and finalization routines
 *****************************************************************************/

static void dos_config_fini(void)
{
  int i;

  if(cfg)
  {
    if(cfg->params)
    {
      for(i = 0; i < cfg->nparams; i++)
        if(cfg->params[i])
          free(cfg->params[i]);
      free(cfg->params);
    }
    if(cfg->req)
      free(cfg->req);
    free(cfg);
    cfg = NULL;
  }

  if(short_options)
    free(short_options);
  if(long_options)
    free(long_options);
}

static char *set_default_file(char **paths, char *file)
{
  struct stat buf;
  char tmp[PATH_MAX], *r, *t;

  /* in the worst case (file not found) we will return */
  /* directly a copy of string pointed by 'file'       */
  r = file;

  /* search file 'file' in the list of 'paths' */
  for(; *paths; paths++)
  {
    if(strlen(*paths) > 0)
    {
      if(snprintf(tmp, PATH_MAX, "%s%s%s",
                  *paths, (*paths)[strlen(*paths)-1] != '/' ? "/" : "", file) > PATH_MAX)
        D_FAT("String '%s/%s' is longer than PATH_MAX characters (%d).",
              *paths, file, PATH_MAX);
      t = tmp;
    } else
      t = file;

    if(!stat(t, &buf) && S_ISREG(buf.st_mode))
    {
      r = t;
      break;
    }
  }

  /* return a copy */
  if((r = strdup(r)) == NULL)
    D_FAT("No memory for path '%s'.", tmp);

  return r;
}

DOS_COMMAND *dos_config_init(int argc, char **argv, int *error)
{
  DOS_COMMAND *cmd;
  int i, j;
  char *s;
  char *datadirs[] = {
    ".",
    DOS_PATH_DATA,
    "/usr/share",
    NULL
  };
  char *etcdirs[] = {
    ".",
    DOS_PATH_ETC,
    "/etc",
    NULL
  };
  char tmp[255];

  /* first of all get concious about dead */
  if(atexit(dos_config_fini))
    D_FAT("Cannot set finalization routine.");

  /* initialize getopt tables */
  if(!(short_options = calloc((CMD_OPTIONS_N * 2) + 1, sizeof(char)))
  || !(long_options = calloc(CMD_OPTIONS_N + 1, sizeof(struct option))))
    D_FAT("No memory for getopt tables.");

  s = short_options;
  j = 0;
  for(i = 0; i < CMD_OPTIONS_N; i++)
  {
    if(cmd_options[i].shortopt)
    {
      *s++ = cmd_options[i].shortopt;
      if(cmd_options[i].has_arg == 1)
        *s++ = ':';
    }
    if(cmd_options[i].longopt)
    {
      long_options[j].name    = cmd_options[i].longopt;
      long_options[j].has_arg = cmd_options[i].has_arg;
      long_options[j].flag    = NULL;
      long_options[j].val     = cmd_options[i].shortopt
                                  ? cmd_options[i].shortopt
                                  : j;
      j++;
    }
  }
  *s = '\0';

  /* create the base configuration */
  if((cfg = malloc(sizeof(DOS_CONFIG))) == NULL)
    D_FAT("Cannot alloc space for global configuration.");

  /* set basic configuration */
  memcpy(cfg, &cfg_default, sizeof(DOS_CONFIG));

  /* read config and command from command line */
  cmd = dos_config_parse_command(argc, argv, error);
  if(*error)
    return cmd;

  /* check parameters */
  if(dos_param_get_float("hit-ratio") < 0.0)
    FAT("Bad hits per second.");
  if(dos_param_get_int("npackets") < 0)
    FAT("Bad number of packets.");
  if(dos_param_get_int("conn-timeout") <= 0)
    FAT("Too short connection timeout.");
  if(dos_param_get_int("reply-timeout") <= 0)
    FAT("Error getting reply timeout.");
  if(dos_param_get_int("runtime") <= 0)
    FAT("Error getting running time.");
  if(!INET_ADDR_IS_VALID(cfg->shost))
    FAT("A source address is required!");
  if(!INET_ADDR_IS_VALID(cfg->dhost))
    FAT("A destination address is required!");
  if(dos_param_get_int("clients") - dos_param_get_int("listen") > 0
  && dos_param_get_int("clients") - dos_param_get_int("listen") > dos_param_get_int("npackets"))
  {
    WRN("More sender threads than packets. Limiting sender threads to %d.", dos_param_get_int("npackets") + 1);
    dos_param_set_int("npackets", cfg->packets + cfg->l);
  }
  if(!cfg->req)
  {
    cfg->req = strdup("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    cfg->req_size = strlen(cfg->req);
    WRN("Assuming default request (http://<addr>/)");
  }

  /* print program header and config (if debug verbosity enabled) */
  dos_help_program_header();

  D_DBG("Configuration");
  D_DBG("  verbosity level             = %d", cfg->verbosity);
  ip_addr_snprintf(&cfg->shost, sizeof(tmp), tmp);
  D_DBG("  source address              = %s", tmp);
  ip_addr_snprintf(&cfg->dhost, sizeof(tmp), tmp);
  D_DBG("  target address              = %s", tmp);
  D_DBG("  source port random          = %s", cfg->shost.port_defined ? "no" : "yes");
  D_DBG("  target port random          = %s", cfg->dhost.port_defined ? "no" : "yes");
  D_DBG("  number of threads           = %d", cfg->c);
  D_DBG("  listener threads            = %d", cfg->l);
  D_DBG("  packets                     = %d", cfg->packets);
  D_DBG("  hits per second             = %f", cfg->hits);
  D_DBG("  timeout cwait               = %u", cfg->cwait);
  D_DBG("  timeout rwait               = %u", cfg->rwait);
  D_DBG("  runtime                     = %u", cfg->runtime);
  if(cmd)
  {
    D_DBG("  command [%s]", cmd->name[0]);
    if(cfg->params)
    {
      D_DBG("  with parameters (%d):", cfg->nparams);
      for(i = 0; i < cfg->nparams; i++)
        D_DBG("    %02d [%s]", i+1, cfg->params[i]);
    } else
      D_DBG("  no parameters pased.");
  } else
    D_DBG("  no command; launching a command line interface (CLI).");

  return cmd;
}

