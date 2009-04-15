/*****************************************************************************
 * dosconfig.c
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

/* default config and global configuration pointer */
DOS_CONFIG cfg = {
  /* verbosity        */ LOG_LEVEL_WARNING,
  /* output filename  */ NULL,
  /* script filename  */ NULL,
  /* max threads      */ 100,
};
DOS_CONFIG cfg;

/* private object's global variables */
static struct option *long_options = NULL;
static char *short_options = NULL;

typedef struct _tag_CMD_OPTION {
  char shortopt;
  char *longopt;
  int   has_arg; /* 0 no arg; 1 yes; 2 optional */
} DOS_CMD_OPTION;

DOS_CMD_OPTION cmd_options[] = {
  { 'h', "help",          0 },
  { 'o', "output-file",   1 },
  { 'q', "quiet",         0 },
  { 't', "max-threads",   1 },
  { 'v', "verbose",       2 },
  {   0, NULL,            0 },
};
#define CMD_OPTIONS_N (sizeof(cmd_options) / sizeof(DOS_CMD_OPTION))

/*****************************************************************************
 * Command Line Parser
 *
 *   Following code parses command line input (with getopt(3) help), updating
 *   current configuration (cfg).
 *
 *****************************************************************************/

static void dos_config_parse_command(int argc, char **argv)
{
  int c, fin,
      option_index = 0;
  char *s;

  /* configure and reset getopt */
  opterr = 0;
  optind = 1;

  /* get options */
  fin = 0;
  while(!fin)
  {
    c = getopt_long(argc, argv, short_options, long_options, &option_index);

    switch(c)
    {
      case 'h':
          print_help();
          exit(0);
          break;
      case 'o':
          if(!optarg || strlen(optarg) == 0)
            D_FAT("Required a valid filename.");
          if((cfg.output = strdup(optarg)) == NULL)
            D_FAT("No mem for ouput filename.");
          break;
      case 'q':
          cfg.verbosity = 0;
          break;
      case 't':
          cfg.maxthreads = atoi(optarg);
          if(cfg.maxthreads < 1)
            D_FAT("A minimum of 1 thread is needed.");
          break;
      case 'v':
          if(!optarg)
            s = "3";
          cfg.verbosity = atoi(s);
          break;
      case -1:
          fin = -1;
          break;
      default:
          D_FAT("Invalid option '%c'.", c); 
    }
  }

  if(argc - optind > 1)
    D_FAT("Specify only one script file.");
  if(argc - optind < 1)
    cfg.script = NULL;
  else
    if((cfg.script = strdup(argv[optind])) == NULL)
      D_FAT("No mem for script filename.");
}

/*****************************************************************************
 * Initialization and finalization routines
 *****************************************************************************/

static void dos_config_fini(void)
{
  if(cfg.output)       free(cfg.output);
  if(cfg.script)       free(cfg.script);
  if(cfg.of != stdout) fclose(cfg.of);

  if(short_options)
    free(short_options);
  if(long_options)
    free(long_options);
}

void dos_config_init(int argc, char **argv)
{
  int i, j;
  char *s;

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

  /* read config and command from command line */
  dos_config_parse_command(argc, argv);

  /* open files */
  if(cfg.script)
  {
    close(0);
    if(open(argv[optind], O_RDONLY) < 0)
      D_FAT("Cannot read file '%s': %s.", argv[optind], strerror(errno));
  } else
    D_WRN("Reading standard input.");

  if(cfg.output)
  {
    if((cfg.of = fopen(cfg.output, "w")) == NULL)
      D_FAT("Cannot write output file '%s'.", cfg.output);
  } else {
    D_WRN("Writing to standard output.");
    cfg.of = stdout;
  }

  /* print program header and config (if debug verbosity enabled) */
  dos_help_program_header();
  D_DBG("Configuration");
  D_DBG("  verbosity level = %d", cfg.verbosity);
  D_DBG("  script file     = %s", cfg.script ? cfg.script : "<standard input>");
  D_DBG("  output file     = %s", cfg.output ? cfg.output : "<standard output>");
}

