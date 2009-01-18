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
#include "dosconfig.h"
#include "log.h"
#include "tcpopen.h"

void handle_termination__signal(int s)
{
  if(!dos_param_get_bool("finalize"))
  {
    WRN("One more termination signal will force program termination.");
    dos_param_set("finalize", "true");
  } else {
    FAT("Program termination forced.");
    exit(1);
  }
}

int main(int argc, char *argv[])
{
  int res;

  log_init();

  /* install signal handlers */
  signal(SIGHUP,  handle_termination__signal);
  signal(SIGINT,  handle_termination__signal);
  signal(SIGQUIT, handle_termination__signal);
  signal(SIGTERM, handle_termination__signal);

  if(dos_config_init(argc, argv, &res))
  {
    FAT("bad config");
  }

  /* get input parameters */
#if 0
  while((opt = getopt(argc, argv, "c:C:d:D:H:l:p:r:R:s:S:T:v:")) != -1)
  {
    switch(opt)
    {
      case 'c':
        if((config.c = atol(optarg)) < 0)
          FAT("You cannot use less than 0 threads.");
        break;
      case 'C':
        if (!(config.cwait = atol(optarg)))
          FAT("Error getting connection timeout.");
        break;
      case 'd':
        if(optarg && ip_addr_parse(optarg, &config.dhost))
            FAT("Bad target IP address.");
        break;
      case 'D':
        if(optarg)
        {
          res = atoi(optarg);
          if(!res)
            FAT("Failed to convert the desired destination port.");
          config.rdport = 0;
          ip_addr_set_port(&config.dhost, res);
        }
        break;
      case 'H':
        sscanf(optarg, "%lf", &config.hits);
        if(config.hits < 0.0)
          FAT("Error getting hits per second.");
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
      case 's':
        if(optarg && ip_addr_parse(optarg, &config.shost))
            FAT("Bad source IP address.");
        break;
      case 'S':
        if(optarg)
        {
          res = atoi(optarg);
          if(!res)
            FAT("Failed to convert the desired source port.");
          config.rsport = 0;
          ip_addr_set_port(&config.shost, res);
        }
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
      default:
        FAT("Bad option.");
        exit(-1);
    }
  }

  /* set the rest of options */
  config.rdport   = config.dhost.port ? 0 : 1;
  if(!config.req)
  {
    config.req = strdup("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    config.req_size = strlen(config.req);
    WRN("Assuming default request (http://<addr>/)");
  }

  if(!INET_ADDR_IS_VALID(config.shost))
    FAT("A source address is required!");
  if(!INET_ADDR_IS_VALID(config.dhost))
    FAT("A destination address is required!");
  if(!config.dhost.port)
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
#endif
  LOG("Finished.");

  return 0;
}

