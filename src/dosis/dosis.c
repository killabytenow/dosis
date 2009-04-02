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
  DOS_COMMAND *c;

  log_init();

  /* install signal handlers */
  signal(SIGHUP,  handle_termination__signal);
  signal(SIGINT,  handle_termination__signal);
  signal(SIGQUIT, handle_termination__signal);
  signal(SIGTERM, handle_termination__signal);

  if((c = dos_config_init(argc, argv, &res)) == NULL)
  {
    FAT("bad config");
  }

  /* XXX */
  c->command();

  LOG("Finished.");

  return 0;
}

