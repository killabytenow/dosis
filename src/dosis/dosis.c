/*****************************************************************************
 * dosis.c
 *
 * DoS generator.
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
#include "dosis.h"
#include "dosconfig.h"
#include "log.h"
#include "tea.h"

void handle_termination__signal(int s)
{
  if(!cfg.finalize)
  {
    WRN("One more termination signal will force program termination.");
    cfg.finalize = -1;
  } else {
    FAT("Program termination forced.");
    exit(1);
  }
}

int main(int argc, char *argv[])
{
  SNODE *script;

  log_init();
  tea_init();
  script_init();
#ifdef HAVE_SSL
  SSL_thread_init();
#endif

  /* install signal handlers */
  signal(SIGHUP,  handle_termination__signal);
  signal(SIGINT,  handle_termination__signal);
  signal(SIGQUIT, handle_termination__signal);
  signal(SIGTERM, handle_termination__signal);

  /* read command line parameters */
  dos_config_init(argc, argv);

  /* parse script */
  if((script = script_parse()) == NULL)
    FAT("Cannot parse input script.");

  tea_timer(script);

  LOG("Finished.");

  return 0;
}

