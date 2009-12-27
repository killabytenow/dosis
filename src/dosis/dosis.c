/*****************************************************************************
 * dosis.c
 *
 * DoS generator.
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

#include <config.h>
#include "dosis.h"
#include "dosconfig.h"
#include "log.h"
#include "tea.h"

#ifdef HAVE_SSL
#include "sslthread.h"
#endif

void handle_termination__signal(int s)
{
  if(!cfg.finalize)
  {
    WRN("One more termination signal will force program termination.");
    cfg.finalize = -1;
  } else {
    ERR("Program termination forced (signal %d).", s);

    /* print stacktrace and exit */
    d_stacktrace(LOG_LEVEL_DEBUG);
    exit(EXIT_FAILURE);
  }
}

void handle_crash__signal(int s)
{
  ERR("Snow crash!");
  d_stacktrace(LOG_LEVEL_DEBUG);
  abort();
}

int handle_pthreadex_eintr(void)
{
  ERR("EINTR at pthreadex!");
  return cfg.finalize ? -1 : 0;
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
  (void) pthreadex_set_signal_callback(handle_pthreadex_eintr);
  if(signal(SIGHUP,  handle_termination__signal) == SIG_ERR
  || signal(SIGINT,  handle_termination__signal) == SIG_ERR
  || signal(SIGQUIT, handle_termination__signal) == SIG_ERR
  || signal(SIGTERM, handle_termination__signal) == SIG_ERR
  || signal(SIGILL,  handle_crash__signal) == SIG_ERR
  || signal(SIGFPE,  handle_crash__signal) == SIG_ERR
  || signal(SIGSEGV, handle_crash__signal) == SIG_ERR)
    FAT("Cannot install signal handlers.");

  /* read command line parameters */
  dos_config_init(argc, argv);

  /* parse script */
  if((script = script_parse()) == NULL)
    FAT("Cannot parse input script.");

  /* execute script */
  tea_timer(script);

  LOG("Finished.");

  return 0;
}

