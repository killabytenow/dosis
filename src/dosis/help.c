/*****************************************************************************
 * help.c
 *
 * Helpful messages.
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
#include "help.h"
#include "log.h"

void dos_help_program_header(void)
{
  char *msg[] = {
    PACKAGE_NAME " version " PACKAGE_VERSION ", Copyright (C) 2006-2009 Gerardo García Peña",
    PACKAGE_NAME " is free software and comes with ABSOLUTELY NO WARRANTY;",
    "you are welcome to redistribute it under certain conditions;",
    "for details see the file `COPYING' that accompanies this software.",
    "----------------------------------------------------------------------",
    "",
    NULL
  };
  char **i;

  for(i = msg; *i; i++)
    d_log(NULL, NULL, "%s", *i);
}

void print_help(void)
{
  char *msg[] = {
    "Usage: dosis [option] ... [script_file]",
    "Denial-of-Service suite.",
    "",
    "Mandatory arguments to long options are mandatory for short options too."
    "",
    "  -h, --help              This help message.",
    "  -i, --interface=IFACE   Choose input interface (for iptales/ipq).",
    "  -I, --include=DIR       Add a scripts/files source directory.",
    "  -q, --quiet             Shut up.",
    "  -o, --output-file=FILE  Write results to FILE.",
    "  -t, --max-threads=FILE  Set maximum thread parallelism (default 100).",
    "  -T, --tstamp-log        Time stamped log messages (default no).",
    "  -v, --verbose[=LEVEL]   Don't stop writing baby (default). LEVEL is a value",
    "                          between 0 (errors) and 4 (deep debugging messages).",
    "  -Z, --debug             Very verbose. Specially funny with a slow SSH session.",
    NULL
  };
  char **i;

  for(i = msg; *i; i++)
    d_log(NULL, NULL, "%s", *i);
}

