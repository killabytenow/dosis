/*****************************************************************************
 * help.c
 *
 * Helpful messages.
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
#include "help.h"

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
    D_LOG(NULL, NULL, *i);
}

void print_help(void)
{
}

