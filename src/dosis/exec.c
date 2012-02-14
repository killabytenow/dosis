/*****************************************************************************
 * exec.c
 *
 * external command execution
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2012 Gerardo García Peña <gerardo@kung-foo.net>
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
#include "log.h"
#include "dosconfig.h"

int dosis_exec_pipe_inout(int fin, int fout, int ferr, char **cmd)
{
  int pid;

  if((pid = dosis_fork()) == 0)
  {
    /* redirected fin, fout & ferr (if fxxx > 0) */
    if(fin  >  0) { close(0); if(dup(fin)  < 0) FAT_ERRNO("dup(fin)");  }
    if(fout >= 0) { close(1); if(dup(fout) < 0) FAT_ERRNO("dup(fout)"); }
    if(ferr >= 0) { close(2); if(dup(ferr) < 0) FAT_ERRNO("dup(ferr)"); }

    /* child */
    {
    char **c;
    DBG("Going to execute:");
    for(c = cmd; *c; c++)
      DBG("  [%s]", *c);
    }
    execv(cmd[0], cmd);
    FAT_ERRNO("Cannot execute %s", cmd[0]);
  }

  return pid;
}

void dosis_exec_inout(int fin, int fout, int ferr, char **cmd)
{
  int pid, r;

  /* launch program in background */
  pid = dosis_exec_pipe_inout(fin, fout, ferr, cmd);

  /* wait program to finish */
  waitpid(pid, &r, 0);
  if(r != 0)
    FAT("Command %s failed.", cmd[0]);
}

void dosis_exec_log_output(int loglevel, int finput, char **cmd)
{
  int pid, r;
  int p[2];
  char buff[1000];
  FILE *f;

  /* build pipe to fetch stdout and stderr */
  if(pipe(p) < 0)
      FAT_ERRNO("Cannot pipe");

  /* launch program in background */
  pid = dosis_exec_pipe_inout(finput, p[0], p[0], cmd);

  /* write output to log */
  close(p[1]);
  if((f = fdopen(p[0], "r")) == NULL)
    FAT_ERRNO("Cannot fdopen pipe");

  while(fgets(buff, sizeof(buff), f) != NULL)
  {
    char *s;
    for(s = buff; *s; s++)
      if(*s == '\r' || *s == '\n')
        *s = '\0';
    d_log_level(loglevel, (char *) __FILE__, cmd[0], "%s", buff);
  }
  fclose(f);
  close(p[0]);

  /* wait program to finish */
  waitpid(pid, &r, 0);
  if(r != 0)
    FAT("Command %s failed.", cmd[0]);
}

