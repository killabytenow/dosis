/*****************************************************************************
 * log.c
 *
 * This file implements a simple log system.
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

#include "dosconfig.h"
#include "dosis.h"
#include "log.h"

#if HAVE_DLFCN_H
void *lst;
#endif

/******************************************************************************
 * Internal log functions
 *
 *   These functions are the kernel of this library. These functions should not
 *   be used directly, instead you must use the d_log, d_error, .. functions
 *   and their macros (see 'log.h').
 */

FILE *logfile = NULL;

static char *d_log_get_level_desc(int level)
{
  char *type = NULL;

  switch(level)
  {
    case LOG_LEVEL_DEBUG2:  type = "DEBUG2:";   break;
    case LOG_LEVEL_DEBUG:   type = "DEBUG:";   break;
    case LOG_LEVEL_LOG:     type = "";         break;
    case LOG_LEVEL_WARNING: type = "warning:"; break;
    case LOG_LEVEL_ERROR:   type = "ERROR:";   break;
    case LOG_LEVEL_FATAL:   type = "ERROR:";   break;
    default:
      FAT("Unknown log level when printing message.");
  }

  return type;
}

static void d_log_prefix_print(int level, char *file, char *function)
{
  fputs(d_log_get_level_desc(level), logfile);
  if(file)     fprintf(logfile, "%s:", file);
  if(function) fprintf(logfile, "%s:", function);
}

static void d_log_level_print(int level, char *file, char *function, char *format, va_list args)
{
  if(cfg.verbosity < level)
    return;

/* XXX: When threaded, get log library lock here */
  d_log_prefix_print(level, file, function);

  vfprintf(logfile, format, args);
  fputc('\n', logfile);
}

/******************************************************************************
 * Public log functions
 *
 *   These functions only use the previous functions to expose a rich log API.
 */

void d_log_level(int level, char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(level, file, function, format, args);
  va_end(args);
  
  if(level == LOG_LEVEL_FATAL)
    exit(1);
}

void d_db2(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_DEBUG2, file, function, format, args);
  va_end(args);
}

void d_dbg(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_DEBUG, file, function, format, args);
  va_end(args);
}

void d_log(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_LOG, file, function, format, args);
  va_end(args);
}

void d_wrn(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_WARNING, file, function, format, args);
  va_end(args);
}

void d_err(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_ERROR, file, function, format, args);
  va_end(args);
}

void d_fat(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_FATAL, file, function, format, args);
  va_end(args);

  exit(1);
}

void d_stacktrace(int level)
{
#if HAVE_DLFCN_H
  if(lst)
  {
    void *(*stacktrace)(void) = dlsym(lst, "stacktrace");
    stacktrace();
  } else
    DBG("stacktrace library not available.");
#endif
}

static void log_fini(void)
{
  if(logfile != stderr)
    fclose(logfile);
#if HAVE_DLFCN_H
  if(lst)
    dlclose(lst);
#endif
}

void log_init(char *argv0)
{
  /* init log file */
  logfile = stderr;

  /* init libstacktrace (if available) */
#if HAVE_DLFCN_H
  if((lst = dlopen("libstacktrace.so", RTLD_LAZY)) != NULL)
  {
    void (*stacktrace_init)(int) = dlsym(lst, "stacktrace_init");
    stacktrace_init(-1);
  } else
    DBG("Cannot load libstacktrace.");
#endif

  /* get concious about dead */
  if(atexit(log_fini))
    FAT("Cannot set finalization routine.");
}

