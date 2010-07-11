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

/* important: pthreadex.h always must be included after log.h */
#ifdef HAVE_PTHREADEX_H
#include <pthreadex.h>
#endif

#if HAVE_DLFCN_H
void *lst = NULL;
#endif

/******************************************************************************
 * Internal log functions
 *
 *   These functions are the kernel of this library. These functions should not
 *   be used directly, instead you must use the d_log, d_error, .. functions
 *   and their macros (see 'log.h').
 */

FILE *logfile = NULL;
static struct timeval tstamp_pstart;
#ifdef HAVE_PTHREADEX_H
pthreadex_mutex_t ivedapowa;
#endif

static char *d_log_get_level_desc(int level)
{
  char *type = NULL;

  switch(level)
  {
    case LOG_LEVEL_DEBUG2:  type = "DB2:";     break;
    case LOG_LEVEL_DEBUG:   type = "DBG:";     break;
    case LOG_LEVEL_LOG:     type = "LOG:";     break;
    case LOG_LEVEL_WARNING: type = "WARNING:"; break;
    case LOG_LEVEL_ERROR:   type = "ERROR:";   break;
    case LOG_LEVEL_FATAL:   type = "FATAL:";   break;
    default:
      FAT("Unknown log level when printing message.");
  }

  return type;
}

static void d_log_prefix_print(int level, char *file, char *function)
{
  if(cfg.log_tstamp)
  {
    struct timeval temptv;
    if(gettimeofday(&temptv, NULL) < 0)
      FAT_ERRNO("Cannot get current time");
    temptv.tv_usec -= tstamp_pstart.tv_usec;
    temptv.tv_sec  -= tstamp_pstart.tv_sec;
    if(temptv.tv_usec < 0)
    {
      temptv.tv_usec += 1000000;
      temptv.tv_sec  += 1;
    }
    fprintf(logfile, "[%3ld.%06ld] ",
            temptv.tv_sec, temptv.tv_usec);
  }
  fputs(d_log_get_level_desc(level), logfile);
  if(cfg.log_srcloc)
  {
    if(file)     fprintf(logfile, "%s:", file);
    if(function) fprintf(logfile, "%s:", function);
  }
}

static void d_log_level_print(int level, char *file, char *function, char *format, va_list args)
{
  if(cfg.verbosity < level)
    return;

  /* (when threaded) get log library lock here */
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_begin(&ivedapowa);
#endif

  /* print The Pretty Log Line (tm) */
  d_log_prefix_print(level, file, function);
  vfprintf(logfile, format, args);
  fputc('\n', logfile);

  /* (when threaded) unlock the log lock */
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_end();
#endif
}

/******************************************************************************
 * Public log functions
 *
 *   These functions only use the previous functions to expose a rich log API.
 */

void d_log_level_v(int level, char *file, char *function, char *format, va_list args)
{
  d_log_level_print(level, file, function, format, args);
  
  if(level == LOG_LEVEL_FATAL)
    exit(1);
}

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

/******************************************************************************
 * Dump function
 *
 *   A nice hex-dumper!
 */

void d_dump(int level, char *file, char *func, char *prefix, void *buff, int size)
{
  char dump[255], *s;
  unsigned char c;
  int i, j, m, w;

  if(cfg.verbosity < level)
    return;

  /* (if threaded) get the log lock now */
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_begin(&ivedapowa);
#endif

  /* dump... */
  if(!prefix)
    prefix = "";

  w = 16;
  for(i = 0; i < size; i += w)
  {
    /* max chars for this churro */
    m = i + w;
    /* start printing hex info */
    s = dump;
    for(j = i; j < m; j++)
    {
      if(!(j & 0x7)) *s++ = ' ';
      if(j >= size)
      {
        *s++ = ' ';
        *s++ = ' ';
        *s++ = ' ';
      } else
        s += sprintf(s, " %02x", *(((unsigned char *) buff) + j));
    }
    /* concat printable-string churro */
    *s++ = ' ';
    if(m > size) m = size;
    for(j = i; j < m; j++)
    {
      c = *(((unsigned char *) buff) + j);
      if(!(j & 0x7)) *s++ = ' ';
      *s++ = isgraph(c) ? c : '.';
    }
    *s = '\0';
    /* output churro */
    /* XXX: When threaded, get log library lock here */
    d_log_prefix_print(level, file, func);
    fprintf(logfile, "%s%04x %s\n", prefix, i, dump);
  }

  /* (if threaded) free da lock */
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_end();
#endif
  
  if(level == LOG_LEVEL_FATAL)
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
#endif
    DBG("stacktrace library not available.");
}

static void log_fini(void)
{
  if(logfile != stderr)
    fclose(logfile);
#if HAVE_DLFCN_H
  if(lst)
  {
    DBG("Closing libstacktrace.");
    dlclose(lst);
  }
  lst = NULL;
#endif
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_destroy(&ivedapowa);
#endif
}

void log_init(void)
{
#if HAVE_DLFCN_H
  int  (*stacktrace_version_check)(int, int, int);
  void (*stacktrace_init_siglist)(int, ...);
#endif

  /* init log file */
  logfile = stderr;

  /* init thread lock */
#ifdef HAVE_PTHREADEX_H
  pthreadex_mutex_init(&ivedapowa);
  pthreadex_mutex_name(&ivedapowa, "log-lock");
#endif

  /* init libstacktrace (if available) */
#if HAVE_DLFCN_H
  if((lst = dlopen("libstacktrace.so", RTLD_LAZY)) != NULL)
  {
    stacktrace_version_check = dlsym(lst, "stacktrace_version_check");

    if(!dlerror() && stacktrace_version_check(1, 2, 1))
    {
      stacktrace_init_siglist = dlsym(lst, "stacktrace_init_siglist");
      if(!dlerror())
      {
        stacktrace_init_siglist(1,
                                SIGILL, SIGFPE, SIGSEGV,
                                SIGABRT, SIGBUS, 0);
        DBG("libstacktrace loaded.");
      }
    } else {
      dlclose(lst);
      lst = NULL;
    }
  } else
    DBG("Cannot load libstacktrace.");
#endif

  /* get program start timestamp */
  if(gettimeofday(&tstamp_pstart, NULL) < 0)
    FAT_ERRNO("Cannot get current time");

  /* get concious about dead */
  if(atexit(log_fini))
    FAT("Cannot set finalization routine.");
}

