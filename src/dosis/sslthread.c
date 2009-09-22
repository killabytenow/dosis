/*****************************************************************************
 * sslthread.c
 *
 * SSL threading support initialization/finalization.
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
#include "log.h"
#include "pthreadex.h"
#include "sslthread.h"

static pthread_mutex_t *lock_cs;
static long            *lock_count;

static void SSL_pthreads_locking_callback(int mode, int type, char *file, int line)
{
  if(mode & CRYPTO_LOCK)
  {
    pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
  } else
    pthread_mutex_unlock(&(lock_cs[type]));
}

static unsigned long SSL_pthreads_thread_id(void)
{
  return (unsigned long) pthread_self();
}

static void SSL_thread_fini(void)
{
  int x;

  CRYPTO_set_locking_callback(NULL);
  for(x = 0; x < CRYPTO_num_locks(); x++)
    pthread_mutex_destroy(&(lock_cs[x]));
  OPENSSL_free(lock_cs);
  OPENSSL_free(lock_count);
}

void SSL_thread_init(void)
{
  int x;

  if(atexit(SSL_thread_fini))
    FAT("Cannot install SSL thread finalization function.");

  lock_cs = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  lock_count = (long *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

  for(x = 0; x < CRYPTO_num_locks(); x++)
  {
    lock_count[x] = 0;
    pthread_mutex_init(&(lock_cs[x]), NULL);
  }

  CRYPTO_set_id_callback((unsigned long (*)()) SSL_pthreads_thread_id);
  CRYPTO_set_locking_callback((void (*)()) SSL_pthreads_locking_callback);
}

