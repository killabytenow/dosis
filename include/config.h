/*****************************************************************************
 * config.h
 *
 * In this file are used in correct order the header files marked by the
 * configuration script of Dosis. Are declared also some constants with help
 * of hints given by the configuration script.
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

#ifndef __DOS_CONFIG_H__
#define __DOS_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include "autoconfig.h"
#endif

/* Now include the string library of C */
#if HAVE_STRING_H
#  include <string.h>
#else
#  if HAVE_STRINGS_H
#    include <strings.h>
#  endif
#endif

/* mandatory includes */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <assert.h>
#include <limits.h>

/* uio */
#include <sys/uio.h>

/* network hardcore */
#include <libnet.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

/* Some functions as log functions (d_debug, d_log, d_error ...)     */
/* have a variable number of parameters so 'stdarg.h' will be needed */
#include <stdarg.h>

/* getopt is used to read command line parameters */
#include <getopt.h>

/* offsetof macro (if not exists then use this implementation) */
#ifndef offsetof
#define offsetof(st, f)  (((char *) &(((st *) 0)->f)) - ((char *) 0))
#endif

/* openssl includes */
#ifdef HAVE_SSL
# define OPENSSL_THREAD_DEFINES

# ifdef HAVE_E_OS_H
#  include <openssl/e_os.h>
# endif
# ifdef HAVE_E_OS2_H
#  include <openssl/e_os2.h>
# endif
# include <openssl/lhash.h>
# include <openssl/crypto.h>
# include <openssl/buffer.h>
# include <openssl/x509.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# include <openssl/pem.h>

# include <openssl/opensslconf.h>
# if !defined(THREADS) && !defined(OPENSSL_THREADS)
#  error "Your openssl libraries were compiled without thread support."
# endif
#endif

/* data types */
#if HAVE_INT8_T
# define INT8_T         int8_t
#elif SIZEOF_CHAR == 1
# define INT8_T         char
#else
# error "I don't know how to define INT8_T"
#endif

#if HAVE_UINT8_T
# define UINT8_T        uint8_t
#elif HAVE_U_INT8_T
# define UINT8_T        u_int8_t
#elif SIZEOF_CHAR == 1
# define UINT8_T        unsigned char
#else
# error "I don't know how to define UINT8_T"
#endif

#if HAVE_INT16_T
# define INT16_T        int16_t
#elif SIZEOF_SHORT_INT == 2
# define INT16_T        short
#elif SIZEOF_INT == 2
# define INT16_T        int
#else
# error "I don't know how to define INT16_T"
#endif

#if HAVE_UINT16_T
# define UINT16_T       uint16_t
#elif HAVE_U_INT16_T
# define UINT16_T       u_int16_t
#elif SIZEOF_SHORT_INT == 2
# define UINT16_T       unsigned short
#elif SIZEOF_INT == 2
# define UINT16_T       unsigned int
#else
# error "I don't know how to define UINT16_T"
#endif

#if HAVE_INT32_T
# define INT32_T        int32_t
#elif SIZEOF_INT == 4
# define INT32_T        int
#elif SIZEOF_LONG_INT == 4
# define INT32_T        long int
#else
# error "I don't know how to define INT32_T"
#endif

#if HAVE_UINT32_T
# define UINT32_T       uint32_t
#elif HAVE_U_INT32_T
# define UINT32_T       u_int32_t
#elif SIZEOF_INT == 4
# define UINT32_T       unsigned int
#elif SIZEOF_LONG_INT == 4
# define UINT32_T       unsigned long int
#else
# error "I don't know how to define UINT32_T"
#endif

#if HAVE_INT64_T
# define INT64_T        int64_t
#elif SIZEOF_INT == 8
# define INT64_T        int
#elif SIZEOF_LONG_INT == 8
# define INT64_T        long int
#elif SIZEOF_LONG_LONG == 8
# define INT64_T        long long
#else
# warning "I don't know how to define INT64_T"
#endif

#if HAVE_UINT64_T
# define UINT64_T       uint64_t
#elif HAVE_U_INT64_T
# define UINT64_T       u_int64_t
#elif SIZEOF_INT == 8
# define UINT64_T       unsigned int
#elif SIZEOF_LONG_INT == 8
# define UINT64_T       unsigned long int
#elif SIZEOF_LONG_LONG == 8
# define UINT64_T       unsigned long long
#else
# warning "I don't know how to define U_INT64_T"
#endif

#if SIZEOF_VOID_P == 4
# define UINT_POINTER   UINT32_T
# define INT_POINTER    INT32_T
#elif SIZEOF_VOID_P == 8
# define UINT_POINTER   UINT64_T
# define INT_POINTER    INT64_T
#else
# error "Unknown sizeof (void *)"
#endif

#if SIZEOF_VOID_P == SIZEOF_INT
# define STRF_PTR_D   "%d"
# define STRF_PTR_X   "%04x"
#else
# define STRF_PTR_D   "%ld"
# define STRF_PTR_X   "%08lx"
#endif

#ifdef __cplusplus
}
#endif

#endif
