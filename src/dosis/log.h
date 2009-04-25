/*****************************************************************************
 * log.h
 *
 * This header file exports a simple log system.
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

#ifndef __LOG_H__
#define __LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_LEVEL_FATAL       -1
#define LOG_LEVEL_ERROR       0
#define LOG_LEVEL_WARNING     1
#define LOG_LEVEL_LOG         2
#define LOG_LEVEL_DEBUG       3
#define LOG_LEVEL_DEBUG2      4

#define LOG_LEVEL_ALL         4

#define THIS                  (char *) __FILE__, (char *) __FUNCTION__

#define FAT(...)              d_fat(THIS, __VA_ARGS__)
#define ERR(...)              d_err(THIS, __VA_ARGS__)
#define WRN(...)              d_wrn(THIS, __VA_ARGS__)
#define LOG(...)              d_log(THIS, __VA_ARGS__)
#define DBG(...)              d_dbg(THIS, __VA_ARGS__)
#define DBG2(...)             d_db2(THIS, __VA_ARGS__)

#define D_FAT(...)            FAT(__VA_ARGS__)
#define D_ERR(...)            ERR(__VA_ARGS__)
#define D_WRN(...)            WRN(__VA_ARGS__)
#define D_LOG(...)            LOG(__VA_ARGS__)
#define D_DBG(...)            DBG(__VA_ARGS__)
#define D_DBG2(...)           DBG2(__VA_ARGS__)

void d_log_level(int level, char *file, char *function, char *format, ...);
void d_dbg(char *file, char *function, char *format, ...);
void d_db2(char *file, char *function, char *format, ...);
void d_log(char *file, char *function, char *format, ...);
void d_wrn(char *file, char *function, char *format, ...);
void d_err(char *file, char *function, char *format, ...);
void d_fat(char *file, char *function, char *format, ...) __attribute__ ((__noreturn__));;

void log_init(void);

#ifdef __cplusplus
}
#endif

#endif
