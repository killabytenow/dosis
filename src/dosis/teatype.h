/*****************************************************************************
 * teatype.h
 *
 * Types used during tea time.
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2010 Gerardo García Peña <gerardo@kung-foo.net>
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

#ifndef __TEATYPE_H__
#define __TEATYPE_H__

enum {
  TEA_TYPE_ADDR_PORT_ID = 1,
  TEA_TYPE_BOOL_ID,
  TEA_TYPE_DATA_ID,
  TEA_TYPE_FLOAT_ID,
  TEA_TYPE_INT_ID,
  TEA_TYPE_PORT_ID,
  TEA_TYPE_STRING_ID,
} TEA_TYPE_ID_LIST;

struct __TEA_DATA {
  void     *data;
  unsigned  size;
};

typedef struct _tag_TEA_TYPE_ADDR_PORT {
  INET_ADDR addr;
  int       port;
} TEA_TYPE_ADDR_PORT;
typedef int               TEA_TYPE_BOOL;
typedef struct __TEA_DATA TEA_TYPE_DATA;
typedef double            TEA_TYPE_FLOAT;
typedef int               TEA_TYPE_INT;
typedef char *            TEA_TYPE_STRING;

#endif
