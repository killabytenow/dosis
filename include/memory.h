/*****************************************************************************
 * memory.h
 *
 * Macros to acces memory without worrying if addresses are aligned (on certain
 * platforms)
 *
 * ---------------------------------------------------------------------------
 * DioNiSio - DNS scanner
 *   (C) 2006-2008 Gerardo García Peña
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

#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <config.h>

#if ALLOW_UNALIGNED_16
#define GET_UINT16_T(p)   (*((UINT16_T *) (p)))
#define SET_UINT16_T(p,v) (*((UINT16_T *) (p)) = v)
#else
static UINT16_T GET_UINT16_T(UINT16_T *p)
{
  return ((int) p) & 0x01
           ? (UINT16_T) ((*(((unsigned char *) p)) << 8) | *((((unsigned char *) p)+1)))
           : *p;
}
static UINT16_T SET_UINT16_T(UINT16_T *p, UINT16_T v)
{
  if(((int) p) & 0x01)
  {
    *(((unsigned char *) p)    ) = v >> 8;
    *(((unsigned char *) p) + 1) = v;
  } else
    *((UINT16_T *) p) = v;

  return v;
}
#endif

#if ALLOW_UNALIGNED_32
#define GET_UINT32_T(p)   (*((UINT32_T *) (p)))
#define SET_UINT32_T(p,v) (*((UINT32_T *) (p)) = v)
#else
static UINT32_T GET_UINT32_T(UINT32_T *p)
{
  switch(((int) p) & 0x03)
  {
    case 1:
    case 3:
      return (UINT32_T)
             ( (*((unsigned char *)  p)   << 24)
             | (*((unsigned short *) ((void *) p+1)) <<  8)
             | (*((unsigned char *)  p+3)));
    case 2:
      return (UINT32_T)
             ( (*((unsigned short *) p  ) <<  16)
             | (*((unsigned short *) p+1)));
    default:
      return *p;
  }
}
static UINT32_T SET_UINT32_T(UINT32_T *p, UINT32_T v)
{
  switch(((int) p) & 0x03)
  {
    case 0:
      *p = v;
      break;
    case 1:
    case 3:
      *((unsigned char *)  p)              = (v >> 24) & 0x000000FF;
      *((unsigned short *) ((void *) p+1)) = (v >>  8) & 0x0000FFFF;
      *((unsigned char *)  p+3)            = (v      ) & 0x000000FF;
      break;
    case 2:
      *((unsigned short *) p  ) = (v >> 16) & 0x0000FFFF;
      *((unsigned short *) p+1) = (v      ) & 0x0000FFFF;
      break;
  }
      
  return v;
}
#endif
#endif
