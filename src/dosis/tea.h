/*****************************************************************************
 * tea.h
 *
 * Is now the tea time?
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

#ifndef __TEA_H__
#define __TEA_H__

#include "pthreadex.h"

typedef struct _tag_TEA_MSG {
  unsigned int   s;
  unsigned char *b;
} TEA_MSG;

typedef struct _tag_TEA_OBJECT {
  void (*launch)(THREAD_WORK *tw);
  void (*listen)(THREAD_WORK *tw, TEA_MSG *msg);
  void (*stop)(THREAD_WORK *tw);
  int  (*configure)(THREAD_WORK *tw);
} TEA_OBJECT;

typedef struct _tag_THREAD_WORK {
  int                  id;
  pthread_t            pthread_id;
  pthreadex_barrier_t *start;
} THREAD_WORK;

typedef int  (*tea_attack_go2work)(void);
typedef void (*tea_attack_thread)(THREAD_WORK *w);

void tea_timer(tea_attack_go2work go2work,
               tea_attack_thread attack_thread);

#endif
