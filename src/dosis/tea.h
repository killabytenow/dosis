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
#include "script.h"

typedef struct _tag_TEA_MSG {
  unsigned int         s;
  unsigned char       *b;
  struct _tag_TEA_MSG *next;
} TEA_MSG;

typedef struct _tag_TEA_MSG_QUEUE {
  TEA_MSG           *first;
  TEA_MSG           *last;
  pthreadex_mutex_t *mutex;
} TEA_MSG_QUEUE;

typedef struct _tag_THREAD_WORK {
  int                     id;
  pthread_t               pthread_id;
  pthreadex_flag_t       *mwaiting;
  TEA_MSG_QUEUE          *mqueue;
  struct _tag_TEA_OBJECT *methods;
  void                   *data;
} THREAD_WORK;

typedef struct _tag_TEA_OBJECT {
  void (*configure)(THREAD_WORK *tw);
  void (*cleanup)(THREAD_WORK *tw);
  void (*thread)(THREAD_WORK *tw);
  void (*listen)(THREAD_WORK *tw);
  void (*listen_check)(THREAD_WORK *tw, char *msg, unsigned size);
} TEA_OBJECT;

void tea_timer_init(SNODE *program);
void tea_timer(SNODE *program);

#endif
