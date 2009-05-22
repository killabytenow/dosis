/*****************************************************************************
 * tea.h
 *
 * Is now the tea time?
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2009 Gerardo García Peña <gerardo@kung-foo.dhs.org>
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
  unsigned int         bs;
  unsigned char       *b;
  struct _tag_TEA_MSG *prev;
  struct _tag_TEA_MSG *next;
} TEA_MSG;

typedef struct _tag_TEA_MSG_QUEUE {
  int                no_moar;
  TEA_MSG           *first;
  TEA_MSG           *last;
  pthreadex_mutex_t  mutex;
} TEA_MSG_QUEUE;

typedef struct _tag_THREAD_WORK {
  /* generic info */
  int                      id;
  pthread_t                pthread_id;
  struct _tag_TEA_OBJECT  *methods;
  void                    *data;

  /* listener info */
  TEA_MSG_QUEUE           *mqueue;
  pthreadex_flag_t         mwaiting;
  struct _tag_THREAD_WORK *prev_listener;
  struct _tag_THREAD_WORK *next_listener;
} THREAD_WORK;

typedef struct _tag_TEA_OBJECT {
  char *name;
  int   initialized;
  void (*global_init)(void);
  int  (*configure)(THREAD_WORK *tw, SNODE *command);
  void (*cleanup)(THREAD_WORK *tw);
  void (*thread)(THREAD_WORK *tw);
  void (*listen)(THREAD_WORK *tw);
  int  (*listen_check)(THREAD_WORK *tw, char *msg, unsigned size);
} TEA_OBJECT;

/*- THREAD MANAGAMENT -------------------------------------------------------*/
int  tea_thread_msg_push(int tid, TEA_MSG *m);
int  tea_thread_search_listener(char *b, unsigned int l);

/*- MQUEUE MANAGAMENT -------------------------------------------------------*/
void     tea_mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m);
TEA_MSG *tea_mqueue_shift(TEA_MSG_QUEUE *mq);

/*- MESSAGE MANAGAMENT ------------------------------------------------------*/
TEA_MSG *tea_msg_allocate(void);
void     tea_msg_destroy(TEA_MSG *m);
void     tea_msg_fill(TEA_MSG *m, char *b, unsigned int s);
TEA_MSG *tea_msg_get(void);
void     tea_msg_release(TEA_MSG *msg);

/*- NODE UTILITIES ----------------------------------------------------------*/
char    *tea_get_var(SNODE *n);
char    *tea_get_string(SNODE *n);
int      tea_get_int(SNODE *n);
double   tea_get_float(SNODE *n);

/*- CORE --------------------------------------------------------------------*/
void tea_init(void);
void tea_timer(SNODE *program);

#endif
