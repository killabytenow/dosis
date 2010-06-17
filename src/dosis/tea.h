/*****************************************************************************
 * tea.h
 *
 * Is now the tea time?
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2010 Gerardo Garc�a Pe�a <gerardo@kung-foo.net>
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
#include "lnet.h"
#include "mqueue.h"
#include "script.h"
#include "teatype.h"

typedef struct _tag_THREAD_WORK {
  /* generic info */
  int                      id;
  pthread_t                pthread_id;
  struct _tag_TEA_OBJECT  *to;
  void                    *data;

  /* listener/sender info */
  TEA_MSG_QUEUE           *mqueue;
  pthreadex_flag_t         mwaiting;
  /* XXX optimization not implemented XXX */
  /*struct _tag_THREAD_WORK *prev_listener;*/
  /*struct _tag_THREAD_WORK *next_listener;*/
} THREAD_WORK;

typedef struct _tag_TEA_OBJCFG {
  char     *name;
  int       type;
  int       needed;
  unsigned  offset;
  int       (*handler)(struct _tag_TEA_OBJCFG *oc, THREAD_WORK *tw);
} TEA_OBJCFG;
#define TOC_BEGIN(x)     TEA_OBJCFG x[] = {
#define TOC(n,t,m,s,f,h) { n, t##_ID, m, offsetof(s, f), h },
#define TOC_END          { NULL, 0, 0, 0 } };

typedef struct _tag_TEA_OBJECT {
  char       *name;
  int         initialized;
  unsigned    datasize;
  TEA_OBJCFG *cparams;
  int         listener;
  int         sender;

  void (*global_init)(void);
  int  (*configure)(THREAD_WORK *tw, SNODE *command, int first_time);
  void (*cleanup)(THREAD_WORK *tw);
  void (*thread)(THREAD_WORK *tw);
  int  (*listen_check)(THREAD_WORK *tw, int proto, char *msg, unsigned size);
} TEA_OBJECT;

/*- THREAD MANAGAMENT -------------------------------------------------------*/
TEA_MSG *tea_thread_msg_get(THREAD_WORK *tw);
TEA_MSG *tea_thread_msg_wait(THREAD_WORK *tw);
int      tea_thread_msg_push(int tid, INET_ADDR *addr, void *msg, int msg_size);
int      tea_thread_listener_search(int proto, char *b, unsigned int l, int pivot_id);
int      tea_thread_msg_send(LN_CONTEXT *lnc, TEA_MSG *m, int delay);

/*- THREAD LOG UTILITIES ----------------------------------------------------*/
#define GFAT(msg, ...)   FAT("[%s] " msg, MODNAME, ## __VA_ARGS__)
#define GERR(msg, ...)   ERR("[%s] " msg, MODNAME, ## __VA_ARGS__)
#define GWRN(msg, ...)   WRN("[%s] " msg, MODNAME, ## __VA_ARGS__)
#define GLOG(msg, ...)   LOG("[%s] " msg, MODNAME, ## __VA_ARGS__)
#define GDBG(msg, ...)   DBG("[%s] " msg, MODNAME, ## __VA_ARGS__)
#define GDBG2(msg, ...)  DBG2("[%s] " msg, MODNAME, ## __VA_ARGS__)

#define TFAT(msg, ...)   FAT("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TERR(msg, ...)   ERR("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TWRN(msg, ...)   WRN("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TLOG(msg, ...)   LOG("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TDBG(msg, ...)   DBG("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TDBG2(msg, ...)  DBG2("[%d/%s] " msg, tw->id, tw->to->name, ## __VA_ARGS__)
#define TDUMP(l,b,s)     {                                                \
                           char __dump_prefix[256];                       \
                           snprintf(__dump_prefix, sizeof(__dump_prefix), \
                                    "[%d/%s] ", tw->id, tw->to->name);    \
                           DUMP(l, __dump_prefix, b, s);                  \
                         }

/*- CORE --------------------------------------------------------------------*/
void tea_init(void);
void tea_timer(SNODE *program);

#endif
