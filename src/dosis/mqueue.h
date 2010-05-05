/*****************************************************************************
 * mqueue.h
 *
 * Messages and message queue management.
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

#ifndef __MQUEUE_H__
#define __MQUEUE_H__

#include "ip.h"
#include "log.h"
#include "mqueue.h"
#include "pthreadex.h"
#include "teatype.h"

typedef struct _tag_TEA_MSG {
  unsigned int         s;    /* msg size                               */
  unsigned char       *b;    /* msg bytes                              */
  unsigned int         bs;   /* real buffer size (bs always >= than s) */
  union {
    unsigned int       ui;
    void              *vp;
    struct timespec    ts;
  } x;
  struct _tag_TEA_MSG *prev; /* (double linked list) previous message  */
  struct _tag_TEA_MSG *next; /* (double linked list) next message      */
} TEA_MSG;

typedef struct _tag_TEA_MSG_QUEUE {
  TEA_MSG           *first;  /* first msg in list                      */
  TEA_MSG           *last;   /* last msg (adding optimization)         */
  pthreadex_mutex_t  mutex;  /* mutual exclusion lock to avoid RC      */
} TEA_MSG_QUEUE;

/*- MQUEUE MANAGAMENT -------------------------------------------------------*/
void           mqueue_init(void);
void           mqueue_fini(void);
TEA_MSG_QUEUE *mqueue_create(void);
void           mqueue_destroy(TEA_MSG_QUEUE *mq);
void           mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m);
TEA_MSG       *mqueue_shift(TEA_MSG_QUEUE *mq);

/*- MESSAGE MANAGAMENT ------------------------------------------------------*/
TEA_MSG *msg_get(void);
void     msg_fill(TEA_MSG *m, char *b, unsigned int s);
void    *msg_buffer(TEA_MSG *m, unsigned int s);
void     msg_release(TEA_MSG *msg);

/*- MESSAGE PACKET BUILDING -------------------------------------------------*/
TEA_MSG *msg_build_ip_udp_packet(TEA_TYPE_ADDR *shost,
                                 TEA_TYPE_ADDR *dhost,
                                 char *data, int data_sz);
TEA_MSG *msg_build_ip_tcp_packet(TEA_TYPE_ADDR *shost, 
                                 TEA_TYPE_ADDR *dhost,
                                 int flags, int window,
                                 int seq, int ack,
                                 char *data, int data_sz,
                                 char *opts, int opts_sz);

#endif
