/*****************************************************************************
 * mqueue.c
 *
 * Messages and message queue management.
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

#include "config.h"
#include "mqueue.h"
#include "log.h"

static TEA_MSG_QUEUE    *msg_free;

static void msg_destroy(TEA_MSG *m);

/*---------------------------------------------------------------------------*
 * MQUEUE MANAGAMENT
 *
 *   MQUEUE objects are threadsafe queues for making FIFO queues of raw
 *   network messages. This interface provides a simple message passing
 *   facility to deliver raw packets from the listener threads to other
 *   types of threads that need a raw network input.
 *---------------------------------------------------------------------------*/

TEA_MSG_QUEUE *mqueue_create(void)
{
  TEA_MSG_QUEUE *mq;

  if((mq = calloc(1, sizeof(TEA_MSG_QUEUE))) == NULL)
    FAT("No memory for a tea message queue.");
  pthreadex_mutex_init(&(mq->mutex));
  pthreadex_mutex_name(&(mq->mutex), "mqueue-mutex");

  return mq;
}

void mqueue_destroy(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  /* empty queue */
  while((m = mqueue_shift(mq)) != NULL)
    if(mq == msg_free)
      msg_destroy(m);
    else
      msg_release(m);

  /* destroy mutex */
  pthreadex_mutex_destroy(&mq->mutex);

  /* free queue */
  free(mq);
}

void mqueue_push(TEA_MSG_QUEUE *mq, TEA_MSG *m)
{
  pthreadex_mutex_begin(&(mq->mutex));
  m->next = NULL;
  m->prev = mq->last;
  if(mq->last)
    mq->last->next = m;
  else
    mq->first = m;
  mq->last = m;
  pthreadex_mutex_end();
}

TEA_MSG *mqueue_shift(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;

  if(!mq)
    return NULL;

  pthreadex_mutex_begin(&(mq->mutex));
  m = mq->first;
  if(m)
  {
    mq->first = m->next;
    if(mq->first)
      mq->first->prev = NULL;
    else
      mq->last = NULL;
    m->prev = NULL;
    m->next = NULL;
  }
  pthreadex_mutex_end();

  return m;
}

void mqueue_fini(void)
{
  mqueue_destroy(msg_free);
}

void mqueue_init(void)
{
  msg_free = mqueue_create();
}

/*---------------------------------------------------------------------------*
 * MESSAGE MANAGAMENT
 *
 *   Following functions create, get, release and destroy messages.
 *---------------------------------------------------------------------------*/

static void msg_destroy(TEA_MSG *m)
{
  free(m->b);
  m->b  = NULL;
  m->s  = 0;
  m->bs = 0;
}

TEA_MSG *msg_get(void)
{
  TEA_MSG *m;

  if((m = mqueue_shift(msg_free)) == NULL)
  {
    if((m = calloc(1, sizeof(TEA_MSG))) == NULL)
      FAT("No memory for msg.");

    m->b  = NULL;
    m->s  = 0;
    m->bs = 0;
  }

  return m;
}

void msg_release(TEA_MSG *m)
{
  mqueue_push(msg_free, m);
}

void *msg_buffer(TEA_MSG *m, unsigned int s)
{
  unsigned char *p;

  if(s > m->bs)
  {
    if((p = realloc(m->b, s)) == NULL)
      return NULL;
    m->b  = p;
    m->bs = s;
  } else
    p = m->b;
  m->s = s;

  return p;
}

void msg_fill(TEA_MSG *m, char *b, unsigned int s)
{
  /* get moar mem, if necessary */
  if(msg_buffer(m, s) == NULL)
    FAT("No memory for msg of size %d.", s);

  /* copy msg */
  if(s > 0)
    memcpy(m->b, b, s);
}

