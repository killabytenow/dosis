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
#include "lnet.h"

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

    msg_buffer(m, TEA_MSG_FIRST_BUFFER);
    m->s  = 0;
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

void msg_set_addr(TEA_MSG *m, INET_ADDR *a)
{
  memcpy(&m->dest, a, sizeof(INET_ADDR));
}

TEA_MSG *msg_build_ip_udp_packet(INET_ADDR *saddr, int sport,
                                 INET_ADDR *daddr, int dport,
                                 char *data, int datasz)
{
  TEA_MSG *m = msg_get();
  int s;

  if((s = ln_build_ip_udp_packet(NULL,
                                 saddr, sport,
                                 daddr, dport,
                                 data, datasz,
                                 NULL)) < 0)
  {
    ERR("Cannot calculate UDP packet size.");
    return NULL;
  }
  msg_set_addr(m, daddr);
  if(!msg_buffer(m, s))
  {
    ERR("Cannot grow TEA_MSG 0x%08x to %d bytes.",
          (unsigned) m, s);
    return NULL;
  }
  if((s = ln_build_ip_udp_packet(m->b,
                                 saddr, sport,
                                 daddr, dport,
                                 data, datasz,
                                 NULL)) < 0)
  {
    ERR("Cannot fill UDP packet.");
    return NULL;
  }

  return m;
}

TEA_MSG *msg_build_ip_tcp_packet(INET_ADDR *saddr, int sport,
                                 INET_ADDR *daddr, int dport,
                                 int flags, int window,
                                 int seq, int ack,
                                 char *data, int datasz,
                                 char *opts, int optssz)
{
  TEA_MSG *m = msg_get();
  int s;

  if((s = ln_build_ip_tcp_packet(NULL,
                                 saddr, sport,
                                 daddr, dport,
                                 flags, window, seq, ack,
                                 data, datasz,
                                 opts, optssz,
                                 NULL)) < 0)
  {
    ERR("Cannot calculate TCP packet size.");
    return NULL;
  }
  msg_set_addr(m, daddr);
  if(!msg_buffer(m, s))
  {
    ERR("Cannot grow TEA_MSG 0x%08x to %d bytes.",
          (unsigned) m, s);
    return NULL;
  }
  if((s = ln_build_ip_tcp_packet(m->b,
                                 saddr, sport,
                                 daddr, dport,
                                 flags, window, seq, ack,
                                 data, datasz,
                                 opts, optssz,
                                 NULL)) < 0)
  {
    ERR("Cannot fill TCP packet.");
    return NULL;
  }

  return m;
}

void mqueue_insert_delayed(TEA_MSG_QUEUE *mq, TEA_MSG *m)
{
  TEA_MSG *ff, *lf;

  pthreadex_mutex_begin(&(mq->mutex));

  m->prev = m->next = m->ff_prev = m->ff_next = NULL;

DBG("POLLA STARTS.");
  if(!mq->last)
  {
    mq->first =
      mq->last =
        mq->ff_last = m;
  } else
  if(m->w.tv_sec > mq->last->w.tv_sec)
  {
DBG("POLLA CASE: new last ff");
    /* this message defines the new last ff group (new sec group) */
    /* set as last message and last ff */
    m->prev    = mq->last;
    m->ff_prev = mq->ff_last;
    if(mq->last)
    {
      mq->last->next = m;
      mq->ff_last->ff_next = m;
    } else
      mq->first = m;
    mq->last = m;
    mq->ff_last = m;
  } else
  if((m->w.tv_sec  < mq->first->w.tv_sec)
  || (m->w.tv_sec == mq->first->w.tv_sec && m->w.tv_nsec <= mq->first->w.tv_nsec))
  {
DBG("POLLA CASE: first msg and perhaps new ff group");
    /* this message is first, and perhaps is a new ff group (new sec group) */
    /* set message as first (and first ff if tv_sec fields aren't equal)    */
    m->next = mq->first;
    if(mq->first)
    {
      mq->first->prev = m;
      if(m->w.tv_sec == mq->first->w.tv_sec)
      {
DBG("POLLA CASE: removes current ff, and set this msg as first ff.");
        /* removes current ff, and set this msg as first ff */
        m->ff_next = mq->first->ff_next;
        if(m->ff_next)
          m->ff_next->ff_prev = m;
        mq->first->ff_next = NULL;
        mq->first->ff_prev = NULL;
      } else {
DBG("POLLA CASE: set this msg as first ff.");
        /* set this msg as first ff */
        m->ff_next = mq->first;
        mq->first->ff_prev = m;
      }
    } else {
DBG("POLLA CASE: me chirrian los huevos.");
      m->ff_next  = NULL;
      mq->last    = m;
      mq->ff_last = m;
    }
    mq->first = m;
  } else {
DBG("POLLA CASE: insert msg into proper ff segment.");
    /* insert msg into proper ff segment, or create a new segment */
    /* 0 - search nearest time segment (ff can be equal or older) */
    ff = mq->ff_last;
    lf = mq->last;
    while(ff && m->w.tv_sec > ff->w.tv_sec)
    {
      lf = ff->prev;
      ff = ff->ff_prev;
    }
    if(!ff)
      FAT("This code should never be executed.");

    /* add msg or create new segment */
    if(m->w.tv_sec < ff->w.tv_sec)
    {
DBG("POLLA CASE: new segment coes to the party.");
      /* 1 - a new segment comes to the party! */
      /* msg */
      m->prev = ff;
      m->next = ff->next;
      if(m->next)
        m->next->prev = m;
      ff->next = m;

      /* seg */
      m->ff_prev = ff;
      m->ff_next = ff->ff_next;
      if(m->ff_next)
        m->ff_next->ff_prev = m;
      ff->ff_next = m;
    } else {
      /* 2 - search the best place in segment for this msg */
      /* m must be installed between 'ff' and 'lf' */
      for( ; lf != ff->prev; lf = lf->prev)
      {
        if(m->w.tv_nsec <= lf->w.tv_nsec)
        {
          /* msg */
          m->prev = lf;
          m->next = lf->next;
          if(m->next)
            m->next->prev = m;
          lf->next = m;

          /* seg - removes current ff, and set this msg as new ff */
          if(lf == ff)
          {
            m->ff_prev = lf->ff_prev;
            m->ff_next = lf->ff_next;
            if(m->ff_next)
              m->ff_next->ff_prev = m;
            if(m->ff_prev)
              m->ff_prev->ff_next = m;
            ff->ff_next = NULL;
            ff->ff_prev = NULL;
          }
          break;
        }
      }
    }
  }

  pthreadex_mutex_end();
}

