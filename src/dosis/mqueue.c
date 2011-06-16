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

TEA_MSG *mqueue_peek(TEA_MSG_QUEUE *mq)
{
  TEA_MSG *m;
  pthreadex_mutex_begin(&(mq->mutex));
  m = mq ? mq->first : NULL;
  pthreadex_mutex_end();
  return m;
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

void mqueue_dump(int level, TEA_MSG_QUEUE *mq, char *prefixfrm, ...)
{
  va_list prefixarg;
  TEA_MSG *m, *lf;
  char prefix[256];

  if(prefixfrm)
  {
    va_start(prefixarg, prefixfrm);
    vsnprintf(prefix, sizeof(prefix), prefixfrm, prefixarg);
    va_end(prefixarg);
  } else
    *prefix = '\0';

  for(m = lf = mq->first; m; m = m->next)
  {
    d_log_level(level, THIS, "%s%s %ld.%09ld [0x" STRF_PTR_X "]",
                prefix,
                m == lf ? "==" : "| ",
                m->w.tv_sec, m->w.tv_nsec, (UINT_POINTER) m);
    if(m == lf)
      lf = lf->ff_next;
  }
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
  TEA_MSG *ff, *lf, *c;

  pthreadex_mutex_begin(&(mq->mutex));

  m->prev = m->next = m->ff_prev = m->ff_next = NULL;

DBG("POLLA STARTS.");
  if(!mq->last)
  {
DBG("POLLA CASE: set this msg [0x" STRF_PTR_X "] as the only pollancre.", (UINT_POINTER) m);
    mq->first =
      mq->last =
        mq->ff_last = m;
  } else
  if((m->w.tv_sec  > mq->last->w.tv_sec)
  || (m->w.tv_sec == mq->last->w.tv_sec && m->w.tv_nsec >= mq->first->w.tv_nsec))
  {
DBG("POLLA CASE: new last msg");
    /* this message defines the new last ff group (new sec group) */
    /* set as last message and last ff */
    m->prev = mq->last;
    mq->last->next = m;
    if(m->w.tv_sec != mq->last->w.tv_sec)
    {
      m->ff_prev = mq->ff_last;
      mq->ff_last->ff_next = m;
      mq->ff_last = m;
    }
    mq->last = m;
  } else
  if((m->w.tv_sec  < mq->first->w.tv_sec)
  || (m->w.tv_sec == mq->first->w.tv_sec && m->w.tv_nsec <= mq->first->w.tv_nsec))
  {
DBG("POLLA CASE: first msg and perhaps new ff group");
    /* this message is first, and perhaps is a new ff group (new sec group) */
    /* set message as first (and first ff if tv_sec fields aren't equal)    */
    m->next = mq->first;
    mq->first->prev = m;
    if(m->w.tv_sec == mq->first->w.tv_sec)
    {
DBG("POLLA CASE: removes current ff, and set this msg as first ff.");
      /* removes current ff, and set this msg as first ff */
      m->ff_next = mq->first->ff_next;
      if(m->ff_next)
        m->ff_next->ff_prev = m;
      mq->first->ff_next = NULL;
    } else {
DBG("POLLA CASE: set this msg as first ff.");
      /* set this msg as first ff */
      m->ff_next = mq->first;
      mq->first->ff_prev = m;
    }
    mq->first = m;
  } else {
DBG("POLLA CASE: insert msg [0x" STRF_PTR_X "] into proper ff segment.",  (UINT_POINTER) m);
    /* insert msg into proper ff segment, or create a new segment */
    /* 0 - search nearest segment ff-lf                           */
//(2, 2.9) (3, 3.8) (4.2, 4.9) (5)
    ff = mq->ff_last;
    lf = mq->last;
    while(m->w.tv_sec < ff->w.tv_sec)
    {
      lf = ff->prev;
      ff = ff->ff_prev;
    }

    /* add msg or create new segment */
    if(m->w.tv_sec > ff->w.tv_sec)
    {
      /* ff->ff_prev > m > lf > ff            */
      /*   =>                                 */
      /* (ff->ff_prev, ..., ff->prev) [m] (ff, ..., lf) */
DBG("POLLA CASE: new segment comes to the party.");
      /* 1 - a new segment comes to the party! */
      /* msg */
      m->prev = ff->prev;
      m->next = ff;
      m->prev->next = m;
      m->next->prev = m;

      /* seg */
      m->ff_prev = ff->ff_prev;
      m->ff_next = ff;
      m->ff_prev->ff_next = m;
      m->ff_next->ff_prev = m;
    } else {
DBG("POLLA CASE: inserting in segment between ff[0x" STRF_PTR_X "] and lf[0x" STRF_PTR_X "].", (UINT_POINTER) ff, (UINT_POINTER) lf);
      /* ff->ff_prev < m == lf == ff          */
      /*   =>                                 */
      /* (ff, ??[m]??, lf) */
      /* 2 - search the best place in segment, between  */
      /* 'ff' and 'lf', where msg m should be installed */
      
      /* if m should be sent later than c, then go to previous c */
      for(c = lf; m->w.tv_nsec < c->w.tv_nsec; c = c->prev)
        ;

      /* current c is equal or less (should be sent before) than m */
      /* insert msg */
      m->next = c->next;
      m->prev = c;
      m->prev->next = m;
      m->next->prev = m;

      /* seg - removes current ff, and set this msg as new ff */
      if(c == ff)
      {
        m->ff_next = c->ff_next;
        m->ff_prev = c->ff_prev;
        if(m->ff_next) m->ff_next->ff_prev = m;
        if(m->ff_prev) m->ff_prev->ff_next = m;
        c->ff_next = NULL;
        c->ff_prev = NULL;
      }
    }
DBG("POLLA CASE: pollaaaaaaaaaaaaaaaaa finish'd.");
  }

  mqueue_dump(LOG_LEVEL_DEBUG, mq, NULL);

  pthreadex_mutex_end();
}

