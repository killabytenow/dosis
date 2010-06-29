/*****************************************************************************
 * sender.c
 *
 * Raw packet sender (used by some scheduled listeners like tcpopen).
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

#include <config.h>
#include "dosconfig.h"
#include "log.h"
#include "lnet.h"
#include "tea.h"

#define MODNAME        teaSENDER.name

typedef struct _tag_SENDER_CFG {
  /* options */
  TEA_TYPE_BOOL  debug;

  /* config */
  LN_CONTEXT     lnc;
} SENDER_CFG;

/*****************************************************************************
 * SENDER THREAD
 *****************************************************************************/

static void sender__thread(THREAD_WORK *tw)
{
  SENDER_CFG *scfg = (SENDER_CFG *) tw->data;
  TEA_MSG *m;
  long long tout = 100;
  struct timespec now;

  /* send packets */
  while(!cfg.finalize)
  {
    /* wait for signal/timeout */
    if(pthreadex_flag_wait_timeout(&tw->mwaiting, tout) == ETIMEDOUT)
      TDBG2("timeout after %lld miliseconds!", tout);
    else
      TDBG2("something received");

    /* send packets in cronological order */
    TDBG("sending everything scheduled until now!");
    if(clock_gettime(CLOCK_REALTIME, &now) < 0)
    {
      ERR_ERRNO("Cannot read CLOCK_REALTIME");
      continue;
    }

    while((m = mqueue_shift(tw->mqueue)) != NULL
    && (now.tv_sec > m->w.tv_sec
    || (now.tv_sec == m->w.tv_sec && now.tv_nsec > m->w.tv_nsec)))
    {
      if(scfg->debug)
      {
        TLOG("Going to send following packet:");
        TDUMPMSG(LOG_LEVEL_LOG, m->dest.type,  m->b, m->s);
      }
      ln_send_packet(&scfg->lnc, m->b, m->s, &m->dest);
    }
  }
}

static void sender__cleanup(THREAD_WORK *tw)
{
  SENDER_CFG *scfg = (SENDER_CFG *) tw->data;

  /* XXX close raw socket */
  if(scfg)
  {
    ln_destroy_context(&scfg->lnc);
  }
  TDBG("Finalized.");
}

static int sender__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  SENDER_CFG *scfg = (SENDER_CFG *) tw->data;

  if(first_time)
  {
    /* open raw socket */
    /* XXX TODO: allow other protocols (IP/UDP/TCP) */
    ln_init_context(&scfg->lnc);
  }

  if(scfg->debug)
    TLOG("SENDER debug mode enabled. Debug info will be printed.");

  return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * SENDER TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(sender_cfg_def)
  TOC("debug", TEA_TYPE_BOOL, 0, SENDER_CFG, debug, NULL)
TOC_END

TEA_OBJECT teaSENDER = {
  .name        = "SENDER",
  .datasize    = sizeof(SENDER_CFG),
  .configure   = sender__configure,
  .cleanup     = sender__cleanup,
  .thread      = sender__thread,
  .cparams     = sender_cfg_def,
};

