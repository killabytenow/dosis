/*****************************************************************************
 * listener.c
 *
 * Raw IPQ listener (used by raw listeners like tcpopen).
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

#include <config.h>
#include "log.h"
#include "dosconfig.h"
#include "ipqex.h"
#include "listener.h"
#include "lnet.h"
#include "iptables.h"
#include "tea.h"

#define MODNAME        teaLISTENER.name
#define BUFSIZE        65535

static int               ipq_on;
static ipqex_info_t      ipq;
static pthreadex_mutex_t ipq_mutex;

typedef struct _tag_LISTENER_CFG {
  /* options */
  TEA_TYPE_BOOL      debug;

  /* other things */
  ipqex_msg_t imsg;
} LISTENER_CFG;

/*****************************************************************************
 * GLOBAL INITIALIZATION
 *****************************************************************************/

static void listener__global_fini(void)
{
  /* finish ipq */
  pthreadex_mutex_begin(&ipq_mutex);
  ipq_on = 0;
  ipqex_destroy(&ipq);
  pthreadex_mutex_end();

  /* restore initial iptables state */
  iptables_restore();

  /* XXX: commented... is necesary until program exit */
  /* pthreadex_mutex_destroy(&ipq_mutex); */
  GDBG("listener threads finished.");
}

static void listener__global_init(void)
{
  int f;
  char **a,
       *iscript[] = {
          "/sbin/iptables", "-t", "filter", "-F", NULL,
          "/sbin/iptables", "-t", "nat",    "-F", NULL,
          "/sbin/iptables", "-t", "mangle", "-F", NULL,
          "/sbin/iptables", "-t", "raw",    "-F", NULL,
          "/sbin/iptables", "-F", NULL,
          NULL },
       *igscript[] = {
          "/sbin/iptables", "-A", "FORWARD", "-j", "QUEUE", NULL,
          "/sbin/iptables", "-A", "INPUT",   "-j", "QUEUE", NULL,
          NULL },
       *isscript[] = {
          "/sbin/iptables", "-A", "FORWARD", "-i", NULL, "-j", "QUEUE", NULL,
          "/sbin/iptables", "-A", "INPUT",   "-i", NULL, "-j", "QUEUE", NULL,
          NULL },
       *ifscript[] = {
          "/sbin/iptables", "-L", "-v", NULL,
          NULL };

  /* init mutex */
  pthreadex_mutex_init(&ipq_mutex);
  pthreadex_mutex_name(&ipq_mutex, "listener-ipq-mutex");

  GDBG2("save iptables config.");
  iptables_save();

  /* read/change ipforward */
  GDBG2("Enable ip_forward flag.");
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    GFAT_ERRNO("/proc/sys/net/ipv4/ip_forward");
  if(write(f, "1\n", 2) < 0)
    GFAT_ERRNO("Cannot write ip_forward status");
  close(f);

  /* prepare the ipqueue */
  GDBG2("Init iptables config.");
  if(cfg.interfaces[0] == NULL)
  {
    iptables_apply_script(iscript);
    iptables_apply_script(igscript);
  } else {
    for(a = cfg.interfaces; *a; a++)
      if(*a)
      {
        isscript[4] = *a;
        isscript[12] = *a;
        iptables_apply_script(isscript);
      }
  }
  iptables_apply_script(ifscript);

  /* initialize ipq */
  GDBG2("Initializing ipq.");
  if(ipqex_init(&ipq, BUFSIZE))
    GFAT("!! Cannot initialize IPQ.");
  ipq_on = -1;

  /* set the finalization routine */
  dosis_atexit(MODNAME, listener__global_fini);

  GDBG("Initialized.");
}

/*****************************************************************************
 * LISTENER THREAD
 *****************************************************************************/

static void listener__thread(THREAD_WORK *tw)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;
  INET_ADDR addr;
  int id = 0;
  int r, proto;

  /* get packets and classify */
  while(!cfg.finalize)
  {
    pthreadex_mutex_begin(&ipq_mutex);
    if(ipq_on)
    {
      r = ipqex_msg_read(&lcfg->imsg, 1000000);
      if(r < 0)
        TERR("Error reading from IPQ: %s", ipq.err);
    } else
      r = -1;
    pthreadex_mutex_end();
    if(r <= 0)
      continue;

    /* fix protocol (if packet comes from ethernet)*/
    proto = 0;
    if(lcfg->imsg.m->hw_type == ARPHRD_ETHER
    || lcfg->imsg.m->hw_type == ARPHRD_LOOPBACK)
    {
      switch(ntohs(lcfg->imsg.m->hw_protocol))
      {
        case ETHERTYPE_IP:   proto = INET_FAMILY_IPV4; break;
        case ETHERTYPE_IPV6: proto = INET_FAMILY_IPV6; break;
        default:
          TWRN("Unknown ethernet type %d.", ntohs(lcfg->imsg.m->hw_protocol));
      }
    } else {
      TWRN("Unknown hardware type (hw_type) %d (0x%04x). Ignoring data package.",
             lcfg->imsg.m->hw_type,
             lcfg->imsg.m->hw_type);
    }

    if(lcfg->debug)
    {
      TLOG("Received following packet:");
      TDUMPMSG(LOG_LEVEL_LOG, proto, lcfg->imsg.m->payload, lcfg->imsg.m->data_len);
    }

repeat_search:
    id = proto != 0
           ? tea_thread_listener_search(proto, (char *) lcfg->imsg.m->payload, lcfg->imsg.m->data_len, id+1)
           : -1;
    if(id >= 0)
    {
      /* defer cancelation as much as possible */
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

      /* copy destination address */
      addr.type = proto;
      switch(proto)
      {
        case INET_FAMILY_IPV4:
          memcpy(&addr.in.inaddr, &IPV4_TADDR(lcfg->imsg.m->payload), sizeof(addr.in.inaddr));
          break;
        case INET_FAMILY_IPV6:
          /* XXX: IPv6 address not implemented (see issue #2 in github) */
          break;
        default:
          TWRN("Unknown protocol %d.", proto);
      }

      /* copy this msg and send to the thread */
      r = tea_thread_msg_push(id, &addr, lcfg->imsg.m->payload, lcfg->imsg.m->data_len);

      /* if the msg cannot be pushed... repeat this until it is pushed       */
      /* NOTE: rarely result (r) will be a negative number, because it would */
      /* mean that thread 'id' has been killed between 'search_listener' and */
      /* 'msg_push' calls. So it is not so inneficient as it seems...        */
      if(r < 0)
      {
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
        pthread_testcancel();
        goto repeat_search;
      } else
        if(lcfg->debug)
          TLOG("Packet pushed to thread %d", id);

      /* ok... msg pushed (accepted) so drop package */
      pthreadex_mutex_begin(&ipq_mutex);
      if(cfg.finalize)
        break;

      if(ipq_on)
      {
        if(ipqex_set_verdict(&lcfg->imsg, NF_DROP) <= 0)
          TERR("Cannot ACCEPT IPQ packet.");
      }
      pthreadex_mutex_end();

      /* accept cancellations */
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
      pthread_testcancel();
    } else {
      pthreadex_mutex_begin(&ipq_mutex);
      if(cfg.finalize)
        break;

      if(ipq_on)
      {
        if(ipqex_set_verdict(&lcfg->imsg, NF_ACCEPT) <= 0)
          TERR("Cannot ACCEPT IPQ packet.");
        if(lcfg->debug)
          TLOG("Packet not handled - ACCEPTED");
      }
      pthreadex_mutex_end();
    }
  }
}

static void listener__cleanup(THREAD_WORK *tw)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;

  pthreadex_mutex_begin(&ipq_mutex);
  ipqex_msg_destroy(&lcfg->imsg);
  pthreadex_mutex_end();
}

static int listener__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;

  if(first_time)
  {
    pthreadex_mutex_begin(&ipq_mutex);
    ipqex_msg_init(&lcfg->imsg, &ipq);
    pthreadex_mutex_end();
  }

  if(lcfg->debug)
    TLOG("LISTENER debug mode enabled. Packets will be printed.");

  return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * LISTENER TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(listener_cfg_def)
  TOC("debug", TEA_TYPE_BOOL, 0, LISTENER_CFG, debug, NULL)
TOC_END

TEA_OBJECT teaLISTENER = {
  .name        = "LISTENER",
  .datasize    = sizeof(LISTENER_CFG),
  .global_init = listener__global_init,
  .configure   = listener__configure,
  .cleanup     = listener__cleanup,
  .thread      = listener__thread,
  .cparams     = listener_cfg_def,
};

