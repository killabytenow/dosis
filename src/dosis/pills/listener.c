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
#include "tea.h"

#define MODNAME        teaLISTENER.name
#define BUFSIZE        65535

#define IPV4_SADDR_P(p,x)  INET_ADDR_IPV4_GETP(p, IPV4_SADDR(x))
#define IPV4_TADDR_P(p,x)  INET_ADDR_IPV4_GETP(p, IPV4_TADDR(x))

static char              iptables_tmp[255];
static char              ip_forward_status;
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
  int f, pid, r;
  char buf[100];

  /* finish ipq */
  pthreadex_mutex_begin(&ipq_mutex);
  ipq_on = 0;
  ipqex_destroy(&ipq);
  pthreadex_mutex_end();

  /* restore ipforward */
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    GFAT("/proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  buf[0] = ip_forward_status;
  buf[1] = '\n';
  if(write(f, buf, 2) < 0)
    GFAT("Cannot set ip_forward: %s", strerror(errno));
  close(f);

  /* restore iptables */
  if((pid = dosis_fork()) == 0)
  {
    /* child */
    /* restore iptables state */
    close(0);
    if(open(iptables_tmp, O_RDONLY) < 0)
      GFAT("Cannot read %s: %s", iptables_tmp, strerror(errno));
    execl("/sbin/iptables-restore", "/sbin/iptables-restore", NULL);
    /* if this code is executed, we have an error */
    GFAT("/sbin/iptables-restore: %s", strerror(errno));
  }
  /* parent */
  waitpid(pid, &r, 0);
  if(r != 0)
    GFAT("iptables-restore failed.");
  if(unlink(iptables_tmp) < 0)
    GFAT("Cannot unlink %s: %s", iptables_tmp, strerror(errno));

  /* XXX: commented... is necesary until program exit */
  /* pthreadex_mutex_destroy(&ipq_mutex); */

  GDBG("listener threads finished.");
}

static void apply_iptables_script(char **script)
{
  int pid, r;
  char **a;
  int p[2];
  char buff[1000];
  FILE *f;

  for(a = script; *a; )
  {
    if(pipe(p) < 0)
        GFAT("Cannot pipe: %s", strerror(errno));

    if((pid = dosis_fork()) == 0)
    {
      /* output redirected to pipe */
      close(p[0]);
      close(1);
      close(2);
      if(dup(p[1]) < 0) GFAT("Cannot dup(1): %s", strerror(errno));
      if(dup(p[1]) < 0) GFAT("Cannot dup(2): %s", strerror(errno));

      /* child */
      execv(a[0], a);
      GFAT("Cannot execute /sbin/iptables: %s", strerror(errno));
    }

    /* write output to log */
    close(p[1]);
    if((f = fdopen(p[0], "r")) == NULL)
      GFAT("Cannot fdopen pipe: %s", strerror(errno));

    while(fgets(buff, sizeof(buff), f) != NULL)
    {
      char *s;
      for(s = buff; *s; s++)
        if(*s == '\r' || *s == '\n')
          *s = '\0';
      GDBG2("%s: %s", a[0], buff);
    }
    fclose(f);

    /* parent */
    waitpid(pid, &r, 0);
    if(r != 0)
      GFAT("Command failed.");

    /* next command */
    while(*a++ != NULL)
      ;
  }
}

static void listener__global_init(void)
{
  int f, pid, r;
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

  /* read/change ipforward */
  GDBG2("Enable ip_forward flag.");
  if((f = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY)) < 0)
    GFAT("/proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  r = read(f, &ip_forward_status, 1);
  if(r == 0)
    GFAT("Invalid ip_forward content.");
  if(r < 0)
    GFAT("Cannot read ip_forward status: %s", strerror(errno));
  close(f);
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    GFAT("/proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  if(write(f, "1\n", 2) < 0)
    GFAT("Cannot write ip_forward status: %s", strerror(errno));
  close(f);

  /* prepare the ipqueue */
  GDBG2("save iptables config.");
  strcpy(iptables_tmp, "iptables-state-XXXXXX");
  f = mkstemp(iptables_tmp);
  if((pid = dosis_fork()) == 0)
  {
      /* child */
      /* save iptables state */
      close(1);
      if(dup(f) < 0)
        GFAT("Cannot dup: %s", strerror(errno));
      close(f);
      execl("/sbin/iptables-save", "/sbin/iptables-save", NULL);
      /* if this code is executed, we have an error */
      GFAT("Cannot execute /sbin/iptables-save: %s", strerror(errno));
  }
  /* here continues parent */
  close(f);
  waitpid(pid, &r, 0);
  if(r != 0)
    GFAT("iptables-save failed.");

  GDBG2("Init iptables config.");
  if(cfg.interfaces[0] == NULL)
  {
    apply_iptables_script(iscript);
    apply_iptables_script(igscript);
  } else {
    for(a = cfg.interfaces; *a; a++)
      if(*a)
      {
        isscript[4] = *a;
        isscript[12] = *a;
        apply_iptables_script(isscript);
      }
  }
  apply_iptables_script(ifscript);

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
        TERR("Error reading from IPQ: %s", lcfg->imsg.err.str);
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
DBG("Analizing packet hw_type = %d (%x)", lcfg->imsg.m->hw_type, lcfg->imsg.m->hw_type);
      switch(ntohs(lcfg->imsg.m->hw_protocol))
      {
        case ETHERTYPE_IP:   proto = INET_FAMILY_IPV4; break;
        case ETHERTYPE_IPV6: proto = INET_FAMILY_IPV6; break;
        default:
          TDBG("Unknown ethernet protocol %d.", ntohs(lcfg->imsg.m->hw_protocol));
      }
DBG("Analizing packet proto = %d", proto);
    } else {
      TWRN("Unknown hardware type (hw_type) %d (0x%04x). Ignoring data package.",
             lcfg->imsg.m->hw_type,
             lcfg->imsg.m->hw_type);
    }

    if(lcfg->debug)
    {
      switch(proto)
      {
        case INET_FAMILY_IPV4:
          if(IPV4_UDP_HDRCK(lcfg->imsg.m->payload, lcfg->imsg.m->data_len))
          {
            TLOG("IPv4/UDP packet (%d bytes) %d.%d.%d.%d:%d->%d.%d.%d.%d:%d:",
                   lcfg->imsg.m->data_len,
                   IPV4_SADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(0, lcfg->imsg.m->payload),
                   ntohs(IPV4_UDP_HDR(lcfg->imsg.m->payload)->uh_sport),
                   IPV4_TADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(0, lcfg->imsg.m->payload),
                   ntohs(IPV4_UDP_HDR(lcfg->imsg.m->payload)->uh_dport));
          } else
          if(IPV4_TCP_HDRCK(lcfg->imsg.m->payload, lcfg->imsg.m->data_len))
          {
            TLOG("IPv4/TCP packet (%d bytes) %d.%d.%d.%d:%d->%d.%d.%d.%d:%d [%s%s%s%s%s%s]:",
                   lcfg->imsg.m->data_len,
                   IPV4_SADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(0, lcfg->imsg.m->payload),
                   ntohs(IPV4_TCP_HDR(lcfg->imsg.m->payload)->th_sport),
                   IPV4_TADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(0, lcfg->imsg.m->payload),
                   ntohs(IPV4_TCP_HDR(lcfg->imsg.m->payload)->th_dport),
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->fin ? "F" : "",
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->syn ? "S" : "",
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->rst ? "R" : "",
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->psh ? "P" : "",
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->ack ? "A" : "",
                   IPV4_TCP_HDR(lcfg->imsg.m->payload)->urg ? "U" : "");
          } else
          if(IPV4_HDRCK(lcfg->imsg.m->payload, lcfg->imsg.m->data_len))
          {
            TLOG("IPv4/Unknown(%d) packet received (%d bytes) from %d.%d.%d.%d to %d.%d.%d.%d:",
                   IPV4_PROTOCOL(lcfg->imsg.m->payload),
                   lcfg->imsg.m->data_len,
                   IPV4_SADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_SADDR_P(0, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(3, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(2, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(1, lcfg->imsg.m->payload),
                   IPV4_TADDR_P(0, lcfg->imsg.m->payload));
          } else {
            TLOG("Malformed IPV4 packet received (%d bytes):", lcfg->imsg.m->data_len);
          }
          break;
        case INET_FAMILY_IPV6:
          TLOG("IPv6 packet received (%d bytes):", lcfg->imsg.m->data_len);
          break;
        default:
          TLOG("Unknown protocol %d packet received (%d bytes):", proto, lcfg->imsg.m->data_len);
      }
      TDUMP(LOG_LEVEL_LOG, lcfg->imsg.m->payload, lcfg->imsg.m->data_len);
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
#warning "TODO: copy destination address"

      /* copy this msg and send to the thread */
      r = tea_thread_msg_push(id, NULL, lcfg->imsg.m->payload, lcfg->imsg.m->data_len);

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

