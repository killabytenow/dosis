/*****************************************************************************
 * listener.c
 *
 * Raw IPQ listener (used by raw listeners like tcpopen).
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

#include <config.h>
#include "dosconfig.h"
#include "ipqex.h"
#include "listener.h"
#include "log.h"
#include "tea.h"

#if 0
#include "dosis.h"
#include "tcpopen.h"
#include "lnet.h"
#include "pthreadex.h"
#include "ip.h"
#endif

#define BUFSIZE 65535

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

static char              iptables_tmp[255];
static char              ip_forward_status;
static ipqex_info_t      ipq;
static pthreadex_mutex_t ipq_mutex;

typedef struct _tag_TCPRAW_CFG {
  ipqex_msg_t imsg;
} LISTENER_CFG;

/*****************************************************************************
 * GLOBAL INITIALIZATION
 *****************************************************************************/

static void listener__global_fini(void)
{
  int f, pid, r;
  char buf[100];
  int p[2];

  if(pipe(p) < 0)
    FAT("Cannot create pipe: %s", iptables_tmp, strerror(errno));

  /* restore ipforward */
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    FAT("Cannot open /proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  buf[0] = ip_forward_status;
  buf[1] = '\n';
  if(write(f, buf, 2) < 0)
    FAT("Cannot write ip_forward status: %s", strerror(errno));
  close(f);

  /* restore iptables */
  switch(pid = fork())
  {
    case -1:
      FAT("Cannot fork: %s", strerror(errno));
      break;

    case 0:
      /* save iptables state */
      close(p[1]);
      execl("/sbin/iptables-restore", "/sbin/iptables-restore", NULL);
      /* if this code is executed, we have an error */
      FAT("Cannot execute /sbin/iptables-save: %s", strerror(errno));
      break;

    default:
      close(p[0]);
      if((f = open(iptables_tmp, O_RDONLY)) < 0)
        FAT("Cannot read %s: %s", iptables_tmp, strerror(errno));
      while((r = read(f, buf, sizeof(buf))) <= 0)
        write(p[1], buf, r);
      close(p[1]);
      close(f);
      waitpid(pid, &r, 0);
      if(r != 0)
        FAT("iptables-restore failed.");
      if(unlink(iptables_tmp) < 0)
        FAT("Cannot unlink %s: %s", iptables_tmp, strerror(errno));
  }

  /* finish ipq */
  ipqex_destroy(&ipq);
  pthreadex_mutex_destroy(&ipq_mutex);
}

static void listener__global_init(void)
{
  int f, pid, r;
  char **a, *iscript[] = {
      "/sbin/iptables", "-t", "filter", "-F", NULL,
      "/sbin/iptables", "-t", "nat",    "-F", NULL,
      "/sbin/iptables", "-t", "mangle", "-F", NULL,
      "/sbin/iptables", "-t", "raw",    "-F", NULL,
      "/sbin/iptables", "-F", NULL,
      "/sbin/iptables", "-A", "FORWARD", "-j", "QUEUE", NULL,
      "/sbin/iptables", "-A", "INPUT",   "-j", "QUEUE", NULL,
      "/sbin/iptables", "-L", NULL,
      NULL };

  /* set the finalization routine */
  if(atexit(listener__global_fini))
    D_FAT("Cannot set finalization routine.");

  /* init mutex */
  pthreadex_mutex_init(&ipq_mutex);

  /* read/change ipforward */
  if((f = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY)) < 0)
    FAT("Cannot open /proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  switch(read(f, &ip_forward_status, 1))
  {
    case 0:
      FAT("Invalid ip_forward content.");
    case -1:
      FAT("Cannot read ip_forward status: %s", strerror(errno));
    default:
      DBG("ip_forward status %c.", ip_forward_status);
  }
  close(f);
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    FAT("Cannot open /proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
  if(write(f, "1\n", 2) < 0)
    FAT("Cannot write ip_forward status: %s", strerror(errno));
  close(f);

  /* prepare the ipqueue */
  strcpy(iptables_tmp, "iptables-state-XXXXXX");
  f = mkstemp(iptables_tmp);
  switch(pid = fork())
  {
    case -1:
      FAT("Cannot fork: %s", strerror(errno));
      break;

    case 0:
      /* save iptables state */
      close(1);
      dup(f);
      close(f);
      execl("/sbin/iptables-save", "/sbin/iptables-save", NULL);
      /* if this code is executed, we have an error */
      FAT("Cannot execute /sbin/iptables-save: %s", strerror(errno));
      break;

    default:
      close(f);
      waitpid(pid, &r, 0);
      if(r != 0)
        FAT("iptables-save failed.");
  }
  DBG("init iptables config.");
  for(a = iscript; *a; )
  {
    if((pid = fork()) < 0)
        FAT("Cannot fork: %s", strerror(errno));

    /* child */
    if(!pid)
    {
      execv(a[0], a);
      FAT("Cannot execute /sbin/iptables-save: %s", strerror(errno));
    }

    /* parent */
    waitpid(pid, &r, 0);
    if(r != 0)
      FAT("Command failed.");

    /* next command */
    while(*a++ != NULL)
      ;
  }
  DBG("finished iptables config.");

  /* initialize ipq */
  DBG("[%s] Initializing ipq.", teaLISTENER.name);
  if(ipqex_init(&ipq, BUFSIZE))
    FAT("[%s]  !! Cannot initialize IPQ.", teaLISTENER.name);

  DBG("[%s] Initialized.", teaLISTENER.name);
}

/*****************************************************************************
 * LISTENER THREAD
 *****************************************************************************/

static void listener__thread(THREAD_WORK *tw)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;
  TEA_MSG *tmsg;
  int id;
  int r;

  /* get packets and classify */
DBG("ZITIFLOYER");
  while(!cfg.finalize)
  {
    pthreadex_mutex_begin(&ipq_mutex);
#if 1
DBG(" ----------------------------------------------------------- imsg");
    r = ipqex_msg_read(&lcfg->imsg, 0);
DBG("ZUSPITOYER ==================================================");
    if(r < 0)
      ERR("Error reading from IPQ: %s (errno %s)", ipq_errstr(), strerror(errno));
    pthreadex_mutex_end();
    if(r <= 0)
      continue;

repeat_search:
    id = tea_thread_search_listener((char *) lcfg->imsg.m->payload, lcfg->imsg.m->data_len);
    if(id >= 0)
    {
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
      tmsg = tea_msg_get();
      tea_msg_fill(tmsg, (char *) lcfg->imsg.m->payload, lcfg->imsg.m->data_len);
      r = tea_thread_msg_push(id, tmsg);
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
      pthread_testcancel();
      /* if the msg cannot be pushed... repeat this until it is pushed */
      if(r < 0)
      {
        tea_msg_release(tmsg);
        tmsg = NULL;
        goto repeat_search;
      }
    } else {
#warning "decide here the best policy for not handled packets in IPQ."
      pthreadex_mutex_begin(&ipq_mutex);
      if(ipqex_set_verdict(&lcfg->imsg, NF_DROP) <= 0)
        ERR("Cannot DROP IPQ packet.");
      pthreadex_mutex_end();
#if 0
      /* policy: accept anything unknown */
      if(ipqex_set_verdict(&tw->msg, NF_ACCEPT) <= 0)
        ERR("[LL_%02u] Cannot ACCEPT IPQ packet.", tw->w->id);
#endif
    }
#else
sleep(2);
DBG("kinki kinki");
      pthreadex_mutex_end();
#endif
  }
DBG("FUSKARRO");
}

static void listener__cleanup(THREAD_WORK *tw)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;

  pthreadex_mutex_begin(&ipq_mutex);
  ipqex_msg_destroy(&lcfg->imsg);
  pthreadex_mutex_end();

  free(tw->data);
  tw->data = NULL;

  DBG("[%02u] Finalized.", tw->id);
}

static int listener__configure(THREAD_WORK *tw, SNODE *command)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;

  if(lcfg == NULL)
  {
    if((lcfg = calloc(1, sizeof(LISTENER_CFG))) == NULL)
      D_FAT("[%02d] No memory for LISTENER_CFG.", tw->id);
    tw->data = (void *) lcfg;

    pthreadex_mutex_begin(&ipq_mutex);
    ipqex_msg_init(&lcfg->imsg, &ipq);
    pthreadex_mutex_end();
  }

  return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * LISTENER TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaLISTENER = {
  .name        = "LISTENER",
  .global_init = listener__global_init,
  .configure   = listener__configure,
  .cleanup     = listener__cleanup,
  .thread      = listener__thread,
};

