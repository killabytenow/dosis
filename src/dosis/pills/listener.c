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
#include "dosconfig.h"
#include "ipqex.h"
#include "listener.h"
#include "log.h"
#include "tea.h"

#define MODNAME        teaLISTENER.name
#define BUFSIZE        65535

static char              iptables_tmp[255];
static char              ip_forward_status;
static int               ipq_on;
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
  TEA_MSG *tmsg;
  int id = 0;
  int r;

  /* get packets and classify */
  while(1)
  {
    pthreadex_mutex_begin(&ipq_mutex);
    if(ipq_on)
    {
      r = ipqex_msg_read(&lcfg->imsg, 500000);
      if(r < 0)
        TERR("Error reading from IPQ: %s", lcfg->imsg.err.str);
    } else
      r = -1;
    pthreadex_mutex_end();
    if(r <= 0)
      continue;

repeat_search:
    id = tea_thread_search_listener((char *) lcfg->imsg.m->payload, lcfg->imsg.m->data_len, id+1);
    if(id >= 0)
    {
      /* defer cancelation as much as possible */
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

      /* copy this msg and send to the thread */
      tmsg = msg_get();
      msg_fill(tmsg, (char *) lcfg->imsg.m->payload, lcfg->imsg.m->data_len);
      r = tea_thread_msg_push(id, tmsg);

      /* if the msg cannot be pushed... repeat this until it is pushed */
      if(r < 0)
      {
        msg_release(tmsg);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
        pthread_testcancel();
        goto repeat_search;
      }
      /* ok... msg pushed (accepted) so drop package */
      pthreadex_mutex_begin(&ipq_mutex);
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
      if(ipq_on)
      {
        if(ipqex_set_verdict(&lcfg->imsg, NF_ACCEPT) <= 0)
          TERR("Cannot ACCEPT IPQ packet.");
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

  free(tw->data);
  tw->data = NULL;
}

static int listener__configure(THREAD_WORK *tw, SNODE *command)
{
  LISTENER_CFG *lcfg = (LISTENER_CFG *) tw->data;

  if(lcfg == NULL)
  {
    if((lcfg = calloc(1, sizeof(LISTENER_CFG))) == NULL)
      TFAT("No memory for LISTENER_CFG.");
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

