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

#define BUFSIZE 4096

typedef struct _tag_TCP_CFG {
  /* options */
  TEA_TYPE_BOOL      debug;
  TEA_TYPE_ADDR      dhost;
  TEA_TYPE_DATA      payload;
  TEA_TYPE_BOOL      ssl;
  TEA_TYPE_STRING    sslcipher;
  TEA_TYPE_INT       tcp_cwait;
  TEA_TYPE_INT       tcp_rwait;
  TEA_TYPE_INT       pattern;
  TEA_TYPE_INT       n;
  TEA_TYPE_FLOAT     hitratio;

  /* other things */
  int                sock;
  pthreadex_timer_t  timer;
  struct timeval     sockwait_cwait;
  struct timeval     sockwait_rwait;
  struct sockaddr    dsockaddr;

  /* ssl things */
#ifdef HAVE_SSL
  SSL                *ssl_conn;
  SSL_CTX            *ssl_ctx;
  BIO                *ssl_bio;
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
    if(tt->ssl_conn)
    {
      SSL_shutdown(tt->ssl_conn);
      SSL_free(tt->ssl_conn);
    }
    if(tt->ssl_ctx)
      SSL_CTX_free(tt->ssl_ctx);
    tt->ssl_conn = NULL;
    tt->ssl_bio = NULL;
    tt->ssl_ctx = NULL;
  }
}

int SSL_initialize(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;
  int  serr;

  tt->ssl_conn    = NULL;
  tt->ssl_ctx    = NULL;
  tt->ssl_bio    = NULL;

  SSL_load_error_strings();
  SSL_library_init();

  if((tt->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
  {
    SSL_error_stack();
    TERR("Error creating new ctx.");
    return 1;
  }

  DBG("New SSL context");
  DBG("  - Session cache = SSL_SESS_CACHE_BOTH");
  SSL_CTX_set_mode(tt->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_CTX_set_session_cache_mode(tt->ssl_ctx, SSL_SESS_CACHE_BOTH);
  DBG("  - SSL timeout = 500000 (constant)");
  SSL_CTX_set_timeout(tt->ssl_ctx, 500000);
  DBG("  - cipher list = %s", tt->sslcipher);
  if(!SSL_CTX_set_cipher_list(tt->ssl_ctx, tt->sslcipher))
  {
    TERR("SSL_CTX_set_cipher_list");
    return 1;
  }

  if((tt->ssl_conn = SSL_new(tt->ssl_ctx)) == NULL)
  {
    SSL_error_stack();
    TERR("Error creating new ssl.");
    return 1;
  }
  SSL_set_fd(tt->ssl_conn, tt->sock);

  tt->ssl_bio = BIO_new_socket(tt->sock, BIO_NOCLOSE);
  SSL_set_bio(tt->ssl_conn, tt->ssl_bio, tt->ssl_bio);

  serr = SSL_connect(tt->ssl_conn);
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
    TDBG2("  Connecting...");

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
    if(tt->ssl)
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
      r = SSL_write(tt->ssl_conn, tt->payload.data, tt->payload.size);
      if(r < tt->payload.size)
      {
        TERR("SSL_write error.");
        continue;
      }
#else
      TFAT("Not compiled with SSL support.");
#endif
    } else {
      /* send request */
      r = send(tt->sock, tt->payload.data, tt->payload.size, 0);
      if(r < tt->payload.size)
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
    if(tt->debug)
    {
      while((r = SSL_read(tt->ssl_conn, nullbuff, sizeof(nullbuff))) > 0)
      {
        TLOG("  data readed:");
        TDUMP(LOG_LEVEL_LOG, nullbuff, r);
      }
      if(r < 0)
        TERR("  SSL error %d (see SSL_get_error(3SSL).", SSL_get_error(tt->ssl_conn, r));
    } else {
      while((r = read(tt->sock, nullbuff, sizeof(nullbuff))) > 0)
        TDBG2("  read %d bytes...", r);
    }

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

static int tcp__configure(THREAD_WORK *tw, SNODE *command, int first_time)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;

  /* first initialization (specialized work thread data) */
  if(first_time)
  {
    /* init timer */
    pthreadex_timer_init(&(tt->timer), 0.0);
    pthreadex_timer_name(&(tt->timer), "tcp-timer");
  }

  /* check params sanity */
  if(tt->pattern != TYPE_PERIODIC)
  {
    TERR("Uknown pattern %d.", tt->pattern);
    return -1;
  }
  if(tt->n)
    TWRN("Talking about number of packets here has non sense (ignoring periodic.n value %d).", tt->n);
  if(tt->hitratio < 0)
  {
    TERR("Bad hit ratio '%f'.", tt->hitratio);
    return -1;
  }

  /* update calculated params */
  tt->sockwait_cwait.tv_sec  = tt->tcp_cwait / 1000000;
  tt->sockwait_cwait.tv_usec = tt->tcp_cwait % 1000000;
  tt->sockwait_rwait.tv_sec  = tt->tcp_rwait / 1000000;
  tt->sockwait_rwait.tv_usec = tt->tcp_rwait % 1000000;

  pthreadex_timer_set_frequency(&(tt->timer), tt->hitratio);

  /* convert dhost to sockaddr */
  ip_addr_to_socket(&tt->dhost, &tt->dsockaddr);

  return 0;
}

static void tcp__cleanup(THREAD_WORK *tw)
{
  TCP_CFG *tt = (TCP_CFG *) tw->data;

  /* collect libnet data */
  pthreadex_timer_destroy(&tt->timer);

#ifdef HAVE_SSL
  if(tt->ssl)
    SSL_finalize(tw);
#endif
  if(tt->sslcipher)
    free(tt->sslcipher);

  TDBG("Finalized.");
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TCP TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(tcp_cfg_def)
  TOC("debug",          TEA_TYPE_BOOL,   0, TCP_CFG, debug,      NULL)
  TOC("dst_addr",       TEA_TYPE_ADDR,   1, TCP_CFG, dhost,      NULL)
  TOC("dst_port",       TEA_TYPE_PORT,   0, TCP_CFG, dhost,      NULL)
  TOC("pattern",        TEA_TYPE_INT,    1, TCP_CFG, pattern,    NULL)
  TOC("periodic_ratio", TEA_TYPE_FLOAT,  1, TCP_CFG, hitratio,   NULL)
  TOC("periodic_n",     TEA_TYPE_INT,    1, TCP_CFG, n,          NULL)
  TOC("pattern",        TEA_TYPE_INT,    1, TCP_CFG, pattern,    NULL)
  TOC("payload",        TEA_TYPE_DATA,   1, TCP_CFG, payload,    NULL)
  TOC("ssl",            TEA_TYPE_BOOL,   0, TCP_CFG, ssl,        NULL)
  TOC("ssl_cipher",     TEA_TYPE_STRING, 0, TCP_CFG, sslcipher,  NULL)
  TOC("tcp_cwait",      TEA_TYPE_INT,    1, TCP_CFG, tcp_cwait,  NULL)
  TOC("tcp_rwait",      TEA_TYPE_INT,    1, TCP_CFG, tcp_rwait,  NULL)
TOC_END

TEA_OBJECT teaTCP = {
  .name         = "TCP",
  .datasize     = sizeof(TCP_CFG),
  .configure    = tcp__configure,
  .cleanup      = tcp__cleanup,
  .thread       = tcp__thread,
  .cparams      = tcp_cfg_def
};

