/*****************************************************************************
 * iptables.c
 *
 * iptables management
 *
 * ---------------------------------------------------------------------------
 * dosis - DoS: Internet Sodomizer
 *   (C) 2008-2012 Gerardo García Peña <gerardo@kung-foo.net>
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
#include "exec.h"
#include "log.h"
#include "dosconfig.h"

static char ip_forward_status;
static char iptables_tmp[255];

//typedef struct _tag_IPTABLES_RULE {
//  int    type;
//#define IPTABLES_RULE_QUEUE 1
//#define IPTABLES_RULE_DROP  2
//  
//  char  *iface;
//  char  *proto;
//  char  *dport;
//  char  *sport;
//    struct {
//      char 
//      
//  char **params;
//} IPTABLES_RULE;

void iptables_restore(void)
{
  int f;
  char buf[100];
  char *iptables_restore_cmd[] = { "/sbin/iptables-restore", NULL };

  /* restore ipforward */
  if((f = creat("/proc/sys/net/ipv4/ip_forward", 640)) < 0)
    FAT_ERRNO("/proc/sys/net/ipv4/ip_forward");
  buf[0] = ip_forward_status;
  buf[1] = '\n';
  if(write(f, buf, 2) < 0)
    FAT_ERRNO("Cannot set ip_forward");
  close(f);

  /* restore iptables */
  if((f = open(iptables_tmp, O_RDONLY)) < 0)
    FAT_ERRNO("Cannot read %s", iptables_tmp);
  dosis_exec_log_output(LOG_LEVEL_LOG, f, iptables_restore_cmd);
  close(f);
  if(unlink(iptables_tmp) < 0)
    FAT_ERRNO("Cannot unlink %s", iptables_tmp);
}

void iptables_save(void)
{
  int f, r;
  char *iptables_save_cmd[] = { "/sbin/iptables-save", NULL };

  /* save ip forward state */
  if((f = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY)) < 0)
    FAT_ERRNO("/proc/sys/net/ipv4/ip_forward");
  r = read(f, &ip_forward_status, 1);
  if(r == 0)
    FAT("Invalid ip_forward content.");
  if(r < 0)
    FAT_ERRNO("Cannot read ip_forward status");
  close(f);

  /* save iptables status */
  if(*iptables_tmp)
  {
    WRN("iptables state already saved in '%s'.", iptables_tmp);
    return;
  }

  strcpy(iptables_tmp, "iptables-state-XXXXXX");
  f = mkstemp(iptables_tmp);
  dosis_exec_inout(-1, f, -1, iptables_save_cmd);
  close(f);
}

void iptables_apply_script(char **script)
{
  char **a;

  for(a = script; *a; )
  {
    dosis_exec_log_output(LOG_LEVEL_DEBUG, 0, a);

    /* next command */
    while(*a++ != NULL)
      ;
  }
}

//void iptables_reset(void)
//{
//  char *iscript[] = {
//          "/sbin/iptables", "-t", "filter", "-F", NULL,
//          "/sbin/iptables", "-t", "filter", "-X", NULL,
//          "/sbin/iptables", "-t", "nat",    "-F", NULL,
//          "/sbin/iptables", "-t", "nat",    "-X", NULL,
//          "/sbin/iptables", "-t", "mangle", "-F", NULL,
//          "/sbin/iptables", "-t", "mangle", "-X", NULL,
//          "/sbin/iptables", "-t", "raw",    "-F", NULL,
//          "/sbin/iptables", "-t", "raw",    "-X", NULL,
//          "/sbin/iptables", "-F", NULL,
//          "/sbin/iptables", "-X", NULL,
//          NULL },
//
//  iptables_apply_script(iscript);
//}
//
