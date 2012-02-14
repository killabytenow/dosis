/*****************************************************************************
 * ignorer.c
 *
 * Raw ignorer "listener"
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
#include "dosconfig.h"
#include "log.h"
#include "iptables.h"
#include "ignorer.h"
#include "tea.h"

#define MODNAME        teaIGNORER.name
#define BUFSIZE        65535

/*****************************************************************************
 * GLOBAL INITIALIZATION
 *****************************************************************************/

static void ignorer__global_fini(void)
{
  /* restore initial iptables state */
  iptables_restore();

  GDBG("ignorer threads finished.");
}

static void ignorer__global_init(void)
{
  char **a,
       *iscript[] = {
          "/sbin/iptables", "-t", "filter", "-F", NULL,
          "/sbin/iptables", "-t", "nat",    "-F", NULL,
          "/sbin/iptables", "-t", "mangle", "-F", NULL,
          "/sbin/iptables", "-t", "raw",    "-F", NULL,
          "/sbin/iptables", "-F", NULL,
          NULL },
       *igscript[] = {
          "/sbin/iptables", "-A", "FORWARD", "-j", "DROP", NULL,
          "/sbin/iptables", "-A", "INPUT",   "-j", "DROP", NULL,
          NULL },
       *isscript[] = {
          "/sbin/iptables", "-A", "FORWARD", "-i", NULL, "-j", "DROP", NULL,
          "/sbin/iptables", "-A", "INPUT",   "-i", NULL, "-j", "DROP", NULL,
          NULL },
       *ifscript[] = {
          "/sbin/iptables", "-L", "-v", NULL,
          NULL };

  GDBG2("save iptables config.");
  iptables_save();

  GDBG2("Init iptables config.");
  if(cfg.interfaces[0] == NULL)
  {
    iptables_apply_script(iscript);
    iptables_apply_script(igscript);
  } else {
    for(a = cfg.interfaces; *a; a++)
      if(*a)
      {
        isscript[4] = *a;
        isscript[12] = *a;
        iptables_apply_script(isscript);
      }
  }
  iptables_apply_script(ifscript);

  /* set the finalization routine */
  dosis_atexit(MODNAME, ignorer__global_fini);

  GDBG("Initialized.");
}

/*****************************************************************************
 * IGNORER THREAD
 *****************************************************************************/

static void ignorer__thread(THREAD_WORK *tw)
{
  /* do nothing */
  return;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * IGNORER TEA OBJECT
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

TOC_BEGIN(ignorer_cfg_def)
TOC_END

TEA_OBJECT teaIGNORER = {
  .name        = "IGNORER",
  .datasize    = 0,
  .global_init = ignorer__global_init,
  .configure   = NULL,
  .cleanup     = NULL,
  .thread      = ignorer__thread,
  .cparams     = ignorer_cfg_def,
};

