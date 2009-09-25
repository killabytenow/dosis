/*****************************************************************************
 * ipqex.c
 *
 * ip_queue extended.
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

#include <stdlib.h>
#include "ipqex.h"
#include "log.h"

int ipqex_init_mode(ipqex_info_t *i, unsigned bufsize, unsigned mode)
{
  int status;

  if((i->ipqh = ipq_create_handle(0, PF_INET)) == NULL)
  {
    ERR("[LL] Cannot create a IPQ object.");
    return -1;
  }
  i->bufsize = bufsize;
  if((status = ipq_set_mode(i->ipqh, mode, bufsize)) <= 0)
  {
    ERR("Cannot set mode %d (error %d).", mode, status);
    ipq_destroy_handle(i->ipqh);
    return -1;
  }

  return 0;
}

int ipqex_init(ipqex_info_t *i, int bufsize)
{
  return ipqex_init_mode(i, bufsize, IPQ_COPY_PACKET);
}

void ipqex_destroy(ipqex_info_t *i)
{
  ipq_destroy_handle(i->ipqh);
}

int ipqex_msg_init(ipqex_msg_t *m, ipqex_info_t *i)
{
  if((m->b = malloc(i->bufsize)) == NULL)
  {
    ERR("Cannot allow memory for a buffer of %d bytes.", i->bufsize);
    return -1;
  }
  m->m = NULL;
  m->s = 0;
  m->i = i;

  return 0;
}

void ipqex_msg_destroy(ipqex_msg_t *m)
{
  free(m->b);
}

int ipqex_msg_read(ipqex_msg_t *m, int timeout)
{
  if((m->s = ipq_read(m->i->ipqh, m->b, m->i->bufsize, timeout)) != 0)
  { 
    switch(ipq_message_type(m->b))
    {
      case NLMSG_ERROR:
        m->e = ipq_get_msgerr(m->b);
        break;

      case IPQM_PACKET:
        m->m = ipq_get_packet(m->b);
        break;

      default:
        m->s = -1;
        m->e = 74; /* Bad message */
    }
  } else
    m->e = m->s < 0
            ? 5 /* Input/output error */
            : errno;

  return m->s;
}

