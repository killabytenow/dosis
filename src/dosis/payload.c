/*****************************************************************************
 * payload.c
 *
 * Payload generator.
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
#include "log.h"
#include "tea.h"

void payload_get(SNODE *n, char **buffer, unsigned int *size)
{
  struct stat pls;
  int i, f;
  char *s, *s2;

  if(*buffer)
  {
    free(*buffer);
    *buffer = NULL;
  }
  *size = 0;

  /* apply config */
  switch(n->type)
  {
    case TYPE_OPT_PAYLOAD_FILE:
      s2 = tea_get_string(n->option.payload);
      s = dosis_search_file(s2);
      free(s2);
      DBG("********************************** Reading %s.", s);
      if(stat(s, &pls) < 0)
        FAT("%d: Cannot stat file '%s': %s", n->line, s, strerror(errno));
      *size = pls.st_size;
      if((*buffer = malloc(*size)) == NULL)
        FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
      if((f = open(s, O_RDONLY)) < 0)
        FAT("%d: Cannot open payload: %s", n->line, strerror(errno));
      if(read(f, *buffer, *size) < *size)
        FAT("%d: Cannot read the payload file: %s", n->line, strerror(errno));
      close(f);
      free(s);
      break;

    case TYPE_OPT_PAYLOAD_NULL:
      break;

    case TYPE_OPT_PAYLOAD_RANDOM:
      *size = tea_get_int(n->option.payload);
      if(*size > 0)
      {
        if((*buffer = malloc(*size)) == NULL)
          FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
        srand(time(NULL));
        for(i = 0; i < *size; i++)
          *(*buffer + i) = rand() & 0x000000FF;
      }
      break;

    case TYPE_OPT_PAYLOAD_STR:
      *buffer = tea_get_string(n->option.payload);
      *size   = strlen(*buffer);
      break;
      
    default:
      FAT("%d: Uknown option %d.", n->line, n->type);
  }
}
