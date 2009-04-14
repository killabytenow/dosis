/*****************************************************************************
 * script.y
 *
 * Dosis script language.
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

%{
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
  #endif

  #include <string.h>
  #include <ctype.h>

  #include "script.h"
  #include "log.h"
  #include "ip.h"

  int yylex (void);
  void yyerror (char const *);
  SNODE *new_node(int type);
%}
%union {
  SNODE     *snode;
  int        nint;
  double     nfloat;
  char      *string;
}
%token <nint>     NINT
%type  <nint>     nint
%token <nfloat>   NFLOAT
%type  <nfloat>   nfloat
%token <string>   STRING
%token <string>   VAR
%type  <snode>    command option options pattern
%type  <snode>    list_num list_num_enum selector
%type  <snode>    line input
%token            PERIODIC
%token            CMD_ON CMD_MOD CMD_OFF
%token            OPT_UDP OPT_TCP OPT_SRC OPT_DST
%% /* Grammar rules and actions follow.  */
input: /* empty */  { $$ = NULL;     }
       | input line { $$ = $1;
                      $$->command.next = $2; }
       ;

line: '\n'         { $$ = NULL; }
    | command '\n' { $$ = $1; }
    ;

nint: NINT
    | VAR   { $$ = atol($1); free($1); }
    ;

nfloat: NFLOAT
      | NINT   { $$ = $1; }
      | VAR    { $$ = atof($1); free($1); }
      ;

list_num_enum: nint                   { $$ = new_node(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = NULL; }
             | nint ',' list_num_enum { $$ = new_node(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = $3; }
             ;

list_num: '[' nint ':' nint ']' { int i;
                                  SNODE *n = NULL;
                                  for(i = $2; i <= $4; i++)
                                  {
                                    $$ = new_node(TYPE_LIST_NUM);
                                    $$->list_num.val  = i;
                                    $$->list_num.next = NULL;
                                    if(n) n->list_num.next = $$;
                                  } }
        | nint                  { $$ = new_node(TYPE_LIST_NUM);
                                  $$->list_num.val  = $1;
                                  $$->list_num.next = NULL; }
        | '[' list_num_enum ']' { $$ = $2; }
        ;

selector: '*'          { $$ = new_node(TYPE_SELECTOR);
                         $$->selector.rmin = -1;
                         $$->selector.rmax = -1; }
        | list_num     { $$ = $1; }
        ;

option: OPT_TCP          { $$ = new_node(TYPE_OPT_TCP); }
      | OPT_UDP          { $$ = new_node(TYPE_OPT_UDP); }
      | OPT_SRC STRING   { $$ = new_node(TYPE_OPT_SRC);
                           $$->option.addr = $2; }
      | OPT_DST STRING   { $$ = new_node(TYPE_OPT_DST);
                           $$->option.addr = $2; }
      ;

options: /* empty */    { $$ = NULL; }
       | option options { $$ = $1;
                          $$->option.next = $2; }
       ;

pattern: PERIODIC '[' nfloat ',' nint ']' { $$ = new_node(TYPE_PERIODIC);
                                            $$->pattern.periodic.ratio = $3;
                                            $$->pattern.periodic.n     = $5; }
       ;

command: nfloat CMD_ON list_num options pattern  { $$ = new_node(TYPE_CMD_ON);
                                                   $$->command.time     = $1;
                                                   $$->command.list_num = $3;
                                                   $$->command.options  = $4;
                                                   $$->command.pattern  = $5; }
       | nfloat CMD_MOD selector options pattern { $$ = new_node(TYPE_CMD_MOD);
                                                   $$->command.time     = $1;
                                                   $$->command.selector = $3;
                                                   $$->command.options  = $4;
                                                   $$->command.pattern  = $5; }
       | nfloat CMD_OFF selector                 { $$ = new_node(TYPE_CMD_OFF);
                                                   $$->command.time     = $1;
                                                   $$->command.selector = $3; }
       ;
%%
SNODE *new_node(int type)
{
  SNODE *n;
  if((n = calloc(1, sizeof(SNODE))) == NULL)
    D_FAT("Cannot alloc SNODE (%d).", type);
  n->type = type;
  return n;
}

/* The lexical analyzer returns a double floating point
   number on the stack and the token NUM, or the numeric code
   of the character read if not a number.  It skips all blanks
   and tabs, and returns 0 for end-of-input.  */
#define SRESET()     { i = 0; buff[0] = '\0'; }
#define SADD(c)      { if(i >= sizeof(buff))   \
                         goto ha_roto_la_olla; \
                       buff[i++] = (c);        \
                       buff[i] = '\0'; }

int yylex(void)
{
  int c, i, f;
  char buff[256], *s;
  struct {
    char *token;
    int  id;
  } tokens[] = {
    { "DST",      TYPE_OPT_DST  },
    { "MOD",      TYPE_CMD_MOD  },
    { "OFF",      TYPE_CMD_OFF  },
    { "ON",       TYPE_CMD_ON   },
    { "PERIODIC", TYPE_PERIODIC },
    { "SRC",      TYPE_OPT_SRC  },
    { "TCP",      TYPE_OPT_TCP  },
    { "UDP",      TYPE_OPT_UDP  },
    { NULL,       0             }
  };

  /* Skip white space.  */
  while(isblank(c = getchar()))
    ;
  /* Return end-of-input.  */
  if(c == EOF)
    return 0;

  /* reset */
  SRESET();

  /* Process numbers and network addresses */
  if(c == '.' || isdigit(c))
  {
    f = 0;
    do {
      SADD(c);
      if(c == '.') f++;
    } while(isdigit(c = getchar()) || c == '.');
    ungetc(c, stdin);
    /* check if it is a number */
    if(f <= 1 && i > f)
    {
      if(f == 0)
      {
        sscanf(buff, "%d", &(yylval.nint));
        return NINT;
      }
      sscanf(buff, "%lf", &(yylval.nfloat));
      return NFLOAT;
    }
    /* oooh... it is not a number; it is a string */
    while(!isblank(c = getchar()) && c != EOF)
      SADD(c);
    ungetc(c, stdin);
    if((yylval.string = strdup(buff)) == NULL)
      D_FAT("No mem for string '%s'.", buff);
    return STRING;
  }

  /* Process env var */
  if(c == '$')
  {
    i = 0;
    while(isalnum(c = getchar()))
      SADD(c);
    ungetc(c, stdin);
    s = getenv(buff);
    if(!s)
      D_FAT("Variable '%s' not defined.", buff);
    s = strdup(s);
    if(!s)
      D_FAT("No mem for var '%s'.", buff);
    yylval.string = buff;
    return VAR;
  }

  /* Process strings */
  if(c == '\'')
  {
    while((c = getchar()) != '\'' && c != EOF)
      if(c == '\\')
      {
        c = getchar();
        if(c != EOF)
          SADD(c);
        else
          ungetc(c, stdin);
      }
    s = strdup(s);
    if(!s)
      D_FAT("No mem for var '%s'.", buff);
    yylval.string = buff;
    return VAR;
  } else
  if(c == '"')
  {
    while((c = getchar()) != '"' && c != EOF)
      if(c == '\\')
      {
        c = getchar();
        if(c != EOF)
          SADD(c);
        else
          ungetc(c, stdin);
     } else
     if(c == '$'
  } else {
  }

  /* Return a single char.  */
  return c;

ha_roto_la_olla:
  D_FAT("You have agoted my pedazo of buffer (%s...).", buff);
}

void yyerror(char const *str)
{
  D_FAT("parsing error: %s", str);
}

