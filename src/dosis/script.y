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

  static int lineno = 1;
  static SNODE *script;
%}
%union {
  SNODE     *snode;
  int        nint;
  double     nfloat;
  char      *string;
}
%token <nint>     NINT
%token <nfloat>   NFLOAT
%token <string>   STRING LITERAL
%token <string>   VAR
%type  <snode>    nint nfloat ntime ntime_val string var
%type  <snode>    o_ntime command option options pattern
%type  <snode>    list_num selection list_num_enum range
%type  <snode>    input to
%token            PERIODIC
%token            CMD_ON CMD_MOD CMD_OFF
%token            OPT_RAW OPT_SRC OPT_DST OPT_FLAGS
%token            TO_UDP TO_TCP TO_LISTEN
%% /* Grammar rules and actions follow.  */
script: input       { script = $1; }
      ;

input: /* empty */        { $$ = NULL; }
     | '\n' input         { $$ = $2;   }
     | command '\n' input { $$ = $1;
                            D_DBG("$$=%p $3=%p", $$, $3);
                            $$->command.next = $3; }
     ;

var:  VAR   { $$ = new_node(TYPE_VAR);
              $$->varname = $1; }
    ;

nint: NINT  { $$ = new_node(TYPE_NINT);
               $$->nint = $1; }
    | var
    ;

nfloat: NFLOAT { $$ = new_node(TYPE_NFLOAT);
                 $$->nfloat = $1; }
      | NINT   { $$ = new_node(TYPE_NFLOAT);
                 $$->nfloat = $1; }
      | var
      ;

ntime_val: NFLOAT { $$ = new_node(TYPE_NTIME);
                    $$->ntime.n     = $1; }
         | NINT   { $$ = new_node(TYPE_NTIME);
                    $$->ntime.n     = $1; }
         | var
         ;

ntime: '+' ntime_val { $$ = $2;
                       $$->ntime.rel = -1; }
     | ntime_val
     ;

string: STRING  { $$ = new_node(TYPE_STRING);
                  $$->string.parse = -1;
                  $$->string.value = $1; }
      | LITERAL { $$ = new_node(TYPE_STRING);
                  $$->string.parse = 0;
                  $$->string.value = $1; }
      | var
      /*
      | NFLOAT  { $$ = new_node(TYPE_NFLOAT);
                  $$->nfloat     = $1; }
      | NINT    { $$ = new_node(TYPE_NINT);
                  $$->nfloat     = $1; }
      */
      ;

list_num_enum: nint                   { $$ = new_node(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = NULL; }
             | nint ',' list_num_enum { $$ = new_node(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = $3; }
             ;

list_num: nint                  { $$ = new_node(TYPE_LIST_NUM);
                                  $$->list_num.val  = $1;
                                  $$->list_num.next = NULL; }
        | '[' list_num_enum ']' { $$ = $2; }
        ;

range: '*'                   { $$ = new_node(TYPE_SELECTOR);
                               $$->range.min = NULL;
                               $$->range.max = NULL; }
     | '[' nint ':' nint ']' { $$ = new_node(TYPE_SELECTOR);
                               $$->range.min = $2;
                               $$->range.max = $4; }
     ;

selection: range
         | list_num
         ;

option: OPT_SRC string            { $$ = new_node(TYPE_OPT_SRC);
                                    $$->option.addr = $2;
                                    $$->option.port = NULL; }
      | OPT_SRC string '/' nint   { $$ = new_node(TYPE_OPT_SRC);
                                    $$->option.addr = $2;
                                    $$->option.port = $4; }
      | OPT_DST string            { $$ = new_node(TYPE_OPT_DST);
                                    $$->option.addr = $2;
                                    $$->option.port = NULL; }
      | OPT_DST string '/' nint   { $$ = new_node(TYPE_OPT_DST);
                                    $$->option.addr = $2;
                                    $$->option.port = $4; }
      | OPT_FLAGS string          { $$ = new_node(TYPE_OPT_FLAGS);
                                    $$->option.flags = $2; }
      /*
      | OPT_PAYLOAD STRING {
      | OPT_PAYLOAD FILE '(' STRING ')' {
      */
      ;

options: /* empty */    { $$ = NULL; }
       | option options { $$ = $1;
                          $$->option.next = $2; }
       ;

pattern: PERIODIC '[' nfloat ',' nint ']' { $$ = new_node(TYPE_PERIODIC);
                                            $$->pattern.periodic.ratio = $3;
                                            $$->pattern.periodic.n     = $5; }
       ;

o_ntime: /* empty */ { $$ = NULL; }
       | ntime       { $$ = $1;   }
       ;

to: TO_TCP options pattern         { $$ = new_node(TYPE_TO_TCP);
                                     $$->to.options = $2;
                                     $$->to.pattern = $3; }
  | TO_UDP options pattern         { $$ = new_node(TYPE_TO_UDP);
                                     $$->to.options = $2;
                                     $$->to.pattern = $3; }
  | TO_TCP OPT_RAW options pattern { $$ = new_node(TYPE_TO_TCPRAW);
                                     $$->to.options = $3;
                                     $$->to.pattern = $4; }
  | TO_LISTEN                      { $$ = new_node(TYPE_TO_LISTEN);
                                     $$->to.options = NULL;
                                     $$->to.pattern = NULL; }
  ;

command: o_ntime CMD_ON selection to  { $$ = new_node(TYPE_CMD_ON);
                                        $$->command.time          = $1;
                                        $$->command.thc.selection = $3;
                                        $$->command.thc.to        = $4; }
       | o_ntime CMD_MOD selection to { $$ = new_node(TYPE_CMD_MOD);
                                        $$->command.time          = $1;
                                        $$->command.thc.selection = $3;
                                        $$->command.thc.to        = $4; }
       | o_ntime CMD_OFF selection    { $$ = new_node(TYPE_CMD_OFF);
                                        $$->command.time          = $1;
                                        $$->command.thc.selection = $3;
                                        $$->command.thc.to        = NULL; }
       | o_ntime LITERAL '=' string   { $$ = new_node(TYPE_CMD_SETVAR);
                                        $$->command.time          = $1;
                                        $$->command.setvar.var    = $2;
                                        $$->command.setvar.val    = $4; }
       ;
%%
SNODE *new_node(int type)
{
  SNODE *n;
  if((n = calloc(1, sizeof(SNODE))) == NULL)
    D_FAT("Cannot alloc SNODE (%d).", type);
  n->type = type;
  n->line = lineno;
  return n;
}

/* The lexical analyzer returns a double floating point
   number on the stack and the token NUM, or the numeric code
   of the character read if not a number.  It skips all blanks
   and tabs, and returns 0 for end-of-input.  */
#define BUFFLEN      512
#define SRESET()     { bi = 0; buff[0] = '\0'; }
#define SADD(c)      { if(bi >= BUFFLEN)             \
                         goto ha_roto_la_olla;       \
                       buff[bi++] = (c);             \
                       buff[bi] = '\0'; }
#define SCAT(s)      { if(bi + strlen(s) >= BUFFLEN) \
                         goto ha_roto_la_olla;       \
                       strcat(buff, s);              \
                       bi += strlen(s); }

void readvar(char *buff, int *real_bi)
{
  int c;
  char *v;
  int bi = *real_bi;

  /* read var name in buffer */
  v = buff + bi;
  c = getchar();
  if(c == EOF)
    D_FAT("Bad identifier.");
  SADD(c);
  if(c == '{')
  {
    while((c = getchar()) != '}' && isalnum(c) && c != '\n' && c != EOF)
      SADD(c);
    if(c == '\n')
      D_FAT("Non-terminated var.");
    if(isblank(c) || c == EOF)
      D_FAT("Bad identifier.");
  } else {
    while(isalnum(c = getchar()) && c != EOF)
      SADD(c);
  }
  ungetc(c, stdin);

  D_DBG("Readed var name '%s'.", v);

  /* update real_bi */
  *real_bi = bi;

  return;

ha_roto_la_olla:
  D_FAT("You have agoted my pedazo of buffer (%s...).", buff);
}

int yylex(void)
{
  int c, bi, f, i;
  char buff[BUFFLEN], *s;
  struct {
    char *token;
    int  id;
  } tokens[] = {
    { "DST",      OPT_DST    },
    { "FLAGS",    OPT_FLAGS  },
    { "LISTEN",   TO_LISTEN  },
    { "MOD",      CMD_MOD    },
    { "OFF",      CMD_OFF    },
    { "ON",       CMD_ON     },
    { "PERIODIC", PERIODIC   },
    { "RAW",      OPT_RAW    },
    { "SRC",      OPT_SRC    },
    { "TCP",      TO_TCP     },
    { "UDP",      TO_UDP     },
    { NULL,       0          }
  }, *token;

  /* Skip white space.  */
  while(isblank(c = getchar()))
    ;
  /* Return end-of-input.  */
  if(c == EOF)
  {
    D_DBG("YYLEX EOF!");
    return 0;
  }

  /* ignore comments */
  if(c == '#')
  {
    while((c = getchar()) != '\n' && c != EOF)
      ;
    if(c == '\n')
    {
      D_DBG("TOKEN[NEWLINE]");
      lineno++;
      return c;
    }
    D_DBG("YYLEX EOF!");
    return 0;
  }

  /* reset */
  SRESET();

  /* Process numbers and network addresses */
  if(c == '.' || isdigit(c))
  {
    f = 0;
    do {
      SADD(c);
      if(c == ':') f = -1;
      if(f >= 0 && c == '.') f++;
    } while(isdigit(c = getchar()) || c == '.' || c == ':');
    ungetc(c, stdin);
    /* check if it is a number */
    switch(f)
    {
      case 0:
        /* hex num ? */
        if(bi > 2
        && buff[0] == '0'
        && (buff[1] == 'x' || buff[1] == 'X'))
        {
          for(i = 2; i < bi; i++)
            if(!isdigit(buff[i])
            || !strchr(buff[i], "abcdefABCDEF"))
              D_FAT("%d: Bad hex number.", lineno);
          sscanf(buff + 2, "%x", &(yylval.nint));
          D_DBG("TOKEN[NINT] = HEX(%s)", buff);
          return NINT;
        }
        /* bin num ? */
        if(bi > 2
        && buff[0] == '0'
        && (buff[1] == 'b' || buff[1] == 'B'))
        {
          yylval.nint = 0;
          for(i = 2; i < bi; i++)
          {
            yylval.nint <<= 1;
            if(buff[i] != '0' && buff[i] != '1')
              D_FAT("%d: Bad bin number.", lineno);
            yylval.nint |= (buff[i] == '1' ? 1 : 0);
          }
          D_DBG("TOKEN[NINT] = BIN(%s)", buff);
          return NINT;
        }
        /* octal num ? */
        if(bi > 1 && buff[0] == '0')
        {
          for(i = 1; i < bi; i++)
            if(buff[i] < '0' || buff[i] > '7')
              D_FAT("%d: Bad octal number.", lineno);
          sscanf(buff, "%o", &(yylval.nint));
          D_DBG("TOKEN[NINT] = OCT(%s)", buff);
          return NINT;
        }
        /* normal integer */
        sscanf(buff, "%d", &(yylval.nint));
        D_DBG("TOKEN[NINT] = %s", buff);
        return NINT;

      case 1:
        if(bi == 1)
          D_FAT("%d: Only a dot. WTF?", lineno);
        sscanf(buff, "%lf", &(yylval.nfloat));
        D_DBG("TOKEN[NFLOAT] = '%s'", buff);
        return NFLOAT;

      default:
        /* oooh... it is not a number; it is a string */
        while(!isspace(c = getchar()) && c != EOF)
          SADD(c);
        ungetc(c, stdin);
        if((yylval.string = strdup(buff)) == NULL)
          D_FAT("No mem for string '%s'.", buff);
        D_DBG("TOKEN[STRING] = '%s'", buff);
        return STRING;
    }
  }

  /* Process env var */
  if(c == '$')
  {
    readvar(buff, &bi);
    if((yylval.string = strdup(buff)) == NULL)
      D_FAT("No mem for string '%s'.", buff);
    D_DBG("TOKEN[VAR] = '$%s'", buff);
    return VAR;
  }

  /* Process strings */
  if(c == '\'')
  {
    while((c = getchar()) != '\'' && c != '\n' && c != EOF)
      if(c == '\\')
      {
        c = getchar();
        SADD(c);
        if(c == EOF)
          ungetc(c, stdin);
      } else {
        SADD(c);
      }
    if(c == '\n')
      D_FAT("%d: Non-terminated string.", lineno);
    s = strdup(buff);
    if(!s)
      D_FAT("No mem for string '%s'.", buff);
    yylval.string = s;
    D_DBG("TOKEN['LITERAL'] = '%s'", buff);
    return LITERAL;
  }

  if(c == '"')
  {
    while((c = getchar()) != '"' && c != '\n' && c != EOF)
      if(c == '\\')
      {
        c = getchar();
        SADD(c);
        if(c == EOF)
          ungetc(c, stdin);
      } else
      if(c == '$')
      {
        /* get var name */
        readvar(buff, &bi);
      } else {
        SADD(c);
      }
    if(c == '\n')
      D_FAT("Non-terminated string.");
    s = strdup(buff);
    if(!s)
      D_FAT("No mem for string \"%s\".", buff);
    yylval.string = s;
    D_DBG("TOKEN[\"STRING\"] = '%s'", buff);
    return STRING;
  }

  /* special chars (chocolate minitokens) */
  if(c == '\n')
  {
    D_DBG("TOKEN[NEWLINE]");
    lineno++;
    return c;
  }
  if(c == ','
  || c == ':'
  || c == '='
  || c == '*' || c == '/'
  || c == '[' || c == ']'
  || c == '(' || c == ')')
  {
    D_DBG("TOKEN[CHAR(%d)] = '%c'", c, c);
    return c;
  }

  /* ummm.. read word (string) or token */
  do {
    SADD(c);
  } while(isalnum(c = getchar()) && c != EOF);
  ungetc(c, stdin);
  /* is a language token? */
  for(token = tokens; token->token; token++)
    if(!strcasecmp(buff, token->token))
    {
      D_DBG("TOKEN[%s]", buff);
      return token->id;
    }
  /* return string */
  s = strdup(buff);
  if(!s)
    D_FAT("No mem for string \"%s\".", buff);
  yylval.string = s;
  D_DBG("TOKEN[LITERAL] = '%s'", buff);
  return LITERAL;

ha_roto_la_olla:
  D_FAT("You have agoted my pedazo of buffer (%s...).", buff);
  return 0;
}

void yyerror(char const *str)
{
  D_ERR("parsing error: %s", str);
}

SNODE *script_parse(void)
{
  yyparse();

  return script;
}


