/*****************************************************************************
 * script.y
 *
 * Dosis script language.
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

%{
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
  #endif

  #include <string.h>
  #include <ctype.h>

  #include "script.h"
  #include "log.h"
  #include "ip.h"
  #include "dosconfig.h"

  int yylex (void);
  void yyerror (char const *);
  SNODE *new_node(int type);

  static int lineno;
  static SNODE *script;
  static SNODE *allocated_list;
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
%type  <snode>    input
%type  <snode>    var nint nfloat ntime string
%type  <snode>    list_num_enum list_num range selection
%type  <snode>    opts pattern
%type  <snode>    o_ntime command
%type  <snode>    to
%token            PERIODIC _FILE RANDOM
%token            CMD_ON CMD_MOD CMD_OFF
%token            OPT_OPEN OPT_RAW OPT_SRC OPT_DST OPT_FLAGS OPT_MSS OPT_SLOW
%token            OPT_PAYLOAD OPT_NULL OPT_DLL OPT_SSL OPT_ZWIN
%token            OPT_WINDOW
%token            TO_LISTEN TO_TCP TO_UDP
%token            OPT_CWAIT OPT_RWAIT
%% /* Grammar rules and actions follow.  */
/*---------------------------------------------------------------------------
    SCRIPT
  ---------------------------------------------------------------------------*/

script: input       { script = $1; }
      ;

input: /* empty */        { $$ = NULL; }
     | '\n' input         { $$ = $2;   }
     | command '\n' input { $$ = $1;
                            $$->command.next = $3; }
     ;

/*---------------------------------------------------------------------------
    BASIC TYPES
  ---------------------------------------------------------------------------*/

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

ntime: '+' nfloat { $$ = new_node(TYPE_NTIME);
                    $$->ntime.rel = -1;
                    $$->ntime.n   = $2; }
     | nfloat     { $$ = new_node(TYPE_NTIME);
                    $$->ntime.rel = 0;
                    $$->ntime.n   = $1; }
     ;

string: STRING                  { $$ = new_node(TYPE_STRING);
                                  $$->string.parse = -1;
                                  $$->string.value = $1; }
      | LITERAL                 { $$ = new_node(TYPE_STRING);
                                  $$->string.parse = 0;
                                  $$->string.value = $1; }
      | RANDOM '(' nint ')'     { $$ = new_node(TYPE_RANDOM);
                                  $$->random.len = $3; }
      | _FILE '(' string ')'    { $$ = new_node(TYPE_FILE);
                                  $$->random.path = $3; }
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
     | '[' nint '%' nint ']' { $$ = new_node(TYPE_SELECTOR);
                               $$->range.min = $2;
                               $$->range.max = $4; }
     ;

selection: range
         | list_num
         ;

/*---------------------------------------------------------------------------
    OPTIONS (all possible dosis command parameters)
  ---------------------------------------------------------------------------*/

opts:
  /* none */                { $$ = hash_new(); }
 /* SSL [ciphersuite] */
| OPT_PAYLOAD OPT_NULL opts { $$ = $3; hash_add_entry($$, "payload",   NULL); }
| OPT_PAYLOAD string opts   { $$ = $3; hash_add_entry($$, "payload",   $2);   }
| OPT_SSL opts              { $$ = $2; hash_add_entry($$, "ssl",       NULL); }
| OPT_SSL string opts       { $$ = $3; hash_add_entry($$, "ssl",       $2);   }
| OPT_SRC string opts       { $$ = $3; hash_add_entry($$, "src_addr",  $2);   }
| OPT_SRC string nint opts  { $$ = $4; hash_add_entry($$, "src_addr",  $2);
                                       hash_add_entry($$, "src_port",  $3);   }
| OPT_DST string opts       { $$ = $3; hash_add_entry($$, "dst_addr",  $2);   }
| OPT_DST string nint opts  { $$ = $4; hash_add_entry($$, "dst_addr",  $2);
                                       hash_add_entry($$, "dst_port",  $3);   }
| OPT_MSS nint opts         { $$ = $3; hash_add_entry($$, "tcp_mss",   $2);   }
| OPT_FLAGS string opts     { $$ = $3; hash_add_entry($$, "tcp_flags", $2);   }
| OPT_CWAIT nint opts       { $$ = $3; hash_add_entry($$, "tcp_cwait", $2);   }
| OPT_RWAIT nint opts       { $$ = $3; hash_add_entry($$, "tcp_rwait", $2);   }
| OPT_WINDOW nint opts      { $$ = $3; hash_add_entry($$, "tcp_win",   $2);   }
       /*| OPT_PAYLOAD OPT_DLL '(' string ')'
                                 { $$ = new_node(TYPE_OPT_PAYLOAD_DLL);
                                   $$->option.payload = $4; }*/
         ;

/*---------------------------------------------------------------------------
    PATTERNS
  ---------------------------------------------------------------------------*/

pattern: PERIODIC '[' nfloat ',' nint ']'
           { $$ = new_node(TYPE_PERIODIC);
             $$->pattern.periodic.ratio = $3;
             $$->pattern.periodic.n     = $5; }
       | PERIODIC '[' nfloat ']'
           { $$ = new_node(TYPE_PERIODIC_LIGHT);
             $$->pattern.periodic.ratio = $3; }
       ;

/*---------------------------------------------------------------------------
    COMMANDS
  ---------------------------------------------------------------------------*/

o_ntime: /* empty */ { $$ = NULL; }
       | ntime       { $$ = $1;   }
       ;

to: TO_TCP opts pattern                 { $$ = new_node(TYPE_TO_TCP);
                                          $$->to.options = $2;
                                          $$->to.pattern = $3; }
  | TO_UDP opts pattern                 { $$ = new_node(TYPE_TO_UDP);
                                          $$->to.options = $2;
                                          $$->to.pattern = $3; }
  | TO_TCP OPT_OPEN opts                { $$ = new_node(TYPE_TO_TCPOPEN);
                                          $$->to.options = $3;
                                          $$->to.pattern = NULL; }
  | TO_TCP OPT_ZWIN opts                { $$ = new_node(TYPE_TO_ZWIN);
                                          $$->to.options = $3;
                                          $$->to.pattern = NULL; }
  | TO_TCP OPT_SLOW opts                { $$ = new_node(TYPE_TO_SLOW);
                                          $$->to.options = $3;
                                          $$->to.pattern = NULL; }
  | TO_TCP OPT_RAW opts pattern         { $$ = new_node(TYPE_TO_TCPRAW);
                                          $$->to.options = $3;
                                          $$->to.pattern = $4; }
  | TO_LISTEN                           { $$ = new_node(TYPE_TO_LISTEN);
                                          $$->to.options = NULL;
                                          $$->to.pattern = NULL; }
  ;

command: o_ntime CMD_ON selection to    { $$ = new_node(TYPE_CMD_ON);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = $4; }
       | o_ntime CMD_MOD selection to   { $$ = new_node(TYPE_CMD_MOD);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = $4; }
       | o_ntime CMD_OFF selection      { $$ = new_node(TYPE_CMD_OFF);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = NULL; }
       | o_ntime LITERAL '=' string     { $$ = new_node(TYPE_CMD_SETVAR);
                                          $$->command.time          = $1;
                                          $$->command.setvar.var    = $2;
                                          $$->command.setvar.val    = $4;
                                          $$->command.setvar.cond   = 0; }
       | o_ntime '?' LITERAL '=' string { $$ = new_node(TYPE_CMD_SETVAR);
                                          $$->command.time          = $1;
                                          $$->command.setvar.var    = $3;
                                          $$->command.setvar.val    = $5;
                                          $$->command.setvar.cond   = -1; }
    /* | o_ntime CMD_INCLUDE string     { } */
       ;
%%
static SNODE *new_node(int type)
{
  SNODE *n;
  if((n = calloc(1, sizeof(SNODE))) == NULL)
    FAT("Cannot alloc SNODE (%d).", type);
  n->type = type;
  n->line = lineno;

  n->next_allocated = allocated_list;
  allocated_list = n;

  return n;
}

static void script_fini(void)
{
  SNODE *n, *n2;

  for(n = allocated_list; n; )
  {
    n2 = n->next_allocated;
    switch(n->type)
    {
      case TYPE_CMD_SETVAR:
        free(n->command.setvar.var);
        break;

      case TYPE_STRING:
        free(n->string.value);
        break;

      case TYPE_VAR:
        free(n->varname);
        break;
    }
    free(n);
    n = n2;
  }
}

void script_init(void)
{
  lineno = 1;
  allocated_list = NULL;

  dosis_atexit("SCRIPT", script_fini);
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
    FAT("Bad identifier.");
  SADD(c);
  if(c == '{')
  {
    while((c = getchar()) != '}' && isalnum(c) && c != '\n' && c != EOF)
      SADD(c);
    if(c == '\n')
      FAT("Non-terminated var.");
    if(isblank(c) || c == EOF)
      FAT("Bad identifier.");
  } else {
    while(isalnum(c = getchar()) && c != EOF)
      SADD(c);
  }
  ungetc(c, stdin);

  /* update real_bi */
  *real_bi = bi;

  return;

ha_roto_la_olla:
  FAT("You have agoted my pedazo of buffer (%s...).", buff);
}

int yylex(void)
{
  int c, bi, f;
  char buff[BUFFLEN], *s;
  struct {
    char *token;
    int  id;
  } tokens[] = {
    { "CWAIT",    OPT_CWAIT   },
    { "DLL",      OPT_DLL     },
    { "DST",      OPT_DST     },
    { "FILE",     OPT_FILE    },
    { "FLAGS",    OPT_FLAGS   },
    { "LISTEN",   TO_LISTEN   },
    { "MOD",      CMD_MOD     },
    { "MSS",      OPT_MSS     },
    { "NULL",     OPT_NULL    },
    { "OFF",      CMD_OFF     },
    { "ON",       CMD_ON      },
    { "OPEN",     OPT_OPEN    },
    { "PAYLOAD",  OPT_PAYLOAD },
    { "PERIODIC", PERIODIC    },
    { "RANDOM",   OPT_RANDOM  },
    { "RAW",      OPT_RAW     },
    { "RWAIT",    OPT_RWAIT   },
    { "SLOW",     OPT_SLOW    },
    { "SRC",      OPT_SRC     },
    { "SSL",      OPT_SSL     },
    { "TCP",      TO_TCP      },
    { "UDP",      TO_UDP      },
    { "WINDOW",   OPT_WINDOW  },
    { "ZWIN",     OPT_ZWIN    },
    { NULL,       0           }
  }, *token;

  /* Skip white space.  */
  while(isblank(c = getchar()))
    ;
  /* Return end-of-input.  */
  if(c == EOF)
  {
    DBG("Readed a script of %d lines.", lineno - 1);
    return 0;
  }

  /* ignore comments */
  if(c == '#')
  {
    while((c = getchar()) != '\n' && c != EOF)
      ;
    if(c == '\n')
    {
      lineno++;
      return c;
    }
    DBG("Readed a script of %d lines.", lineno - 1);
    return 0;
  }

  /* reset */
  SRESET();

  /* process hex, bin and octal numbers */
  if(c == '0')
  {
    /* one more! */
    c = getchar();

    /* hex num ? */
    if(c == 'x' || c == 'X')
    {
      while(isdigit(c = getchar())
         || (c >= 'a' && c <= 'f')
         || (c >= 'A' && c <= 'F'))
      {
        SADD(c);
      }
      if(isalpha(c) || bi < 1)
        FAT("%d: Bad hex number.", lineno);
      sscanf(buff + 2, "%x", &(yylval.nint));
      return NINT;
    }

    /* bin num ? */
    if(c == 'b' || c == 'B')
    {
      yylval.nint = 0;
      while((c = getchar()) != '0' && c != '1')
      {
        yylval.nint <<= 1;
        yylval.nint |= (c == '1' ? 1 : 0);
        SADD(c);
      }
      if(isalnum(c) || bi < 1)
        FAT("%d: Bad bin number.", lineno);
      return NINT;
    }

    /* octal num or network-address-like string? */
    if(isdigit(c) || strchr("89abcdefABCDEF:", c) != NULL)
    {
      /* read until non-octal char */
      do {
        SADD(c);
      } while((c = getchar()) >= '0' && c <= '7');
      ungetc(c, stdin);

      /* check if it is an address ... */
      if(strchr("89abcdefABCDEF.:", c) != NULL)
      {
        while(strchr("89abcdefABCDEF.:", c) != NULL)
          SADD(c);
        ungetc(c, stdin);
DBG("TOKEN[STRING] = '%s' (network address?)", buff);
        return STRING;
      }

      /* it is an octal num */
      sscanf(buff, "%o", &(yylval.nint));
      return NINT;
    }
    /* else... it should be a float number or something like that */
  }

  if(isdigit(c) || c == '.')
  {
    /* get input and count '.' or detect ':' */
    f = 0;
    do {
      SADD(c);
      if(f >= 0)
      {
        if(c == ':') f = -1;
        if(f >= 0 && c == '.') f++;
      }
    } while(isdigit(c = getchar()) || c == '.' || c == ':');
    ungetc(c, stdin);

    /* check if it is a number */
    switch(f)
    {
      case 0:
        /* normal integer */
        sscanf(buff, "%d", &(yylval.nint));
        return NINT;

      case 1:
        sscanf(buff, "%lf", &(yylval.nfloat));
        return NFLOAT;

      default:
        /* oooh... it is not a number; it is a string */
        while(!isspace(c = getchar()) && c != EOF)
          SADD(c);
        ungetc(c, stdin);
        if((yylval.string = strdup(buff)) == NULL)
          FAT("No mem for string '%s'.", buff);
        return STRING;
    }
  }

  /* Process env var */
  if(c == '$')
  {
    readvar(buff, &bi);
    if((yylval.string = strdup(buff)) == NULL)
      FAT("No mem for string '%s'.", buff);
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
      FAT("%d: Non-terminated string.", lineno);
    s = strdup(buff);
    if(!s)
      FAT("No mem for string '%s'.", buff);
    yylval.string = s;
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
      FAT("Non-terminated string.");
    s = strdup(buff);
    if(!s)
      FAT("No mem for string \"%s\".", buff);
    yylval.string = s;
    return STRING;
  }

  /* special chars (chocolate minitokens) */
  if(c == '\n')
  {
    lineno++;
    return c;
  }
  if(c == ','
  || c == ':'
  || c == '='
  || c == '*' || c == '/'
  || c == '[' || c == ']'
  || c == '(' || c == ')'
  || c == '?'
  || c == '%')
    return c;

  /* ummm.. read word (string) or token */
  do {
    SADD(c);
  } while(isalnum(c = getchar()) && c != EOF);
  ungetc(c, stdin);
  /* is a language token? */
  for(token = tokens; token->token; token++)
    if(!strcasecmp(buff, token->token))
      return token->id;
  /* return string */
  s = strdup(buff);
  if(!s)
    FAT("No mem for string \"%s\".", buff);
  yylval.string = s;
  return LITERAL;

ha_roto_la_olla:
  FAT("You have agoted my pedazo of buffer (%s...).", buff);
  return 0;
}

void yyerror(char const *str)
{
  ERR("parsing error: %d: %s", lineno, str);
}

SNODE *script_parse(void)
{
  yyparse();

  return script;
}

/*---------------------------------------------------------------------------*
 * NODE UTILITIES                                                            *
 *                                                                           *
 *   Helper funcs to read and manipulate SNODE structures.                   *
 *---------------------------------------------------------------------------*/

char *tea_snode_get_var(SNODE *n)
{
  char *r;

  if(n->type != TYPE_VAR)
    FAT("Node of type %d is not a var.", n->type);

  r = getenv(n->varname);
  if(!r)
    FAT("Non-existent variable '%s'.", n->varname);

  if((r = strdup(r)) == NULL)
    FAT("No memory for var '%s' content.", n->varname);

  return r;
}

char *tea_snode_get_string(SNODE *n)
{
  char *r = NULL;

  switch(n->type)
  {
    case TYPE_STRING:
      if((r = strdup(n->string.value)) == NULL)
        FAT("Cannot dup string.");
      break;
    case TYPE_VAR:
      r = tea_snode_get_var(n);
      break;
    default:
      FAT("Node of type %d cannot be converted to string.", n->type);
  }

  return r;
}

int tea_snode_get_int(SNODE *n)
{
  int r;
  char *v;

  switch(n->type)
  {
    case TYPE_NINT:
      r = n->nint;
      break;
    case TYPE_VAR:
      v = tea_snode_get_var(n);
      r = atoi(v);
      free(v);
      break;
    default:
      FAT("Node of type %d cannot be converted to integer.", n->type);
  }

  return r;
}

double tea_snode_get_float(SNODE *n)
{
  double r;
  char *v;

  switch(n->type)
  {
    case TYPE_NINT:
      r = (double) n->nint;
      break;
    case TYPE_NFLOAT:
      r = n->nfloat;
      break;
    case TYPE_VAR:
      v = tea_snode_get_var(n);
      r = atof(v);
      free(v);
      break;
    default:
      FAT("Node of type %d cannot be converted to float.", n->type);
  }

  return r;
}

/*---------------------------------------------------------------------------*
 * ITERATORS                                                                 *
 *                                                                           *
 *   Functions related to iterators.                                         *
 *---------------------------------------------------------------------------*/

int tea_iter_get(TEA_ITER *ti)
{
  int i = 0;
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      i = ti->i;
      break;
    case TYPE_LIST_NUM:
      i = ti->c
            ? tea_snode_get_int(ti->c->list_num.val)
            : 0;
      break;
    default:
      FAT("Bad selector node.");
  }
  return i;
}

int tea_iter_start(SNODE *s, TEA_ITER *ti)
{
  ti->first = s;
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      ti->i1 = ti->first->range.min != NULL
                 ? tea_snode_get_int(ti->first->range.min)
                 : 0;
      ti->i2 = ti->first->range.max != NULL
                 ? tea_snode_get_int(ti->first->range.max)
                 : cfg.maxthreads - 1;
      if(ti->i1 < 0)
        FAT("Bad range minimum value '%d'.", ti->i1);
      if(ti->i2 >= cfg.maxthreads)
        FAT("Bad range maximum value '%d' (maxthreads set to %d).", ti->i2, cfg.maxthreads);
      if(ti->i1 > ti->i2)
        FAT("Bad range.");
      ti->i = ti->i1;
      break;
    case TYPE_LIST_NUM:
      ti->c = ti->first;
      break;
    default:
      FAT("Bad selector node.");
  }

  return tea_iter_get(ti);
}

int tea_iter_finish(TEA_ITER *ti)
{
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      return ti->i > ti->i2;
    case TYPE_LIST_NUM:
      return ti->c == NULL;
    default:
      FAT("Bad selector node.");
  }
  return -1;
}

int tea_iter_next(TEA_ITER *ti)
{
  switch(ti->first->type)
  {
    case TYPE_SELECTOR:
      ti->i++;
      break;
    case TYPE_LIST_NUM:
      if(ti->c)
        ti->c = ti->c->list_num.next;
      break;
    default:
      FAT("Bad selector node.");
  }

  return tea_iter_get(ti);
}


