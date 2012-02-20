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

  #include "config.h"

  #include "script.h"
  #include "log.h"
  #include "ip.h"
  #include "dosconfig.h"

  static int yylex (void);
  static void yyerror (char const *);

  static SNODE *node_new(int type);
  static SNODE *node_new_bool(int val);
  static SNODE *node_new_float(double val);
  static SNODE *node_new_int(int val);
  static SNODE *node_new_string(char *val, int parse, int dup);
  static SNODE *node_new_var(char *varname, int dup);

  static int lineno;
  static SNODE *script;
  static SNODE *allocated_list = NULL;

  static HASH *defvalues;

  typedef struct _tag_TOKEN {
    char *token;
    int   value;
    char *name;
  } TOKEN;
%}
%union {
  HASH      *hash;
  SNODE     *snode;
  int        nbool;
  int        nint;
  double     nfloat;
  char      *string;
  char      *name;
}
%token <nbool>    NBOOL
%token <nint>     NINT
%token <nfloat>   NFLOAT
%token <string>   STRING LITERAL
%token <string>   VAR
%token <name>     CMD_OPT_BOOL CMD_OPT_INT CMD_OPT_STR CMD_OPT_DATA CMD_OPT_ADDR_PORT
%type  <hash>     opts pattern
%type  <snode>    input
%type  <snode>    data nbool nfloat nint ntime string var varval addr_port
%type  <snode>    list_num_enum list_num range selection
%type  <snode>    o_ntime command
%type  <snode>    to to_pattern to_no_patt
%token            PERIODIC
%token            DATA_NULL DATA_ZERO DATA_BYTE DATA_RANDOM DATA_FILE
%token            CMD_ON CMD_MOD CMD_OFF
%token            TO_LISTEN TO_IGNORE TO_SEND TO_TCP TO_UDP
%token            OPT_OPEN OPT_RAW OPT_SLOW OPT_ZWIN
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

var:  VAR         { $$ = node_new_var($1, 0); }
    ;
nbool: NBOOL      { $$ = node_new_bool($1); }
     | var
     ;
nint: NINT        { $$ = node_new_int($1); }
    | var
    ;
nfloat: NFLOAT    { $$ = node_new_float($1); }
      | NINT      { $$ = node_new_float($1); }
      | var
      ;
ntime: '+' nfloat { $$ = node_new(TYPE_NTIME);
                    $$->ntime.rel = -1;
                    $$->ntime.n   = $2; }
     | nfloat     { $$ = node_new(TYPE_NTIME);
                    $$->ntime.rel = 0;
                    $$->ntime.n   = $1; }
     ;
string: STRING                  { $$ = node_new_string($1, 1, 0); }
      | LITERAL                 { $$ = node_new_string($1, 0, 0); }
      | var
      ;
data:   string
      | DATA_NULL                       { $$ = NULL; }
      | DATA_RANDOM '(' nint ')'        { $$ = node_new(TYPE_RANDOM);
                                          $$->random.len = $3; }
      | DATA_ZERO '(' nint ')'          { $$ = node_new(TYPE_BYTEREP);
                                          $$->byterep.len = $3;
                                          $$->byterep.val = '\0'; }
      | DATA_BYTE '(' nint ',' nint ')' { $$ = node_new(TYPE_BYTEREP);
                                          $$->byterep.len = $3;
                                          $$->byterep.val = $5; }
      | DATA_FILE '(' string ')'        { $$ = node_new(TYPE_FILE);
                                          $$->file.path = $3; }
      ;
addr_port: string      { $$ = node_new(TYPE_ADDR_PORT);
                         $$->addr_port.addr = $1;
                         $$->addr_port.port = NULL; }
         | string nint { $$ = node_new(TYPE_ADDR_PORT);
                         $$->addr_port.addr = $1;
                         $$->addr_port.port = $2; }
         ;
list_num_enum: nint                   { $$ = node_new(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = NULL; }
             | nint ',' list_num_enum { $$ = node_new(TYPE_LIST_NUM);
                                        $$->list_num.val  = $1;
                                        $$->list_num.next = $3; }
             ;

list_num: nint                  { $$ = node_new(TYPE_LIST_NUM);
                                  $$->list_num.val  = $1;
                                  $$->list_num.next = NULL; }
        | '[' list_num_enum ']' { $$ = $2; }
        ;

range: '*'                   { $$ = node_new(TYPE_SELECTOR);
                               $$->range.min = NULL;
                               $$->range.max = NULL; }
     | '[' nint '%' nint ']' { $$ = node_new(TYPE_SELECTOR);
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
  /* none */                       { $$ = hash_new(); }
| CMD_OPT_BOOL      opts           { $$ = $2; hash_entry_add($$, $1, node_new_bool(1)); }
| CMD_OPT_BOOL      nbool     opts { $$ = $3; hash_entry_add($$, $1, $2);   }
| CMD_OPT_STR       string    opts { $$ = $3; hash_entry_add($$, $1, $2);   }
| CMD_OPT_INT       nint      opts { $$ = $3; hash_entry_add($$, $1, $2);   }
| CMD_OPT_DATA      data      opts { $$ = $3; hash_entry_add($$, $1, $2);   }
| CMD_OPT_ADDR_PORT addr_port opts { $$ = $3; hash_entry_add($$, $1, $2);   }
       /*| OPT_PAYLOAD OPT_DLL '(' string ')'
                                 { $$ = node_new(TYPE_OPT_PAYLOAD_DLL);
                                   $$->option.payload = $4; }*/
         ;

/*---------------------------------------------------------------------------
    PATTERNS
  ---------------------------------------------------------------------------*/

pattern: PERIODIC '[' nfloat ',' nint ']'
           { $$ = hash_new();
             hash_entry_add($$, "pattern",        node_new_int(TYPE_PERIODIC));
             hash_entry_add($$, "periodic_ratio", $3);
             hash_entry_add($$, "periodic_n",     $5); }
       | PERIODIC '[' nfloat ']'
           { $$ = hash_new();
             hash_entry_add($$, "pattern",        node_new_int(TYPE_PERIODIC));
             hash_entry_add($$, "periodic_ratio", $3);
             hash_entry_add($$, "periodic_n",     node_new_int(1)); }
       ;

/*---------------------------------------------------------------------------
    COMMANDS
  ---------------------------------------------------------------------------*/

o_ntime: /* empty */ { $$ = NULL; }
       | ntime       { $$ = $1;   }
       ;

to_pattern: TO_TCP          { $$ = node_new(TYPE_TO_TCP);     }
          | TO_UDP          { $$ = node_new(TYPE_TO_UDP);     }
          | TO_TCP OPT_RAW  { $$ = node_new(TYPE_TO_TCPRAW);  }
          ;
to_no_patt: TO_TCP OPT_OPEN { $$ = node_new(TYPE_TO_TCPOPEN); }
          | TO_TCP OPT_ZWIN { $$ = node_new(TYPE_TO_ZWIN);    }
          | TO_TCP OPT_SLOW { $$ = node_new(TYPE_TO_SLOW);    }
          | TO_LISTEN       { $$ = node_new(TYPE_TO_LISTEN);  }
          | TO_IGNORE       { $$ = node_new(TYPE_TO_IGNORE);  }
          | TO_SEND         { $$ = node_new(TYPE_TO_SEND);    }
          ;
to: to_pattern opts pattern { $$ = $1;
                              $1->options = hash_merge($2, $3, NULL);
                              hash_destroy($3, NULL); }
  | to_no_patt opts         { $$ = $1;
                              $1->options = $2; }
  ;

varval: string  { $$ = $1; }
      | NBOOL   { char *s;
                  if((s = strdup($1 ? "TRUE" : "FALSE")) == NULL)
                    FAT("No mem. Cannot dup boolean.");
                  $$ = node_new_string(s, 0, 0);
                  WRN("%d: Var assigment requires BOOL to STRING conversion.", lineno); }
      | NINT    { char buff[255], *s;
                  snprintf(buff, sizeof(buff), "%d", $1);
                  if((s = strdup(buff)) == NULL)
                    FAT("No mem. Cannot dup integer.");
                  $$ = node_new_string(s, 0, 0);
                  WRN("%d: Var assigment requires INT to STRING conversion.", lineno); }
      | NFLOAT  { char buff[255], *s;
                  snprintf(buff, sizeof(buff), "%f", $1);
                  if((s = strdup(buff)) == NULL)
                    FAT("No mem. Cannot dup float.");
                  $$ = node_new_string(s, 0, 0);
                  WRN("%d: Var assigment requires FLOAT to STRING conversion.", lineno); }
      ;
command: o_ntime CMD_ON selection to    { $$ = node_new(TYPE_CMD_ON);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = $4; }
       | o_ntime CMD_MOD selection to   { $$ = node_new(TYPE_CMD_MOD);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = $4; }
       | o_ntime CMD_OFF selection      { $$ = node_new(TYPE_CMD_OFF);
                                          $$->command.time          = $1;
                                          $$->command.thc.selection = $3;
                                          $$->command.thc.to        = NULL; }
       | o_ntime LITERAL '=' varval     { $$ = node_new(TYPE_CMD_SETVAR);
                                          $$->command.time          = $1;
                                          $$->command.setvar.var    = $2;
                                          $$->command.setvar.val    = $4;
                                          $$->command.setvar.cond   = 0; }
       | o_ntime '?' LITERAL '=' varval { $$ = node_new(TYPE_CMD_SETVAR);
                                          $$->command.time          = $1;
                                          $$->command.setvar.var    = $3;
                                          $$->command.setvar.val    = $5;
                                          $$->command.setvar.cond   = -1; }
    /* | o_ntime CMD_INCLUDE string     { } */
       ;
%%
/*****************************************************************************
 * YYPARSE FUNCTIONS (SYNTAX PARSER)
 *****************************************************************************/

static SNODE *node_new(int type)
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

static SNODE *node_new_float(double val)
{
  SNODE *n = node_new(TYPE_NFLOAT);
  n->nfloat = val;
  return n;
}

static SNODE *node_new_int(int val)
{
  SNODE *n = node_new(TYPE_NINT);
  n->nint = val;
  return n;
}

static SNODE *node_new_string(char *val, int parse, int dup)
{
  SNODE *n = node_new(TYPE_STRING);
  if(!dup)
    n->string.value = val;
  else
    if((n->string.value = strdup(val)) == NULL)
      FAT("No mem for string '%s'.", val);
  n->string.parse = parse;
  return n;
}

static SNODE *node_new_var(char *varname, int dup)
{
  SNODE *n = node_new(TYPE_VAR);
  if(!dup)
    n->varname = varname;
  else
    if((n->varname = strdup(varname)) == NULL)
      FAT("No mem for var name '%s'.", varname);
  return n;
}

static SNODE *node_new_bool(int v)
{
  SNODE *n = node_new(TYPE_BOOL);
  n->nbool = v != 0;
  return n;
}

static void node_free(SNODE *n)
{
  if(!n)
    return;

  switch(n->type)
  {
    case TYPE_BOOL:
    case TYPE_BYTEREP:
    case TYPE_CMD_MOD:
    case TYPE_CMD_OFF:
    case TYPE_CMD_ON:
    case TYPE_FILE:
    case TYPE_LIST_NUM:
    case TYPE_NFLOAT:
    case TYPE_NINT:
    case TYPE_NTIME:
    case TYPE_RANDOM:
    case TYPE_SELECTOR:
    case TYPE_TO_LISTEN:
    case TYPE_TO_IGNORE:
    case TYPE_TO_SEND:
    case TYPE_ADDR_PORT:
      /* do nothing */
      break;

    case TYPE_TO_SLOW:
    case TYPE_TO_TCP:
    case TYPE_TO_TCPOPEN:
    case TYPE_TO_TCPRAW:
    case TYPE_TO_UDP:
    case TYPE_TO_ZWIN:
      hash_destroy(n->options, NULL);
      break;

    case TYPE_STRING:
      free(n->string.value);
      break;

    case TYPE_CMD_SETVAR:
      free(n->command.setvar.var);
      break;

    case TYPE_VAR:
      free(n->varname);
      break;

    default:
      FAT("Unknown node type %d.", n->type);
  }
  free(n);
}

SNODE *script_parse(void)
{
  yyparse();

  return script;
}

/*****************************************************************************
 * YYLEX FUNCTIONS (LEXICAL PARSER)
 *****************************************************************************/

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

static void readvar(char *buff, int *real_bi)
{
  int c;
  int bi = *real_bi;

  /* read var name in buffer */
  c = getchar();
  if(c == EOF)
    FAT("%d: Bad identifier.", lineno);
  SADD(c);
  if(c == '{')
  {
    while((c = getchar()) != '}' && isalnum(c) && c != '\n' && c != EOF)
      SADD(c);
    if(c == '\n')
      FAT("%d: Non-terminated var.", lineno);
    if(isblank(c) || c == EOF)
      FAT("%d: Bad identifier.", lineno);
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

#ifdef PARSER_DEBUG
static int yylex_real(void);

static int yylex(void)
{
  int r = yylex_real();
  
  switch(r)
  {
    case 0:              DBG("yylex: EOF (%d lines)", lineno - 1);  break;
    case NINT:           DBG("yylex: NINT = %d", yylval.nint);      break;
    case NBOOL:          DBG("yylex: NBOOL = %d", yylval.nbool);    break;
    case NFLOAT:         DBG("yylex: NFLOAT = %f", yylval.nfloat);  break;
    case LITERAL:        DBG("yylex: LITERAL = %s", yylval.string); break;
    case STRING:         DBG("yylex: STRING = %s", yylval.string);  break;
    case DATA_FILE:      DBG("yylex: DATA_FILE");                   break;
    case DATA_RANDOM:    DBG("yylex: DATA_RANDOM");                 break;
    case DATA_BYTE:      DBG("yylex: DATA_BYTE");                   break;
    case DATA_ZERO:      DBG("yylex: DATA_ZERO");                   break;
    case DATA_NULL:      DBG("yylex: DATA_NULL");                   break;
    case VAR:            DBG("yylex: VAR = %s", yylval.string);     break;
    case PERIODIC:       DBG("yylex: PERIODIC");                    break;
    case CMD_ON:         DBG("yylex: CMD_ON");                      break;
    case CMD_MOD:        DBG("yylex: CMD_MOD");                     break;
    case CMD_OFF:        DBG("yylex: CMD_OFF");                     break;
    case OPT_OPEN:       DBG("yylex: OPT_OPEN");                    break;
    case OPT_RAW:        DBG("yylex: OPT_RAW");                     break;
    case OPT_MSS:        DBG("yylex: OPT_MSS");                     break;
    case OPT_SLOW:       DBG("yylex: OPT_SLOW");                    break;
    case OPT_ZWIN:       DBG("yylex: OPT_ZWIN");                    break;
    case TO_LISTEN:      DBG("yylex: TO_LISTEN");                   break;
    case TO_IGNORE:      DBG("yylex: TO_IGNORE");                   break;
    case TO_SEND:        DBG("yylex: TO_SEND");                     break;
    case TO_TCP:         DBG("yylex: TO_TCP");                      break;
    case TO_UDP:         DBG("yylex: TO_UDP");                      break;
    case '\n':           DBG("yylex: New line.");                   break;
    case '?':
    case '=':
    case '[':
    case '%':
    case ']':
    case ',':
    case '*':
      DBG("yylex: [%c]", r);
      break;

    default:
      FAT("%d: Unknown token %d (%c).", lineno, r, r);
  }

  return r;
}

static int yylex_real(void)
#else
static int yylex(void)
#endif
{
  int c, bi, f;
  char buff[BUFFLEN];
  TOKEN tokens[] = {
    { "BYTE",      DATA_BYTE,         NULL            },
    { "FILE",      DATA_FILE,         NULL            },
    { "ZERO",      DATA_ZERO,         NULL            },
    { "RANDOM",    DATA_RANDOM,       NULL            },
    { "NULL",      DATA_NULL,         NULL            },

    { "ON",        CMD_ON,            NULL            },
    { "MOD",       CMD_MOD,           NULL            },
    { "OFF",       CMD_OFF,           NULL            },

    { "LISTEN",    TO_LISTEN,         NULL            },
    { "IGNORE",    TO_IGNORE,         NULL            },
    { "SEND",      TO_SEND,           NULL            },
    { "TCP",       TO_TCP,            NULL            },
    { "UDP",       TO_UDP,            NULL            },
    { "OPEN",      OPT_OPEN,          NULL            },
    { "RAW",       OPT_RAW,           NULL            },
    { "SLOW",      OPT_SLOW,          NULL            },
    { "ZWIN",      OPT_ZWIN,          NULL            },
    { "PERIODIC",  PERIODIC,          NULL            },

    { "CIPHER",    CMD_OPT_STR,       "ssl_cipher"    },
    { "CWAIT",     CMD_OPT_INT,       "tcp_cwait"     },
    { "DEBUG",     CMD_OPT_BOOL,      "debug"         },
    { "DELAY",     CMD_OPT_INT,       "delay"         },
    { "DLL",       CMD_OPT_STR,       "dll"           },
    { "DST",       CMD_OPT_ADDR_PORT, "dst_addr_port" },
    { "FLAGS",     CMD_OPT_STR,       "tcp_flags"     },
    { "MSS",       CMD_OPT_INT,       "tcp_mss"       },
    { "PAYLOAD",   CMD_OPT_DATA,      "payload"       },
    { "RWAIT",     CMD_OPT_INT,       "tcp_rwait"     },
    { "SACK",      CMD_OPT_BOOL,      "tcp_sack"      },
    { "SRC",       CMD_OPT_ADDR_PORT, "src_addr_port" },
    { "SSL",       CMD_OPT_BOOL,      "ssl"           },
    { "TCPTSTAMP", CMD_OPT_BOOL,      "tcp_tstamp"    },
    { "WINDOW",    CMD_OPT_INT,       "tcp_win"       },

    { NULL,        0,                 NULL            }
  }, bool_tokens[] = {
    { "TRUE",      -1,                NULL            },
    { "ENABLE",    -1,                NULL            },
    { "ENABLED",   -1,                NULL            },
    { "FALSE",      0,                NULL            },
    { "DISABLE",    0,                NULL            },
    { "DISABLED",   0,                NULL            },
    { NULL,         0,                NULL            }
  }, *token;

  /* Skip white space.  */
again_skip:
  while(isblank(c = getchar()))
    ;
  if(c == EOF)
    return 0;
  if(c == '\\')
  {
    c = getchar();
    if(c == '\r')
      c = getchar();
    if(c == '\n')
      goto again_skip;
    if(c == EOF)
      return 0;
    FAT("%d: Unexpected char '%c' after \\.", lineno, c);
  }

  /* ignore comments */
  if(c == '#')
  {
    while((c = getchar()) != '\n' && c != '\r' && c != EOF)
      ;
    if(c == '\r')
      c = getchar();
    if(c == EOF)
      return 0;
    if(c == '\n')
    {
      lineno++;
      return c;
    }
    FAT("%d: Unexpected char '%c' after '\\r'.", lineno, c);
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

    /* octal number? */
    if(c >= '0' && c <= '7')
    {
      /* read until non-octal char */
      SADD(c);
      do {
        SADD(c);
      } while((c = getchar()) >= '0' && c <= '7');

      if(c != EOF && (isdigit(c) || isalpha(c)))
        FAT("%d: Unexpected char '%c' after octal number '%s'.", lineno, c, buff);

      /* it is an octal num */
      sscanf(buff, "%o", &(yylval.nint));
      return NINT;
    }

    /* float number? */
    if(c == '.')
    {
      SADD('0');
      SADD('.');
      while(isdigit(c = getchar()))
        SADD(c);
      if(c != EOF)
        ungetc(c, stdin);

      if(c != EOF && (c == '.' || c == ':'))
      {
        /* it is not a float... maybe and address or something like that */
        while(isdigit(c = getchar()) || c == '.' || c == ':')
          SADD(c);
        if((yylval.string = strdup(buff)) == NULL)
          FAT("No mem for string '%s'.", buff);
        if(c != EOF)
          ungetc(c, stdin);
        return STRING;
      }

      sscanf(buff, "%lf", &(yylval.nfloat));
      return NFLOAT;
    }

    /* if is not an alpha and not [0-7], do ungetc and return 0! */
    if(c != EOF)
    {
      ungetc(c, stdin);
      if(c != EOF && (isdigit(c) || isalpha(c)))
          FAT("%d: Unexpected char '%c' after zero.", lineno, c);
    }

    yylval.nint = 0;
    return NINT;
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
    ;
    if((yylval.string = strdup(buff)) == NULL)
      FAT("No mem for string '%s'.", buff);
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
      FAT("%d: Non-terminated string.", lineno);
    if((yylval.string = strdup(buff)) == NULL)
      FAT("No mem for string \"%s\".", buff);
    return STRING;
  }

  /* special chars (chocolate minitokens) */
  if(c == '\r')
  {
    c = getchar();
    if(c == EOF)
      return 0;
    if(c != '\n')
      FAT("%d: Unexpected char '%c' after '\\r'.", lineno, c);
  }
  if(c == '\n')
  {
    lineno++;
    return c;
  }
  if(c == ','
  || c == '+'
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
  /* is a boolean const? */
  for(token = bool_tokens; token->token; token++)
    if(!strcasecmp(buff, token->token))
    {
      yylval.nbool = token->value;
      return NBOOL;
    }
  /* is a language token? */
  for(token = tokens; token->token; token++)
    if(!strcasecmp(buff, token->token))
    {
      if(token->name)
        if((yylval.name = strdup(token->name)) == NULL)
          FAT("No mem for token \"%s\".", buff);
      return token->value;
    }
  /* return string */
  if((yylval.string = strdup(buff)) == NULL)
    FAT("No mem for string \"%s\".", buff);
  return LITERAL;

ha_roto_la_olla:
  FAT("You have agoted my pedazo of buffer (%s...).", buff);
  return 0;
}

/*****************************************************************************
 * INITIALIZATION AND FINALIZATION ROUTINES
 *****************************************************************************/

static void script_fini(void)
{
  SNODE *n, *n2;

  for(n = allocated_list; n; )
  {
    n2 = n->next_allocated;
    node_free(n);

    n = n2;
  }
  hash_destroy(defvalues, NULL);
}

void script_init(void)
{
  lineno = 1;
  allocated_list = NULL;

  dosis_atexit("SCRIPT", script_fini);

  /* create config skeleton and set default config */
  defvalues = hash_new();
  hash_entry_add(defvalues, "payload",        NULL);
  hash_entry_add(defvalues, "ssl",            NULL);
  hash_entry_add(defvalues, "ssl_cipher",     node_new_string("DES-CBC3-SHA", 0, 1));
  hash_entry_add(defvalues, "src_addr_port",  NULL);
  hash_entry_add(defvalues, "dst_addr_port",  NULL);
  hash_entry_add(defvalues, "tcp_mss",        NULL);
  hash_entry_add(defvalues, "tcp_flags",      NULL);
  hash_entry_add(defvalues, "tcp_cwait",      node_new_int(3000000));
  hash_entry_add(defvalues, "tcp_rwait",      node_new_int(10000000));
  hash_entry_add(defvalues, "tcp_sack",       node_new_bool(0));
  hash_entry_add(defvalues, "tcp_tstamp",     node_new_bool(0));
  hash_entry_add(defvalues, "tcp_tstamp_val", NULL);
  hash_entry_add(defvalues, "tcp_tstamp_ecr", NULL);
  hash_entry_add(defvalues, "tcp_win",        node_new_int(14600));
  hash_entry_add(defvalues, "tcp_wscale",     NULL);
  hash_entry_add(defvalues, "pattern",        NULL);
  hash_entry_add(defvalues, "periodic_ratio", NULL);
  hash_entry_add(defvalues, "periodic_n",     NULL);
  hash_entry_add(defvalues, "delay",          node_new_int(0));
  hash_entry_add(defvalues, "debug",          node_new_bool(0));
}

static void yyerror(char const *str)
{
  ERR("parsing error: %d: %s", lineno, str);
}

/*---------------------------------------------------------------------------*
 * NODE UTILITIES                                                            *
 *                                                                           *
 *   Helper funcs to read and manipulate SNODE structures.                   *
 *---------------------------------------------------------------------------*/

char *script_get_data(SNODE *n, unsigned int *size)
{
  struct stat pls;
  int i, f;
  char *s, *s2;
  char *buffer;

  *size = 0;
  buffer = NULL;

  /* apply config */
  switch(n->type)
  {
    case TYPE_STRING:
      if((buffer = strdup(n->string.value)) == NULL)
        FAT("Cannot dup string.");
      *size = strlen(buffer);
      break;

    case TYPE_VAR:
      buffer = script_get_var(n);
      *size = strlen(buffer);
      break;

    case TYPE_FILE:
      s2 = script_get_string(n->file.path);
      s = dosis_search_file(s2);
      free(s2);
      if(stat(s, &pls) < 0)
        FAT_ERRNO("%d: Cannot stat file '%s'", n->line, s);
      *size = pls.st_size;
      if((buffer = malloc(*size + 1)) == NULL)
        FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
      buffer[*size] = '\0';
      if((f = open(s, O_RDONLY)) < 0)
        FAT_ERRNO("%d: Cannot open payload", n->line);
      if(read(f, buffer, *size) < *size)
        FAT_ERRNO("%d: Cannot read the payload file", n->line);
      close(f);
      free(s);
      break;

    case TYPE_BYTEREP:
      *size = script_get_int(n->byterep.len);
      i     = script_get_int(n->byterep.val);
      if(*size > 0)
      {
        if((buffer = malloc(*size + 1)) == NULL)
          FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
        memset(buffer, i, *size);
        buffer[*size] = '\0';
      }
      break;

    case TYPE_RANDOM:
      *size = script_get_int(n->random.len);
      if(*size > 0)
      {
        if((buffer = malloc(*size + 1)) == NULL)
          FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
        srand(time(NULL));
        for(i = 0; i < *size; i++)
          *(buffer + i) = rand() & 0x000000FF;
        buffer[*size] = '\0';
      }
      break;

    default:
      FAT("%d: Uknown option %d.", n->line, n->type);
  }

  return buffer;
}

char *script_get_string(SNODE *n)
{
  char *r = NULL;
  unsigned int l;

  r = script_get_data(n, &l);
  if(strlen(r) != l)
    FAT("%d: String contains null characters.", n->line);

  return r;
}


int script_get_bool(SNODE *n)
{
  int r = 0;
  char *v, *p, *s;

  switch(n->type)
  {
    case TYPE_BOOL:
      r = n->nbool;
      break;
    case TYPE_NINT:
      r = (n->nint != 0);
      break;
    case TYPE_VAR:
      v = script_get_var(n);
      p = v;
      while(*p && isspace(*p))
        p++;
      s = p;
      if(*p && *p == '-')
        p++;
      while(*p && *p >= '0' && *p <= '9')
        p++;
      while(*p && isspace(*p))
        *p++ = '\0';
      if(*p)
      {
        /* it is not a number... check for constants */
        if(!strcasecmp(s, "TRUE")
        || !strcasecmp(s, "ENABLE")
        || !strcasecmp(s, "ENABLED")) r = (1 != 0);
        else
        if(!strcasecmp(s, "FALSE")
        || !strcasecmp(s, "DISABLE")
        || !strcasecmp(s, "DISABLED")) r = 0;
        else
        FAT("Cannot convert variable '%s' (with value %s) to boolean.", n->varname, s);
      } else {
        /* convert integer to bool ... */
        r = (atoi(v) != 0);
      }
      free(v);
      break;
    default:
      FAT("Node of type %d cannot be converted to boolean.", n->type);
  }

  return r;
}

int script_get_int(SNODE *n)
{
  int r = 0;
  char *v;

  switch(n->type)
  {
    case TYPE_NINT:
      r = n->nint;
      break;
    case TYPE_VAR:
      v = script_get_var(n);
      r = atoi(v);
      free(v);
      break;
    default:
      FAT("Node of type %d cannot be converted to integer.", n->type);
  }

  return r;
}

double script_get_float(SNODE *n)
{
  double r = 0.0;
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
      v = script_get_var(n);
      r = atof(v);
      free(v);
      break;
    default:
      FAT("Node of type %d cannot be converted to float.", n->type);
  }

  return r;
}

char *script_get_var(SNODE *n)
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


/*---------------------------------------------------------------------------
 * CONFIGURATION
 *---------------------------------------------------------------------------*/

SNODE *script_get_default(char *param)
{
  /* try to get default value from default config */
  if(!hash_key_exists(defvalues, param))
    FAT("Parameter '%s' does not exist in dosis' parameter list/hash.", param);

  return hash_entry_get(defvalues, param);
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
            ? script_get_int(ti->c->list_num.val)
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
                 ? script_get_int(ti->first->range.min)
                 : 0;
      ti->i2 = ti->first->range.max != NULL
                 ? script_get_int(ti->first->range.max)
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


