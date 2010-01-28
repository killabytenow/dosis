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

  static SNODE *new_node(int type);
  static SNODE *new_node_bool(int val);
  static SNODE *new_node_float(double val);
  static SNODE *new_node_int(int val);
  static SNODE *new_node_string(char *val, int parse);
  static SNODE *new_node_var(char *varname);

  static int lineno;
  static SNODE *script;
  static SNODE *allocated_list;

  static HASH *defvalues;
%}
%union {
  HASH      *hash;
  SNODE     *snode;
  int        nint;
  double     nfloat;
  char      *string;
}
%token <nint>     NINT
%token <nfloat>   NFLOAT
%token <string>   STRING LITERAL
%token <string>   VAR
%type  <hash>     opts pattern
%type  <snode>    input
%type  <snode>    data nbool nfloat nint ntime string var
%type  <snode>    list_num_enum list_num range selection
%type  <snode>    o_ntime command
%type  <snode>    to to_pattern to_no_patt
%token            BFALSE BTRUE
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

var:  VAR         { $$ = new_node_var($1); }
    ;
nbool: BTRUE      { $$ = new_node_bool(1); }
     | BFALSE     { $$ = new_node_bool(1); }
     ;
nint: NINT        { $$ = new_node_int($1); }
    | var
    ;
nfloat: NFLOAT    { $$ = new_node_float($1); }
      | NINT      { $$ = new_node_float($1); }
      | var
      ;
ntime: '+' nfloat { $$ = new_node(TYPE_NTIME);
                    $$->ntime.rel = -1;
                    $$->ntime.n   = $2; }
     | nfloat     { $$ = new_node(TYPE_NTIME);
                    $$->ntime.rel = 0;
                    $$->ntime.n   = $1; }
     ;
string: STRING                  { $$ = new_node_string($1, 1); }
      | LITERAL                 { $$ = new_node_string($1, 0); }
      | var
      ;
data:   string
      | RANDOM '(' nint ')'     { $$ = new_node(TYPE_RANDOM);
                                  $$->random.len = $3; }
      | _FILE '(' string ')'    { $$ = new_node(TYPE_FILE);
                                  $$->file.path = $3; }
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
| OPT_PAYLOAD OPT_NULL opts { $$ = $3; hash_add_entry($$, "payload",    NULL); }
| OPT_PAYLOAD data opts     { $$ = $3; hash_add_entry($$, "payload",    $2);   }
| OPT_SSL nbool opts        { $$ = $3; hash_add_entry($$, "ssl",        $2);   }
| OPT_SSL opts              { $$ = $2; hash_add_entry($$, "ssl",        new_node_bool(1)); }
| OPT_SSL string opts       { $$ = $3; hash_add_entry($$, "ssl",        new_node_bool(1));
                                       hash_add_entry($$, "ssl_cipher", $2);   }
| OPT_SRC string opts       { $$ = $3; hash_add_entry($$, "src_addr",   $2);   }
| OPT_SRC string nint opts  { $$ = $4; hash_add_entry($$, "src_addr",   $2);
                                       hash_add_entry($$, "src_port",   $3);   }
| OPT_DST string opts       { $$ = $3; hash_add_entry($$, "dst_addr",   $2);   }
| OPT_DST string nint opts  { $$ = $4; hash_add_entry($$, "dst_addr",   $2);
                                       hash_add_entry($$, "dst_port",   $3);   }
| OPT_MSS nint opts         { $$ = $3; hash_add_entry($$, "tcp_mss",    $2);   }
| OPT_FLAGS string opts     { $$ = $3; hash_add_entry($$, "tcp_flags",  $2);   }
| OPT_CWAIT nint opts       { $$ = $3; hash_add_entry($$, "tcp_cwait",  $2);   }
| OPT_RWAIT nint opts       { $$ = $3; hash_add_entry($$, "tcp_rwait",  $2);   }
| OPT_WINDOW nint opts      { $$ = $3; hash_add_entry($$, "tcp_win",    $2);   }
       /*| OPT_PAYLOAD OPT_DLL '(' string ')'
                                 { $$ = new_node(TYPE_OPT_PAYLOAD_DLL);
                                   $$->option.payload = $4; }*/
         ;

/*---------------------------------------------------------------------------
    PATTERNS
  ---------------------------------------------------------------------------*/

pattern: PERIODIC '[' nfloat ',' nint ']'
           { $$ = hash_new();
             hash_add_entry($$, "pattern", new_node_int(TYPE_PERIODIC));
             hash_add_entry($$, "periodic_ratio", $3);
             hash_add_entry($$, "periodic_n",     $5); }
       | PERIODIC '[' nfloat ']'
           { $$ = hash_new();
             hash_add_entry($$, "pattern", new_node_int(TYPE_PERIODIC));
             hash_add_entry($$, "periodic_ratio", $3);
             hash_add_entry($$, "periodic_n",     new_node_int(1)); }
       ;

/*---------------------------------------------------------------------------
    COMMANDS
  ---------------------------------------------------------------------------*/

o_ntime: /* empty */ { $$ = NULL; }
       | ntime       { $$ = $1;   }
       ;

to_pattern: TO_TCP          { $$ = new_node(TYPE_TO_TCP);     }
          | TO_UDP          { $$ = new_node(TYPE_TO_UDP);     }
          | TO_TCP OPT_RAW  { $$ = new_node(TYPE_TO_TCPRAW);  }
          ;
to_no_patt: TO_TCP OPT_OPEN { $$ = new_node(TYPE_TO_TCPOPEN); }
          | TO_TCP OPT_ZWIN { $$ = new_node(TYPE_TO_ZWIN);    }
          | TO_TCP OPT_SLOW { $$ = new_node(TYPE_TO_SLOW);    }
          ;
to: to_pattern opts pattern { $$ = $1;
                              $1->options = hash_merge($2, $3, NULL);
                              hash_destroy($3, NULL); }
  | to_no_patt opts         { $$ = $1;
                              $1->options = $2; }
  | TO_LISTEN               { $$ = new_node(TYPE_TO_LISTEN);
                              $$->options = NULL; }
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
/*****************************************************************************
 * YYPARSE FUNCTIONS (SYNTAX PARSER)
 *****************************************************************************/

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

static SNODE *new_node_float(double val)
{
  SNODE *n = new_node(TYPE_NFLOAT);
  n->nfloat = val;
  return n;
}

static SNODE *new_node_int(int val)
{
  SNODE *n = new_node(TYPE_NINT);
  n->nint = val;
  return n;
}

static SNODE *new_node_string(char *val, int parse)
{
  SNODE *n = new_node(TYPE_STRING);
  n->string.value = val;
  n->string.parse = parse;
  return n;
}

static SNODE *new_node_var(char *varname)
{
  SNODE *n = new_node(TYPE_VAR);
  n->varname = varname;
  return n;
}

static SNODE *new_node_bool(int v)
{
  SNODE *n = new_node(TYPE_BOOL);
  n->nbool = v != 0;
  return n;
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

static int yylex(void)
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
    { "FALSE",    BFALSE      },
    { "FILE",     TYPE_FILE   },
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
    { "RANDOM",   TYPE_RANDOM },
    { "RAW",      OPT_RAW     },
    { "RWAIT",    OPT_RWAIT   },
    { "SLOW",     OPT_SLOW    },
    { "SRC",      OPT_SRC     },
    { "SSL",      OPT_SSL     },
    { "TCP",      TO_TCP      },
    { "TRUE",     BTRUE       },
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

/*****************************************************************************
 * INITIALIZATION AND FINALIZATION ROUTINES
 *****************************************************************************/

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

  /* create config skeleton */
  defvalues = hash_new();
  hash_add_entry(defvalues, "payload",    NULL);
  hash_add_entry(defvalues, "ssl",        NULL);
  hash_add_entry(defvalues, "ssl_cipher", NULL);
  hash_add_entry(defvalues, "src_addr",   NULL);
  hash_add_entry(defvalues, "src_port",   NULL);
  hash_add_entry(defvalues, "dst_addr",   NULL);
  hash_add_entry(defvalues, "dst_port",   NULL);
  hash_add_entry(defvalues, "tcp_mss",    NULL);
  hash_add_entry(defvalues, "tcp_flags",  NULL);
  hash_add_entry(defvalues, "tcp_cwait",  NULL);
  hash_add_entry(defvalues, "tcp_rwait",  NULL);
  hash_add_entry(defvalues, "tcp_win",    NULL);
  hash_add_entry(defvalues, "ssl_cipher", NULL);

  /* set default config */
  hash_set_entry(defvalues, "tcp_cwait",  new_node_int(3000000));
  hash_set_entry(defvalues, "tcp_rwait",  new_node_int(10000000));
  hash_set_entry(defvalues, "tcp_win",    new_node_int(31337));
  hash_set_entry(defvalues, "ssl_cipher", new_node_string("DES-CBC3-SHA", 0));

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
        FAT("%d: Cannot stat file '%s': %s", n->line, s, strerror(errno));
      *size = pls.st_size;
      if((buffer = malloc(*size + 1)) == NULL)
        FAT("%d: Cannot alloc %d bytes for payload.", n->line, *size);
      buffer[*size] = '\0';
      if((f = open(s, O_RDONLY)) < 0)
        FAT("%d: Cannot open payload: %s", n->line, strerror(errno));
      if(read(f, buffer, *size) < *size)
        FAT("%d: Cannot read the payload file: %s", n->line, strerror(errno));
      close(f);
      free(s);
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


int script_get_int(SNODE *n)
{
  int r;
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
    FAT("Cannot get invalid parameter '%s'.", param);

  return hash_get_entry(defvalues, param);
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


