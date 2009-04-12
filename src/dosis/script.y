%{
  #include <script.h>

  #define YYSTYPE double

  int yylex (void);
  void yyerror (char const *);

  /* The lexical analyzer returns a double floating point
     number on the stack and the token NUM, or the numeric code
     of the character read if not a number.  It skips all blanks
     and tabs, and returns 0 for end-of-input.  */

  #include <ctype.h>

  int yylex (void)
  {
    int c;

    /* Skip white space.  */
    while(isblank(c = getchar()))
      ;
    /* Return end-of-input.  */
    if(c == EOF)
      return 0;
    /* Process numbers.  */
    if(c == '.' || isdigit(c))
    {
      ungetc(c, stdin);
      scanf("%lf", &yylval);
      return NFLOAT;
    }
    /* Return a single char.  */
    return c;
  }
%}

%token NINT NFLOAT IPADDR VAR
%token PERIODIC
%token CMD_ON CMD_MOD CMD_OFF
%token OPT_UDP OPT_TCP OPT_SRC OPT_DST
%% /* Grammar rules and actions follow.  */
input: /* empty */
       | input line
       ;

line: '\n'
    | command '\n' { printf ("\t%.10g\n", $1); }
    ;

nint: NINT
    | VAR
    ;

nfloat: NFLOAT
      | nint
      ;

list_num_more: /* empty */
        
list_num: nint
        | '[' nint '..' nint ']'
        | '[' nint ']'
        | '[' nint ',' list_num_more ']'
        ;

selector: '*'
        | list_num
        ;

options: /* empty */
       | OPT_TCP options
       | OPT_UDP options
       | OPT_SRC IPADDR options
       | OPT_DST IPADDR options
       ;

command: nfloat CMD_ON list_num options pattern
       | nfloat CMD_MOD selector options pattern
       | nfloat CMD_OFF selector
       ;

pattern: PERIODIC '[' nfloat ',' nint ']'
       ;
%%

