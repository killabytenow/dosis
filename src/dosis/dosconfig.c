/*****************************************************************************
 * dosconfig.c
 *
 * Configuration structure.
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

#include <config.h>
#include <datadir.h>
#include "dosconfig.h"
#include "help.h"
#include "log.h"

/* default config and global configuration pointer */
DOS_CONFIG cfg = {
  /* verbosity        */ LOG_LEVEL_LOG,
  /* output filename  */ NULL,
  /* script filename  */ NULL,
  /* max threads      */ 100,
};

/* unix wrappers */
typedef struct tag_DOSIS_ATEXIT {
  char *name;
  void (*func)(void);
  struct tag_DOSIS_ATEXIT *next;
} DOSIS_ATEXIT;

static int dosis_forked;
DOSIS_ATEXIT *dosis_atexit_list = NULL;

/* private object's global variables */
static struct option *long_options = NULL;
static char *short_options = NULL;

typedef struct _tag_CMD_OPTION {
  char shortopt;
  char *longopt;
  int   has_arg; /* 0 no arg; 1 yes; 2 optional */
} DOS_CMD_OPTION;

DOS_CMD_OPTION cmd_options[] = {
  { 'h', "help",          0 },
  { 'i', "interface",     1 },
  { 'I', "include",       1 },
  { 'q', "quiet",         0 },
  { 'o', "output-file",   1 },
  { 't', "max-threads",   1 },
  { 'v', "verbose",       2 },
  { 'Z', "debug",         0 },
  {   0, NULL,            0 },
};
#define CMD_OPTIONS_N (sizeof(cmd_options) / sizeof(DOS_CMD_OPTION))

/*****************************************************************************
 * Command Line Parser
 *
 *   Following code parses command line input (with getopt(3) help), updating
 *   current configuration (cfg).
 *
 *****************************************************************************/

static void dos_config_parse_command(int argc, char **argv)
{
  int c, fin, option_index = 0;
  char *s;

  /* configure and reset getopt */
  opterr = 0;
  optind = 1;

  /* get options */
  fin = 0;
  while(!fin)
  {
    c = getopt_long(argc, argv, short_options, long_options, &option_index);

    switch(c)
    {
      case 'h':
          dos_help_program_header();
          print_help();
          exit(0);

      case 'o':
          if(!optarg || strlen(optarg) == 0)
            FAT("Required a valid filename.");
          if(cfg.output)
            free(cfg.output);
          if((cfg.output = strdup(optarg)) == NULL)
            FAT("No mem for ouput filename.");
          break;
      case 'q':
          cfg.verbosity = 0;
          break;
      case 'i':
          {
            int i;
            if(!optarg || strlen(optarg) == 0)
              FAT("Required interface.");
            for(i = 0; i < MAX_INTERFACES && cfg.interfaces[i]; i++)
              ;
            if(i >= MAX_INTERFACES)
              FAT("No space for more interfaces.");
            if((cfg.interfaces[i] = strdup(optarg)) == NULL)
              FAT("No mem for interface.");
          }
          break;
      case 'I':
          if(!optarg || strlen(optarg) == 0)
            FAT("Required pathname.");
          dosis_add_include_dir(optarg, 0);
          break;
      case 't':
          cfg.maxthreads = atoi(optarg);
          if(cfg.maxthreads < 1)
            FAT("A minimum of 1 thread is needed.");
          break;
      case 'v':
          s = optarg ? optarg : "3";
          cfg.verbosity = atoi(s);
          break;
      case 'Z':
          cfg.verbosity = LOG_LEVEL_ALL;
          break;
      case -1:
          fin = -1;
          break;
      default:
          FAT("Invalid option '%c'.", c); 
    }
  }

  if(argc - optind > 1)
    FAT("Specify only one script file.");
  if(argc - optind < 1)
    cfg.script = NULL;
  else {
    dosis_add_include_dir(argv[optind], 1);
    if((cfg.script = dosis_search_file(argv[optind])) == NULL)
      FAT("Script '%s' not found.", argv[optind]);
  }
}

/*****************************************************************************
 * Initialization and finalization routines
 *****************************************************************************/

#define READ_FIELD(n, s) for(j = 0; j < sizeof(buff) - 1; j++)      \
                         {                                          \
                           c = fgetc(f);                            \
                           buff[j] = c;                             \
                           if(c == EOF)                             \
                           {                                        \
                             buff[j] = '\0';                        \
                             goto eof;                              \
                           }                                        \
                           if(c == s)                               \
                           {                                        \
                             buff[j] = '\0';                        \
                             break;                                 \
                           }                                        \
                         }                                          \
                         buff[j] = '\0';

void dos_get_routes(void)
{
  int i, j, c;
  DOS_ROUTE_INFO *r, *r2;
  char buff[255];
  FILE *f;

  /* open /proc/net/route */
  if((f = fopen("/proc/net/route", "r")) == NULL)
    FAT("Cannot read route table (/proc/net/route).");

  /* ignore first line */
  while((c = fgetc(f)) != '\n' && c != EOF)
    ;
  if(c == EOF)
  {
    WRN("Void route table!");
    goto eof;
  }

  /* read routes */
  for(i = 0; i < MAX_ROUTES; i++)
  {
    /* new route info */
    if((r = calloc(1, sizeof(DOS_ROUTE_INFO))) == NULL)
      FAT("Cannot alloc a DOS_ROUTE_INFO struct.");
    for(r2 = cfg.routes; r2 && r2->next; r2 = r2->next)
      ;
    if(r2)
      r2->next = r;
    else
      cfg.routes = r;

    /* read input */
    READ_FIELD("iface", '\t');       /* + iface       */
    if((r->iface = strdup(buff)) == NULL)
      FAT("No memory for iface name (%s).", buff);
    READ_FIELD("destination", '\t'); /* + destination */
    if(ip_addr_parse(buff, &r->destination, NULL))
      FAT("Cannot parse destination address '%s'.", buff);
    READ_FIELD("gateway",     '\t'); /* + gateway     */
    if(ip_addr_parse(buff, &r->gateway, NULL))
      FAT("Cannot parse gateway address '%s'.", buff);
    READ_FIELD("flags",       '\t'); /* - flags       */
    READ_FIELD("refcnt",      '\t'); /* - refcnt      */
    READ_FIELD("use",         '\t'); /* - use         */
    READ_FIELD("metric",      '\t'); /* - metric      */
    READ_FIELD("mask",        '\t'); /* + mask        */
    if(ip_addr_parse(buff, &r->mask, NULL))
      FAT("Cannot parse mask address '%s'.", buff);
    READ_FIELD("MTU",         '\t'); /* - MTU         */
    READ_FIELD("window",      '\t'); /* - window      */
    READ_FIELD("irtt",        '\n'); /* - IRTT        */

    /* check default gw */
    r->defaultgw = INET_ADDR_IS_ZERO(r->mask);

    /* debug info */
    DBG("+ iface %s.", r->iface);
    ip_addr_snprintf(&r->destination, -1, (int) sizeof(buff), buff);
    DBG("· destination %s.", buff);
    ip_addr_snprintf(&r->gateway, -1, (int) sizeof(buff), buff);
    DBG("· gateway %s.", buff);
    ip_addr_snprintf(&r->mask, -1, (int) sizeof(buff), buff);
    DBG("· mask %s.", buff);
  }

eof:
  fclose(f);
}

#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
#define IFRSIZE   ((int)(size * sizeof (struct ifreq)))

void dos_get_addresses(void)
{
  int                sockfd, size  = 0;
  struct ifreq       *ifr;
  struct ifconf      ifc;
  DOS_ADDR_INFO *a;
  char buff[255];

  if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
    FAT("Cannot open socket.\n");

  ifc.ifc_len = IFRSIZE;
  ifc.ifc_req = NULL;

  /* get buffer for all the interfaces */
  size = sizeof(struct ifreq);
  do {
    size <<= 1;
    ifc.ifc_len = size;
    if((ifc.ifc_req = realloc(ifc.ifc_req, ifc.ifc_len)) == NULL)
      FAT("Out of memory.\n");
    if(ioctl(sockfd, SIOCGIFCONF, &ifc))
      FAT_ERRNO("Cannot ioctl SIOCFIFCONF");
  } while(size <= ifc.ifc_len);

  /* get the info! */
  cfg.addr = NULL;
  for(ifr = ifc.ifc_req; 
      ifr < (struct ifreq *) (((void *) ifc.ifc_req) + ifc.ifc_len);
      ifr++)
  {
    /* check flags */
    if(ioctl(sockfd, SIOCGIFFLAGS, ifr))
      continue;  /* failed to get flags, skip it */

    if(!(ifr->ifr_flags & IFF_UP))
    {
      WRN("Interface %s is down.", ifr->ifr_name);
      continue;
    }

    /* alloc a new address info structure */
    if((a = calloc(1, sizeof(DOS_ADDR_INFO))) == NULL)
      FAT("Cannot alloc a DOS_ADDR_INFO struct.");
    a->next = cfg.addr;
    cfg.addr = a;
    if((a->name = strdup(ifr->ifr_name)) == NULL)
      FAT("No mem for interface name.");

    /* get PA */
    if(!ioctl(sockfd, SIOCGIFADDR, ifr))
      ip_socket_to_addr(&ifr->ifr_addr, &a->addr, NULL);
    else
      WRN("Interface %s has not a primary address.", a->name);

    /* get PA netmask */
    if(!ioctl(sockfd, SIOCGIFNETMASK, ifr))
      ip_socket_to_addr(&ifr->ifr_addr, &a->mask, NULL);
    else
      WRN("Interface %s has not a PA network mask.", a->name);

    /* get HW address */
    if(ioctl(sockfd, SIOCGIFHWADDR, ifr) == 0
    && (ifr->ifr_hwaddr.sa_family == ARPHRD_NETROM
     || ifr->ifr_hwaddr.sa_family == ARPHRD_ETHER
     || ifr->ifr_hwaddr.sa_family == ARPHRD_PPP
     || ifr->ifr_hwaddr.sa_family == ARPHRD_EETHER
     || ifr->ifr_hwaddr.sa_family == ARPHRD_IEEE802))
      memcpy(a->hwaddr, &ifr->ifr_addr.sa_data, sizeof(a->hwaddr));

    DBG("Interface:  %s", a->name);
    DBG("  - HW Address: %02x:%02x:%02x:%02x:%02x:%02x",
        a->hwaddr[0], a->hwaddr[1], a->hwaddr[2],
        a->hwaddr[3], a->hwaddr[4], a->hwaddr[5]);
    ip_addr_snprintf(&a->addr, -1, sizeof(buff), buff);
    DBG("  - IP Address: %s", buff);
    ip_addr_snprintf(&a->mask, -1, sizeof(buff), buff);
    DBG("  - IP Mask:    %s", buff);
  }

  free(ifc.ifc_req);
  close(sockfd);
}

DOS_ADDR_INFO *dos_get_interface(INET_ADDR *ta)
{
  DOS_ADDR_INFO *r, *sa;
  DOS_ROUTE_INFO *ri;
char buff[255];

  r = NULL;

  /* check local networks (interfaces) */
  for(sa = cfg.addr; !r && sa; sa = sa->next)
    if(ip_addr_check_mask(ta, &sa->addr, &sa->mask))
    {
ip_addr_snprintf(ta, -1, sizeof(buff), buff);
DBG("  - Local iface %s (%s) is ok.", sa->name, buff);
      r = sa;
    }

  /* check now routing table (for special cases) */
  for(ri = cfg.routes; ri; ri = ri->next)
  {
ip_addr_snprintf(&ri->destination, -1, sizeof(buff), buff);
ip_addr_snprintf(&ri->mask, -1, sizeof(buff) - strlen(buff) - 1, buff + strlen(buff) + 1);
DBG("  - route %s/%s (defaultgw = %s)", buff, buff + strlen(buff) + 1, ri->defaultgw ? "yes" : "no");
    if(ip_addr_check_mask(ta, &ri->destination, &ri->mask) && (!ri->defaultgw || !r))
      for(sa = cfg.addr; sa; sa = sa->next)
        if(!strcmp(sa->name, ri->iface))
        {
          DBG("    + USING ROUTE");
          return sa;
        } else
          WRN("Route table references an interface that not exists or is down (%s).",
              ri->iface);
  }

  /* if routing table does not provide a better option, return the */
  /* first interface attached to a network that meets target       */
  return r;
}

int dos_get_source_address(INET_ADDR *s, INET_ADDR *t)
{
  DOS_ADDR_INFO *ai;
  char buff[255];

ip_addr_snprintf(t, -1, sizeof(buff), buff);
DBG("Searching source address/interface for '%s'...", buff);

  /* check target address */
  if(t->type == INET_FAMILY_NONE)
  {
    ERR("I need a valid target address.");
    return -1;
  }

  /* select most suitable interface for such target address */
  if((ai = dos_get_interface(t)) == NULL)
  {
    ip_addr_snprintf(t, -1, sizeof(buff), buff);
    WRN("Cannot find a suitable source address/interface for '%s'.", buff);
    return -1;
  }

  /* copy interface address */
  ip_addr_copy(s, &ai->addr);
  
  return 0;
}

int dosis_fork(void)
{
  int r;

  r = fork();
  if(r < 0)
    FAT_ERRNO("Cannot fork");
  if(r == 0)
    dosis_forked = -1;

  return r;
}

void dosis_atexit(char *name, void (*func)(void))
{
  DOSIS_ATEXIT *a;

  if((a = calloc(1, sizeof(DOSIS_ATEXIT))) == NULL)
    FAT("Cannot alloc a DOSIS_ATEXIT node.");
  a->name = strdup(name);
  a->func = func;
  a->next = dosis_atexit_list;
  dosis_atexit_list = a;
}

void dosis_add_include_dir(char *p, int dirname)
{
  int i, j;

  if((p = strdup(p)) == NULL)
    FAT("No mem for pathname.");

  if(dirname)
  {
    for(i = 0; p[i] && p[i] != '/'; i++)
      ;
    if(!p[i])
    {
      free(p);
      return;
    }
    j = i;
    while(p[++i])
      if(p[i] == '/')
        j = i;
    p[j] = '\0';
  }

  for(i = 0; i < MAX_INCLUDE_DIRS && cfg.includedir[i]; i++)
    ;
  if(i >= MAX_INCLUDE_DIRS)
    FAT("No space for more include directories.");
  if((cfg.includedir[i] = p) == NULL)
    FAT("No mem for pathname.");
}

char *dosis_search_file(char *file)
{
  struct stat buf;
  char tmp[PATH_MAX], *r;
  char **paths;

  /* in the worst case (file not found) we will return NULL */
  r = NULL;

  /* if absolute path, then return the same file */
  if(*file == '/')
    r = file;

  /* if file is present in current dir, then return the same file */
  if(!stat(file, &buf) && S_ISREG(buf.st_mode))
    r = file;

  /* search file 'file' in the list of 'paths' */
  for(paths = cfg.includedir; !r && *paths; paths++)
  {
    if(snprintf(tmp, PATH_MAX, "%s/%s", *paths, file) > PATH_MAX)
      FAT("String '%s/%s' is longer than PATH_MAX characters (%d).",
          *paths, file, PATH_MAX);
    if(!stat(tmp, &buf) && S_ISREG(buf.st_mode))
      r = tmp;
  }

  /* return a copy */
  if(r)
    if((r = strdup(r)) == NULL)
      FAT("No memory for path '%s'.", tmp);

  return r;
}

static void dos_config_fini(void)
{
  DOSIS_ATEXIT *atx;
  DOS_ADDR_INFO *addr;
  int i;

  cfg.finalize = -1;

  if(dosis_forked)
  {
    DBG("Ignoring atexit on fork.");
    return;
  }

  while((atx = dosis_atexit_list) != NULL)
  {
    DBG("Executing atexit [%s]", atx->name);
    dosis_atexit_list = atx->next;
    atx->func();
    free(atx->name);
    free(atx);
  }
  DBG("Atexit finished.");

  if(cfg.output)                 free(cfg.output);
  if(cfg.script)                 free(cfg.script);
  if(cfg.of != stdout && cfg.of) fclose(cfg.of);

  while((addr = cfg.addr) != NULL)
  {
    cfg.addr = addr->next;
    free(addr->name);
    free(addr);
  }

  for(i = 0; i < MAX_INCLUDE_DIRS; i++)
    if(cfg.includedir[i])
    {
      free(cfg.includedir[i]);
      cfg.includedir[i] = NULL;
    }

  if(short_options)
    free(short_options);
  if(long_options)
    free(long_options);

  DBG("dosconfig finished.");
}

void dos_config_init(int argc, char **argv)
{
  int i, j;
  char *s;

  /* first of all get concious about dead */
  if(atexit(dos_config_fini))
    FAT("Cannot set finalization routine.");

  /* zero include dirs and interfaces array */
  memset(cfg.includedir, 0, sizeof(cfg.includedir));

  /* initialize getopt tables */
  if(!(short_options = calloc((CMD_OPTIONS_N * 2) + 1, sizeof(char)))
  || !(long_options = calloc(CMD_OPTIONS_N + 1, sizeof(struct option))))
    FAT("No memory for getopt tables.");

  s = short_options;
  j = 0;
  for(i = 0; i < CMD_OPTIONS_N; i++)
  {
    if(cmd_options[i].shortopt)
    {
      *s++ = cmd_options[i].shortopt;
      if(cmd_options[i].has_arg == 1)
        *s++ = ':';
    }
    if(cmd_options[i].longopt)
    {
      long_options[j].name    = cmd_options[i].longopt;
      long_options[j].has_arg = cmd_options[i].has_arg;
      long_options[j].flag    = NULL;
      long_options[j].val     = cmd_options[i].shortopt
                                  ? cmd_options[i].shortopt
                                  : j;
      j++;
    }
  }
  *s = '\0';

  /* read config and command from command line */
  dos_config_parse_command(argc, argv);

  /* open output file */
  if(cfg.output)
  {
    if((cfg.of = fopen(cfg.output, "w")) == NULL)
      FAT("Cannot write output file '%s'.", cfg.output);
  } else {
    WRN("Writing to standard output.");
    cfg.of = stdout;
  }

  /* get network interfaces and ip addresses */
  dos_get_addresses();

  /* get routing table */
  dos_get_routes();

  /* print program header and config (if debug verbosity enabled) */
  dos_help_program_header();
  DBG("Configuration");
  DBG("  verbosity level = %d", cfg.verbosity);
  DBG("  script file     = %s", cfg.script ? cfg.script : "<standard input>");
  DBG("  output file     = %s", cfg.output ? cfg.output : "<standard output>");
  for(i = 0; i < MAX_INTERFACES; i++)
    if(cfg.interfaces[i])
      DBG("  interface[%d]   = %s", i, cfg.interfaces[i]);
  for(i = 0; i < MAX_INCLUDE_DIRS; i++)
    if(cfg.includedir[i])
      DBG("  include dir[%d] = %s", i, cfg.includedir[i]);

  /* open script file */
  if(cfg.script)
  {
    close(0);
    if(open(cfg.script, O_RDONLY) < 0)
      FAT_ERRNO("Cannot read file '%s'", argv[optind]);
  } else
    WRN("Reading standard input.");
}

