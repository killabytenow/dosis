/*****************************************************************************
 * log.c
 *
 * This file implements a simple log system.
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

#include "dosconfig.h"
#include "dosis.h"
#include "log.h"

/******************************************************************************
 * Internal log functions
 *
 *   These functions are the kernel of this library. These functions should not
 *   be used directly, instead you must use the d_log, d_error, .. functions
 *   and their macros (see 'log.h').
 */

FILE *logfile = NULL;
int   binfile = -1;

static char *d_log_get_level_desc(int level)
{
  char *type = NULL;

  switch(level)
  {
    case LOG_LEVEL_DEBUG2:  type = "DEBUG2:";   break;
    case LOG_LEVEL_DEBUG:   type = "DEBUG:";   break;
    case LOG_LEVEL_LOG:     type = "";         break;
    case LOG_LEVEL_WARNING: type = "warning:"; break;
    case LOG_LEVEL_ERROR:   type = "ERROR:";   break;
    case LOG_LEVEL_FATAL:   type = "ERROR:";   break;
    default:
      FAT("Unknown log level when printing message.");
  }

  return type;
}

static void d_log_prefix_print(int level, char *file, char *function)
{
  fputs(d_log_get_level_desc(level), logfile);
  if(file)     fprintf(logfile, "%s:", file);
  if(function) fprintf(logfile, "%s:", function);
}

static void d_log_level_print(int level, char *file, char *function, char *format, va_list args)
{
  if(cfg.verbosity < level)
    return;

/* XXX: When threaded, get log library lock here */
  d_log_prefix_print(level, file, function);

  vfprintf(logfile, format, args);
  fputc('\n', logfile);
}

/******************************************************************************
 * Public log functions
 *
 *   These functions only use the previous functions to expose a rich log API.
 */

void d_log_level(int level, char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(level, file, function, format, args);
  va_end(args);
  
  if(level == LOG_LEVEL_FATAL)
    exit(1);
}

void d_db2(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_DEBUG2, file, function, format, args);
  va_end(args);
}

void d_dbg(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_DEBUG, file, function, format, args);
  va_end(args);
}

void d_log(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_LOG, file, function, format, args);
  va_end(args);
}

void d_wrn(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_WARNING, file, function, format, args);
  va_end(args);
}

void d_err(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_ERROR, file, function, format, args);
  va_end(args);
}

void d_fat(char *file, char *function, char *format, ...)
{
  va_list args;

  va_start(args, format);
  d_log_level_print(LOG_LEVEL_FATAL, file, function, format, args);
  va_end(args);

  exit(1);
}

/******************************************************************************
 * Back/Stacktrace function party
 *
 *   Support for printing stacktraces, useful when debugging
 */

struct _tag_d_stacktrace_info {
  int              ptok;
  struct link_map *lm;
  ElfW(Addr)       stringTable;
  ElfW(Word)       stringTableSize;
  ElfW(Addr)       symbolTable;
  ElfW(Word)       symbolSize;
  ElfW(Addr)       hashTable;

  Elf_Symndx      *hashTableData;
  Elf_Symndx       hashTableSize;
} d_stacktrace_info;

#define IO_GET_PT(x,y)   case DT_##x: d_stacktrace_info.y = dyn->d_un.d_ptr; break;
#define IO_GET_VL(x,y)   case DT_##x: d_stacktrace_info.y = dyn->d_un.d_val; break;
#define LINUX_LIBC_VABS(x,y,z)  (((((x) * 1000) + (y)) * 1000) + (z))
#define LINUX_LIBC_MINVER       LINUX_LIBC_VABS(LINUX_LIBC_VMAJ_MIN, \
                                                LINUX_LIBC_VMIN_MIN, \
                                                LINUX_LIBC_VREV_MIN)
#define LINUX_LIBC_MAXVER       LINUX_LIBC_VABS(LINUX_LIBC_VMAJ_MAX, \
                                                LINUX_LIBC_VMIN_MAX, \
                                                LINUX_LIBC_VREV_MAX)
static void d_stacktrace_init(int level)
{
  static int initialized = 0;
  unsigned int vlibc_maj,
               vlibc_min,
               vlibc_rev,
               vlibc;
  ElfW(Dyn) *dyn;

  /* one time execution */
  if(initialized)
    return;

  /* get gnu libc version */
  if(sscanf(gnu_get_libc_version(), "%u.%u.%u",
            &vlibc_maj, &vlibc_min, &vlibc_rev) != 3)
  {
    vlibc_rev = 0;
    if(sscanf(gnu_get_libc_version(), "%u.%u", &vlibc_maj, &vlibc_min) != 2)
      FAT(THIS, "GNU libc version string cannot be parsed (%s)",
                 gnu_get_libc_version());
  }
  vlibc = LINUX_LIBC_VABS(vlibc_maj, vlibc_min, vlibc_rev);

  /* search MAIN link map */
  d_stacktrace_info.lm = _r_debug.r_map;
  d_log_level(level, THIS, "link map head '%s' 0x%08x",
              d_stacktrace_info.lm->l_name, d_stacktrace_info.lm->l_addr);

  /* parse Elf structures */
  for(dyn = d_stacktrace_info.lm->l_ld; dyn->d_tag != DT_NULL; dyn++)
    switch(dyn->d_tag)
    {
      IO_GET_PT(STRTAB, stringTable)
      IO_GET_VL(STRSZ,  stringTableSize)
      IO_GET_PT(SYMTAB, symbolTable)
      IO_GET_VL(SYMENT, symbolSize)
      case DT_HASH:
        d_stacktrace_info.hashTable = vlibc < LINUX_LIBC_VABS(2,3,0)
                                        ? dyn->d_un.d_ptr + d_stacktrace_info.lm->l_addr
                                        : dyn->d_un.d_ptr;
        d_stacktrace_info.hashTableData = ((Elf_Symndx *) d_stacktrace_info.hashTable) + 2;
        d_stacktrace_info.hashTableSize = *(((Elf_Symndx *) d_stacktrace_info.hashTable) + 0)
                                        + *(((Elf_Symndx *) d_stacktrace_info.hashTable) + 1);
        break;
    }

  /* check mandatory sections are present */
  d_stacktrace_info.ptok = d_stacktrace_info.stringTable     != 0
                        && d_stacktrace_info.stringTableSize != 0
                        && d_stacktrace_info.symbolTable     != 0
                        && d_stacktrace_info.symbolSize      != 0
                        && d_stacktrace_info.hashTable       != 0;
  if(!d_stacktrace_info.ptok)
    WRN("Mandatory elf sections not found; resolving static symbols is not possible.");

  initialized = -1;
}

#if HAVE_EXECINFO_H && HAVE_ELF_H
struct elf_info {
  void       *base;
  off_t       size;
  int         nsyms;
  ElfW(Shdr) *symtab;
  ElfW(Shdr) *strtab;
};

static void d_elf_close(struct elf_info *ei)
{
  if(!ei->base)
    return;
  if(munmap(ei->base, ei->size) < 0)
    ERR("Cannot munmap() binfile.");
  ei->base = NULL;
  ei->size = 0;
}

static void d_elf_open(int f, struct elf_info *ei)
{
  ElfW(Ehdr) *ehdr;
  ElfW(Shdr) *shdr;
  struct stat stbuf;
  int i;

  /* map binary */
DBG("mapping bin");
  if(fstat(binfile, &stbuf) < 0)
    ERR("Cannot stat binfile.");
  ei->size = stbuf.st_size;
  if((ei->base = mmap(NULL, ei->size, PROT_READ, MAP_PRIVATE, f, 0)) < 0)
    ERR("Cannot mmap binfile.");

  /* parse header and search sections */
DBG("parsing bin headers");
  ehdr = ei->base;
  for(i = 0; i < ehdr->e_shnum; i++)
  {
    shdr = ei->base + ehdr->e_shoff + i * ehdr->e_shentsize;
    if((void *) shdr >= ei->base + ei->size)
    {
      ERR("Invalid ELF binfile (shdr out of range).");
      d_elf_close(ei);
      return;
    }
    switch(shdr->sh_type)
    {
      case SHT_SYMTAB: ei->symtab = shdr; break;
      case SHT_STRTAB: ei->strtab = shdr; break;
    }
  }
DBG("  * symtab = 0x%08x", ei->symtab);
DBG("  * strtab = 0x%08x", ei->strtab);
  ei->nsyms = ei->symtab->sh_size / ei->symtab->sh_entsize;
  if(ei->symtab->sh_size > (ei->nsyms * ei->symtab->sh_entsize))
    WRN("symtab is not multiple of entsize(%d)", ei->symtab->sh_entsize);
DBG("  * nsysm  = %d", ei->nsyms);
}

static char *d_elf_symname(struct elf_info *ei, ElfW(Sym) *sym)
{
  int i;
  if(sym->st_name >= ei->strtab->sh_size)
  {
    i = ((unsigned) sym - (unsigned) ei->base - ei->symtab->sh_offset) / ei->symtab->sh_entsize;
    i = 0;
    ERR("Symbol %d (binfile offset 0x%08x), name outside of string table (st_name = 0x%08x).",
        i, ei->symtab->sh_offset + ei->symtab->sh_entsize * i,
        sym->st_name);
    return NULL;
  }
  return !sym->st_name
           ? "[no-name]"
           : ei->base + ei->strtab->sh_offset + sym->st_name;
}

static char *d_elf_resolve(struct elf_info *ei, void *addr)
{
  int i;
  ElfW(Sym) *sym, *minsym = NULL;

DBG("searching pointer 0x%08x", addr);
  for(i = 0; i < ei->nsyms; i++)
  {
    sym = ei->base + ei->symtab->sh_offset + ei->symtab->sh_entsize * i;
    if((void *) sym->st_value == addr)
      return d_elf_symname(ei, sym);
    if(minsym == NULL
    || (sym->st_value > minsym->st_value && sym->st_value < (ElfW(Addr)) addr))
      minsym = sym;
  }

  return minsym != NULL ? d_elf_symname(ei, minsym) : NULL;
}
#endif

void d_stacktrace(int level)
{
#if HAVE_EXECINFO_H
  void *stt[255];
  char **syt, *name;
  size_t s, i;
#if HAVE_ELF_H
  struct elf_info ei;
#endif

  d_stacktrace_init(level);

  /* get void*'s for all entries on the stack */
  s = backtrace(stt, sizeof(stt)/sizeof(void *));
  syt = backtrace_symbols(stt, s);

  /* open elf file (if system supports elf bin format) */
#if HAVE_ELF_H
  d_elf_open(binfile, &ei);
#endif

  /* print out all the frames to stderr */
  d_log_level(level, THIS, "Stacktrace (size %d):", s);
  for(i = 0; i < s; i++)
  {
#if HAVE_ELF_H
    name = d_elf_resolve(&ei, stt[i]);
#endif
    if(!name)
      name = syt[i];
    d_log_level(level, THIS, "%s at 0x%08x", name, (UINT_POINTER) stt[i]);
  }
  d_log_level(level, THIS, "<< end of stacktrace >>");

  /* close elf file */
#if HAVE_ELF_H
  d_elf_close(&ei);
#endif

  free(syt);
#else
  d_log_level(level, THIS, "<< STACKTRACE NOT AVAILABLE >>");
#endif
}

static void log_fini(void)
{
  if(logfile != stderr)
    fclose(logfile);
  if(binfile >= 0)
    close(binfile);
}

void log_init(char *argv0)
{
  logfile = stderr;
  if(argv0)
    binfile = open(argv0, O_RDONLY);

  /* get concious about dead */
  if(atexit(log_fini))
    FAT("Cannot set finalization routine.");
}

