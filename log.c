
#include "log.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

static int log_level = LOG_LEVEL_INFO;
static char process_name[32];

static inline int
log_message(int level, FILE *stream, const char *prefix, const char *fmt,
            va_list ap)
{
  if (level <= log_level) {
    char new_fmt[strlen(prefix) + strlen(fmt) + sizeof(process_name) + 15];

    snprintf(new_fmt, sizeof(new_fmt), "[%s:%d] %s: %s\n",
             process_name, getpid(), prefix, fmt);

    return vfprintf(stream, new_fmt, ap);
  }
  
  return 0;
}

void
set_process_name(const char *p)
{
  snprintf(process_name, sizeof(process_name), "%s", p);
}

void
set_log_level(int level)
{
  log_level = level;
}

int
lerr(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_ERR, stderr, "ERR", fmt, ap);
}

int
lwarn(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_WARN, stderr, "WRN", fmt, ap);
}

int
linfo(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_INFO, stdout, "INF", fmt, ap);
}

int
ldbg(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_DBG, stdout, "DBG", fmt, ap);
}
