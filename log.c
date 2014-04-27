
#include "log.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

static int log_level = LOG_LEVEL_INFO;

static inline int
log_message(int level, FILE *stream, const char *prefix, const char *fmt,
            va_list ap)
{
  if (level <= log_level) {
    char new_fmt[strlen(prefix) + strlen(fmt) + 15];

    snprintf(new_fmt, sizeof(new_fmt), "[%d] %s: %s\n", getpid(), prefix, fmt);

    return vfprintf(stream, new_fmt, ap);
  }
  
  return 0;
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
