
#include "log.h"

#include <stdarg.h>
#include <string.h>
#include <stdio.h>

static int log_level = LOG_LEVEL_INFO;

static int 
log_message(int level, FILE *stream, const char *prefix, const char *fmt,
            va_list ap)
{
  if (level <= log_level) {
    char new_fmt[strlen(prefix) + strlen(fmt) + 1 + 1];

    strcpy(new_fmt, prefix);
    strcat(new_fmt, fmt);
    strcat(new_fmt, "\n");

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
  return log_message(LOG_LEVEL_ERR, stderr, "ERR: ", fmt, ap);
}

int
lwarn(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_WARN, stderr, "WRN: ", fmt, ap);
}

int
linfo(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_INFO, stdout, "INF: ", fmt, ap);
}

int
ldbg(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  return log_message(LOG_LEVEL_DBG, stdout, "DBG: ", fmt, ap);
}
