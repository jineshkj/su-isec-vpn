#ifndef ISEC_LOG_H
#define ISEC_LOG_H

#define LOG_LEVEL_ERR   0
#define LOG_LEVEL_WARN  1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DBG   3

void
set_log_level(int level);

int
lerr(const char *fmt, ...);

int
lwarn(const char *fmt, ...);

int
linfo(const char *fmt, ...);

int
ldbg(const char *fmt, ...);

#endif // ISEC_LOG_H
