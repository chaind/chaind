#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "logging.h"

static void do_log(int priority, char const* fmt, va_list ap)
{
    va_list copy;
    int i = 256;

    do {
        char* buf = (char*)alloca(i);

        va_copy(copy, ap);
        int n = vsnprintf(buf, i, fmt, ap);
        va_end(copy);

        if(n > -1 && n < i) {
            syslog(priority, "%s", buf);
#ifdef LOG_STDOUT
            printf("%s\n", buf);
#endif
            break;
        }

        i <<= 1;
    } while(1);
}

void log_debug(char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    do_log(LOG_DEBUG, fmt, ap);
    va_end(ap);
}

void log_info(char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    do_log(LOG_INFO, fmt, ap);
    va_end(ap);
}

void log_notice(char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    do_log(LOG_NOTICE, fmt, ap);
    va_end(ap);
}

void log_warning(char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    do_log(LOG_WARNING, fmt, ap);
    va_end(ap);
}

