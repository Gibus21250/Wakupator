//
// Created by Nathan on 22/09/2024.
//
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

void init_log()
{
    openlog("Wakupator", LOG_PID | LOG_CONS, LOG_USER);
}

void close_log()
{
    closelog();
}

void log_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);

#ifdef DEBUG_MODE
    printf("[INFO] ");
    vprintf(format, args);
#else
    vsyslog(LOG_INFO, format, args);
#endif
    va_end(args);
}

void log_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);

#ifdef DEBUG_MODE
    printf("[ERROR] ");
    vprintf(format, args);
#else
    vsyslog(LOG_ERR, format, args);
#endif
    va_end(args);
}

void log_fatal(const char *format, ...)
{
    {
        va_list args;
        va_start(args, format);

#ifdef DEBUG_MODE
        printf("[FATAL] ");
    vprintf(format, args);
#else
        vsyslog(LOG_EMERG, format, args);
#endif
        va_end(args);
    }
}

void log_debug(const char *format, ...)
{
#ifdef DEBUG_MODE
    va_list args;
    va_start(args, format);

    printf("[DEBUG] ");
    vprintf(format, args);
    va_end(args);
#endif
}
