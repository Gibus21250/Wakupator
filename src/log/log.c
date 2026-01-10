#include <stdio.h>
#include <stdarg.h>

#include "wakupator/log/log.h"

#include <string.h>
#include <time.h>
#include <sys/time.h>

static void print_timestamp(FILE *stream) {
    time_t now;
    char buffer[64];

    time(&now);
    struct tm *timeinfo = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    fprintf(stream, "[%s] ", buffer);
}

static const char* get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (!filename) filename = strrchr(path, '\\');
    return filename ? filename + 1 : path;
}

void log_info(const char *format, ...) {
    va_list args;
    va_start(args, format);

#ifdef DEBUG_MODE
    print_timestamp(stdout);
#endif

    fprintf(stdout, "[INFO] ");
    vfprintf(stdout, format, args);
    fflush(stdout);

    va_end(args);
}

void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);

#ifdef DEBUG_MODE
    print_timestamp(stdout);
#endif

    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fflush(stderr);

    va_end(args);
}

void log_fatal(const char *format, ...) {
    va_list args;
    va_start(args, format);

#ifdef DEBUG_MODE
    print_timestamp(stdout);
#endif

    fprintf(stderr, "[FATAL] ");
    vfprintf(stderr, format, args);
    fflush(stderr);

    va_end(args);
}

void log_debug_internal(const char *file, const char *func, int line, const char *format, ...) {
#ifdef DEBUG_MODE
        va_list args;
        va_start(args, format);

        print_timestamp(stdout);
        fprintf(stdout, "[DEBUG] [%s:%s:%d] ", get_filename(file), func, line);
        vfprintf(stdout, format, args);
        fflush(stdout);

        va_end(args);
#endif
}