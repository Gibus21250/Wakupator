//
// Created by Nathan on 22/09/2024.
//

#ifndef WAKUPATOR_LOGGER_H
#define WAKUPATOR_LOGGER_H

void log_info(const char *format, ...);
void log_error(const char *format, ...);
void log_fatal(const char *format, ...);

void log_debug_internal(const char *file, const char *func, int line, const char *format, ...);

#define log_debug(format, ...) \
    log_debug_internal(__FILE__, __func__, __LINE__, format, ##__VA_ARGS__)

#endif //WAKUPATOR_LOGGER_H
