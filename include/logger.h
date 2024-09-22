//
// Created by Nathan on 22/09/2024.
//

#ifndef WAKUPATOR_LOGGER_H
#define WAKUPATOR_LOGGER_H

void init_log();
void close_log();

void log_info(const char *format, ...);
void log_error(const char *format, ...);
void log_fatal(const char *format, ...);
void log_debug(const char *format, ...);


#endif //WAKUPATOR_LOGGER_H
