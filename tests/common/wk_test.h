#pragma once
#include <stdio.h>
#include <stdlib.h>

#define WK_SKIP_CODE 77

#define WK_CHECK(cond) do { if (!(cond)) { fprintf(stderr, "%s:%d: CHECK FAILED: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

#define WK_RUN(fn) do { fprintf(stderr, "[ RUN  ] %s\n", #fn); fn(); fprintf(stderr, "[  OK  ] %s\n", #fn); } while (0)

#define WK_LOG(...) do { fprintf(stderr, "   | "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

#define WK_FAIL(...) do {  fprintf(stderr, "%s:%d: FAILED: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); exit(1); } while (0)