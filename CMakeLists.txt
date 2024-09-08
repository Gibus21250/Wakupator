cmake_minimum_required(VERSION 3.10)

project(Wakupator VERSION 0.0.1 LANGUAGES C)

add_library(cJSON STATIC
        ${PROJECT_SOURCE_DIR}/libs/cJSON/src/cJSON.c
        ${PROJECT_SOURCE_DIR}/libs/cJSON/src/cJSON_Utils.c
)

target_include_directories(cJSON PUBLIC
        ${PROJECT_SOURCE_DIR}/libs/cJSON/include/cJSON
)
