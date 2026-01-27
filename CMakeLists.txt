cmake_minimum_required(VERSION 3.10)

project(Wakupator VERSION 1.2 LANGUAGES C)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer -g")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

add_library(cJSON STATIC
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/src/cJSON.c
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/src/cJSON_Utils.c
)

target_include_directories(cJSON PUBLIC
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/include/cJSON
)

find_package(Threads REQUIRED)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG_MODE)
endif()

add_executable(wakupator src/main.c
        src/utils/utils.c
        src/core/core.c
        src/parser/parser.c
        src/core/monitor.c
        src/utils/bpf.c
        src/core/client.c
        src/log/log.c
        include/wakupator/utils/net.h
        src/utils/net.c
        include/wakupator/core/manager.h
        src/core/manager.c
)

target_include_directories(wakupator PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/include
)

add_custom_command(
        TARGET wakupator
        POST_BUILD
        COMMAND sudo setcap cap_net_raw,cap_net_admin+ep $<TARGET_FILE:wakupator>
        COMMENT "Setting ap_net_raw and cap_net_admin capabilities to Wakupator"
)

target_link_libraries(wakupator PRIVATE cJSON pthread)

install(TARGETS wakupator DESTINATION bin)