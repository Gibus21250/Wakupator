cmake_minimum_required(VERSION 3.16)

set(WAKUPATOR_VERSION "" CACHE STRING "Version override")
project(Wakupator VERSION 1.2.0 LANGUAGES C)

if(NOT WAKUPATOR_VERSION)
    set(WAKUPATOR_VERSION "${PROJECT_VERSION}~dev")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

# --------------------------------------------------- Build Options ----------------------------------------------------

add_library(wakupator_build_options INTERFACE)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(wakupator_build_options INTERFACE
            -Waddress-of-packed-member

            "$<$<CONFIG:Debug>:-fsanitize=address>"
            "$<$<CONFIG:Debug>:-fno-omit-frame-pointer>"

            "$<$<CONFIG:Release>:-Os>"
            "$<$<CONFIG:Release>:-ffunction-sections>"
            "$<$<CONFIG:Release>:-fdata-sections>"
    )

    target_link_options(wakupator_build_options INTERFACE
            "$<$<CONFIG:Debug>:-fsanitize=address>"
            "$<$<CONFIG:Release>:-Wl,--gc-sections>"
    )
endif()

# --------------------------------------------------- cJSON Library ----------------------------------------------------

add_library(cJSON STATIC
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/src/cJSON.c
)

target_include_directories(cJSON PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cJSON/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cJSON/include/cJSON
)

target_link_libraries(cJSON PRIVATE
        wakupator_build_options
)

# -------------------------------------------------- Wakupator Library -------------------------------------------------

add_library(wakupator_lib
        src/core/core.c
        src/core/manager.c
        src/core/monitor.c
        src/core/client.c

        src/log/log.c

        src/net/net.c
        src/net/bpf.c
        src/net/socket.c

        src/parser/parser.c

        src/utils/utils.c
)

target_include_directories(wakupator_lib PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/third_party/cJSON/include
)

target_compile_definitions(wakupator_lib PRIVATE
        $<$<CONFIG:Debug>:DEBUG_MODE>
)

target_link_libraries(wakupator_lib PUBLIC
        wakupator_build_options
        cJSON
        Threads::Threads
)

# ------------------------------------------------ Wakupator Executable ------------------------------------------------

add_executable(wakupator
        src/main.c
)

target_link_libraries(wakupator PRIVATE
        wakupator_lib
)

# ---------------------------------------------------      Test      ---------------------------------------------------

option(WAKUPATOR_BUILD_TESTS "Build tests" OFF)
option(WAKUPATOR_UNIT_ONLY "Only socket-free tests" OFF)

if(WAKUPATOR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------     CPack      ---------------------------------------------------

include(GNUInstallDirs)

install(TARGETS wakupator RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES packaging/linux/systemd/wakupator@.service
        DESTINATION lib/systemd/system)
install(FILES packaging/linux/config/eth0.conf.example
        DESTINATION /etc/wakupator)

set(CPACK_PACKAGE_NAME "wakupator")
set(CPACK_PACKAGE_VERSION "${WAKUPATOR_VERSION}")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_PACKAGE_CONTACT "jacquinet.nathan@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Automatically starts machines based on incoming traffic, using smart local IP spoofing and Wake-on-LAN.")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON CACHE BOOL "")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/postinst;${CMAKE_SOURCE_DIR}/packaging/linux/scripts/prerm")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/prerm")
include(CPack)