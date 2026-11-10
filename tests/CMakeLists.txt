add_library(wk_testlib STATIC
        common/test_env.c
        common/test_pkt.c
        common/test_expect.c
)

target_include_directories(wk_testlib PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
)

target_link_libraries(wk_testlib PUBLIC
        wakupator_lib
)

function(wk_enable_test_assertions target)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -UNDEBUG)
    endif()
endfunction()

wk_enable_test_assertions(wk_testlib)

function(wk_add_test name label)
    add_executable(${name}
            "${CMAKE_CURRENT_SOURCE_DIR}/${label}/${name}.c"
    )

    target_link_libraries(${name} PRIVATE wk_testlib)

    wk_enable_test_assertions(${name})

    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
            LABELS "${label}"
    )
endfunction()

# ------------ Unit Tests ------------

wk_add_test(test_icmpv6_checksum unit)
wk_add_test(test_packet_layout unit)
wk_add_test(test_arp_probe unit)
wk_add_test(test_arp_reply unit)
wk_add_test(test_na unit)
wk_add_test(test_ns unit)

# ------------ Integration Tests ------------

if(NOT WAKUPATOR_UNIT_ONLY)
    wk_add_test(test_integ_arp_socket integ)
    wk_add_test(test_integ_ns_socket integ)
    wk_add_test(test_integ_arp_flow integ)
    wk_add_test(test_integ_nd_flow integ)

    set_tests_properties(
            test_integ_arp_socket
            test_integ_ns_socket
            test_integ_arp_flow
            test_integ_nd_flow
            PROPERTIES
            TIMEOUT 15
            SKIP_RETURN_CODE 77
    )
endif()
