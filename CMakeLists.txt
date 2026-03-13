cmake_minimum_required(VERSION 3.21)

project(embeddedipsec VERSION 0.1.0 LANGUAGES C)

option(EMBEDDEDIPSEC_BUILD_TESTS "Build the in-repo structural test harness" ON)
option(EMBEDDEDIPSEC_ENABLE_AH "Enable Authentication Header support" ON)
option(EMBEDDEDIPSEC_ENABLE_ESP "Enable Encapsulating Security Payload support" ON)
option(EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE "Enable IPsec tunnel mode" ON)
option(EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE "Enable IPsec transport mode" ON)

if(NOT EMBEDDEDIPSEC_ENABLE_AH AND NOT EMBEDDEDIPSEC_ENABLE_ESP)
    message(FATAL_ERROR "At least one of EMBEDDEDIPSEC_ENABLE_AH or EMBEDDEDIPSEC_ENABLE_ESP must be ON")
endif()

if(NOT EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE AND NOT EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE)
    message(FATAL_ERROR "At least one of EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE or EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE must be ON")
endif()

if(EMBEDDEDIPSEC_ENABLE_AH)
    set(EMBEDDEDIPSEC_ENABLE_AH_DEFINE 1)
else()
    set(EMBEDDEDIPSEC_ENABLE_AH_DEFINE 0)
endif()

if(EMBEDDEDIPSEC_ENABLE_ESP)
    set(EMBEDDEDIPSEC_ENABLE_ESP_DEFINE 1)
else()
    set(EMBEDDEDIPSEC_ENABLE_ESP_DEFINE 0)
endif()

if(EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE)
    set(EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE_DEFINE 1)
else()
    set(EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE_DEFINE 0)
endif()

if(EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE)
    set(EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE_DEFINE 1)
else()
    set(EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE_DEFINE 0)
endif()

set(EMBEDDEDIPSEC_CORE_SOURCES
    tiny-aes/aes.c
    src/core/aes_cbc.c
    src/core/ah.c
    src/core/des.c
    src/core/esp.c
    src/core/ipsec.c
    src/core/md5.c
    src/core/sa.c
    src/core/sha1.c
    src/core/util.c
)

add_library(embeddedipsec STATIC ${EMBEDDEDIPSEC_CORE_SOURCES})

target_include_directories(embeddedipsec
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tiny-aes
)

target_compile_definitions(embeddedipsec
    PUBLIC
        __NO_TCPIP_STACK__
        _CRT_SECURE_NO_WARNINGS
        IPSEC_ENABLE_AH=${EMBEDDEDIPSEC_ENABLE_AH_DEFINE}
        IPSEC_ENABLE_ESP=${EMBEDDEDIPSEC_ENABLE_ESP_DEFINE}
        IPSEC_ENABLE_TUNNEL_MODE=${EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE_DEFINE}
        IPSEC_ENABLE_TRANSPORT_MODE=${EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE_DEFINE}
        CBC=1
        ECB=0
        CTR=0
)

target_compile_features(embeddedipsec PUBLIC c_std_99)

if(MSVC)
    target_compile_options(embeddedipsec PRIVATE /W3)
else()
    target_compile_options(embeddedipsec PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(EMBEDDEDIPSEC_BUILD_TESTS)
    enable_testing()

    add_executable(embeddedipsec_structural_tests
        src/testing/structural/aes_test.c
        src/testing/structural/ah_test.c
        src/testing/structural/des_test.c
        src/testing/structural/esp_test.c
        src/testing/structural/ipv6_test.c
        src/testing/structural/main.c
        src/testing/structural/md5_test.c
        src/testing/structural/sa_test.c
        src/testing/structural/sha1_test.c
        src/testing/structural/transport_test.c
        src/testing/structural/util_test.c
    )

    target_link_libraries(embeddedipsec_structural_tests PRIVATE embeddedipsec)

    add_executable(embeddedipsec_packet_dump_tool
        src/testing/packet_dump_tool.c
    )

    target_link_libraries(embeddedipsec_packet_dump_tool PRIVATE embeddedipsec)

    add_test(NAME structural_tests COMMAND embeddedipsec_structural_tests)
    add_test(NAME packet_dump_roundtrip COMMAND embeddedipsec_packet_dump_tool roundtrip ${CMAKE_CURRENT_BINARY_DIR}/embeddedipsec-sample.pcap)
endif()