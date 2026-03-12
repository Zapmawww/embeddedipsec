cmake_minimum_required(VERSION 3.21)

project(embeddedipsec VERSION 0.1.0 LANGUAGES C)

option(EMBEDDEDIPSEC_BUILD_TESTS "Build the in-repo structural test harness" ON)

set(EMBEDDEDIPSEC_CORE_SOURCES
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
)

target_compile_definitions(embeddedipsec
    PUBLIC
        __NO_TCPIP_STACK__
    _CRT_SECURE_NO_WARNINGS
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
        src/testing/structural/ah_test.c
        src/testing/structural/des_test.c
        src/testing/structural/esp_test.c
        src/testing/structural/main.c
        src/testing/structural/md5_test.c
        src/testing/structural/sa_test.c
        src/testing/structural/sha1_test.c
        src/testing/structural/util_test.c
    )

    target_link_libraries(embeddedipsec_structural_tests PRIVATE embeddedipsec)

    add_test(NAME structural_tests COMMAND embeddedipsec_structural_tests)
endif()