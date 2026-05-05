cmake_minimum_required(VERSION 3.20)
project(javelin-linux VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(JVL_ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(JVL_ARCH "aarch64")
else()
    set(JVL_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

option(JVL_BUILD_TESTS "Build tests" ON)
option(JVL_BUILD_EBPF  "Build eBPF programs" ON)
option(JVL_ENABLE_ASAN "Enable AddressSanitizer" OFF)

add_compile_options(
    -Wall -Wextra -Wpedantic
    -fPIC -fvisibility=hidden
    -D_GNU_SOURCE
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g3)
    if(JVL_ENABLE_ASAN)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
else()
    add_compile_options(-O2 -DNDEBUG)
endif()

find_package(Threads REQUIRED)
find_package(PkgConfig)

if(PkgConfig_FOUND)
    pkg_check_modules(LIBBPF libbpf>=1.0)
endif()

if(NOT LIBBPF_FOUND)
    message(WARNING "libbpf not found; loader build may fail")
endif()

# libjavelin.so
add_library(javelin SHARED
    src/javelin/javelin.c
    src/platform/linux/attestation.c
    src/platform/linux/seccomp_shim.c
)

target_link_libraries(javelin PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

set_target_properties(javelin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME "javelin"
    C_VISIBILITY_PRESET "default"
)

# loader binary
if(LIBBPF_FOUND)
    add_executable(javelin-loader src/ebpf/loader.c)
    target_include_directories(javelin-loader PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(javelin-loader PRIVATE ${LIBBPF_LIBRARIES})
    target_compile_options(javelin-loader PRIVATE ${LIBBPF_CFLAGS_OTHER})
else()
    message(STATUS "Skipping javelin-loader (libbpf unavailable)")
endif()

# status tool (connects to loader socket and prints events)
add_executable(javelin-status src/javelin-status.c)

# tests
if(JVL_BUILD_TESTS)
    enable_testing()

    add_executable(test_javelin
        tests/unit/test_javelin.c
        src/javelin/javelin.c
        src/platform/linux/attestation.c
    )
    target_link_libraries(test_javelin PRIVATE Threads::Threads)
    add_test(NAME javelin COMMAND test_javelin)

    add_executable(test_seccomp
        tests/unit/test_seccomp.c
        src/platform/linux/seccomp_shim.c
    )
    add_test(NAME seccomp COMMAND test_seccomp)

    add_executable(memscan_benchmark
        tests/perf/memscan_benchmark.c
    )
    target_link_libraries(memscan_benchmark PRIVATE Threads::Threads)
    add_test(NAME memscan_benchmark COMMAND memscan_benchmark)

    add_executable(test_cross_process
        tests/integration/test_cross_process.c
        src/javelin/javelin.c
        src/platform/linux/attestation.c
    )
    target_link_libraries(test_cross_process PRIVATE Threads::Threads)
    add_test(NAME cross_process COMMAND test_cross_process)
    set_tests_properties(cross_process PROPERTIES SKIP_RETURN_CODE 77)
endif()

# install
include(GNUInstallDirs)

install(TARGETS javelin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(TARGET javelin-loader)
    install(TARGETS javelin-loader
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(TARGETS javelin-status
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES src/javelin/javelin.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY docs/
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    FILES_MATCHING PATTERN "*.md"
)

message(STATUS "")
message(STATUS "javelin linux ${PROJECT_VERSION}")
message(STATUS "arch: ${JVL_ARCH}")
message(STATUS "build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "tests: ${JVL_BUILD_TESTS}")
message(STATUS "ebpf: ${JVL_BUILD_EBPF}")
message(STATUS "asan: ${JVL_ENABLE_ASAN}")
message(STATUS "prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
