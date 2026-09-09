cmake_minimum_required(VERSION 3.20)
project(certibridge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/W4 /EHsc /utf-8 /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WINDOWS TLSH_LIB BUCKETS_128)
endif()

# vendored include dirs
set(VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/vendor")

add_executable(certibridge_core
    src/core/main.cpp
    src/core/config.cpp
    src/core/diary.cpp
    src/core/server.cpp
    src/core/sigscanner.cpp
    src/vendor/tlsh/src/tlsh.cpp
    src/vendor/tlsh/src/tlsh_impl.cpp
    src/vendor/tlsh/src/tlsh_util.cpp
)

target_include_directories(certibridge_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
    "${VENDOR_DIR}/httplib"
    "${VENDOR_DIR}/json/include"
    "${VENDOR_DIR}/tomlplusplus/include"
    "${VENDOR_DIR}/spdlog/include"
    "${VENDOR_DIR}/simdjson/include"
    "${VENDOR_DIR}/miniz"
    "${VENDOR_DIR}/zydis/include"
    "${VENDOR_DIR}/zydis/dependencies/zycore/include"
    "${VENDOR_DIR}/asmjit/src"
    "${VENDOR_DIR}/tlsh/include"
)

if (WIN32)
    target_link_libraries(certibridge_core PRIVATE ws2_32 crypt32)
endif()

add_library(certibridge_tlsh SHARED
    src/core/tlsh_export.cpp
    src/vendor/tlsh/src/tlsh.cpp
    src/vendor/tlsh/src/tlsh_impl.cpp
    src/vendor/tlsh/src/tlsh_util.cpp
)

target_include_directories(certibridge_tlsh PRIVATE
    "${VENDOR_DIR}/tlsh/include"
)
