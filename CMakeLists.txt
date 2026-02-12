cmake_minimum_required(VERSION 3.10)
project(ota-fetch LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(CTest)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(OPENSSL REQUIRED openssl)

find_path(CJSON_INCLUDE_DIR cjson/cJSON.h)
find_library(CJSON_LIBRARY cjson)

if(NOT CJSON_INCLUDE_DIR OR NOT CJSON_LIBRARY)
    message(FATAL_ERROR "Could not find cJSON")
endif()

function(ota_fetch_apply_defaults target_name)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target_name} PRIVATE
            -Wall
            -Wextra
            -fstack-protector-strong
        )
    endif()
endfunction()

add_library(ota_fetch
    src/ota_fetch.c
    src/config.c
    src/ini.c
    src/manifest.c
    src/verify_libcrypto.c
    src/hash.c
    src/logging.c
)

target_include_directories(ota_fetch
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    PRIVATE
        ${CURL_INCLUDE_DIRS}
        ${CJSON_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIRS}
)

target_link_libraries(ota_fetch
    PRIVATE
        ${CURL_LIBRARIES}
        ${CJSON_LIBRARY}
        ${OPENSSL_LIBRARIES}
)

ota_fetch_apply_defaults(ota_fetch)

add_executable(ota-fetch src/main.c)
target_link_libraries(ota-fetch PRIVATE ota_fetch)
ota_fetch_apply_defaults(ota-fetch)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
