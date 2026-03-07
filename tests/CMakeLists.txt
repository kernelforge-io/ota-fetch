# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

set(TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/data")
set(TEST_DATA_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/data")

file(COPY "${TEST_DATA_SOURCE_DIR}/" DESTINATION "${TEST_DATA_BINARY_DIR}")

function(add_ota_fetch_test test_name source_file)
    add_executable(${test_name} "${source_file}")
    target_link_libraries(${test_name} PRIVATE ota_fetch_lib)
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(${test_name} PRIVATE
        TEST_DATA_DIR=\"${TEST_DATA_BINARY_DIR}\"
    )
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endfunction()

add_ota_fetch_test(test_config test_config.c)
add_ota_fetch_test(test_manifest test_manifest.c)
add_ota_fetch_test(test_hash test_hash.c)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(ENROLL_CTEST_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/scripts/enroll_ctest.py")

add_test(
    NAME enroll_success_writes_identity_and_deletes_token
    COMMAND ${Python3_EXECUTABLE}
            ${ENROLL_CTEST_SCRIPT}
            --ota-fetch
            $<TARGET_FILE:ota-fetch>
            --case
            success
)

add_test(
    NAME enroll_refuses_when_identity_exists_without_force
    COMMAND ${Python3_EXECUTABLE}
            ${ENROLL_CTEST_SCRIPT}
            --ota-fetch
            $<TARGET_FILE:ota-fetch>
            --case
            refuse_existing
)

add_test(
    NAME enroll_force_overwrites_identity
    COMMAND ${Python3_EXECUTABLE}
            ${ENROLL_CTEST_SCRIPT}
            --ota-fetch
            $<TARGET_FILE:ota-fetch>
            --case
            force_overwrite
)
