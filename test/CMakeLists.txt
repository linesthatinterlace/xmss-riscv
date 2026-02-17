cmake_minimum_required(VERSION 3.16)

# Helper: add a test that links against xmss with standard include paths.
# Extra include dirs can be appended after the test name.
function(add_xmss_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} xmss)
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${ARGN}
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# Fast tests (no tree operations, < 1 s each)
add_xmss_test(test_params)
add_xmss_test(test_address)
add_xmss_test(test_hash          ${CMAKE_SOURCE_DIR}/src/hash)
add_xmss_test(test_wots)
add_xmss_test(test_xmssmt_params)
add_xmss_test(test_utils_internal ${CMAKE_SOURCE_DIR}/src/hash)

set_tests_properties(
    test_params test_address test_hash test_wots test_xmssmt_params test_utils_internal
    PROPERTIES LABELS "fast"
)

# Slow tests (keygen/sign/verify roundtrips, KAT, BDS)
add_xmss_test(test_xmss)
add_xmss_test(test_kat)
add_xmss_test(test_bds)
add_xmss_test(test_bds_serial)
add_xmss_test(test_xmssmt)

set_tests_properties(
    test_xmss test_kat test_bds test_bds_serial test_xmssmt
    PROPERTIES LABELS "slow"
)
