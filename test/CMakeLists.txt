cmake_minimum_required(VERSION 3.16)

# test_params
add_executable(test_params test_params.c)
target_link_libraries(test_params xmss)
target_include_directories(test_params PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_params COMMAND test_params)

# test_address
add_executable(test_address test_address.c)
target_link_libraries(test_address xmss)
target_include_directories(test_address PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_address COMMAND test_address)

# test_hash
add_executable(test_hash test_hash.c)
target_link_libraries(test_hash xmss)
target_include_directories(test_hash PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/hash
)
add_test(NAME test_hash COMMAND test_hash)

# test_wots
add_executable(test_wots test_wots.c)
target_link_libraries(test_wots xmss)
target_include_directories(test_wots PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_wots COMMAND test_wots)

# test_xmss (integration: keygen/sign/verify)
add_executable(test_xmss test_xmss.c)
target_link_libraries(test_xmss xmss)
target_include_directories(test_xmss PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_xmss COMMAND test_xmss)

# test_kat (KAT cross-validated against xmss-reference)
add_executable(test_kat test_kat.c)
target_link_libraries(test_kat xmss)
target_include_directories(test_kat PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_kat COMMAND test_kat)
