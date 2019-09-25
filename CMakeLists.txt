cmake_minimum_required(VERSION 2.8)

project(crypto_test)

#set(PROJECT_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
set(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/bin")

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

file(MAKE_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})

file(GLOB SOURCES
    "${PROJECT_SOURCE_DIR}/src/**/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/**/*.cc"
    "${PROJECT_SOURCE_DIR}/src/*.cc"
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
)

include_directories("${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/lib/gzip-hpp/include")

add_compile_options(-std=c++2a)
add_compile_options(-g)
add_compile_options(-pthread)

add_executable(crypto_test src/main.cpp)
add_executable(spn_test test/test_spn.cpp src/spn.cpp)
add_executable(analyse_test test/test_analyse.cpp src/spn.cpp src/analyse.cpp src/differential_cryptanalysis.cpp)
add_executable(rsa_test src/rsa.cpp src/math_utils test/test_rsa.cpp)
add_executable(pgp_test src/pgp.cpp src/ecc.cpp test/test_pgp.cpp)
add_executable(rainbow_test src/rainbow.cpp test/test_rainbow.cpp)
target_link_libraries(spn_test z)
target_link_libraries(analyse_test pthread z)
target_link_libraries(rsa_test gmp)
target_link_libraries(rsa_test gmpxx)
target_link_libraries(pgp_test ssl crypto z)
target_link_libraries(rainbow_test ssl crypto b64 pthread)