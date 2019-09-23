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

include_directories("${PROJECT_SOURCE_DIR}/include")

add_compile_options(-std=c++17)
add_compile_options(-g)
add_compile_options(-pthread)

add_executable(crypto_test src/main.cpp)
add_executable(spn_test test/test_spn.cpp src/spn.cpp)
add_executable(analyse_test test/test_analyse.cpp src/spn.cpp src/analyse.cpp src/differential_cryptanalysis.cpp)
add_executable(rsa_test src/rsa.cpp test/test_rsa.cpp)
target_link_libraries(analyse_test pthread)
target_link_libraries(rsa_test gmp)
target_link_libraries(rsa_test gmpxx)