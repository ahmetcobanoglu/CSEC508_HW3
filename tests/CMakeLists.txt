cmake_minimum_required(VERSION 3.10)

project(PresentTests CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)


# Add executable for roundKey test
add_executable(test_roundKey test_roundKey.cpp)
target_link_libraries(test_roundKey PRIVATE cipher_present_lib)
target_include_directories(test_roundKey PRIVATE ${CMAKE_SOURCE_DIR}/components/cipher_present/include)

# Add executable for performance test
add_executable(test_performance test_performance.cpp)
target_link_libraries(test_performance PRIVATE cipher_present_lib)
target_include_directories(test_performance PRIVATE ${CMAKE_SOURCE_DIR}/components/cipher_present/include)

add_test(NAME PerformanceTest COMMAND test_performance)
add_test(NAME RoundKeyTest COMMAND test_roundKey)
