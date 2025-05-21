cmake_minimum_required(VERSION 3.10)

project(cipher_present CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Create the library
add_library(cipher_present_lib src/present.cpp)

# Add compiler flags for CPU specific instructions
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(cipher_present_lib PRIVATE -mbmi2)
endif()

# Specify include directories for the library and for targets linking against it
target_include_directories(cipher_present_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        # Add any private include dirs for the library itself if needed
)

# Optional: If you want to install this library
# install(TARGETS cipher_present_lib DESTINATION lib)
# install(FILES include/present.hh DESTINATION include)
