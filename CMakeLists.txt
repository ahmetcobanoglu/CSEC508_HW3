# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)

project(PresentCipherProject CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add subdirectories for components
add_subdirectory(components/cipher_present)

# Add the main differential experiment executable
add_executable(differential_experiment src/differential_experiment.cpp)
target_link_libraries(differential_experiment PRIVATE cipher_present_lib)

# Add tests
enable_testing()
add_subdirectory(tests)