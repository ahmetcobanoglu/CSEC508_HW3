# PRESENT Block Cipher Implementation and Differential Cryptanalysis

## Description

This project provides an implementation of the PRESENT block cipher and tools for performing differential cryptanalysis on a reduced-round version. PRESENT is a lightweight block cipher designed for constrained environments, featuring a 64-bit block size and configurable key sizes (80-bit or 128-bit).

The core cipher implementation can be found in `components/cipher_present`. The differential cryptanalysis experiment is located in `src/differential_experiment.cpp`.

## Building the Project

The project uses CMake for building.

1.  **Navigate to the build directory (or create it if it doesn't exist):**
    ```bash
    mkdir -p build
    cd build
    ```

2.  **Run CMake to configure the project:**
    ```bash
    cmake ..
    ```

3.  **Build the project:**
    ```bash
    make
    ```
    This will compile the PRESENT cipher library and the executables for experiments and tests.

## Running the Differential Cryptanalysis Experiment

The main experiment for differential cryptanalysis can be run as follows:

1.  **Ensure the project is built** (see "Building the Project").
2.  **Navigate to the build directory:**
    ```bash
    cd ./build
    ```
3.  **Run the `differential_experiment` executable:**
    ```bash
    ./differential_experiment
    ```
    The program will output the progress and results of the experiment, which involves testing multiple keys and plaintexts to find differential characteristics. The results from the last run are:
    *   Total successes (sum of all C_i): 13884
    *   Total trials (NUM_KEYS * N): 3,355,443,200
    *   Experimental Probability (P_exp): 2^(-17.88)

    The results of the experiment are also typically logged in `differential_cryptanalysis_results.md`.

## Running Tests

The project includes tests for the PRESENT cipher implementation.

1.  **Ensure the project is built.**
2.  **Navigate to the build directory:**
    ```bash
    cd ./build
    ```
3.  **Run the test executables directly (e.g., `test_roundKey`, `test_performance`):**
    ```bash
    ./tests/test_roundKey
    ./tests/test_performance
    ```
    Alternatively, if CTest is configured, you might be able to run:
    ```bash
    ctest
    ```

## Project Structure

-   `CMakeLists.txt`: Main CMake build script.
-   `README.md`: This file.
-   `differential_cryptanalysis_results.md`: Log of results from the differential cryptanalysis experiment.
-   `build/`: Directory for all build-related files and output executables.
-   `cmake/`: Contains custom CMake modules (e.g., `FindExternalLibrary.cmake`).
-   `components/`: Contains reusable components.
    -   `cipher_present/`: Implementation of the PRESENT block cipher.
        -   `include/present.hh`: Header file for the PRESENT cipher.
        -   `src/present.cpp`: Source file for the PRESENT cipher.
-   `src/`: Contains source code for executables.
    -   `differential_experiment.cpp`: Source code for the differential cryptanalysis experiment.
-   `tests/`: Contains test code.
    -   `test_performance.cpp`: Performance tests for the cipher.
    -   `test_roundKey.cpp`: Tests for round key generation.

## Dependencies

- A C++ compiler supporting C++20 or later.
- CMake (version 3.10 or later recommended).

## Author

Ahmet Çobanoğlu <cobanoglu.ahmet@metu.edu.tr>

## License

Copyright (c) 2025 Ahmet Çobanoğlu
All rights reserved.

This file is proprietary and confidential. Unauthorized copying, distribution, modification, or use of this file, via any medium, is strictly prohibited without express written permission from the copyright holder.
