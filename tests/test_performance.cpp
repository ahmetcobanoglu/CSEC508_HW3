#include "present.hh"
#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip> // For std::fixed, std::setprecision
#include <chrono>    // For timing
#include <numeric>   // For std::accumulate (if needed for more complex stats)

void test_encryption_performance(long long num_encryptions = 100000) {
    std::cout << "--- Test Case: PRESENT Encryption Performance ---" << std::endl;

    // Initialize cipher (e.g., 80-bit key, 31 rounds)
    Present cipher(Present::KeySize::KEY_80, 31);
    std::cout << "Cipher: PRESENT-80, 31 rounds" << std::endl;

    // Generate and set a random key
    std::vector<uint8_t> key = cipher.generateRandomKey();
    try {
        cipher.setKey(key.data(), key.size());
    } catch (const std::exception& e) {
        std::cerr << "Error setting key: " << e.what() << std::endl;
        return;
    }
    std::cout << "Key set with a randomly generated 80-bit key." << std::endl;

    std::cout << "Performing " << num_encryptions << " encryptions..." << std::endl;

    std::vector<uint64_t> plaintexts(num_encryptions);
    for (long long i = 0; i < num_encryptions; ++i) {
        plaintexts[i] = Present::generateRandomPlaintext();
    }

    volatile uint64_t dummy_accumulator = 0; // To prevent optimizer from removing encryption calls

    auto start_time = std::chrono::high_resolution_clock::now();

    for (long long i = 0; i < num_encryptions; ++i) {
        dummy_accumulator += cipher.encrypt(plaintexts[i]);
    }

    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> duration_ms = end_time - start_time;
    double total_seconds = duration_ms.count() / 1000.0;

    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Total time for " << num_encryptions << " encryptions: " << total_seconds << " seconds." << std::endl;

    if (total_seconds > 0) {
        double enc_per_second = num_encryptions / total_seconds;
        double time_per_enc_us = (total_seconds * 1e6) / num_encryptions;
        // Each block is 8 bytes (64 bits)
        double bytes_per_second = (num_encryptions * 8) / total_seconds;
        double mb_per_second = bytes_per_second / (1024 * 1024);

        std::cout << std::setprecision(0);
        std::cout << "Encryptions per second: " << enc_per_second << std::endl;
        std::cout << std::setprecision(3);
        std::cout << "Average time per encryption: " << time_per_enc_us << " microseconds." << std::endl;
        std::cout << "Throughput: " << mb_per_second << " MB/s." << std::endl;
    } else {
        std::cout << "Total time was too short to measure performance accurately." << std::endl;
    }
    // Use dummy_accumulator to show it's used, preventing optimization issues.
    if (dummy_accumulator == 0xBADF00D) { // Unlikely to be true, just to use it.
        std::cout << "Accumulator check." << std::endl;
    }

    std::cout << "--- Test Case End ---" << std::endl << std::endl;
}

int main(int argc, char* argv[]) {
    long long num_ops = 100000; // Default number of operations
    if (argc > 1) {
        try {
            num_ops = std::stoll(argv[1]);
            if (num_ops <= 0) {
                std::cerr << "Number of encryptions must be positive. Using default: " << 100000 << std::endl;
                num_ops = 100000;
            }
        } catch (const std::exception& e) {
            std::cerr << "Invalid argument for number of encryptions: " << argv[1] << ". Using default: " << 100000 << std::endl;
            num_ops = 100000;
        }
    }
    test_encryption_performance(num_ops);
    return 0;
}
