#include "present.hh" // Assumes build system is configured for this include path
#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <stdexcept> // For std::runtime_error (though not strictly needed for this version)

// This function outlines a test case for the PRESENT cipher's round key generation
// with an 80-bit all-zero key.
void test_all_zero_key_80bit() {
    std::cout << "--- Test Case: PRESENT 80-bit All-Zero Key Round Keys ---" << std::endl;

    // Use default 31 rounds for an 80-bit key
    Present cipher(Present::KeySize::KEY_80, 31);

    uint8_t key_bytes[10]; // 80 bits = 10 bytes
    for (int i = 0; i < 10; ++i) {
        key_bytes[i] = 0x00;
    }
    std::cout << "Input Key (80-bit): ";
    for (int i = 0; i < 10; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_bytes[i]);
    }
    std::cout << std::dec << std::endl; // Switch back to decimal for normal output

    try {
        cipher.setKey(key_bytes, sizeof(key_bytes));
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error setting key: " << e.what() << std::endl;
        return;
    }
}

void test_encryption_all_zero_pt_key_80bit() {
    std::cout << "--- Test Case: PRESENT 80-bit Encryption (All-Zero PT & Key) ---" << std::endl;

    Present cipher(Present::KeySize::KEY_80, 31);

    uint8_t key_bytes[10]; // 80 bits = 10 bytes
    for (int i = 0; i < 10; ++i) {
        key_bytes[i] = 0x00;
    }
    uint64_t plaintext = 0x0000000000000000ULL;
    uint64_t expected_ciphertext = 0x5579c1387b228445ULL;

    std::cout << "Input Key (80-bit): ";
    for (int i = 0; i < 10; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_bytes[i]);
    }
    std::cout << std::dec << std::endl;
    std::cout << "Input Plaintext:  0x" << std::hex << std::setw(16) << std::setfill('0') << plaintext << std::dec << std::endl;

    try {
        cipher.setKey(key_bytes, sizeof(key_bytes));
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error setting key: " << e.what() << std::endl;
        return;
    }

    uint64_t actual_ciphertext = 0;
    try {
        actual_ciphertext = cipher.encrypt(plaintext);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error during encryption: " << e.what() << std::endl;
        return;
    }

    std::cout << "Expected Ciphertext: 0x" << std::hex << std::setw(16) << std::setfill('0') << expected_ciphertext << std::dec << std::endl;
    std::cout << "Actual Ciphertext:   0x" << std::hex << std::setw(16) << std::setfill('0') << actual_ciphertext << std::dec << std::endl;

    if (actual_ciphertext == expected_ciphertext) {
        std::cout << "Test PASSED!" << std::endl;
    } else {
        std::cout << "Test FAILED!" << std::endl;
    }
    std::cout << "--- Test Case End ---" << std::endl << std::endl;
}

int main() {
    test_all_zero_key_80bit();
    test_encryption_all_zero_pt_key_80bit();

    // You can add more test cases here, for example, for a 128-bit key
    // or other specific key values if you have known round keys for them.

    std::cout << "Round key test structure executed." << std::endl;
    std::cout << "Manual verification or further integration with a testing framework is needed for assertion." << std::endl;

    return 0;
}
