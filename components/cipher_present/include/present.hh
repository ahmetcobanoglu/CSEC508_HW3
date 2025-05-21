/*
 * File: present.h
 * Created on Sat May 10 2025 4:26:25 PM
 * Author: Ahmet Çobanoğlu <cobanoglu.ahmet@metu.edu.tr>
 *
 * Description:    Header file for PRESENT block cipher encryption implementation
 * 
 * This header provides the necessary functions and structures to implement
 * PRESENT block cipher in encryption direction. PRESENT is a lightweight
 * block cipher designed for constrained environments.
 * 
 * Key features:
 * - 64-bit block size
 * - Configurable key size (80-bit or 128-bit)
 * - Simple substitution-permutation network (SPN) structure
 * - 31 rounds (full version)
 *
 * Copyright (c) 2025 Ahmet Çobanoğlu
 * All rights reserved.
 *
 * This file is proprietary and confidential. Unauthorized copying, distribution,
 * modification, or use of this file, via any medium, is strictly prohibited
 * without express written permission from the copyright holder.
 */

#ifndef BF642B3C_376F_42C7_B108_89E08CAB4283
#define BF642B3C_376F_42C7_B108_89E08CAB4283

#include <cstdint>
#include <vector>
#include <random>
#include <stdexcept>

/**
 * @brief Class implementing the PRESENT block cipher encryption
 */
class Present {
public:
    /**
     * @brief Enum defining key size options for PRESENT
     */
    enum class KeySize {
        KEY_80 = 80,   ///< 80-bit key size
        KEY_128 = 128  ///< 128-bit key size
    };

    /**
     * @brief Constructor for Present cipher
     * 
     * @param keySize Size of the key (KeySize::KEY_80 or KeySize::KEY_128)
     * @param rounds Number of rounds to perform (31 for full PRESENT, 4 for differential analysis)
     */
    Present(KeySize keySize = KeySize::KEY_80, int rounds = 31);

    /**
     * @brief Set the encryption key
     * 
     * @param key Pointer to the key bytes
     * @param keyLength Length of the key in bytes (must match the selected KeySize)
     * @throws std::invalid_argument if key length doesn't match the KeySize
     */
    void setKey(const uint8_t* key, size_t keyLength);

    /**
     * @brief Encrypt a plaintext block using PRESENT
     * 
     * @param plaintext 64-bit plaintext block to encrypt
     * @return uint64_t Resulting 64-bit ciphertext
     * @throws std::runtime_error if key has not been set
     */
    uint64_t encrypt(uint64_t plaintext) const;

    /**
     * @brief Generate a random key for the current key size
     * 
     * @return std::vector<uint8_t> Random key of appropriate length
     */
    std::vector<uint8_t> generateRandomKey();

    /**
     * @brief Generate a random plaintext block
     * 
     * @return uint64_t Random 64-bit plaintext
     */
    static uint64_t generateRandomPlaintext();

private:
    /**
     * S-box lookup table for PRESENT substitution layer (4-bit to 4-bit)
     */
    static constexpr uint8_t SBOX[16] = {
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
    };

    /**
     * @brief Apply the substitution layer (S-box) to the state
     * 
     * @param state Current 64-bit state
     * @return uint64_t State after substitution
     */
    uint64_t applySubstitutionLayer(uint64_t state) const;

    /**
     * @brief Apply the permutation layer to the state
     * 
     * @param state Current 64-bit state
     * @return uint64_t State after permutation
     */
    uint64_t applyPermutationLayer(uint64_t state) const;

    /**
     * @brief Add a round key to the current state
     * 
     * @param state Current 64-bit state
     * @param roundKey 64-bit round key
     * @return uint64_t State after key addition
     */
    uint64_t addRoundKey(uint64_t state, uint64_t roundKey) const;

    /**
     * @brief Generate round keys from the master key
     * 
     * @param key Pointer to the key bytes
     * @throws std::invalid_argument if key length doesn't match the KeySize
     */
    void generateRoundKeys(const uint8_t* key);

    KeySize keySize_;                 ///< Selected key size
    int rounds_;                      ///< Number of rounds
    std::vector<uint64_t> roundKeys_; ///< Precomputed round keys
    bool keySet_;                     ///< Flag indicating if key has been set
    static std::random_device rd_;    ///< Random device for key/plaintext generation
    static std::mt19937_64 gen_;      ///< Mersenne Twister RNG
};

#endif /* BF642B3C_376F_42C7_B108_89E08CAB4283 */
