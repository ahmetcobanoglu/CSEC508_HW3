#include <iostream>
#include <iomanip>
#include <bitset>
#include <immintrin.h> // For _pext_u64
#include "present.hh"

Present::Present(Present::KeySize keySize, int rounds)
    : keySize_(keySize), rounds_(rounds), keySet_(false)
{
    roundKeys_.resize(rounds_ + 1); // Pre-allocate space for round keys
    // All necessary member initializations are handled by the member initializer list
    // (keySize_, rounds_, keySet_).
    // The roundKeys_ vector is default-constructed to an empty state, which is appropriate
    // as round keys are generated later when setKey() is called.
    // Static members (rd_, gen_) are initialized elsewhere.
}

void Present::setKey(const uint8_t* key, size_t keyLength)
{
    size_t expectedKeyLengthBytes = static_cast<size_t>(keySize_) / 8;
    if (keyLength != expectedKeyLengthBytes) {
        throw std::invalid_argument("Key length does not match selected KeySize.");
    }

    generateRoundKeys(key);
    keySet_ = true;
}

uint64_t Present::encrypt(uint64_t plaintext) const
{
    if (!keySet_) {
        throw std::runtime_error("Key has not been set. Call setKey() before encryption.");
    }

    uint64_t state = plaintext;

    // Apply rounds_ - 1 full rounds (or rounds_ if thinking 1-indexed)
    // With 0-indexed roundKeys_, K_1 is roundKeys_[0], K_nr is roundKeys_[rounds_-1]
    // The loop runs for K_1 up to K_rounds_
    for (int i = 0; i < rounds_; ++i) {
        state = addRoundKey(state, roundKeys_[i]);
        state = applySubstitutionLayer(state);
        state = applyPermutationLayer(state);

#ifdef DEBUG
        std::cout << "After round " << i + 1 << ": " << std::hex << std::setw(16) << std::setfill('0') << state << std::dec << std::endl;
#endif
    }

    // Final addRoundKey with K_{rounds_+1} (which is roundKeys_[rounds_])
    state = addRoundKey(state, roundKeys_[rounds_]);

#ifdef DEBUG
    std::cout << "Final ciphertext: " << std::hex << std::setw(16) << std::setfill('0') << state << std::dec << std::endl;
#endif

    return state;
}

std::vector<uint8_t> Present::generateRandomKey()
{
    size_t keyLengthBytes = static_cast<size_t>(keySize_) / 8;
    std::vector<uint8_t> key(keyLengthBytes);
    std::uniform_int_distribution<uint8_t> distrib(0, 255);

    for (size_t i = 0; i < keyLengthBytes; ++i) {
        key[i] = distrib(gen_);
    }
    return key;
}

uint64_t Present::generateRandomPlaintext()
{
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    return distrib(gen_);
}

uint64_t Present::applySubstitutionLayer(uint64_t state) const
{
    uint64_t substituted_state = 0;
    for (int i = 0; i < 16; ++i) { // 64 bits / 4 bits per nibble = 16 nibbles
        // Extract the i-th nibble (from right to left, i=0 is LSB nibble)
        uint8_t nibble = (state >> (i * 4)) & 0x0F;
        // Apply S-box
        uint8_t substituted_nibble = SBOX[nibble];
        // Place the substituted nibble back into the result
        substituted_state |= (static_cast<uint64_t>(substituted_nibble) << (i * 4));
    }
    return substituted_state;
}

uint64_t Present::applyPermutationLayer(uint64_t state) const
{
    uint64_t new_state = _pext_u64(state, 0x1111111111111111)
    | (_pext_u64(state, 0x2222222222222222) << 16)
    | (_pext_u64(state, 0x4444444444444444) << 32)
    | (_pext_u64(state, 0x8888888888888888) << 48);

    return new_state;
}

uint64_t Present::addRoundKey(uint64_t state, uint64_t roundKey) const
{
    return state ^ roundKey;
}

void Present::generateRoundKeys(const uint8_t* masterKey)
{
    // Get key size parameters
    int keyLenBits = static_cast<int>(keySize_);
    int keyLenBytes = keyLenBits / 8;
    
    // Create a bitset to hold the key register
    std::bitset<128> key_register; // 128 bits is enough for both 80-bit and 128-bit keys
    
    // Load the master key into the bitset (MSB first)
    for (int i = 0; i < keyLenBytes; ++i) {
        for (int j = 0; j < 8; ++j) {
            if (masterKey[i] & (1 << (7 - j))) {
                key_register.set(i * 8 + j);
            }
        }
    }
    
    // Extract round key function (gets the leftmost 64 bits)
    auto extract_round_key = [&key_register, &keyLenBits]() -> uint64_t {
        uint64_t rk = 0;
        for (int i = 0; i < 64; ++i) {
            if (key_register[keyLenBits - 1 - i]) {
                rk |= (1ULL << (63 - i));
            }
        }
        
        return rk;
    };
    
    // Process each round
    for (int round_idx = 0; round_idx < rounds_ + 1; ++round_idx) {
        // 1. Extract the round key
        roundKeys_[round_idx] = extract_round_key();
        
        
        // 2. Rotate key register left by 61 bits
        // Create a temporary bitset for rotation
        std::bitset<128> rotated;
        for (int i = 0; i < keyLenBits; ++i) {
            int new_pos = (i + 61) % keyLenBits;
            rotated[new_pos] = key_register[i];
        }
        key_register = rotated;
        
        // 3. Apply S-box
        if (keySize_ == KeySize::KEY_80) {
            // Apply S-box to leftmost 4 bits (bits 79-76)
            uint8_t nibble = 0;
            for (int i = 0; i < 4; ++i) {
                if (key_register[keyLenBits - 1 - i]) {
                    nibble |= (1 << (3 - i));
                }
            }
            
            uint8_t sbox_result = SBOX[nibble];
            
            // Replace the nibble with S-box output
            for (int i = 0; i < 4; ++i) {
                key_register[keyLenBits - 1 - i] = (sbox_result >> (3 - i)) & 1;
            }
        } 
        else { // KEY_128
            // Apply S-box to leftmost 8 bits (bits 127-120)
            uint8_t byte_val = 0;
            for (int i = 0; i < 8; ++i) {
                if (key_register[keyLenBits - 1 - i]) {
                    byte_val |= (1 << (7 - i));
                }
            }
            
            // Split byte into nibbles and apply S-box
            uint8_t nibble1 = (byte_val >> 4) & 0x0F;
            uint8_t nibble2 = byte_val & 0x0F;
            uint8_t sbox_result = (SBOX[nibble1] << 4) | SBOX[nibble2];
            
            // Replace the byte with S-box output
            for (int i = 0; i < 8; ++i) {
                key_register[keyLenBits - 1 - i] = (sbox_result >> (7 - i)) & 1;
            }
        }
        
        // 4. XOR round counter with bits k_19 ... k_15
        uint8_t round_c_val = static_cast<uint8_t>(round_idx + 1);
        
        for (int j = 15; j <= 19; ++j) {
            bool rc_bit = (round_c_val >> (j - 15)) & 1;
            if (rc_bit) { // Only XOR if rc_bit is 1
                // Flip the bit at position j
                key_register.flip(j);
            }
        }
    }
    
    #ifdef DEBUG
    std::cout << "Round keys:" << std::endl;
    for (const auto& rk : roundKeys_) {
        std::cout << std::hex << std::setw(16) << std::setfill('0') << rk << std::endl;
    }
    #endif
}

// Initialize static members
std::random_device Present::rd_;
std::mt19937_64 Present::gen_(Present::rd_());

// Definition for the static constexpr SBOX
constexpr uint8_t Present::SBOX[16];