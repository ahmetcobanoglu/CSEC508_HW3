#include <iostream>
#include <vector>
#include <cstdint>
#include <random>
#include <cmath>    // For log2
#include <iomanip>  // For std::fixed, std::setprecision, std::setw, std::setfill
#include <numeric>  // For std::accumulate
#include <string>   // For std::stoll
#include <stdexcept> // For std::runtime_error, std::invalid_argument

#include "present.hh" // Assuming this is in the include path via CMake

// Constants
const int NUM_KEYS = 100;
const int NUM_ROUNDS_CIPHER = 4; // For the PRESENT cipher configuration
const uint64_t ALPHA = 0x0000000000004004ULL; // Input difference: x0=4, x3=4
const uint64_t BETA = ALPHA; // Output difference, same as ALPHA for iterative characteristic

// N_PLAINTEXTS will be configurable, default to 2^25
long long N_PLAINTEXTS = 1LL << 25;

int main(int argc, char* argv[]) {

    std::cout << "Starting differential cryptanalysis experiment on 4-round PRESENT..." << std::endl;
    std::cout << "Parameters:" << std::endl;
    std::cout << "  Number of Keys (NUM_KEYS): " << NUM_KEYS << std::endl;
    std::cout << "  Number of Plaintexts per Key (N): " << N_PLAINTEXTS << std::endl;
    std::cout << "  Cipher Rounds: " << NUM_ROUNDS_CIPHER << std::endl;
    std::cout << "  Alpha (Input Difference):  0x" << std::hex << std::setw(16) << std::setfill('0') << ALPHA << std::dec << std::endl;
    std::cout << "  Beta (Output Difference): 0x" << std::hex << std::setw(16) << std::setfill('0') << BETA << std::dec << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;

    std::vector<long long> counters(NUM_KEYS, 0);
    // Assuming 80-bit key for PRESENT, as it's a common default.
    // The Present class constructor defaults to KeySize::KEY_80.
    Present cipher(Present::KeySize::KEY_80, NUM_ROUNDS_CIPHER);

    for (int k = 0; k < NUM_KEYS; ++k) {
        std::cout << "Processing Key " << std::setw(3) << std::setfill(' ') << k + 1 << "/" << NUM_KEYS << "..." << std::endl;
        std::vector<uint8_t> current_key_bytes = cipher.generateRandomKey();
        try {
            cipher.setKey(current_key_bytes.data(), current_key_bytes.size());
        } catch (const std::exception& e) {
            std::cerr << "Error setting key " << k + 1 << ": " << e.what() << ". Skipping this key." << std::endl;
            continue; // Skip to the next key
        }

        long long report_interval = N_PLAINTEXTS / 10;
        if (report_interval == 0) report_interval = 1; // Avoid division by zero if N_PLAINTEXTS < 10

        for (long long i = 0; i < N_PLAINTEXTS; ++i) {
            if (((i + 1) % report_interval == 0 && N_PLAINTEXTS >= 10) || (i + 1) == N_PLAINTEXTS) {
                 std::cout << "  Key " << std::setw(3) << std::setfill(' ') << k + 1
                           << ": Processed " << std::setw(9) << std::setfill(' ') << i + 1 << "/" << N_PLAINTEXTS << " plaintexts ("
                           << std::fixed << std::setprecision(1) << (static_cast<double>(i + 1) / N_PLAINTEXTS * 100.0)
                           << "%)" << std::endl;
            }

            uint64_t p_i = Present::generateRandomPlaintext();
            uint64_t p_i_star = p_i ^ ALPHA;

            uint64_t enc_p_i = 0;
            uint64_t enc_p_i_star = 0;

            try {
                enc_p_i = cipher.encrypt(p_i);
                enc_p_i_star = cipher.encrypt(p_i_star);
            } catch (const std::runtime_error& e) {
                std::cerr << "Runtime error during encryption for key " << k+1 << ", plaintext " << i+1
                          << ": " << e.what() << ". Skipping this plaintext pair." << std::endl;
                continue; // Skip this plaintext pair
            }

            uint64_t output_diff = enc_p_i ^ enc_p_i_star;

            if (output_diff == BETA) {
                counters[k]++;
            }
        }
        std::cout << "  Key " << std::setw(3) << std::setfill(' ') << k + 1 << " finished. Counter C[" << k << "] = " << counters[k] << std::endl;
    }

    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "Experiment Results:" << std::endl;
    std::cout << "N (Plaintexts per key chosen): " << N_PLAINTEXTS << std::endl;
    std::cout << "Counters C_i for each of the " << NUM_KEYS << " keys:" << std::endl;
    for (int k = 0; k < NUM_KEYS; ++k) {
        std::cout << "C[" << std::setw(2) << std::setfill(' ') << k << "]: " << counters[k] << std::endl;
    }

    long long total_successes = std::accumulate(counters.begin(), counters.end(), 0LL);
    long long total_trials = static_cast<long long>(NUM_KEYS) * N_PLAINTEXTS;

    std::cout << "Total successes (sum of all C_i): " << total_successes << std::endl;
    std::cout << "Total trials (NUM_KEYS * N): " << total_trials << std::endl;

    if (total_trials == 0) {
        std::cout << "No trials performed, cannot calculate probability." << std::endl;
        return 1;
    }

    if (total_successes == 0) {
        std::cout << "No successes observed. Experimental probability is effectively 0." << std::endl;
        std::cout << "Cannot express as 2^(-x.xx) because probability is 0 or too small to measure with N=" << N_PLAINTEXTS << " per key." << std::endl;
    } else {
        double experimental_probability = static_cast<double>(total_successes) / total_trials;
        std::cout << "Experimental Probability (P_exp = Total_Successes / Total_Trials): "
                  << std::scientific << std::setprecision(6) << experimental_probability << std::endl;

        double x = -log2(experimental_probability);
        std::cout << "Experimental Probability (P_exp expressed as 2^(-x.xx)): 2^(-"
                  << std::fixed << std::setprecision(2) << x << ")" << std::endl;
    }
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "Experiment finished." << std::endl;

    return 0;
}
