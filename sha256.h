#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ============================================================
// SHA-256 : Secure Hash Algorithm (256-bit output)
// Converts any input message into a fixed 256-bit digest
// ============================================================
class SHA256 {
public:
    static std::string          hash(const std::string& message);
    static std::vector<uint8_t> hashBytes(const std::string& message);

private:
    static const uint32_t H0[8];   // initial hash values
    static const uint32_t K[64];   // round constants

    static uint32_t rotr(uint32_t x, uint32_t n);
    static uint32_t shr (uint32_t x, uint32_t n);

    static uint32_t sigma0(uint32_t x);
    static uint32_t sigma1(uint32_t x);
    static uint32_t Sigma0(uint32_t x);
    static uint32_t Sigma1(uint32_t x);
    static uint32_t Ch (uint32_t x, uint32_t y, uint32_t z);
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

    static std::vector<uint8_t> preprocess(const std::string& msg);
    static void processBlock(const uint8_t* block, uint32_t hash[8]);
};
