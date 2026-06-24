#pragma once
#include <vector>
#include <string>
#include <cstdint>

// ============================================================
// AES-256 : Advanced Encryption Standard (256-bit key)
// Encrypts actual message content. Mode: CBC with PKCS7 padding
// ============================================================
class AES256 {
public:
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key);
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key);
    static std::vector<uint8_t> encryptString(const std::string& message,
                                               const std::vector<uint8_t>& key);
    static std::string decryptToString(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& key);

private:
    static const int Nb = 4;
    static const int Nk = 8;
    static const int Nr = 14;

    static const uint8_t sbox[256];
    static const uint8_t inv_sbox[256];
    static const uint8_t rcon[11];

    static uint8_t gmul(uint8_t a, uint8_t b);
    static void    keyExpansion(const uint8_t* key, uint8_t roundKeys[240]);
    static void    addRoundKey(uint8_t state[4][4], const uint8_t* roundKey);
    static void    subBytes(uint8_t state[4][4]);
    static void    invSubBytes(uint8_t state[4][4]);
    static void    shiftRows(uint8_t state[4][4]);
    static void    invShiftRows(uint8_t state[4][4]);
    static void    mixColumns(uint8_t state[4][4]);
    static void    invMixColumns(uint8_t state[4][4]);
    static void    encryptBlock(const uint8_t in[16], uint8_t out[16],
                              const uint8_t roundKeys[240]);
    static void    decryptBlock(const uint8_t in[16], uint8_t out[16],
                              const uint8_t roundKeys[240]);
    static std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data);
};
