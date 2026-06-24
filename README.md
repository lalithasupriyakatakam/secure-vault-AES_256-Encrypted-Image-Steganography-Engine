# 🔐 SecureVault

### AES-256 Encrypted Image Steganography Engine

A multi-layer security system built entirely from scratch in C++ — combining cryptographic hashing, elliptic curve key generation, AES-256 encryption, and randomized image steganography into a single end-to-end pipeline. **Zero external libraries.**

---

## 🚀 Overview

SecureVault lets you hide a secret message inside an ordinary image so that:

- The message content is **encrypted** with AES-256 (unreadable without the key)
- The encrypted data is **hidden** inside image pixels (invisible to the eye)
- The message **integrity** is verifiable (tamper detection built-in)
- The hiding key is **deterministically derived** from cryptographic material — not hardcoded

The result: a stego image that looks completely identical to the original, but secretly carries an encrypted message that only the intended recipient can extract and decrypt.

```
"Hello World"  →  SHA-256  →  ECC Key  →  AES-256  →  Hidden in image.bmp
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔑 **SHA-256** | Implemented from scratch — generates a 256-bit integrity fingerprint of the message |
| 📐 **ECC (GF-5)** | Elliptic curve key derivation over a Galois Field — produces a deterministic 256-bit key |
| 🔒 **AES-256-CBC** | Full message encryption with PKCS7 padding — not just the hash, the *entire* message |
| 🖼️ **LSB Steganography** | Hides encrypted bits in the blue channel LSB of image pixels — max ±1 distortion |
| 🎲 **Randomized Embedding** | Bits are scattered across random pixel positions (seeded by the key) instead of sequential pixels — resists basic steganalysis |
| ✅ **Integrity Verification** | Receiver automatically detects if the message was tampered with in transit |
| 📦 **Zero Dependencies** | No OpenSSL, no Crypto++, no image libraries — every algorithm written from first principles |

---

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│   SHA-256   │────▶│  ECC Key    │────▶│  AES-256    │────▶│ Steganography│
│   Hashing   │     │ Generation  │     │ Encryption  │     │  Embedding   │
└─────────────┘     └─────────────┘     └─────────────┘     └──────────────┘
      │                                                              │
      ▼                                                              ▼
 256-bit digest                                              stego.bmp (output)
 (integrity check)                                          looks identical to
                                                              cover.bmp to the eye
```

**Pipeline stages:**

1. **SHA-256** — generates a 256-bit hash of the plaintext message for integrity verification
2. **ECC Key Generation** — derives a 256-bit encryption key using elliptic curve scalar multiplication over `y² = x³ + 2x + 1 (mod 5)`
3. **AES-256-CBC** — encrypts the full message using the ECC-derived key
4. **LSB Steganography** — embeds the encrypted payload into a BMP image using a key-seeded random pixel order

---

## 📂 Project Structure

```
SecureVault/
├── main.cpp              # Sender + Receiver pipeline (entry point)
├── sha256.h / .cpp        # SHA-256 hash implementation
├── aes256.h / .cpp        # AES-256-CBC encryption implementation
├── ecc.h                  # Elliptic Curve key generation (GF-5)
├── steganography.h        # BMP I/O + randomized LSB embedding
└── README.md
```

---

## ⚙️ Installation & Build

### Prerequisites
- A C++17 compatible compiler (`g++`, MinGW-W64, or Clang)

### Build
```bash
git clone https://github.com/<your-username>/SecureVault.git
cd SecureVault
g++ -std=c++17 -O2 -o securevault sha256.cpp aes256.cpp main.cpp
```

### Run
```bash
./securevault
```

You'll be prompted to enter a secret message:
```
Enter secret message (or press Enter for default): Meet me at the usual place
```

---

## 📊 Example Output

```
==========================================================
                    SENDER SIDE
==========================================================
Message : "Meet me at the usual place"

STAGE 1: SHA-256 Hash Generation
SHA-256 Hash: 23e94c85cbc0d198873d360d00ce867f8bbbdc97d9eb1a5a0d1e5f738dd2a8e1

STAGE 2: ECC Key Generation
Scalar k  : 1
Public Q  : (0, 1)

STAGE 3: AES-256 Encryption (Full Message)
Ciphertext size : 32 bytes

STAGE 5: LSB Image Steganography
Stego saved as : stego.bmp
Max distortion : +/-1 (imperceptible)

==========================================================
                    RECEIVER SIDE
==========================================================
Recovered message : "Meet me at the usual place"

Integrity check : PASS - Not tampered
Message match   : PASS - Perfect recovery
```

---

## 🔬 Technical Details

### SHA-256
Implemented from first principles: message padding, 64-round compression function, message schedule expansion using `σ0`, `σ1`, `Σ0`, `Σ1`, `Ch`, and `Maj` functions, exactly per the FIPS 180-4 specification.

### Elliptic Curve Cryptography
Uses a simplified curve `y² = x³ + 2x + 1 (mod 5)` with generator point `G = (0, 1)`. The scalar `k` is deterministically derived from the SHA-256 digest, and the public key `Q = k·G` is computed via point doubling and point addition under modular arithmetic.

### AES-256-CBC
Full implementation including key expansion (14 rounds), `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`, Galois field multiplication, and PKCS7 padding — encrypting the complete message content, not just a hash.

### Steganography
A 24-bit BMP reader/writer built from scratch (handling both top-down and bottom-up row orientation). Data is embedded in the **blue channel LSB**:
- First 32 pixels (sequential) store a 4-byte payload-size header
- Remaining payload bits are scattered across **randomly selected pixels**, using a Fisher-Yates shuffle seeded by the ECC key — so two different messages produce two completely different embedding patterns

---

## 🎯 Use Cases

- Covert communication over public channels (email, social media image sharing)
- Digital watermarking and proof-of-ownership for images
- Secure metadata embedding for forensic / authentication purposes
- Educational demonstration of applied cryptography + steganography integration

---

## 🛣️ Roadmap

- [ ] Replace GF(5) ECC with production-grade `secp256k1` curve
- [ ] Support PNG and JPEG cover images
- [ ] Add ECDSA digital signatures for sender authentication
- [ ] Build a GUI (Qt) or web interface (React)
- [ ] Extend carrier support to audio and video files
- [ ] Deploy as a REST API microservice

---

## ⚠️ Disclaimer

This project uses a simplified GF(5) elliptic curve for educational purposes and **is not cryptographically secure for production use**. For real-world secure communication, use established libraries (OpenSSL, libsodium) with standard curves (secp256k1, NIST P-256). This project's value lies in demonstrating algorithm-level understanding, not in replacing production-grade cryptographic libraries.

---

## 🧑‍💻 Author

**Lalitha Supriya Katakam**
B.Tech, Electronics & Communication Engineering — RGUKT Srikakulam

[Portfolio](https://lalithasupriyakatakam.github.io/my-portfolio/) · [LinkedIn](https://linkedin.com/in/lalitha-supriya-katakam-0018aa320) · [GitHub](https://github.com/lalithasupriyakatakam)

---

