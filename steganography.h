#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <algorithm>

// ============================================================
// Image Steganography - LSB Blue channel
// Fixed BMP I/O (handles both top-down and bottom-up BMP)
// 2-phase embedding:
//   Phase 1: first 32 sequential pixels = 4-byte size header
//   Phase 2: payload at random pixel positions (seeded by ECC key)
// ============================================================

struct Image {
    int width=0, height=0;
    std::vector<uint8_t> pixels; // RGB, 3 bytes per pixel
};

// ── BMP Reader (handles both +height and -height) ─────────────────────────────
inline Image loadBMP(const std::string& filename) {
    std::ifstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + filename);

    uint8_t header[54];
    f.read(reinterpret_cast<char*>(header), 54);

    int width      = *reinterpret_cast<int32_t*>(&header[18]);
    int height_raw = *reinterpret_cast<int32_t*>(&header[22]);
    int offset     = *reinterpret_cast<int32_t*>(&header[10]);
    bool topDown   = (height_raw < 0);
    int height     = topDown ? -height_raw : height_raw;

    f.seekg(offset);
    int rowSize = ((width*3+3)/4)*4;

    Image img;
    img.width = width;
    img.height = height;
    img.pixels.resize(width*height*3);

    std::vector<uint8_t> row(rowSize);
    for (int i = 0; i < height; i++) {
        int y = topDown ? i : (height-1-i);
        f.read(reinterpret_cast<char*>(row.data()), rowSize);
        for (int x = 0; x < width; x++) {
            img.pixels[(y*width+x)*3+0] = row[x*3+2]; // R
            img.pixels[(y*width+x)*3+1] = row[x*3+1]; // G
            img.pixels[(y*width+x)*3+2] = row[x*3+0]; // B
        }
    }
    return img;
}

// ── BMP Writer (saves as top-down, consistent with our load) ─────────────────
inline void saveBMP(const std::string& filename, const Image& img) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + filename);

    int rowSize  = ((img.width*3+3)/4)*4;
    int dataSize = rowSize * img.height;
    int fileSize = 54 + dataSize;

    uint8_t header[54] = {};
    header[0]='B'; header[1]='M';
    *reinterpret_cast<int32_t*>(&header[2])  = fileSize;
    *reinterpret_cast<int32_t*>(&header[10]) = 54;
    *reinterpret_cast<int32_t*>(&header[14]) = 40;
    *reinterpret_cast<int32_t*>(&header[18]) = img.width;
    *reinterpret_cast<int32_t*>(&header[22]) = -img.height; // negative = top-down
    *reinterpret_cast<uint16_t*>(&header[26]) = 1;
    *reinterpret_cast<uint16_t*>(&header[28]) = 24;
    *reinterpret_cast<int32_t*>(&header[34]) = dataSize;
    f.write(reinterpret_cast<char*>(header), 54);

    std::vector<uint8_t> row(rowSize, 0);
    for (int y = 0; y < img.height; y++) {
        for (int x = 0; x < img.width; x++) {
            row[x*3+2] = img.pixels[(y*img.width+x)*3+0]; // R
            row[x*3+1] = img.pixels[(y*img.width+x)*3+1]; // G
            row[x*3+0] = img.pixels[(y*img.width+x)*3+2]; // B
        }
        f.write(reinterpret_cast<char*>(row.data()), rowSize);
    }
}

// ── Steganography ─────────────────────────────────────────────────────────────
class Steganography {
public:
    static Image              embed(const Image& cover,
                                    const std::vector<uint8_t>& data,
                                    uint32_t seed);
    static std::vector<uint8_t> extract(const Image& stego, uint32_t seed);
    static size_t             capacity(const Image& img);
    static void               comparePixels(const Image& cover,
                                            const Image& stego, int count=16);

private:
    static void embedBit(Image& img, int idx, int bit) {
        img.pixels[idx*3+2] = (img.pixels[idx*3+2] & 0xFE) | (bit & 1);
    }
    static int extractBit(const Image& img, int idx) {
        return img.pixels[idx*3+2] & 1;
    }
    static std::vector<int> randomOrder(int total, int needed, uint32_t seed);
};

inline std::vector<int> Steganography::randomOrder(int total, int needed,
                                                     uint32_t seed) {
    std::vector<int> idx;
    idx.reserve(total-32);
    for (int i=32; i<total; i++) idx.push_back(i); // skip header pixels
    uint32_t state = seed;
    for (int i=(int)idx.size()-1; i>0; i--) {
        state = state*1664525u + 1013904223u;
        int j  = state % (i+1);
        std::swap(idx[i], idx[j]);
    }
    if ((int)idx.size() < needed)
        throw std::runtime_error("Image too small for random embedding");
    idx.resize(needed);
    return idx;
}

inline size_t Steganography::capacity(const Image& img) {
    return (img.width * img.height - 32) / 8;
}

inline Image Steganography::embed(const Image& cover,
                                   const std::vector<uint8_t>& data,
                                   uint32_t seed) {
    int total       = cover.width * cover.height;
    uint32_t sz     = (uint32_t)data.size();
    int bitsNeeded  = sz * 8;

    if ((int)capacity(cover) * 8 < bitsNeeded)
        throw std::runtime_error("Image too small");

    Image stego = cover;

    // Phase 1: embed 4-byte size in pixels 0..31 (32 bits)
    for (int bit=0; bit<32; bit++) {
        int byteIdx = bit / 8;
        int bitIdx  = 7 - (bit % 8);
        int bitVal  = (sz >> ((3-byteIdx)*8 + bitIdx)) & 1;
        embedBit(stego, bit, bitVal);
    }

    // Phase 2: embed payload at random pixels
    auto order = randomOrder(total, bitsNeeded, seed);
    for (int bit=0; bit<bitsNeeded; bit++) {
        int byteIdx = bit / 8;
        int bitIdx  = 7 - (bit % 8);
        int bitVal  = (data[byteIdx] >> bitIdx) & 1;
        embedBit(stego, order[bit], bitVal);
    }
    return stego;
}

inline std::vector<uint8_t> Steganography::extract(const Image& stego,
                                                     uint32_t seed) {
    int total = stego.width * stego.height;

    // Phase 1: read 4-byte size from pixels 0..31
    uint32_t sz = 0;
    for (int bit=0; bit<32; bit++) {
        int byteIdx = bit / 8;
        int bitIdx  = 7 - (bit % 8);
        if (extractBit(stego, bit))
            sz |= (1u << ((3-byteIdx)*8 + bitIdx));
    }

    if (sz == 0 || sz > (uint32_t)capacity(stego))
        throw std::runtime_error("Invalid size in header: " + std::to_string(sz));

    // Phase 2: extract payload from random pixels
    int bitsNeeded = sz * 8;
    auto order = randomOrder(total, bitsNeeded, seed);

    std::vector<uint8_t> data(sz, 0);
    for (int bit=0; bit<bitsNeeded; bit++) {
        int byteIdx = bit / 8;
        int bitIdx  = 7 - (bit % 8);
        if (extractBit(stego, order[bit]))
            data[byteIdx] |= (1 << bitIdx);
    }
    return data;
}

inline void Steganography::comparePixels(const Image& cover,
                                          const Image& stego, int count) {
    std::cout << "\n--- Pixel Comparison (Blue channel, first "
              << count << " pixels) ---\n";
    std::cout << "Pixel | Cover B | Stego B | Changed?\n";
    std::cout << "------+---------+---------+---------\n";
    for (int i=0; i<count && i<cover.width*cover.height; i++) {
        uint8_t cb = cover.pixels[i*3+2];
        uint8_t sb = stego.pixels[i*3+2];
        std::cout << "  " << std::setw(3) << i
                  << "  |   " << std::setw(3) << (int)cb
                  << "   |   " << std::setw(3) << (int)sb
                  << "   | " << (cb!=sb ? "YES (+1)" : "no") << "\n";
    }
}
