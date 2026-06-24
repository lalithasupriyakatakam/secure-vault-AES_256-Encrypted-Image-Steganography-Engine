#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

// ============================================================
// ECC : Elliptic Curve Cryptography over GF(5)
// Curve: y^2 = x^3 + 2x + 1 (mod 5)
// Generator G = (0,1), scalar k in {1,2,3,4}
// ============================================================

struct ECPoint {
    int x = 0, y = 0;
    bool isInfinity = false;
};

class ECC {
public:
    static std::vector<uint8_t> generateKey(const std::vector<uint8_t>& digest);
    static int     deriveScalar(const std::vector<uint8_t>& digest);
    static ECPoint scalarMultiply(int k);

private:
    static const int P = 5;
    static const int A = 2;

    static ECPoint generator();
    static ECPoint pointAdd(const ECPoint& P1, const ECPoint& P2);
    static int     modInverse(int a, int mod);
    static int     mod(int a, int m);
};

inline int ECC::mod(int a, int m) { return ((a%m)+m)%m; }

inline int ECC::modInverse(int a, int modulus) {
    a = mod(a, modulus);
    for (int i=1;i<modulus;i++)
        if (mod(a*i,modulus)==1) return i;
    throw std::runtime_error("Modular inverse does not exist");
}

inline ECPoint ECC::generator() { return {0,1,false}; }

inline ECPoint ECC::pointAdd(const ECPoint& P1, const ECPoint& P2) {
    if (P1.isInfinity) return P2;
    if (P2.isInfinity) return P1;
    if (P1.x==P2.x && mod(P1.y+P2.y,P)==0) return {0,0,true};

    int lambda;
    if (P1.x==P2.x && P1.y==P2.y) {
        int num = mod(3*P1.x*P1.x+A,P);
        int den = mod(2*P1.y,P);
        lambda  = mod(num*modInverse(den,P),P);
    } else {
        int num = mod(P2.y-P1.y,P);
        int den = mod(P2.x-P1.x,P);
        lambda  = mod(num*modInverse(den,P),P);
    }
    int x3 = mod(lambda*lambda-P1.x-P2.x,P);
    int y3 = mod(lambda*(P1.x-x3)-P1.y,P);
    return {x3,y3,false};
}

inline ECPoint ECC::scalarMultiply(int k) {
    ECPoint result={0,0,true};
    ECPoint addend=generator();
    while (k>0) {
        if (k&1) result=pointAdd(result,addend);
        addend=pointAdd(addend,addend);
        k>>=1;
    }
    return result;
}

inline int ECC::deriveScalar(const std::vector<uint8_t>& digest) {
    int sum=0;
    for (uint8_t b:digest) { sum+=(b>>4)&0xF; sum+=b&0xF; }
    return (sum%4)+1;
}

inline std::vector<uint8_t> ECC::generateKey(const std::vector<uint8_t>& digest) {
    int k=deriveScalar(digest);
    ECPoint Q=scalarMultiply(k);
    uint16_t pattern9=((k&0x7)<<6)|((Q.y&0x7)<<3)|(Q.x&0x7);
    std::vector<uint8_t> key(32,0);
    for (int bit=0;bit<256;++bit) {
        int patBit=(pattern9>>(8-(bit%9)))&1;
        if (patBit) key[bit/8]|=(1<<(7-(bit%8)));
    }
    return key;
}
