#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

#include "sha256.h"
#include "aes256.h"
#include "ecc.h"
#include "steganography.h"

void printHex(const std::string& label, const std::vector<uint8_t>& data, int maxBytes=32) {
    std::cout << label << ": ";
    int show=std::min((int)data.size(),maxBytes);
    for (int i=0;i<show;i++)
        std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)data[i];
    if ((int)data.size()>maxBytes) std::cout<<"...";
    std::cout<<std::dec<<"\n";
}

Image createTestImage(int w=256,int h=256) {
    Image img; img.width=w; img.height=h;
    img.pixels.resize(w*h*3);
    for (int y=0;y<h;y++)
        for (int x=0;x<w;x++) {
            img.pixels[(y*w+x)*3+0]=(uint8_t)((x+y)%256);
            img.pixels[(y*w+x)*3+1]=(uint8_t)((x*2)%256);
            img.pixels[(y*w+x)*3+2]=(uint8_t)((y*2+128)%256);
        }
    return img;
}

// Pack: [4-byte size][data]
std::vector<uint8_t> pack(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(4+data.size());
    uint32_t sz=(uint32_t)data.size();
    out[0]=(sz>>24)&0xFF; out[1]=(sz>>16)&0xFF;
    out[2]=(sz>> 8)&0xFF; out[3]=(sz    )&0xFF;
    std::copy(data.begin(),data.end(),out.begin()+4);
    return out;
}

void divider(const std::string& t="") {
    std::cout<<"\n----------------------------------------------------------\n";
    if (!t.empty()) {
        std::cout<<"  "<<t<<"\n";
        std::cout<<"----------------------------------------------------------\n";
    }
}

// ── SENDER ────────────────────────────────────────────────────────────────────
void senderSide(const std::string& message,
                const std::string& coverFile,
                const std::string& stegoFile) {

    std::cout<<"\n==========================================================\n";
    std::cout<<"                    SENDER SIDE\n";
    std::cout<<"==========================================================\n";
    std::cout<<"Message : \""<<message<<"\"\n";
    std::cout<<"Length  : "<<message.size()<<" bytes\n";

    // STAGE 1: SHA-256
    divider("STAGE 1: SHA-256 Hash Generation");
    auto digest  = SHA256::hashBytes(message);
    auto hashHex = SHA256::hash(message);
    std::cout<<"SHA-256 Hash:\n  "<<hashHex<<"\n";
    std::cout<<"Hash size : "<<digest.size()*8<<" bits\n";

    // STAGE 2: ECC Key
    divider("STAGE 2: ECC Key Generation");
    int k=ECC::deriveScalar(digest);
    ECPoint Q=ECC::scalarMultiply(k);
    auto eccKey=ECC::generateKey(digest);
    std::cout<<"Curve     : y^2 = x^3 + 2x + 1 (mod 5)\n";
    std::cout<<"Scalar k  : "<<k<<"\n";
    std::cout<<"Public Q  : ("<<Q.x<<", "<<Q.y<<")\n";
    printHex("ECC Key   ",eccKey);

    // STAGE 3: AES-256 encrypt full message
    divider("STAGE 3: AES-256 Encryption (Full Message)");
    auto encryptedMsg=AES256::encryptString(message,eccKey);
    std::cout<<"Plaintext size  : "<<message.size()<<" bytes\n";
    std::cout<<"Ciphertext size : "<<encryptedMsg.size()<<" bytes\n";
    printHex("Ciphertext      ",encryptedMsg,16);

    // Also XOR-encrypt hash for integrity
    std::vector<uint8_t> encryptedHash(32);
    for (int i=0;i<32;i++) encryptedHash[i]=digest[i]^eccKey[i];
    printHex("Encrypted Hash  ",encryptedHash);

    // STAGE 4: Pack payload = [packed(encryptedMsg)][encryptedHash]
    divider("STAGE 4: Payload Packing");
    auto packedMsg=pack(encryptedMsg);
    std::vector<uint8_t> payload;
    payload.insert(payload.end(),packedMsg.begin(),packedMsg.end());
    payload.insert(payload.end(),encryptedHash.begin(),encryptedHash.end());
    std::cout<<"Packed msg size    : "<<packedMsg.size()<<" bytes\n";
    std::cout<<"Encrypted hash size: "<<encryptedHash.size()<<" bytes\n";
    std::cout<<"Total payload      : "<<payload.size()<<" bytes ("<<payload.size()*8<<" bits)\n";

    // STAGE 5: LSB Steganography
    divider("STAGE 5: LSB Image Steganography");
    Image cover;
    try {
        cover=loadBMP(coverFile);
        std::cout<<"Loaded: "<<coverFile<<" ("<<cover.width<<"x"<<cover.height<<")\n";
    } catch(...) {
        std::cout<<"Creating synthetic 256x256 cover image\n";
        cover=createTestImage(256,256);
        saveBMP(coverFile,cover);
    }

    size_t cap=Steganography::capacity(cover);
    std::cout<<"Image capacity : "<<cap<<" bytes\n";
    std::cout<<"Payload size   : "<<payload.size()<<" bytes\n";
    if (cap<payload.size()) {
        std::cerr<<"ERROR: Image too small!\n"; return;
    }

    uint32_t seed=((uint32_t)eccKey[0]<<24)|((uint32_t)eccKey[1]<<16)
                 |((uint32_t)eccKey[2]<<8)|(uint32_t)eccKey[3];
    std::cout<<"Embed seed     : 0x"<<std::hex<<seed<<std::dec<<"\n";

    Image stego=Steganography::embed(cover,payload,seed);
    saveBMP(stegoFile,stego);
    std::cout<<"Stego saved as : "<<stegoFile<<"\n";
    std::cout<<"Max distortion : +/-1 (imperceptible)\n";
    Steganography::comparePixels(cover,stego,16);
    std::cout<<"\n[SENDER DONE]\n";
}

// ── RECEIVER ──────────────────────────────────────────────────────────────────
void receiverSide(const std::string& stegoFile,
                  const std::string& originalMessage) {

    std::cout<<"\n==========================================================\n";
    std::cout<<"                    RECEIVER SIDE\n";
    std::cout<<"==========================================================\n";

    divider("STEP 1: Load Stego Image");
    Image stego=loadBMP(stegoFile);
    std::cout<<"Loaded: "<<stegoFile<<" ("<<stego.width<<"x"<<stego.height<<")\n";

    divider("STEP 2: Regenerate ECC Key");
    auto digest=SHA256::hashBytes(originalMessage);
    auto eccKey=ECC::generateKey(digest);
    int k=ECC::deriveScalar(digest);
    ECPoint Q=ECC::scalarMultiply(k);
    std::cout<<"Scalar k : "<<k<<"\n";
    std::cout<<"Public Q : ("<<Q.x<<", "<<Q.y<<")\n";
    printHex("ECC Key  ",eccKey);

    divider("STEP 3: Extract Hidden Payload");
    uint32_t seed=((uint32_t)eccKey[0]<<24)|((uint32_t)eccKey[1]<<16)
                 |((uint32_t)eccKey[2]<<8)|(uint32_t)eccKey[3];

    auto payload=Steganography::extract(stego,seed);
    std::cout<<"Extracted payload: "<<payload.size()<<" bytes\n";

    divider("STEP 4: Unpack Payload");
    if (payload.size()<4) { std::cerr<<"Payload too small\n"; return; }
    uint32_t msgSize=((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)
                    |((uint32_t)payload[2]<<8)|(uint32_t)payload[3];
    std::cout<<"Encrypted msg size: "<<msgSize<<" bytes\n";

    if (payload.size()<4+msgSize+32) { std::cerr<<"Incomplete payload\n"; return; }
    std::vector<uint8_t> encryptedMsg(payload.begin()+4, payload.begin()+4+msgSize);
    std::vector<uint8_t> encryptedHash(payload.begin()+4+msgSize,
                                        payload.begin()+4+msgSize+32);
    printHex("Encrypted hash",encryptedHash);

    divider("STEP 5: AES-256 Decryption");
    std::string recoveredMsg=AES256::decryptToString(encryptedMsg,eccKey);
    std::cout<<"Recovered message: \""<<recoveredMsg<<"\"\n";

    divider("STEP 6: Integrity Verification");
    std::vector<uint8_t> recoveredHash(32);
    for (int i=0;i<32;i++) recoveredHash[i]=encryptedHash[i]^eccKey[i];
    auto computedHash=SHA256::hashBytes(recoveredMsg);

    bool integrityOK=(recoveredHash==computedHash);
    bool messageOK  =(recoveredMsg==originalMessage);

    printHex("Recovered hash",recoveredHash);
    printHex("Computed hash ",computedHash);

    std::cout<<"\nIntegrity check : "<<(integrityOK?"PASS - Not tampered":"FAIL - TAMPERED!")<<"\n";
    std::cout<<"Message match   : "<<(messageOK  ?"PASS - Perfect recovery":"FAIL")<<"\n";
    std::cout<<"\n[RECEIVER DONE]\n";
}

// ── MAIN ──────────────────────────────────────────────────────────────────────
int main() {
    std::cout<<"==========================================================\n";
    std::cout<<"    Cryptography Assisted Image Steganography v2.0\n";
    std::cout<<"    SHA-256 + ECC + AES-256 + Random LSB Steganography\n";
    std::cout<<"==========================================================\n";

    std::string message;
    std::cout<<"\nEnter secret message (or press Enter for default): ";
    std::getline(std::cin,message);
    if (message.empty())
        message="This is a secret message hidden inside an image using AES-256!";

    senderSide(message,"cover.bmp","stego.bmp");
    receiverSide("stego.bmp",message);

    std::cout<<"\n==========================================================\n";
    std::cout<<"                   FINAL SUMMARY\n";
    std::cout<<"==========================================================\n";
    std::cout<<"  Message        : \""<<message.substr(0,50)
             <<(message.size()>50?"...":"")<<"\"\n";
    std::cout<<"  Hash           : SHA-256 (256-bit fingerprint)\n";
    std::cout<<"  Key            : ECC over GF(5)\n";
    std::cout<<"  Encryption     : AES-256-CBC (full message)\n";
    std::cout<<"  Steganography  : LSB Blue channel, random pixel order\n";
    std::cout<<"  Distortion     : max +/-1 per pixel\n";
    std::cout<<"  Security layers: 3 (Hash + ECC + AES)\n";
    std::cout<<"==========================================================\n";
    return 0;
}
