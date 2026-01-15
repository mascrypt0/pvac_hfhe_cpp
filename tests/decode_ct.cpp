#include <iostream>
#include <fstream>
#include <cstdint>

int main() {
    std::ifstream ifs("bounty3_data/seed.ct", std::ios::binary);
    if (!ifs) {
        std::cerr << "File seed.ct tidak ditemukan!\n";
        return 1;
    }

    // Skip header 16 bytes + num_cts 8 bytes
    ifs.seekg(24);

    std::cout << "--- BOUNTY V3: DIRECT METADATA DECODE ---\n";
    std::cout << "Potential BIP-39 Word Indices:\n";

    // Kita akan scan hingga 100 ciphertext pertama secara manual
    for (int i = 0; i < 100; ++i) {
        uint32_t nL = 0, nE = 0;
        ifs.read((char*)&nL, 4);
        ifs.read((char*)&nE, 4);

        if (ifs.eof()) break;

        for (uint32_t l = 0; l < nL; ++l) {
            uint8_t rule = ifs.get();
            if (rule == 0) { // BASE Rule
                uint64_t ztag = 0;
                uint64_t lo = 0, hi = 0;
                ifs.read((char*)&ztag, 8);
                ifs.read((char*)&lo, 8);
                ifs.read((char*)&hi, 8);
                
                // Cetak indeks jika masuk range BIP-39 (0-2047)
                uint32_t index = (uint32_t)(ztag % 2048);
                std::cout << index << " ";
            } else {
                // Skip PROD (pa + pb = 8 bytes)
                ifs.seekg(8, std::ios::cur);
            }
        }

        // Skip Edges agar pointer ke CT berikutnya akurat
        for (uint32_t e = 0; e < nE; ++e) {
            // Edge: layer_id(4), idx(2), ch(1), pad(1), w_lo(8), w_hi(8) = 24 bytes
            ifs.seekg(24, std::ios::cur);
            uint32_t nbits = 0;
            ifs.read((char*)&nbits, 4);
            // Skip BitVec weights
            ifs.seekg(((nbits + 63) / 64) * 8, std::ios::cur);
        }
    }

    std::cout << "\n\n--- Done ---\n";
    return 0;
}