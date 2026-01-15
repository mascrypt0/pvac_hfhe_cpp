#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Struktur minimal untuk membaca header pvac
struct BaseLayer {
    uint64_t ztag;
    uint64_t lo;
    uint64_t hi;
};

int main(int argc, char** argv) {
    std::string path = "bounty3_data/seed.ct";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return 1;

    ifs.seekg(16); // Skip Header
    uint64_t num_cts;
    ifs.read((char*)&num_cts, 8);

    std::cout << "--- BOUNTY V3: BASE LAYER METADATA EXTRACTION ---\n";
    std::vector<uint64_t> all_ztags;

    for (uint64_t i = 0; i < num_cts; ++i) {
        uint32_t nL, nE;
        ifs.read((char*)&nL, 4);
        ifs.read((char*)&nE, 4);

        for (uint32_t l = 0; l < nL; ++l) {
            uint8_t rule = ifs.get();
            if (rule == 0) { // BASE Rule
                BaseLayer bl;
                ifs.read((char*)&bl.ztag, 8);
                ifs.read((char*)&bl.lo, 8);
                ifs.read((char*)&bl.hi, 8);
                all_ztags.push_back(bl.ztag);
            } else {
                ifs.seekg(8, std::ios::cur); // Skip PROD
            }
        }
        // Skip Edges
        for (uint32_t e = 0; e < nE; ++e) {
            ifs.seekg(4 + 2 + 1 + 1 + 16, std::ios::cur);
            uint32_t nbits;
            ifs.read((char*)&nbits, 4);
            ifs.seekg(((nbits + 63) / 64) * 8, std::ios::cur);
        }
    }

    std::cout << "Detected " << all_ztags.size() << " Z-Tags.\n";
    
    // Interpretasi 1: Z-Tag sebagai karakter ASCII (LSB)
    std::cout << "ASCII Interpretation: ";
    for (auto z : all_ztags) {
        char c = (char)(z & 0xFF);
        if (c >= 32 && c <= 126) std::cout << c;
        else std::cout << ".";
    }
    
    // Interpretasi 2: Nilai Z-Tag sebagai Indeks BIP-39 (0-2047)
    std::cout << "\n\nPotential BIP-39 Indices: ";
    for (size_t i = 0; i < all_ztags.size() && i < 24; ++i) {
        std::cout << (all_ztags[i] % 2048) << " ";
    }
    std::cout << "\n------------------------------------------------\n";

    return 0;
}