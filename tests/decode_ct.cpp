#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>
#include <vector>

using namespace pvac;

namespace io {
    auto get32 = [](std::istream& i) -> uint32_t { uint32_t x = 0; i.read((char*)&x, 4); return x; };
    auto get64 = [](std::istream& i) -> uint64_t { uint64_t x = 0; i.read((char*)&x, 8); return x; };
    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };
}

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";
    std::ifstream fct(dir + "/seed.ct", std::ios::binary);
    std::ifstream fpk(dir + "/pk.bin", std::ios::binary);
    if (!fct || !fpk) return 1;

    // 1. Ekstrak Ztag (m) dari Ciphertext
    fct.seekg(16);
    uint64_t num_cts = io::get64(fct);
    std::vector<uint32_t> m_values;
    for (uint64_t n = 0; n < num_cts; ++n) {
        uint32_t nL = io::get32(fct);
        uint32_t nE = io::get32(fct);
        for (uint32_t l = 0; l < nL; ++l) {
            uint8_t rule = fct.get();
            if (rule == 0) { // BASE
                uint64_t ztag = io::get64(fct);
                m_values.push_back(ztag % 337);
                fct.seekg(16, std::ios::cur); // skip nonce
            } else fct.seekg(8, std::ios::cur); // skip prod
        }
        // Skip edges: layer_id(4)+idx(2)+ch(1)+pad(1)+w(16)+s_nbits(4)
        for (uint32_t e = 0; e < nE; ++e) {
            fct.seekg(4 + 2 + 1 + 1 + 16, std::ios::cur);
            uint32_t nbits = io::get32(fct);
            fct.seekg(((nbits + 63) / 64) * 8, std::ios::cur);
        }
    }

    // 2. Load Matriks H dari Public Key
    fpk.seekg(16 + 40 + 8 + 32); // Skip Header, Params, Canon, Digest
    uint64_t h_rows = io::get64(fpk);
    std::vector<BitVec> H(h_rows);
    for (auto& row : H) row = io::getBv(fpk);

    std::cout << "--- BOUNTY V3: PK-LOOKUP RECOVERY ---\n";
    
    // 3. Ambil bit pertama dari baris H yang ditunjuk oleh m
    std::vector<uint8_t> result;
    uint8_t current = 0;
    int bit_count = 0;

    for (uint32_t m : m_values) {
        if (m < H.size()) {
            bool bit = H[m].w[0] & 1; // Ambil LSB dari baris m
            if (bit) current |= (1 << bit_count);
            if (++bit_count == 8) {
                result.push_back(current);
                current = 0; bit_count = 0;
            }
        }
    }

    std::cout << "Recovered: ";
    for (auto b : result) std::cout << (char)((b >= 32 && b <= 126) ? b : '?');
    
    // Alternative: m itu sendiri adalah karakter ASCII
    std::cout << "\nDirect M: ";
    for (uint32_t m : m_values) {
        uint8_t c = (uint8_t)(m % 256);
        std::cout << (char)((c >= 32 && c <= 126) ? c : '.');
    }
    std::cout << "\n-------------------------------------\n";

    return 0;
}