#include <pvac/pvac.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>

using namespace pvac;

namespace io {
    auto get32 = [](std::istream& i) -> uint32_t { uint32_t x = 0; i.read((char*)&x, 4); return x; };
    auto get64 = [](std::istream& i) -> uint64_t { uint64_t x = 0; i.read((char*)&x, 8); return x; };
    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };
    auto getFp = [](std::istream& i) -> Fp { return { get64(i), get64(i) }; };
}

namespace ser {
    using namespace io;
    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{}; L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) { L.seed.ztag = get64(i); L.seed.nonce.lo = get64(i); L.seed.nonce.hi = get64(i); }
        else if (L.rule == RRule::PROD) { L.pa = get32(i); L.pb = get32(i); }
        return L;
    };
    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{}; e.layer_id = get32(i); i.read((char*)&e.idx, 2);
        e.ch = i.get(); i.get(); e.w = getFp(i); e.s = getBv(i);
        return e;
    };
    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C; uint32_t nL = get32(i), nE = get32(i);
        C.L.resize(nL); C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

int main(int argc, char** argv) {
    std::string path = (argc > 1) ? argv[1] : "bounty3_data/seed.ct";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return 1;

    ifs.seekg(16);
    uint64_t num_cts = io::get64(ifs);
    
    std::vector<uint8_t> all_bytes;
    for (uint64_t n = 0; n < num_cts; ++n) {
        Cipher ct = ser::getCipher(ifs);
        for (const auto& e : ct.E) {
            // Ambil 8 byte dari weight.lo
            for (int j = 0; j < 8; ++j) {
                uint8_t b = (e.w.lo >> (j * 8)) & 0xFF;
                if (b != 0) all_bytes.push_back(b);
            }
        }
    }

    std::cout << "--- BOUNTY V3: STABLE WORD-SEARCH ---\n";
    std::cout << "Collected " << all_bytes.size() << " bytes from all edges.\n";

    // Mencoba XOR brute force dan mencari kata-kata yang masuk akal
    for (int k = 0; k < 256; ++k) {
        std::string current_stream = "";
        int word_count = 0;
        std::string temp_word = "";

        for (uint8_t b : all_bytes) {
            char c = (char)(b ^ k);
            if (c >= 'a' && c <= 'z') {
                temp_word += c;
            } else {
                if (temp_word.length() >= 3) word_count++;
                temp_word = "";
            }
            if (c >= 32 && c <= 126) current_stream += c;
        }

        // Jika ditemukan lebih dari 8 kata, tampilkan kemungkinan ini
        if (word_count > 8) {
            std::cout << "\n[!] Potential Mnemonic (Key XOR " << k << "):\n";
            // Tampilkan hanya karakter yang bersih (bukan titik-titik panjang)
            for (size_t i = 0; i < current_stream.length(); ++i) {
                if (i > 0 && current_stream[i] == ' ' && current_stream[i-1] == ' ') continue;
                std::cout << current_stream[i];
            }
            std::cout << "\n";
        }
    }

    return 0;
}