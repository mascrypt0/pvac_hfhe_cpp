#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iomanip>

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

    ifs.seekg(16); // Skip Header
    std::vector<Cipher> cts(io::get64(ifs));
    for (auto& c : cts) c = ser::getCipher(ifs);

    std::vector<uint8_t> data;
    for (auto& ct : cts) {
        for (auto& e : ct.E) {
            // Kita ambil byte dari lo dan hi secara berurutan
            for(int i=0; i<8; ++i) data.push_back((e.w.lo >> (i*8)) & 0xFF);
            for(int i=0; i<8; ++i) data.push_back((e.w.hi >> (i*8)) & 0xFF);
        }
    }

    std::cout << "--- BOUNTY V3: MNEMONIC RECOVERY ---\n";
    
    // Brute force XOR dengan filter kata mnemonic umum (BIP-39)
    // Kita cari string yang mengandung spasi dan karakter huruf kecil
    for (int k = 0; k < 256; ++k) {
        std::string s = "";
        int word_count = 0;
        std::string current_word = "";

        for (auto b : data) {
            char c = (char)(b ^ k);
            if (c >= 'a' && c <= 'z') {
                current_word += c;
            } else if (c == ' ') {
                if (current_word.length() >= 3) word_count++;
                current_word = "";
            }
            if (c >= 32 && c <= 126) s += c;
            else s += '.';
        }

        // Mnemonic biasanya punya minimal 12 kata
        if (word_count >= 10) {
            std::cout << "\n[!] Potential Mnemonic Found (Key: " << k << ")\n";
            // Bersihkan titik-titik berlebih untuk pembacaan
            std::string cleaned = "";
            for(size_t i=0; i<s.length(); ++i) {
                if (s[i] == '.' && (i>0 && s[i-1] == '.')) continue;
                cleaned += s[i];
            }
            std::cout << cleaned << "\n";
        }
    }
    
    return 0;
}