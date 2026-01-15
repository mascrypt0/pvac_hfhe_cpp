#include <pvac/pvac.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
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

    ifs.seekg(16);
    uint64_t num_cts = io::get64(ifs);
    std::vector<Cipher> cts(num_cts);
    for (auto& c : cts) c = ser::getCipher(ifs);

    std::cout << "--- BOUNTY V3: DEEP BIT-STREAM ANALYSIS ---\n";

    // Teknik 1: Ambil bit ke-0 dari setiap selector (Edge.s)
    std::vector<uint8_t> bit_stream;
    uint8_t current_byte = 0;
    int bits = 0;

    for (auto& ct : cts) {
        for (auto& e : ct.E) {
            bool b = (e.s.w[0] & 1);
            if (b) current_byte |= (1 << bits);
            if (++bits == 8) {
                bit_stream.push_back(current_byte);
                current_byte = 0; bits = 0;
            }
        }
    }

    std::cout << "Attempt 1 (Selector Bit 0): ";
    for (auto b : bit_stream) {
        if (b >= 32 && b <= 126) std::cout << (char)b;
        else if (b != 0) std::cout << "?";
    }
    std::cout << "\n";

    // Teknik 2: Ambil byte pertama dari setiap Edge.w.lo (XOR Scan)
    std::cout << "\nAttempt 2 (Edge Weight XOR Scan):\n";
    std::vector<uint8_t> w_bytes;
    for (auto& ct : cts) {
        for (auto& e : ct.E) {
            if (e.w.lo != 0) w_bytes.push_back(e.w.lo & 0xFF);
        }
    }

    for (int k = 0; k < 256; ++k) {
        std::string res = "";
        int letters = 0;
        for (size_t i = 0; i < w_bytes.size() && i < 50; ++i) {
            char c = (char)(w_bytes[i] ^ k);
            if (c >= 'a' && c <= 'z') letters++;
            res += (c >= 32 && c <= 126) ? c : '.';
        }
        if (letters > 15) { // Threshold untuk kata bahasa Inggris
            std::cout << "Key [" << k << "]: " << res << "...\n";
        }
    }

    return 0;
}