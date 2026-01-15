#include <pvac/pvac.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

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

    std::cout << "--- BOUNTY V3: DYNAMIC BIT-INDEX EXTRACTION ---\n";

    std::vector<uint8_t> recovered_bytes;
    uint8_t current_byte = 0;
    int bit_idx = 0;

    for (const auto& ct : cts) {
        // Cari nilai M (ztag % B) untuk CT ini
        uint32_t m = 0;
        for (const auto& L : ct.L) {
            if (L.rule == RRule::BASE) {
                m = L.seed.ztag % 337;
                break;
            }
        }

        // Ambil bit ke-(m % 64) dari Edge Weight pertama di setiap CT
        if (!ct.E.empty()) {
            uint64_t weight = ct.E[0].w.lo;
            bool bit = (weight >> (m % 64)) & 1;
            
            if (bit) current_byte |= (1 << bit_idx);
            if (++bit_idx == 8) {
                recovered_bytes.push_back(current_byte);
                current_byte = 0; bit_idx = 0;
            }
        }
    }

    std::cout << "Extracted Txt: ";
    for (auto b : recovered_bytes) {
        if (b >= 32 && b <= 126) std::cout << (char)b;
        else std::cout << "[" << (int)b << "]";
    }
    
    // Coba metode cadangan: Seluruh bit dari satu CT
    std::cout << "\nAlternative (CT[0] Full Stream): ";
    current_byte = 0; bit_idx = 0;
    for (const auto& e : cts[0].E) {
        bool bit = e.w.lo & 1;
        if (bit) current_byte |= (1 << bit_idx);
        if (++bit_idx == 8) {
            if (current_byte >= 32 && current_byte <= 126) std::cout << (char)current_byte;
            current_byte = 0; bit_idx = 0;
        }
    }
    std::cout << "\n-----------------------------------------------\n";

    return 0;
}