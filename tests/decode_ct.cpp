#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>

using namespace pvac;
namespace fs = std::filesystem;

namespace Magic {
    constexpr uint32_t CT  = 0x66699666;
    constexpr uint32_t SK  = 0x66666999;
    constexpr uint32_t PK  = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0; i.read(reinterpret_cast<char*>(&x), 4); return x;
    };
    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0; i.read(reinterpret_cast<char*>(&x), 8); return x;
    };
    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };
    auto getFp = [](std::istream& i) -> Fp {
        return { get64(i), get64(i) };
    };
}

namespace ser {
    using namespace io;
    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{};
        L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) {
            L.seed.ztag = get64(i);
            L.seed.nonce.lo = get64(i);
            L.seed.nonce.hi = get64(i);
        } else if (L.rule == RRule::PROD) {
            L.pa = get32(i); L.pb = get32(i);
        }
        return L;
    };
    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = i.get(); i.get();
        e.w = getFp(i); e.s = getBv(i);
        return e;
    };
    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL);
        C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
    auto ver = io::get32(i);
    if (magic != Magic::CT || ver != Magic::VER) throw std::runtime_error("bad ct header");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";
    auto ct_path = dir + "/seed.ct";
    
    try {
        auto cts = loadCts(ct_path);
        std::cout << "--- BOUNTY V3: EDGE-WEIGHT ANALYSIS ---\n";

        std::vector<uint8_t> stream;
        for (const auto& ct : cts) {
            for (const auto& e : ct.E) {
                // Mengambil koefisien 'lo' dari weight Fp
                // Dalam Bounty V3, ini sering berisi delta atau pesan langsung
                uint64_t w_val = e.w.lo;
                if (w_val > 0) {
                    for (int j = 0; j < 8; ++j) {
                        uint8_t b = (uint8_t)((w_val >> (j * 8)) & 0xFF);
                        if (b != 0) stream.push_back(b);
                    }
                }
            }
        }

        std::cout << "Extracted " << stream.size() << " bytes from edges.\n\n";

        // Mencoba Brute XOR pada stream yang lebih besar ini
        for (int k = 0; k < 256; ++k) {
            std::string attempt = "";
            int valid = 0;
            for (size_t i = 0; i < stream.size() && i < 100; ++i) { // Cek 100 byte pertama
                char c = (char)(stream[i] ^ k);
                if (c >= 32 && c <= 126) {
                    attempt += c;
                    valid++;
                } else {
                    attempt += '.';
                }
            }
            if (valid > 40) { // Jika lebih dari 40% terbaca sebagai ASCII
                std::cout << "Key [" << std::setw(3) << k << "]: " << attempt << "\n";
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    return 0;
}