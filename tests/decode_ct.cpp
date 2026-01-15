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
        C.L.resize(nL); C.E.resize(nE);
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
    std::cout << "--- BOUNTY V3: ADVANCED R-EXTRACTION (XOR MODE) ---\n";

    auto ct_path = dir + "/seed.ct";
    if (!fs::exists(ct_path)) {
        std::cout << "Error: " << ct_path << " not found!\n";
        return 1;
    }

    try {
        auto cts = loadCts(ct_path);
        std::cout << "Loaded " << cts.size() << " ciphertexts.\n\n";

        std::string final_recovered = "";

        for (size_t i = 0; i < cts.size(); ++i) {
            std::cout << "CT[" << i << "]: ";
            for (const auto& L : cts[i].L) {
                if (L.rule == RRule::BASE) {
                    // Teknik Ekstraksi R: XOR antara ztag, nonce_lo, dan nonce_hi
                    uint64_t R = L.seed.ztag ^ L.seed.nonce.lo ^ L.seed.nonce.hi;
                    
                    std::cout << "R=" << std::hex << std::setw(16) << std::setfill('0') << R << " ";

                    // Convert hasil XOR ke ASCII bytes
                    for (int j = 0; j < 8; ++j) {
                        char c = (char)((R >> (j * 8)) & 0xFF);
                        if (c >= 32 && c <= 126) {
                            final_recovered += c;
                        } else if (c != 0) {
                            final_recovered += '?'; // Penanda karakter non-printable
                        }
                    }
                }
            }
            std::cout << std::dec << "\n";
        }

        std::cout << "\n--- RECOVERED MNEMONIC / MESSAGE ---\n";
        std::cout << final_recovered << "\n";
        std::cout << "------------------------------------\n";

    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }

    return 0;
}