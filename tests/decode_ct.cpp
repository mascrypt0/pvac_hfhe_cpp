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
    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL); C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        i.seekg(nE * (4 + 2 + 1 + 1 + 16 + 8), std::ios::cur); // Skip edges for speed
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
        uint32_t B = 337; // Parameter pk.B dari hasil sebelumnya

        std::vector<uint32_t> m_values;
        for (const auto& ct : cts) {
            for (const auto& L : ct.L) {
                if (L.rule == RRule::BASE) m_values.push_back(L.seed.ztag % B);
            }
        }

        std::cout << "--- BOUNTY V3: MODULO SHIFT BRUTEFORCE ---\n";
        std::cout << "Target: Find a shift 's' where (m - s) % B is ASCII.\n\n";

        // Mencoba setiap kemungkinan pergeseran s dari 0 sampai 336
        for (uint32_t s = 0; s < B; ++s) {
            std::string attempt = "";
            bool looks_valid = false;
            int printable_count = 0;

            for (uint32_t m : m_values) {
                // Persamaan: (m - s) mod B
                int32_t decoded = (int32_t)m - (int32_t)s;
                while (decoded < 0) decoded += B;
                decoded %= B;

                if (decoded >= 32 && decoded <= 126) {
                    attempt += (char)decoded;
                    printable_count++;
                } else {
                    attempt += "?";
                }
            }

            // Jika lebih dari 60% karakter terbaca, tampilkan
            if (printable_count > (m_values.size() * 0.6)) {
                std::cout << "Shift [" << std::setw(3) << s << "]: " << attempt << "\n";
            }
        }
        std::cout << "\n-------------------------------------------\n";

    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }

    return 0;
}