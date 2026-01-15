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
        i.seekg(nE * (4 + 2 + 1 + 1 + 16 + 8), std::ios::cur); // Skip edges safe-way
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
        uint32_t B = 337; 

        std::cout << "--- BOUNTY V3: PRF-KEYSTREAM DECODING ---\n\n";

        std::string result = "";

        for (size_t i = 0; i < cts.size(); ++i) {
            for (const auto& L : cts[i].L) {
                if (L.rule == RRule::BASE) {
                    // Gunakan ztag sebagai representasi m
                    // Gunakan nonce sebagai mask
                    uint64_t m = L.seed.ztag % B;
                    
                    // Kita coba beberapa kemungkinan kombinasi nonce
                    // 1. (m ^ nonce_low_8bit)
                    uint8_t key = (uint8_t)(L.seed.nonce.lo & 0xFF);
                    uint32_t decoded = (uint32_t)(m ^ key) % B;

                    if (decoded >= 32 && decoded <= 126) result += (char)decoded;
                    else result += "?";
                }
            }
        }

        std::cout << "Attempt 1 (Ztag % B ^ Nonce_Byte): " << result << "\n";

        // Attempt 2: Mencoba pergeseran (shift) dinamis
        result = "";
        for (size_t i = 0; i < cts.size(); ++i) {
            for (const auto& L : cts[i].L) {
                if (L.rule == RRule::BASE) {
                    uint64_t m = L.seed.ztag % B;
                    // Kadang nilai R adalah m - (index * konstanta)
                    int32_t c = (int32_t)m - (int32_t)(i * 7); // 7 adalah step umum
                    while (c < 0) c += B;
                    c %= B;
                    if (c >= 32 && c <= 126) result += (char)c;
                    else result += "?";
                }
            }
        }
        std::cout << "Attempt 2 (Linear Decay): " << result << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    return 0;
}