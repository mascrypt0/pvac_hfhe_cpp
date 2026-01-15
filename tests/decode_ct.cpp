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

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
    auto ver = io::get32(i);
    if (magic != Magic::PK || ver != Magic::VER) throw std::runtime_error("bad pk header");
    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    pk.prm.tuple2_fraction = io::get64(i);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);
    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));
    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));
    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));
    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);
    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);
    return pk;
};

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";
    auto ct_path = dir + "/seed.ct";
    auto pk_path = dir + "/pk.bin";

    try {
        auto cts = loadCts(ct_path);
        auto pk = loadPk(pk_path);
        uint32_t B = pk.prm.B;

        std::cout << "--- BOUNTY V3: PK-MATRIX BIT EXTRACTION ---\n";
        
        std::vector<uint32_t> m_values;
        for (const auto& ct : cts) {
            for (const auto& L : ct.L) {
                if (L.rule == RRule::BASE) m_values.push_back(L.seed.ztag % B);
            }
        }

        std::vector<uint8_t> final_bytes;
        uint8_t current_byte = 0;
        int bit_count = 0;

        for (uint32_t m : m_values) {
            if (m < pk.H.size()) {
                // Akses manual bit ke-0 dari BitVec baris ke-m
                // BitVec biasanya menyimpan bit dalam array 'w' (uint64_t)
                bool bit = (pk.H[m].w[0] & 1); 
                
                if (bit) current_byte |= (1 << bit_count);
                
                bit_count++;
                if (bit_count == 8) {
                    final_bytes.push_back(current_byte);
                    current_byte = 0;
                    bit_count = 0;
                }
            }
        }

        std::cout << "Collected indices: " << m_values.size() << "\n";
        std::cout << "Recovered Data: ";
        for (uint8_t b : final_bytes) {
            if (b >= 32 && b <= 126) std::cout << (char)b;
            else std::cout << "[" << (int)b << "]";
        }
        std::cout << "\n-------------------------------------------\n";

        // Jika hasilnya masih kosong, kita coba ambil bit m dari baris 0
        std::cout << "Alternative (Bit m of Row 0): ";
        current_byte = 0; bit_count = 0;
        for (uint32_t m : m_values) {
            size_t word_idx = m / 64;
            size_t bit_idx = m % 64;
            if (word_idx < pk.H[0].w.size()) {
                bool bit = (pk.H[0].w[word_idx] >> bit_idx) & 1;
                if (bit) current_byte |= (1 << bit_count);
                bit_count++;
                if (bit_count == 8) {
                    std::cout << (char)((current_byte >= 32 && current_byte <= 126) ? current_byte : '.');
                    current_byte = 0; bit_count = 0;
                }
            }
        }
        std::cout << "\n";

    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }

    return 0;
}