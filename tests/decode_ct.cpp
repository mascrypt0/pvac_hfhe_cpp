#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <iterator>

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";
    std::string path = dir + "/seed.ct";
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Gagal membuka file: " << path << std::endl;
        return 1;
    }

    // Membaca file dengan cara yang lebih stabil
    std::vector<uint8_t> buffer;
    file.unsetf(std::ios::skipws);
    buffer.insert(buffer.begin(), std::istream_iterator<uint8_t>(file), std::istream_iterator<uint8_t>());

    if (buffer.empty()) {
        std::cerr << "File kosong atau tidak terbaca." << std::endl;
        return 1;
    }

    std::cout << "--- BOUNTY V3: RAW SCANNER (Size: " << buffer.size() << " bytes) ---\n";

    // Teknik 1: Cari string ASCII murni
    std::string current = "";
    for (uint8_t b : buffer) {
        if (b >= 32 && b <= 126) {
            current += (char)b;
        } else {
            if (current.length() >= 8) { 
                std::cout << "[ASCII Found]: " << current << "\n";
            }
            current = "";
        }
    }

    // Teknik 2: Brute Force XOR
    for (int k = 1; k < 256; ++k) {
        int word_hits = 0;
        std::string temp_word = "";
        for (size_t i = 0; i < buffer.size(); ++i) {
            char c = (char)(buffer[i] ^ k);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                temp_word += c;
            } else {
                if (temp_word.length() >= 4) word_hits++;
                temp_word = "";
            }

            // Jika pola kata bahasa Inggris terdeteksi (minimal 6 kata berdekatan)
            if (word_hits >= 6) {
                std::cout << "\n[!] Potential Mnemonic (XOR Key: " << k << ") at offset " << i << "\n";
                size_t start = (i > 100) ? i - 100 : 0;
                size_t end = (i + 200 < buffer.size()) ? i + 200 : buffer.size();
                
                for (size_t j = start; j < end; ++j) {
                    char pc = (char)(buffer[j] ^ k);
                    std::cout << ((pc >= 32 && pc <= 126) ? pc : '.');
                }
                std::cout << "\n";
                word_hits = 0; // Reset agar tidak flooding
            }
        }
    }

    std::cout << "\n--- Scan Selesai ---\n";
    return 0;
}