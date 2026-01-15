#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iterator>

int main(int argc, char** argv) {
    std::string path = (argc > 1) ? std::string(argv[1]) + "/seed.ct" : "bounty3_data/seed.ct";
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "File tidak ditemukan: " << path << std::endl;
        return 1;
    }

    // Cara paling aman membaca file ke vector byte
    std::vector<unsigned char> data;
    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

    if (data.empty()) {
        std::cerr << "File kosong!" << std::endl;
        return 1;
    }

    std::cout << "--- BOUNTY V3: RAW SCANNER (Bytes: " << data.size() << ") ---\n";

    // 1. Scan ASCII Langsung
    std::string current = "";
    for (size_t i = 0; i < data.size(); ++i) {
        unsigned char b = data[i];
        if (b >= 32 && b <= 126) {
            current += (char)b;
        } else {
            if (current.length() >= 8) {
                std::cout << "[Found]: " << current << "\n";
            }
            current = "";
        }
    }

    // 2. Scan XOR Brute Force
    for (int k = 1; k < 256; ++k) {
        int words = 0;
        std::string word = "";
        for (size_t i = 0; i < data.size(); ++i) {
            char c = (char)(data[i] ^ k);
            if (c >= 'a' && c <= 'z') {
                word += c;
            } else {
                if (word.length() >= 4) words++;
                word = "";
            }

            // Jika ketemu lebih dari 6 kata beruntun
            if (words >= 6) {
                std::cout << "\n[!] Potential Mnemonic (XOR Key: " << k << ")\n";
                size_t start = (i > 150) ? i - 150 : 0;
                size_t end = (i + 150 < data.size()) ? i + 150 : data.size();
                for (size_t j = start; j < end; ++j) {
                    char pc = (char)(data[j] ^ k);
                    std::cout << ((pc >= 32 && pc <= 126) ? pc : '.');
                }
                std::cout << "\n";
                words = 0; // stop flooding for this key
            }
        }
    }

    return 0;
}