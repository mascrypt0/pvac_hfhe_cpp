#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";
    std::string path = dir + "/seed.ct";
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Gagal membuka file: " << path << std::endl;
        return 1;
    }

    // Baca seluruh file ke memori
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "--- BOUNTY V3: RAW SCANNER (Memory Size: " << buffer.size() << " bytes) ---\n";

    // Teknik 1: Cari string ASCII yang terjepit di antara nol
    std::cout << "Mencari string ASCII tersembunyi...\n";
    std::string current = "";
    for (uint8_t b : buffer) {
        if (b >= 32 && b <= 126) {
            current += (char)b;
        } else {
            if (current.length() >= 5) { // Hanya tampilkan jika minimal 5 karakter
                std::cout << "[Ditemukan]: " << current << "\n";
            }
            current = "";
        }
    }

    // Teknik 2: Brute Force XOR seluruh isi file
    // Mnemonic sering di-XOR dengan kunci statis
    std::cout << "\nScanning dengan Brute Force XOR (Mencari pola kata)...\n";
    for (int k = 1; k < 256; ++k) {
        int word_hits = 0;
        std::string line = "";
        for (size_t i = 0; i < buffer.size(); ++i) {
            char c = (char)(buffer[i] ^ k);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                line += c;
            } else if (c == ' ') {
                if (line.length() >= 3) word_hits++;
                line = "";
            } else {
                line = "";
            }

            // Jika dalam blok kecil ditemukan banyak kata, tampilkan
            if (word_hits >= 5) {
                std::cout << "Kunci Potensial [" << k << "] ditemukan di offset " << i << "\n";
                // Cetak area sekitar
                for (size_t j = i - 50; j < i + 150 && j < buffer.size(); ++j) {
                    char print_c = (char)(buffer[j] ^ k);
                    std::cout << ((print_c >= 32 && print_c <= 126) ? print_c : '.');
                }
                std::cout << "\n\n";
                break; 
            }
        }
    }

    std::cout << "------------------------------------------\n";
    return 0;
}