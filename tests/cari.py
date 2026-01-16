from mnemonic import Mnemonic
import nacl.signing
import base58

def index_xor_bruteforce():
    indices = [204, 768, 1071, 45, 32, 1558, 1, 546, 1111, 0, 512, 1781, 256, 1, 0, 771, 
               298, 1487, 1798, 1128, 1022, 512, 632, 41, 528, 479, 512, 768, 1, 1, 
               1136, 0, 910, 1581, 32, 1, 649, 768, 1528, 1571, 1536, 109, 150, 0, 
               1144, 1942, 32, 803, 33, 256, 655, 1536, 1428, 0, 911, 31, 258, 83, 
               1280, 680, 768, 371, 0, 1379, 29, 735, 159, 256, 1, 32, 0, 644, 290, 
               1024, 1226, 1792, 1511, 512, 1604, 270, 1996, 1025, 1652, 933, 1290, 
               1792, 1031, 495, 1792, 0, 32, 1, 578, 0, 1501, 984, 1024, 1072, 73, 
               1492, 0, 512, 935, 0, 876, 1280, 1316, 0, 650, 1024, 1628, 272, 256, 
               51, 0, 937, 244, 1, 707, 761, 0, 1024, 68, 32, 1150, 1978, 0, 1536, 
               1317, 1950, 167, 1024, 108, 1164, 0, 1016, 512, 1897, 125, 1560, 0, 
               1024, 532, 1308, 708, 768, 1284, 614, 32, 1, 0, 421, 1024, 1250, 1796, 
               32, 1, 1, 3, 0, 1041, 456, 32, 1169, 327, 1280, 386, 512, 1980, 1536, 
               0, 775, 69, 448, 0, 1611, 390, 408, 32, 0, 1474, 231, 1590, 0, 630, 135, 
               1280, 0, 1294, 768, 214, 1024, 15, 793, 1280, 1, 32, 722, 94, 1555, 
               1821, 446, 1013, 265, 1525, 0, 0, 651, 153, 1571, 1452, 93, 1879, 321, 
               768, 1060, 0, 1863, 32, 0, 1, 208, 77, 1686, 0, 1511, 1280, 1, 461, 
               512, 423, 1792, 389, 1796, 1451, 183, 1024, 861, 852, 1792, 32, 32, 
               1908, 179, 1024, 79, 714, 32, 0, 745, 1278, 1873, 1686, 90, 1280, 
               1899, 1536, 72, 644, 0, 1995, 0, 168, 852]
    
    target = "oct7rAAiRhdRvKChDQrTJEAUqM9M9sfTBGQsacqME18xe1V"
    mnemo = Mnemonic("english")
    wordlist = mnemo.wordlist

    print("Starting Deep XOR Scan on indices...")

    for mask in range(2048):
        # Terapkan XOR mask ke setiap indeks
        masked_indices = [(idx ^ mask) % 2048 for idx in indices]
        
        for i in range(len(masked_indices) - 12):
            chunk = masked_indices[i:i+12]
            phrase = " ".join([wordlist[idx] for idx in chunk])
            
            if mnemo.check(phrase):
                seed = mnemo.to_seed(phrase)
                sk = nacl.signing.SigningKey(seed[:32])
                pk = sk.verify_key.encode()
                addr = f"oct7r{base58.b58encode(pk).decode('utf-8')}"
                
                if addr == target:
                    print(f"\n[!!!] WINNER FOUND!")
                    print(f"XOR Mask: {mask}")
                    print(f"Offset:   {i}")
                    print(f"Mnemonic: {phrase}")
                    return
        
        if mask % 200 == 0:
            print(f"Progress: Mask {mask}/2048 checked...", end='\r')

    print("\nScan selesai. Tidak ada kecocokan ditemukan.")

index_xor_bruteforce()