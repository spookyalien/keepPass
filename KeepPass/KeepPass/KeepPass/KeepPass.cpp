#include <iostream>
#include <string>
#include "cpputility.h"
#include "PassClass.h"

void launch()
{
    KeepPass pass;
    std::string user_input = "";
    std::cout << "--------------------------------\n";
    std::cout << "\tWelcome to KeepPass\t\n";
    std::cout << "--------------------------------\n";
    print_menu();
    while (user_input.compare("4") != 0) {
        std::cin >> user_input;
        switch (stoi_with_check(user_input)) {
        case 1:
            pass.add_pass();
            break;
        case 2:
            break;
        case 3:
            break;
        default:
            std::cout << "[!] Invalid input.\n";
        }
        print_menu();
    }
    std::cout << "Exiting...\n";
}


int main()
{
    const char* text = "asidlhgfyiuyguaysdgbagasdcvetwee";
    const char* key = "abcdefghijklmnop";
    unsigned char* k = (unsigned char*)key;
    unsigned char* txt = (unsigned char*)text;
    unsigned char* cipher = NULL;
    unsigned char* dec = NULL;

    int n_blocks = aes_encrypt(txt, 32, k, AES_128, &cipher);
    int len = aes_decrypt(cipher, n_blocks, k, AES_128, &dec);
    printf("plain text: ");
    printCharArr(txt, 32, false);
    printf("Key: ");
    printCharArr(k, 16, false);
    printf("Cipher: ");
    printCharArr(cipher, n_blocks*BLOCK_LEN, false);
    printf("Decrypted: ");
    printCharArr(dec, len, false);
    
    free(cipher);
    free(dec);
    //launch();
}