#include <iostream>
#include <string>
#include "Utility/cpputility.h"
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
            pass.remove_pass();
            break;
        case 3:
            pass.print_pass();
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
    const char* txt = "asidlhgfyiuyguaysdgdcvetwee";
    const char* k = "abcdefghijklmnop";
    const char* ivv = "zyxwvutsrqabcdef";
    unsigned char* key = (unsigned char*)k;
    unsigned char* text = (unsigned char*)txt;
    unsigned char* iv = (unsigned char*)ivv;
    unsigned char* cipher = NULL;
    unsigned char* dec = NULL;

    int encr_len = aes_encrypt(text, 27, key, AES_256, AES_CTR, iv, &cipher);
    int decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_CTR, iv, &dec);

    printf("==============AES_CTR\n");
    printf("plain text: ");
    printCharArr(text, 27, false);
    printf("Key: ");
    printCharArr(key, 16, false);
    printf("Cipher: ");
    printCharArr(cipher, encr_len, false);
    printf("Decrypted: ");
    printCharArr(dec, decr_len, false);

    encr_len = aes_encrypt(text, 27, key, AES_256, AES_ECB, NULL, &cipher);
    decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_ECB, NULL, &dec);

    printf("\n==============AES_ECB\n");
    printf("plain text: ");
    printCharArr(text, 27, false);
    printf("Key: ");
    printCharArr(key, 16, false);
    printf("Cipher: ");
    printCharArr(cipher, encr_len, false);
    printf("Decrypted: ");
    printCharArr(dec, decr_len, false);

    encr_len = aes_encrypt(text, 27, key, AES_256, AES_CBC, iv, &cipher);
    decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_CBC, iv, &dec);

    printf("\n==============AES_CBC\n");
    printf("plain text: ");
    printCharArr(text, 27, false);
    printf("Key: ");
    printCharArr(key, 16, false);
    printf("Cipher: ");
    printCharArr(cipher, encr_len, false);
    printf("Decrypted: ");
    printCharArr(dec, decr_len, false);

    free(cipher);
    free(dec);

    //launch();
}