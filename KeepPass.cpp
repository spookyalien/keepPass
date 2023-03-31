#include <string>
#include <iostream>
#include "Utility/cpputility.h"
//#include "Utility/utility.h"
#include "PassClass.h"
#include "PBKDF/pbkdf2.h"
#include "AES/aes.h"

int verify_master(std::string key)
{
    FILE* pass_file = fopen("key.asc","r+");
    const char* tmp_salt = "salt";
    unsigned char* key_to_match;
    unsigned char* salt = (unsigned char*) tmp_salt;
    char ch;

    int key_len = PBKDF2((unsigned char*) key.c_str(), key.length(), salt, strlen((const char*) salt), 40960, 25, &key_to_match);
    char hex_str[key_len];
    string2hexString(key_to_match, hex_str);

    if (is_empty_file(pass_file)) {
        fprintf(pass_file, hex_str);
    }
    else {
        int i = 0;
        do {

            ch = fgetc(pass_file);
            if (ch != EOF) {
                if (ch != hex_str[i]) 
                    return 0;
            }
            i++;
 
        } while (ch != EOF);
    }
    

    fclose(pass_file);
    return 1;
}

void launch()
{
    KeepPass pass;
    std::string user_input = "";
    std::string master_key = "";
    printf("--------------------------------\n");
    printf("\tWelcome to KeepPass\t\n");
    printf("--------------------------------\n");
    printf("[-] Enter the master key: ");
    std::cin >> master_key;
    if (verify_master(master_key)) {
        printf("[+] Key verified, proceed as normal...\n");
    }
    else {
        printf("[!] Error with key, exiting...\n");
        exit(0);
    }

    print_menu();
    while (true) {
        std::cin >> user_input;
        switch (stoi_with_check(user_input)) {
        case 1:
            pass.add_pass(master_key);
            break;
        case 2:
            pass.remove_pass(master_key);
            break;
        case 3:
            pass.print_pass(master_key);
            break;
        case 4:
            exit(0);
        default:
            printf("[!] Invalid input.\n");
        }
        print_menu();
    }
    printf("Exiting...\n");
}

int main()
{

    /*       ----------------HMAC------------ -

    unsigned char key[SHA1_HASH_SIZE];
    HMAC((unsigned char*)"test", (unsigned char*)"test string", key);
    for (int i = 0; i < 20; ++i)
    {
        printf("%02X", key[i]);
    }
    printf("\n");
    */
    


        /*      --------------SHA 1-------- -
     #define TEST2 "xyz"
    SHA1 sha;
    uint8_t msg_digest[20];
    sha = SHA1();
    sha.update((unsigned char*)TEST2, strlen(TEST2));
    sha.result(msg_digest);

        for (int i = 0; i < 20; ++i)
        {
            printf("%02X ", msg_digest[i]);
        }
        printf("\n");
    */


    /*          --------------AES-------- -
    const char* txt = "asidlhgfyiuyguaysdgdcvetwee";
    const char* k = "abcdefghijklmnopabcdefghijklmnop";
    const char* ivv = "zyxwvutsrqponmlk";
    unsigned char* key = (unsigned char*)k;
    unsigned char* text = (unsigned char*)txt;
    unsigned char* iv = (unsigned char*)ivv;
    unsigned char* cipher = NULL;
    unsigned char* dec = NULL;

    int encr_len = aes_encrypt(text, 27, key, AES_256, AES_CTR, iv, &cipher);
    int decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_CTR, iv, &dec);

    printf("==============AES_CTR\n");
    printf("plain text: ");
    printCharArr(text, 27);
    printf("Key: ");
    printCharArr(key, 16);
    printf("Cipher: ");
    printCharArr(cipher, encr_len);
    printf("Decrypted: ");
    printCharArr(dec, decr_len);

    encr_len = aes_encrypt(text, 27, key, AES_256, AES_ECB, NULL, &cipher);
    decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_ECB, NULL, &dec);

    printf("\n==============AES_ECB\n");
    printf("plain text: ");
    printCharArr(text, 27);
    printf("Key: ");
    printCharArr(key, 32);
    printf("Cipher: ");
    printCharArr(cipher, encr_len);
    printf("Decrypted: ");
    printCharArr(dec, decr_len);

    encr_len = aes_encrypt(text, 27, key, AES_256, AES_CBC, iv, &cipher);
    decr_len = aes_decrypt(cipher, encr_len, key, AES_256, AES_CBC, iv, &dec);

    printf("\n==============AES_CBC\n");
    printf("plain text: ");
    printCharArr(text, 27);
    printf("Key: ");
    printCharArr(key, 16);
    printf("Cipher: ");
    printCharArr(cipher, encr_len);
    printf("Decrypted: ");
    printCharArr(dec, decr_len);
    free(cipher);
    free(dec);
*/
    // unsigned char* out;
    // int len = PBKDF2((unsigned char*) "passwordPASSWORDpassword", 24, (unsigned char*) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 40960, 25, &out);
    // printf("%d\n", len);
    // for (int i = 0; i < len; i++) {
    //         printf("%02X ", out[i]);
    // }
    // printf("\n");
    
    launch();
}
