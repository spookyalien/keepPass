#include <string>
#include "Utility/cpputility.h"
#include "PassClass.h"
#include "PBKDF/pkbdf2.h"
#include "AES/aes.h"

void launch()
{
    KeepPass pass;
    std::string user_input = "";
    printf("--------------------------------\n");
    printf("\tWelcome to KeepPass\t\n");
    printf("--------------------------------\n");
    print_menu();
    while (user_input.compare("4") != 0) {
        //std::cin >> user_input;
        switch (stoi_with_check(user_input)) {
        case 1:
            pass.add_pass("5");
            break;
        case 2:
            pass.remove_pass("^");
            break;
        case 3:
            pass.print_pass("7");
            break;
        default:
            printf("[!] Invalid input.\n");
        }
        print_menu();
    }
    printf("Exiting...\n");
}

int main()
{

    /*         ----------------HMAC------------ -

    unsigned char key[SHA1_HASH_SIZE];
    HMAC((unsigned char*)"test", (unsigned char*)"test string", key);
    for (int i = 0; i < 20; ++i)
    {
        printf("%02X", key[i]);
    }
    printf("\n");
    */
    


        /*          --------------SHA 1-------- -
     #define TEST2 "xyz"
    SHA1_CTX sha;
    uint8_t msg_digest[20];
    SHA1_reset(&sha);
    SHA1_input(&sha, (const unsigned char*)TEST2, strlen(TEST2));
    int err;

    err = SHA1_result(&sha, msg_digest);
    if (err)
    {
        fprintf(stderr,
            "SHA1Result Error %d, could not compute message digest.\n",
            err);
    }
    else
    {
        printf("\t");
        for (int i = 0; i < 20; ++i)
        {
            printf("%02X", msg_digest[i]);
        }
        printf("\n");
    } 
    */



    /*          --------------AES-------- -
    const char* txt = "asidlhgfyiuyguaysdgdcvetwee";
    const char* k = "abcdefghijklmnop";
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
    printCharArr(key, 16);
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

    //launch();
}