#include "PassClass.h"

unsigned char* verify_pass()
{
    std::string master_key = "";
    char hex_str_key[DK_LEN*2];
    unsigned char* master_key_encr;
    std::string salt;
    int salt_len;
    int round_count;

    printf("[!] Enter master password: ");
    std::cin >> master_key;
    
    
    std::ifstream file("key.asc");

    if (file.peek() == std::ifstream::traits_type::eof()) {
        std::string temp;
        printf("[!] Enter length of salt to use for master key: ");
        std::cin >> temp;
        salt_len = stoi_with_check(temp);
        printf("[!] Enter number of rounds to use for master key: ");
        std::cin >> temp;
        round_count = stoi_with_check(temp);

        if (salt_len == 0) {
            printf("[!] Error with user input salt length. Resetting to 16...\n");
            salt_len = 16;
        }
        if (round_count == 0) {
            printf("[!] Error with user input round count. Resetting to 100000...\n");
            round_count = 100000;
        }

        salt = generate_salt(salt_len);
        PBKDF2((unsigned char*) master_key.c_str(), master_key.length(), (unsigned char*) salt.c_str(), salt_len, round_count, DK_LEN, &master_key_encr);

        std::ofstream file("key.asc");
        file << salt << std::endl;
        file << salt_len << std::endl;
        file << round_count << std::endl;
    }
    else {
        std::string line;
        std::getline(file, line);
        salt = line;
        std::getline(file, line);
        salt_len = stoi_with_check(line);
        std::getline(file, line);
        round_count = stoi_with_check(line);
        PBKDF2((unsigned char*) master_key.c_str(), master_key.length(), (unsigned char*) salt.c_str(), salt_len, round_count, DK_LEN, &master_key_encr);
    }

    master_key = "";
    file.close();

    return master_key_encr;
}

void launch()
{
    KeepPass pass;
    std::string user_input = "";

    printf("--------------------------------\n");
    printf("\tWelcome to KeepPass\t\n");
    printf("--------------------------------\n");
    unsigned char* master_key = verify_pass();
    for (int i = 0; i < DK_LEN; i++) {
        printf("%02X ", master_key[i]);
    }
    print_menu();
    while (true) {
        printf("> ");
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
            pass.reset_pass();
            break;
        case 5:
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
