#ifndef PASSCLASS_H
#define PASSCLASS_H

#include <fstream>
#include "Utility/cpputility.h"
#include "PBKDF/pbkdf2.h"
#include "AES/aes.h"

#define DEFAULT_ROUNDS 600000
#define DEFAULT_SALT_LEN 16

class KeepPass
{
    public:
        void add_pass(unsigned char* key);
        void remove_pass(unsigned char* key);
        void print_pass(unsigned char* key);
        void reset_pass();
        const char* pass_txt = "pass.txt";
    private:
        struct structure
        {
            std::string word;
            unsigned char* iv;
            unsigned char* cipher;
            int encr_len;
        };
        void write_pass(structure item, unsigned char* key);
};


void KeepPass::write_pass(KeepPass::structure item, unsigned char* key)
{
    std::ofstream pass_file(pass_txt, std::ios::app);
    const char hex[17] = "0123456789ABCDEF";

    std::getline(std::cin, item.word);
    std::string iv = generate_salt(DEFAULT_SALT_LEN);
    auto iv_chrs = iv.c_str();
    item.iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv_chrs));

    auto pass_chrs = item.word.c_str();
    unsigned char* tmp = reinterpret_cast<unsigned char*>(const_cast<char*>(pass_chrs));
    item.encr_len = aes_encrypt(tmp, item.word.size(), key, AES_256, AES_CBC, item.iv, &item.cipher);

    // Clear sensitive info
    memset(tmp, 0, item.word.size());
    item.word.resize(item.word.capacity(), 0);
    cleanse(&item.word[0], item.word.size());
    item.word.clear();

    for (int i = 0; i < item.encr_len; i++) {
        pass_file << hex[item.cipher[i] >> 4] << hex[item.cipher[i] & 0x0f];
    }
    pass_file << item.iv << item.encr_len << std::endl;
}

void KeepPass::add_pass(unsigned char* key)
{
    structure site;
    structure pass;
 
    printf("[+] Enter site for this password to be used: ");
    write_pass(site, key);
    printf("[+] Please enter the password to store: ");
    write_pass(pass, key);
}

void KeepPass::remove_pass(unsigned char* key)
{

}
void KeepPass::print_pass(unsigned char* key)
{
    std::ifstream pass_file(pass_txt, std::ios::out);
    std::string line;
    unsigned char* dec = NULL;

    if (pass_file.is_open()) {
        while (std::getline(pass_file, line)) {
            try {
                int len = line.size() - 2 - DEFAULT_SALT_LEN;
                int num = stoi_with_check(line.substr(line.size() - 2, 2));
                std::string iv_str = line.substr(len, DEFAULT_SALT_LEN);
                std::string encr_pass = line.substr(0, len);
                auto iv_chrs = iv_str.c_str();

                unsigned char* iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv_chrs));
                unsigned char* cipher = hexStringToUnsignedChar(encr_pass);
                int decr_len = aes_decrypt(cipher, num, key, AES_256, AES_CBC, iv, &dec);
                std::cout << dec << std::endl;
            }
            catch (std::out_of_range e) {}
        }
    }

    pass_file.close();
}

void KeepPass::reset_pass() 
{
    if( remove("key.asc") == 0 && remove("pass.txt") == 0)
        puts( "File successfully deleted");
    
    return;
}

#endif