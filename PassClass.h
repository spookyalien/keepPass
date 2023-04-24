#ifndef PASSCLASS_H
#define PASSCLASS_H

#include <string>
#include <iostream>
#include <fstream>
#include "Utility/cpputility.h"
#include "PBKDF/pbkdf2.h"
#include "AES/aes.h"

class KeepPass
{
    public:
        void add_pass(unsigned char* key);
        void remove_pass(unsigned char* key);
        void print_pass(unsigned char* key);
        void reset_pass();

};


void KeepPass::add_pass(unsigned char* key)
{
    std::ofstream pass_file("pass.txt");
    std::string new_pass;

    printf("[+] Please enter the password to store: ");
    std::cin >> new_pass;
}

void KeepPass::remove_pass(unsigned char* key)
{

}
void KeepPass::print_pass(unsigned char* key)
{

}

void KeepPass::reset_pass() 
{
    if( remove("key.asc") != 0 && remove("pass.txt") != 0)
        perror("Error deleting file");
    else
        puts( "File successfully deleted");
    
    return;
}

#endif