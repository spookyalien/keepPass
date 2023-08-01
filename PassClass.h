#ifndef PASSCLASS_H
#define PASSCLASS_H

#include <fstream>
#include "Utility/cpputility.h"
#include "PBKDF/pbkdf2.h"
#include "AES/aes.h"

#include <wx/wxprec.h>
#include <wx/display.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#define WINDOW_X 950
#define WINDOW_Y 540
#define BOX_X 300
#define BOX_Y 50

class keepPassMenu: public wxApp
{
    public:
        virtual bool OnInit();
};

class keepPassFrame: public wxFrame
{
    public:
        keepPassFrame(const wxString& title, const wxPoint& pos, const wxSize& size);
    private:
        void OnHello(wxCommandEvent& event);
        void OnEnterKey(wxCommandEvent& event);
        void OnExit(wxCommandEvent& event);
        void OnAbout(wxCommandEvent& event);
        wxDECLARE_EVENT_TABLE();
};

enum
{
    ID_Hello = 1
};

wxBEGIN_EVENT_TABLE(keepPassFrame, wxFrame)
EVT_MENU(ID_Hello,   keepPassFrame::OnHello)
EVT_MENU(wxID_EXIT,  keepPassFrame::OnExit)
EVT_MENU(wxID_ABOUT, keepPassFrame::OnAbout)
wxEND_EVENT_TABLE()
wxIMPLEMENT_APP(keepPassMenu);


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

    std::cin >> item.word;
    std::string iv = generate_salt(DEFAULT_LEN);
    auto iv_chrs = iv.c_str();
    item.iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv_chrs));

    auto pass_chrs = item.word.c_str();
    unsigned char* tmp = reinterpret_cast<unsigned char*>(const_cast<char*>(pass_chrs));
    
    item.encr_len = aes_encrypt(tmp, item.word.size(), key, AES_256, AES_CBC, item.iv, &item.cipher);
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
            std::string num = line.substr(line.size()-2, 2);
            int len = std::stoi(num);
            std::string iv_str = line.substr(line.size()-2-DEFAULT_LEN, DEFAULT_LEN);
            std::string encr_pass = line.substr(0, line.size()-2-DEFAULT_LEN);
            auto ciph_chrs = encr_pass.c_str();
            auto iv_chrs = iv_str.c_str();

            unsigned char* iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv_chrs));
            unsigned char* cipher = reinterpret_cast<unsigned char*>(const_cast<char*>(ciph_chrs));


            // FIXME: SEGFAULT 
            int decr_len = aes_decrypt(cipher, line.size()-2-DEFAULT_LEN, key, AES_256, AES_CBC, iv, &dec);
            std::cout << dec << std::endl;
        }
    }
    else 
        printf("[+] No active pass file...\n");

    pass_file.close();
}

void KeepPass::reset_pass() 
{
    if( remove("key.asc") == 0 && remove("pass.txt") == 0)
        puts( "File successfully deleted");
    
    return;
}

#endif