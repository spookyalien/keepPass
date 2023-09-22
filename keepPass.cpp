#include "PassClass.h"

#include <stdio.h>

#ifdef _WIN32 
#include <Windows.h>

void* allocate_memory(size_t size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

void free_memory(void* memory, size_t size) {
    VirtualFree(memory, 0, MEM_RELEASE);
}

#else // Code for Unix-like platforms
#include <sys/mman.h>
#include <errno.h>

void* allocate_memory(size_t size) {
    void* memory = malloc(size);
    
    if (memory == NULL) {
        perror("malloc");
        return NULL;
    }
    
    if (mlock(memory, size) != 0) {
        perror("mlock");
        free(memory);
        return NULL;
    }
    
    return memory;
}

void free_memory(void* memory, size_t size) {
    if (munlock(memory, size) != 0) {
        perror("munlock");
    }
    
    free(memory);
}

#endif

bool keepPassMenu::OnInit()
{
    wxDisplay disp;
    wxRect disp_rect = disp.GetClientArea();
    keepPassFrame* frame = new keepPassFrame("keepPass", wxPoint((disp_rect.GetWidth() - WINDOW_X) / 2, (disp_rect.GetHeight() - WINDOW_Y) / 2), wxSize(WINDOW_X, WINDOW_Y));
    frame->Show(true);
    return true;
}

int keepPassFrame::verify_pass(unsigned char** master_key)
{
    wxTextEntryDialog* pass_input = new wxTextEntryDialog(this, "Enter master password.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    pass_input->CenterOnScreen();
    int result = pass_input->ShowModal();

    if (result != wxID_OK)
        exit(0);
    std::string pass = pass_input->GetValue().ToStdString();
    std::string salt;
    int key_len;
    int salt_len = 16;
    int round_count = 100000;
    const char hex[17] = "0123456789ABCDEF";

    std::ifstream file("key.asc");

    // Master hash not created yet add as normal
    if (file.peek() == std::ifstream::traits_type::eof()) {
        salt = generate_salt(salt_len);
        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(pass.c_str())), pass.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, master_key);
        std::ofstream file("key.asc");
        file << salt << std::endl;
        file << round_count << std::endl;
        file << salt_len << std::endl;
    } 
    else {
        std::string line;
        std::getline(file, line);
        salt = line;
        std::getline(file, line);
        round_count = stoi_with_check(line);
        std::getline(file, line);
        salt_len = stoi_with_check(line);
        std::getline(file, line);

        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(pass.c_str())), pass.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, master_key);
    }

    return key_len;
}

keepPassFrame::keepPassFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    master_key = (unsigned char*) allocate_memory(DK_LEN);
    key_length = verify_pass(&master_key);
    wxBoxSizer* menu_sizer = new wxBoxSizer(wxHORIZONTAL);
    auto menuFile = new wxMenu();
    auto menuItemFileQuit = menuFile->Append(wxID_EXIT);
    menuItemFileQuit->SetBitmap(wxArtProvider::GetBitmap(wxART_QUIT, wxART_MENU));
    auto menuEdit = new wxMenu();
    menuEdit->Append(wxID_PREFERENCES);

    auto menuHelp = new wxMenu();
    menuHelp->Append(wxID_ABOUT);

    unlock_pass = new wxButton(this, BUTTON_UNLOCK, _T("Unlock All"), wxDefaultPosition, wxDefaultSize, 0);
    add_pass = new wxButton(this, BUTTON_ADD, _T("Add Password"), wxDefaultPosition, wxDefaultSize, 0);
    del_pass = new wxButton(this, BUTTON_DEL, _T("Remove Password"), wxDefaultPosition, wxDefaultSize, 0);

    unlock_pass->SetBackgroundColour(wxColour(0, 255, 0));
    unlock_pass->SetForegroundColour(wxColour(0, 0, 0));

    menu_sizer->Add(unlock_pass, 0, wxALL, 5);
    menu_sizer->Add(add_pass, 0, wxALL, 5);
    menu_sizer->Add(del_pass, 0, wxALL, 5);

    wxBoxSizer* box_sizer = new wxBoxSizer(wxHORIZONTAL);

    site_list = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, nullptr);
    user_list = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, nullptr);
    pass_list = new wxListBox(this, wxID_ANY, wxDefaultPosition);



    box_sizer->Add(site_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));
    box_sizer->Add(user_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));
    box_sizer->Add(pass_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));


    main_menu->Append(menuFile, "&File");
    main_menu->Append(menuEdit, "&Edit");

    wxBoxSizer* top_sizer = new wxBoxSizer(wxVERTICAL);
    top_sizer->Add(menu_sizer, 0, wxEXPAND);
    top_sizer->Add(box_sizer, 1, wxEXPAND);

    this->SetSizer(top_sizer);
    this->SetMenuBar(main_menu);
    this->Connect(wxEVT_CLOSE_WINDOW, wxCloseEventHandler(keepPassFrame::on_close));
    this->Layout();

}


void keepPassFrame::unlock_all(wxCommandEvent& event)
{
    std::ifstream pass_file("pass.txt", std::ios::app);
    
    if (pass_file.peek() == std::ifstream::traits_type::eof()) {
        wxMessageBox( wxT("No passwords present."), wxT("Error"), wxICON_INFORMATION);
    }
    else {
        if (pass_file.is_open()) {
            std::string line;
            int len_length = 2;
            while (std::getline(pass_file, line)) {
                std::vector<std::string> site_pass = split(line, DELIMITER);
                int count = 0;
                for (auto entry : site_pass) {
                    unsigned char* dec = NULL;
                    std::string num = entry.substr(entry.size() - len_length, len_length);
                    int len = std::stoi(num);
                    std::string iv_str = entry.substr(entry.size() - len_length - DEFAULT_LEN, DEFAULT_LEN);
                    std::string encr_pass = entry.substr(0, entry.size() - len_length - DEFAULT_LEN);
                    auto ciph_chrs = encr_pass.c_str();
                    auto iv_chrs = iv_str.c_str();

                    unsigned char* iv = reinterpret_cast<unsigned char*>(const_cast<char*>(iv_chrs));
                    unsigned char *cipher = (unsigned char*)malloc(len);
                    hex_str(encr_pass, cipher, len);

                    int decr_len = aes_decrypt(cipher, len, master_key, AES_256, AES_CBC, iv, &dec);
                    switch (count) {
                        case 0:
                            site_list->Append(dec);
                            break;
                        case 1:
                            user_list->Append(dec);
                            break;
                        case 2:
                            pass_list->Append(dec);
                            break;
                    }
                    count += 1;
                }
            }
        }
    }
}


void keepPassFrame::on_password(wxCommandEvent& event)
{
    wxTextEntryDialog* site_input = new wxTextEntryDialog(this, "Enter name of site to add.", "keepPass", wxEmptyString, wxOK);
    wxTextEntryDialog* name_input = new wxTextEntryDialog(this, "Enter Username.", "keepPass", wxEmptyString, wxOK);
    wxTextEntryDialog* pass_input = new wxTextEntryDialog(this, "Enter password to add.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    
    if (pass_input->ShowModal() == wxID_OK && site_input->ShowModal() == wxID_OK) {
        std::string password = pass_input->GetValue().ToStdString();
        std::string site_name = site_input->GetValue().ToStdString();
        std::string username = name_input->GetValue().ToStdString();
        std::ofstream pass_file("pass.txt", std::ios::app);
        const char hex[17] = "0123456789ABCDEF";
        pass_format site;
        pass_format pass;
        pass_format user;

        std::string site_iv = generate_salt(DEFAULT_LEN);
        std::string pass_iv = generate_salt(DEFAULT_LEN);
        std::string user_iv = generate_salt(DEFAULT_LEN);

        pass.iv = reinterpret_cast<unsigned char*>(const_cast<char*>(pass_iv.c_str()));
        site.iv = reinterpret_cast<unsigned char*>(const_cast<char*>(site_iv.c_str()));
        user.iv = reinterpret_cast<unsigned char*>(const_cast<char*>(user_iv.c_str()));
        unsigned char* pass_uchar = reinterpret_cast<unsigned char*>(const_cast<char*>(password.c_str()));
        unsigned char* site_uchar = reinterpret_cast<unsigned char*>(const_cast<char*>(site_name.c_str()));
        unsigned char* user_uchar = reinterpret_cast<unsigned char*>(const_cast<char*>(username.c_str()));
        pass.len = aes_encrypt(pass_uchar, password.size(), master_key, AES_256, AES_CBC, pass.iv, &pass.cipher);
        site.len = aes_encrypt(site_uchar, site_name.size(), master_key, AES_256, AES_CBC, site.iv, &site.cipher);
        user.len = aes_encrypt(user_uchar, site_name.size(), master_key, AES_256, AES_CBC, user.iv, &user.cipher);

        for (int i = 0; i < site.len; i++) {
            pass_file << hex[site.cipher[i] >> 4] << hex[site.cipher[i] & 0x0f];
        }
        pass_file << site_iv << site.len;

        pass_file << DELIMITER;

        for (int i = 0; i < user.len; i++) {
            pass_file << hex[user.cipher[i] >> 4] << hex[user.cipher[i] & 0x0f];
        }
        pass_file << user_iv << user.len;
        
        pass_file << DELIMITER;
        
        for (int i = 0; i < pass.len; i++) {
            pass_file << hex[pass.cipher[i] >> 4] << hex[pass.cipher[i] & 0x0f];
        }
        pass_file << pass_iv << pass.len; 


        pass_input->Destroy();
        site_input->Destroy();
    }
    else {
        pass_input->Destroy();
        site_input->Destroy();
    }
}

void keepPassFrame::on_exit(wxCommandEvent& event)
{
    Close(true);
}

void keepPassFrame::on_about(wxCommandEvent& event)
{
    wxMessageBox("This is a password manager that aims to keep passwords safe and accessible using AES256 and PBKDF2.",
        "About keepPass", wxOK | wxICON_INFORMATION);
}

void keepPassFrame::on_close(wxCloseEvent& event)
{
    free_memory(master_key, DK_LEN);
    Destroy();
    wxGetApp().ExitMainLoop();
}


// -----------------------------
// EXAMPLES OF ENCRYPTION/HASHING
// -----------------------------
/*
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
free(dec); */

// unsigned char* out;
// int len = PBKDF2((unsigned char*) "passwordPASSWORDpassword", 24, (unsigned char*) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 40960, 25, &out);
// printf("%d\n", len);
// for (int i = 0; i < len; i++) {
//         printf("%02X ", out[i]);
// }
// printf("\n");


//launch();
//}