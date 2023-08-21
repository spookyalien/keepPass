#include "PassClass.h"

bool verify_pass(std::string master_key)
{
    unsigned char* master_key_encr = NULL;
    std::string salt;
    int key_len;
    int salt_len = 16;
    int round_count = 100000;
    const char hex[17] = "0123456789ABCDEF";

    std::ifstream file("key.asc");

    // Master hash not created yet add as normal
    if (file.peek() == std::ifstream::traits_type::eof()) {
        salt = generate_salt(salt_len);
        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(master_key.c_str())), master_key.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key_encr);
        std::ofstream file("key.asc");
        file << salt << std::endl;
        file << round_count << std::endl;
        file << salt_len << std::endl;

        for (int i = 0; i < key_len; i++) {
            file << hex[master_key_encr[i] >> 4] << hex[master_key_encr[i] & 0x0f];
        }
        file << std::endl;
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
        std::cout << line << std::endl;
        auto ciph_chrs = line.c_str();
        unsigned char* cipher = new unsigned char[line.length() / 2];

        for (int i = 0; i < line.length(); i += 2) {
            std::istringstream iss(line.substr(i, 2));
            int hex_val;
            iss >> std::hex >> hex_val;
            cipher[i / 2] = static_cast<unsigned char>(hex_val);
        }


        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(master_key.c_str())), master_key.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key_encr);

        for (int i = 0; i < key_len; i++) {
            if (master_key_encr[i] != cipher[i]) {
                master_key.resize(master_key.capacity(), 0);
                cleanse(&master_key[0], master_key.size());
                master_key.clear();
                delete[] cipher;
                return false;
            }
        }
        delete[] cipher;
    }


    master_key.resize(master_key.capacity(), 0);
    cleanse(&master_key[0], master_key.size());
    master_key.clear();
    file.close();
    return true;
}

/*
void launch()
{
    KeepPass pass;
    std::string user_input = "";

    printf("--------------------------------\n");
    printf("\tWelcome to KeepPass\t\n");
    printf("--------------------------------\n");

    unsigned char* master_key = verify_pass();
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
            exit(0);
        case 5:
            exit(0);
        default:
            printf("[!] Invalid input.\n");
        }
        print_menu();
    }
    printf("Exiting...\n");
}
*/

bool keepPassMenu::OnInit()
{
    wxDisplay disp;
    wxRect disp_rect = disp.GetClientArea();
    keepPassFrame* frame = new keepPassFrame("keepPass", wxPoint((disp_rect.GetWidth() - WINDOW_X) / 2, (disp_rect.GetHeight() - WINDOW_Y) / 2), wxSize(WINDOW_X, WINDOW_Y));
    frame->Show(true);
    return true;
}

keepPassFrame::keepPassFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    wxTextEntryDialog* pass_input = new wxTextEntryDialog(this, "Enter master password.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    pass_input->CenterOnScreen();
    pass_input->Bind(wxEVT_TEXT_ENTER, &keepPassFrame::OnEnterKey, this, wxID_ANY);
    int result = pass_input->ShowModal();

    if (result == wxID_OK) {
        if (!verify_pass(pass_input->GetValue().ToStdString()))
            exit(0);
    }

    wxFlexGridSizer* fgSizer1;
    fgSizer1 = new wxFlexGridSizer(0, 2, 0, 0);
    fgSizer1->SetFlexibleDirection(wxBOTH);
    fgSizer1->SetNonFlexibleGrowMode(wxFLEX_GROWMODE_SPECIFIED);

    auto menuFile = new wxMenu();
    auto menuItemFileQuit = menuFile->Append(wxID_EXIT);
    menuItemFileQuit->SetBitmap(wxArtProvider::GetBitmap(wxART_QUIT, wxART_MENU));
    auto menuEdit = new wxMenu();
    menuEdit->Append(wxID_PREFERENCES);

    auto menuHelp = new wxMenu();
    menuHelp->Append(wxID_ABOUT);


    add_pass = new wxButton(this, BUTTON_ADD, _T("Add Password"), wxDefaultPosition, wxDefaultSize, 0);
    del_pass = new wxButton(this, BUTTON_DEL, _T("Remove Password"), wxDefaultPosition, wxDefaultSize, 0);
    fgSizer1->Add(add_pass, 0, wxALL, 5);
    fgSizer1->Add(del_pass, 0, wxALL, 5);

    mainMenu->Append(menuFile, "&File");
    mainMenu->Append(menuEdit, "&Edit");
    mainMenu->Append(menuHelp, "&Help");
    
    this->SetSizer(fgSizer1);
    this->Layout();
    this->SetMenuBar(mainMenu); 
    this->Connect(wxEVT_CLOSE_WINDOW, wxCloseEventHandler(keepPassFrame::OnClose));
}

void keepPassFrame::OnPassword(wxCommandEvent& event)
{
    std::ofstream pass("pass.txt");
}

void keepPassFrame::OnEnterKey(wxCommandEvent& event)
{
    wxTextCtrl* passwordEntry = dynamic_cast<wxTextCtrl*>(event.GetEventObject());
    wxString input = passwordEntry->GetValue();
    exit(0);
}

void keepPassFrame::OnExit(wxCommandEvent& event)
{
    Close(true);
}

void keepPassFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox("This is a password manager that aims to keep passwords safe and accessible using AES256 and PBKDF2.",
        "About keepPass", wxOK | wxICON_INFORMATION);
}

void keepPassFrame::OnClose(wxCloseEvent& event)
{
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