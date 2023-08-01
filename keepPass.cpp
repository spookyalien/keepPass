#include "PassClass.h"

/*unsigned char* verify_pass()
{
    std::string master_key = "";
    unsigned char* master_key_encr = NULL;
    std::string salt;
    int salt_len = 16;
    int round_count = 100000;

    printf("[!] Enter master password: ");
    std::getline(std::cin, master_key);
    
    std::ifstream file("key.asc");

    if (file.peek() == std::ifstream::traits_type::eof()) {
        std::string temp;
        printf("[!] Enter length of salt to use for master key (Default - 16): ");
        std::getline(std::cin, temp);

        if (!temp.empty())
            salt_len = stoi_with_check(temp);
    
        printf("[!] Enter number of rounds to use for master key (Default - 100,000): ");
        std::getline(std::cin, temp);

        if (!temp.empty())
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
        PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(master_key.c_str())), master_key.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key_encr);
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
        salt_len = stoi_with_check(line);
        std::getline(file, line);
        round_count = stoi_with_check(line);
        
        PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(master_key.c_str())), master_key.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key_encr);
    }


    master_key.resize(master_key.capacity(), 0);
    cleanse(&master_key[0], master_key.size());
    master_key.clear();
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

    keepPassFrame *frame = new keepPassFrame( "keepPass", wxPoint((disp_rect.GetWidth()-WINDOW_X)/2, (disp_rect.GetHeight()-WINDOW_Y)/2), wxSize(WINDOW_X, WINDOW_Y) );
    frame->Show( true );
    return true;
}

keepPassFrame::keepPassFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
        : wxFrame(NULL, wxID_ANY, title, pos, size)
{

    wxPanel* panel = new wxPanel(this, wxID_ANY);
    //wxMenu *menuFile = new wxMenu;
    /*menuFile->Append(ID_Hello, "&Hello...\tCtrl-H",
                     "Help string shown in status bar for this menu item");
    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);
    wxMenu *menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);
    wxMenuBar *menuBar = new wxMenuBar;
    menuBar->Append( menuFile, "&File" );
    menuBar->Append( menuHelp, "&Help" );
    SetMenuBar( menuBar );
    CreateStatusBar();
    SetStatusText( "keepPass V2.0" );*/
    wxTextCtrl* pass_box = new wxTextCtrl(panel, wxID_ANY, wxEmptyString,
                                              wxPoint((WINDOW_X/2) - (BOX_X/2), (WINDOW_Y/2)-(BOX_Y/2)), wxSize(BOX_X, BOX_Y),
                                              wxTE_PASSWORD | wxTE_PROCESS_ENTER | wxBORDER_SIMPLE);
    pass_box->SetBackgroundColour(wxColour(252, 62, 56));
    pass_box->Bind(wxEVT_TEXT_ENTER, &keepPassFrame::OnEnterKey, this);
    // wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    // sizer->Add(pass_box, 0, wxEXPAND | wxALL, 10);

    // panel->SetSizer(sizer);
}

void keepPassFrame::OnEnterKey(wxCommandEvent& event) 
{
    wxTextCtrl* passwordEntry = dynamic_cast<wxTextCtrl*>(event.GetEventObject());
    wxString password = passwordEntry->GetValue();

}

void keepPassFrame::OnExit(wxCommandEvent& event)
{
    Close( true );
}
void keepPassFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox( "This is a password manager that aims to keep passwords safe and accessible using AES256 and PBKDF2.",
                  "About keepPass", wxOK | wxICON_INFORMATION );
}
void keepPassFrame::OnHello(wxCommandEvent& event)
{
    wxLogMessage("Hello world from wxWidgets!");
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
