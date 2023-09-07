#include "PassClass.h"

bool keepPassMenu::OnInit()
{
    wxDisplay disp;
    wxRect disp_rect = disp.GetClientArea();
    keepPassFrame* frame = new keepPassFrame("keepPass", wxPoint((disp_rect.GetWidth() - WINDOW_X) / 2, (disp_rect.GetHeight() - WINDOW_Y) / 2), wxSize(WINDOW_X, WINDOW_Y));
    frame->Show(true);
    return true;
}

void keepPassFrame::verify_pass(unsigned char* master_key)
{
    wxTextEntryDialog* pass_input = new wxTextEntryDialog(this, "Enter master password.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    pass_input->CenterOnScreen();
    pass_input->Bind(wxEVT_TEXT_ENTER, &keepPassFrame::on_enter, this, wxID_ANY);
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
        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(pass.c_str())), pass.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key);
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

        key_len = PBKDF2(reinterpret_cast<unsigned char*>(const_cast<char*>(pass.c_str())), pass.length(), reinterpret_cast<unsigned char*>(const_cast<char*>(salt.c_str())), salt_len, round_count, DK_LEN, &master_key);
    }
}

keepPassFrame::keepPassFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    // mloc vs virtualalloc
    verify_pass(master_key);

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

    wxListBox* pass_list = new wxListBox(this, wxID_ANY, wxDefaultPosition);
    wxListBox* pass_selection = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, nullptr, wxLB_SORT);


    pass_list->Bind(wxEVT_LISTBOX_DCLICK, [&](wxCommandEvent& event) {
        pass_selection->Append(pass_list->GetStringSelection());
    pass_selection->SetSelection(0);
    pass_list->Delete(pass_list->GetSelection());
        });

    pass_selection->Bind(wxEVT_LISTBOX_DCLICK, [&](wxCommandEvent& event) {
        pass_list->Append(pass_selection->GetStringSelection());
    pass_list->SetSelection(0);
    pass_selection->Delete(pass_selection->GetSelection());
        });

    box_sizer->Add(pass_list, wxSizerFlags(1).Proportion(1).Expand().Border(wxALL, 20));
    box_sizer->Add(pass_selection, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));


    main_menu->Append(menuFile, "&File");
    main_menu->Append(menuEdit, "&Edit");
    main_menu->Append(menuHelp, "&Help");

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
    return;
}

void keepPassFrame::on_password(wxCommandEvent& event)
{
    wxTextEntryDialog* pass_input = new wxTextEntryDialog(this, "Enter password to add.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    wxTextEntryDialog* site_input = new wxTextEntryDialog(this, "Enter name of site to add.", "keepPass", wxEmptyString, wxOK);

    if (pass_input->ShowModal() == wxID_OK && site_input->ShowModal() == wxID_OK) {
        wxString password = pass_input->GetValue();
        wxString site = site_input->GetValue();
        

        pass_input->Destroy();
        site_input->Destroy();
    }
    else {
        pass_input->Destroy();
        site_input->Destroy();
    }
}

void keepPassFrame::on_enter(wxCommandEvent& event)
{
    wxTextCtrl* passwordEntry = dynamic_cast<wxTextCtrl*>(event.GetEventObject());
    wxString input = passwordEntry->GetValue();
    exit(0);
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