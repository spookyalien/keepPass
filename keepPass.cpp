#include "PassClass.h"

#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>

void *allocate_memory(size_t size)
{
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

void free_memory(void *memory, size_t size)
{
    VirtualFree(memory, 0, MEM_RELEASE);
}

#else // Code for Unix-like platforms
#include <sys/mman.h>
#include <errno.h>

void *allocate_memory(size_t size)
{
    void *memory = malloc(size);

    if (memory == NULL)
    {
        perror("malloc");
        return NULL;
    }

    if (mlock(memory, size) != 0)
    {
        perror("mlock");
        free(memory);
        return NULL;
    }

    return memory;
}

void free_memory(void *memory, size_t size)
{
    if (munlock(memory, size) != 0)
    {
        perror("munlock");
    }

    free(memory);
}

#endif

bool keepPassMenu::OnInit()
{
    wxDisplay disp;
    wxRect disp_rect = disp.GetClientArea();
    keepPassFrame *frame = new keepPassFrame("keepPass", wxPoint((disp_rect.GetWidth() - WINDOW_X) / 2, (disp_rect.GetHeight() - WINDOW_Y) / 2), wxSize(WINDOW_X, WINDOW_Y));
    frame->Show(true);
    return true;
}

int keepPassFrame::create_master(unsigned char **master_key)
{
    wxTextEntryDialog *pass_input = new wxTextEntryDialog(this, "Enter master password.", "keepPass", wxEmptyString, wxOK | wxTE_PASSWORD);
    pass_input->CenterOnScreen();
    int result = pass_input->ShowModal();

    if (result != wxID_OK)
        exit(0);
    std::string pass = pass_input->GetValue().ToStdString();
    std::string salt;
    int key_len;
    int salt_len = 16;
    int round_count = 100000;

    std::ifstream file("key.asc");

    // Master hash not created yet add as normal
    if (file.peek() == std::ifstream::traits_type::eof())
    {
        salt = generate_salt(salt_len);
        key_len = PBKDF2(convert_uchar(pass), pass.length(), convert_uchar(salt), salt_len, round_count, DK_LEN, master_key);
        std::ofstream file("key.asc");
        file << salt << std::endl;
        file << round_count << std::endl;
        file << salt_len << std::endl;
        pass.resize(pass.capacity(), 0);
        cleanse(&pass[0], pass.size());
        pass.clear();
    }
    else
    {
        std::string line;
        std::getline(file, line);
        salt = line;
        std::getline(file, line);
        round_count = stoi_with_check(line);
        std::getline(file, line);
        salt_len = stoi_with_check(line);
        std::getline(file, line);

        key_len = PBKDF2(convert_uchar(pass), pass.length(), convert_uchar(salt), salt_len, round_count, DK_LEN, master_key);

        pass.resize(pass.capacity(), 0);
        cleanse(&pass[0], pass.size());
        pass.clear();
    }
    return key_len;
}

keepPassFrame::keepPassFrame(const wxString &title, const wxPoint &pos, const wxSize &size)
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    this->master_key = (unsigned char *)allocate_memory(DK_LEN);
    this->key_length = create_master(&master_key);
    wxBoxSizer *menu_sizer = new wxBoxSizer(wxHORIZONTAL);
    auto menuFile = new wxMenu();
    auto menuItemFileQuit = menuFile->Append(wxID_EXIT);
    menuItemFileQuit->SetBitmap(wxArtProvider::GetBitmap(wxART_QUIT, wxART_MENU));
    auto menuEdit = new wxMenu();
    menuEdit->Append(wxID_PREFERENCES);

    auto menuHelp = new wxMenu();
    menuHelp->Append(wxID_ABOUT);

    add_pass = new wxButton(this, BUTTON_ADD, _T("Add Password"), wxDefaultPosition, wxDefaultSize, 0);
    del_pass = new wxButton(this, BUTTON_DEL, _T("Remove Password"), wxDefaultPosition, wxDefaultSize, 0);

    menu_sizer->Add(add_pass, 0, wxALL, 5);
    menu_sizer->Add(del_pass, 0, wxALL, 5);

    wxBoxSizer *box_sizer = new wxBoxSizer(wxHORIZONTAL);

    site_list = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, nullptr);
    user_list = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, nullptr);
    pass_list = new wxListBox(this, wxID_ANY, wxDefaultPosition);

    box_sizer->Add(site_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));
    box_sizer->Add(user_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));
    box_sizer->Add(pass_list, wxSizerFlags(1).Proportion(2).Expand().Border(wxALL, 20));

    main_menu->Append(menuFile, "&File");
    main_menu->Append(menuEdit, "&Edit");

    wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
    top_sizer->Add(menu_sizer, 0, wxEXPAND);
    top_sizer->Add(box_sizer, 1, wxEXPAND);
    unlocks();
    this->SetSizer(top_sizer);
    this->SetMenuBar(main_menu);
    this->Connect(wxEVT_CLOSE_WINDOW, wxCloseEventHandler(keepPassFrame::on_close));
    this->Layout();
}

void keepPassFrame::unlocks()
{
    std::ifstream pass_file("pass.txt", std::ios::app);

    if (pass_file.peek() == std::ifstream::traits_type::eof())
    {
        wxMessageBox(wxT("No passwords present."), wxT("Error"), wxICON_INFORMATION);
    }
    else
    {
        int flag = 0;
        if (pass_file.is_open())
        {
            std::string line;
            int len_length = 2;
            int decr_len = -1;

            while (std::getline(pass_file, line))
            {
                if (added.find(line) == added.end())
                    added.insert(line);
                else
                    continue;

                std::vector<std::string> site_pass = split(line, DELIMITER);

                for (int i = 0; i < site_pass.size(); i++)
                {
                    unsigned char *dec = NULL;
                    std::string num = site_pass[i].substr(site_pass[i].size() - len_length, len_length);
                    int len = std::stoi(num);
                    // DEFAULT_LEN is 16 for iv length TODO: make dynamic
                    std::string iv_str = site_pass[i].substr(site_pass[i].size() - len_length - DEFAULT_LEN, DEFAULT_LEN);
                    std::string encr_pass = site_pass[i].substr(0, site_pass[i].size() - len_length - DEFAULT_LEN);

                    unsigned char *iv = convert_uchar(iv_str);
                    unsigned char *cipher = (unsigned char *)malloc(len);
                    hex_str(encr_pass, cipher, len);
                    decr_len = aes_decrypt(cipher, len, master_key, AES_256, AES_CBC, iv, &dec);

                    if (decr_len > 0)
                    {
                        std::string decr_pass(reinterpret_cast<char const *>(dec), decr_len);

                        switch (i)
                        {
                        case 0:
                            site_list->Append(decr_pass);
                            break;
                        case 1:
                            user_list->Append(decr_pass);
                            break;
                        case 2:
                            std::string decr_pass(decr_len, '*');
                            pass_list->Append(decr_pass);
                            break;
                        }
                    }
                    else
                    {
                        flag = 1;
                        break;
                    }
                }
            }
        }
        pass_file.close();
        if (flag)
        {

            wxMessageBox(wxT("Password decryption failed."), wxT("Error"), wxICON_INFORMATION);
            std::exit(0);
        }
    }
}

void keepPassFrame::on_delete(wxCommandEvent &event)
{
    std::ifstream pass_file(PASS_FILE, std::ios::app);
    if (pass_file.peek() == std::ifstream::traits_type::eof())
    {
        wxMessageBox(wxT("No passwords present."), wxT("Error"), wxICON_INFORMATION);
        return;
    }
    wxTextEntryDialog *site_input = new wxTextEntryDialog(this, "Enter site to delete.", "keepPass", wxEmptyString, wxOK);

    if (site_input->ShowModal() == wxID_OK)
    {
        if (pass_file.is_open())
        {
            std::string site_input_str = site_input->GetValue().ToStdString();
            unsigned char *del_site = convert_uchar(site_input_str);
            std::string line = "";
            int arr_entry = 0;
            const char hex[17] = "0123456789ABCDEF";

            while (std::getline(pass_file, line))
            {
                unsigned char *user_cipher = NULL;
                int len_length = 2;
                std::string site_line = split(line, DELIMITER).front();
                // use IV on each line to make site AES and compare to encrypted pass segment
                // FORMAT: [ENCR_PASS][IV][ENCR_LEN] delimited by | for site, username, then password respectively
                std::string num = site_line.substr(site_line.size() - len_length, len_length);
                int encr_len = std::stoi(num);
                // DEFAULT_LEN is 16 for iv length TODO: make dynamic
                std::string iv_str = site_line.substr(site_line.size() - len_length - DEFAULT_LEN, DEFAULT_LEN);
                std::string encr_pass = site_line.substr(0, site_line.size() - len_length - DEFAULT_LEN);
                unsigned char *iv = convert_uchar(iv_str);
                aes_encrypt(del_site, site_input_str.size(), master_key, AES_256, AES_CBC, iv, &user_cipher);

                bool flag = false;
                for (int i = 0; i < encr_len; i++)
                {
                    int j = (i * 2);
                    if ((encr_pass[j] != hex[user_cipher[i] >> 4]) && (encr_pass[j + 1] != hex[user_cipher[i] & 0x0f]))
                        flag = false;
                    else
                        flag = true;
                }
                if (flag)
                {
                    added.erase(site_line);
                    delete_line(PASS_FILE, site_line);
                    pass_list->Delete(arr_entry);
                    user_list->Delete(arr_entry);
                    site_list->Delete(arr_entry);
                    break;
                }
                arr_entry++;
            }
        }
    }
}

void keepPassFrame::on_password(wxCommandEvent &event)
{
    PassInput dialog(this, wxID_ANY, "keepPass");
    if (dialog.ShowModal() == wxID_OK)
    {
        std::string password = dialog.GetPassword().ToStdString();
        std::string site_name = dialog.GetSite().ToStdString();
        std::string username = dialog.GetName().ToStdString();

        std::ofstream pass_file(PASS_FILE, std::ios::app);
        const char hex[17] = "0123456789ABCDEF";
        pass_format site;
        pass_format pass;
        pass_format user;

        std::string site_iv = generate_salt(DEFAULT_LEN);
        std::string pass_iv = generate_salt(DEFAULT_LEN);
        std::string user_iv = generate_salt(DEFAULT_LEN);

        pass.iv = convert_uchar(pass_iv);
        site.iv = convert_uchar(site_iv);
        user.iv = convert_uchar(user_iv);
        unsigned char *pass_uchar = convert_uchar(password);
        unsigned char *site_uchar = convert_uchar(site_name);
        unsigned char *user_uchar = convert_uchar(username);

        pass.len = aes_encrypt(pass_uchar, password.size(), master_key, AES_256, AES_CBC, pass.iv, &pass.cipher);
        site.len = aes_encrypt(site_uchar, site_name.size(), master_key, AES_256, AES_CBC, site.iv, &site.cipher);
        user.len = aes_encrypt(user_uchar, username.size(), master_key, AES_256, AES_CBC, user.iv, &user.cipher);

        for (int i = 0; i < site.len; i++)
        {
            pass_file << hex[site.cipher[i] >> 4] << hex[site.cipher[i] & 0x0f];
        }
        pass_file << site_iv << site.len;

        pass_file << DELIMITER;

        for (int i = 0; i < user.len; i++)
        {
            pass_file << hex[user.cipher[i] >> 4] << hex[user.cipher[i] & 0x0f];
        }
        pass_file << user_iv << user.len;

        pass_file << DELIMITER;

        for (int i = 0; i < pass.len; i++)
        {
            pass_file << hex[pass.cipher[i] >> 4] << hex[pass.cipher[i] & 0x0f];
        }
        pass_file << pass_iv << pass.len;
        pass_file << std::endl;
        pass_file.close();
    }
    unlocks();
}

void keepPassFrame::on_exit(wxCommandEvent &event)
{
    Close(true);
}

void keepPassFrame::on_about(wxCommandEvent &event)
{
    wxMessageBox("This is a password manager that aims to keep passwords safe and accessible using AES256 and PBKDF2.",
                 "About keepPass", wxOK | wxICON_INFORMATION);
}

void keepPassFrame::on_close(wxCloseEvent &event)
{
    free_memory(master_key, DK_LEN);
    Destroy();
    wxGetApp().ExitMainLoop();
}
