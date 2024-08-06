#ifndef PASSCLASS_H
#define PASSCLASS_H

#include "Utility/cpputility.h"
#include "PBKDF/pbkdf2.h"
#include "AES/aes.h"
#include <unordered_set>

#include <wx/wxprec.h>
#include <wx/display.h>
#include <wx/artprov.h>
#include <wx/textctrl.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/button.h>
#include <map>
#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif

#define ROUND_COUNT 100000
#define DEFAULT_SALT_LEN 16
#define WINDOW_X 950
#define WINDOW_Y 540
#define DELIMITER '|'
#define PASS_FILE "pass.txt"
#define convert_uchar(strng) reinterpret_cast<unsigned char *>(const_cast<char *>(strng.c_str()))

class keepPassMenu : public wxApp
{
public:
    virtual bool OnInit();
};

class keepPassFrame : public wxFrame
{
public:
    keepPassFrame(const wxString &title, const wxPoint &pos, const wxSize &size);
    wxButton *add_pass;
    wxButton *del_pass;

private:
    void on_password(wxCommandEvent &event);
    void on_delete(wxCommandEvent &event);
    void on_close(wxCloseEvent &event);
    void on_exit(wxCommandEvent &event);
    void on_about(wxCommandEvent &event);
    void unlocks();
    int create_master(unsigned char **master_key);
    wxMenuBar *main_menu = new wxMenuBar();

    wxListBox *pass_list;
    wxListBox *user_list;
    wxListBox *site_list;
    std::unordered_set<std::string> added;
    unsigned char *master_key = NULL;
    int key_length = 0;

    wxDECLARE_EVENT_TABLE();
};

enum
{
    ADD_PASS = 2,
    DEL_PASS = 3
};

enum
{
    ID_OPTIONS = 99,
    BUTTON_ADD = wxID_HIGHEST + ADD_PASS,
    BUTTON_DEL = wxID_HIGHEST + DEL_PASS
};

typedef struct pass_format
{
    unsigned char *iv;
    unsigned char *cipher;
    int len;
} pass_format;

class PassInput : public wxDialog
{
public:
    PassInput(wxWindow *parent, wxWindowID id, const wxString &title)
        : wxDialog(parent, id, title, wxDefaultPosition, wxSize(300, 200))
    {
        wxStaticText *siteLabel = new wxStaticText(this, wxID_ANY, "Enter name of site to add:");
        siteInput = new wxTextCtrl(this, wxID_ANY);

        wxStaticText *nameLabel = new wxStaticText(this, wxID_ANY, "Enter Username:");
        nameInput = new wxTextCtrl(this, wxID_ANY);

        wxStaticText *passLabel = new wxStaticText(this, wxID_ANY, "Enter password to add:");
        passInput = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);

        wxButton *okButton = new wxButton(this, wxID_OK, "OK");
        wxButton *cancelButton = new wxButton(this, wxID_CANCEL, "Cancel");

        wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);
        wxBoxSizer *buttonSizer = new wxBoxSizer(wxHORIZONTAL);

        mainSizer->Add(siteLabel, 0, wxALL, 5);
        mainSizer->Add(siteInput, 0, wxEXPAND | wxALL, 5);
        mainSizer->Add(nameLabel, 0, wxALL, 5);
        mainSizer->Add(nameInput, 0, wxEXPAND | wxALL, 5);
        mainSizer->Add(passLabel, 0, wxALL, 5);
        mainSizer->Add(passInput, 0, wxEXPAND | wxALL, 5);

        buttonSizer->Add(okButton, 0, wxALL, 5);
        buttonSizer->Add(cancelButton, 0, wxALL, 5);

        mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER);

        SetSizerAndFit(mainSizer);

        Bind(wxEVT_BUTTON, &PassInput::OnOk, this, wxID_OK);
    }

    wxString GetSite() const { return siteInput->GetValue().ToStdString(); }
    wxString GetName() const { return nameInput->GetValue().ToStdString(); }
    wxString GetPassword() const { return passInput->GetValue(); }

private:
    void OnOk(wxCommandEvent &event)
    {
        if (Validate() && TransferDataFromWindow())
        {
            EndModal(wxID_OK);
        }
    }

    wxTextCtrl *siteInput;
    wxTextCtrl *nameInput;
    wxTextCtrl *passInput;
};

wxBEGIN_EVENT_TABLE(keepPassFrame, wxFrame)
    EVT_MENU(wxID_EXIT, keepPassFrame::on_exit)
        EVT_MENU(wxID_ABOUT, keepPassFrame::on_about)
            EVT_BUTTON(BUTTON_ADD, keepPassFrame::on_password)
                EVT_BUTTON(BUTTON_DEL, keepPassFrame::on_delete)
                    wxEND_EVENT_TABLE()
                        wxIMPLEMENT_APP(keepPassMenu);

#endif