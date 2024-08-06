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


#endif