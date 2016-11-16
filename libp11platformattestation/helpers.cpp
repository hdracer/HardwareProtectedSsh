#include "stdafx.h"
#include "helpers.h"

//
// http://stackoverflow.com/questions/4891006/how-to-create-a-folder-in-the-home-directory
//
bool PhlpGetUserHomeDirectory(wchar_t **ppwszUserHomeDir)
{
    wchar_t *wszHome = 0;
    size_t cchHome = 0;

    //
    // Find a possible home directory
    //

    _wdupenv_s(&wszHome, 0, L"HOME");
    if (0 == wszHome)
    {
        _wdupenv_s(&wszHome, 0, L"USERPROFILE");
    }
    if (0 == wszHome)
    {
        return false;
    }

    //
    // Return the directory to be used
    //

    *ppwszUserHomeDir = wszHome;
    return true;
}