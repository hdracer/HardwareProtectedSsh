/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "AttestationLib.h"

using namespace TpmCpp;

using namespace utility;


namespace helpers
{
    std::wstring s2ws(std::string& t_str)
    {
        //setup converter
        typedef std::codecvt_utf8<wchar_t> convert_type;
        std::wstring_convert<convert_type, wchar_t> converter;

        //use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
        return converter.from_bytes(t_str);
    }

    std::string ws2s(const std::wstring& wstr)
    {
        using convert_typeX = std::codecvt_utf8<wchar_t>;
        std::wstring_convert<convert_typeX, wchar_t> converterX;

        return converterX.to_bytes(wstr);
    }

    std::string bytesToHex(ByteVec data)
    {
        std::stringstream ss;
        ss << std::hex;
        for (int i = 0; i<data.size(); ++i)
            ss << std::setw(2) << std::setfill('0') << (int)data[i];
        return ss.str();
    }

    utility::string_t getDeviceName()
    {
        utility::string_t ret;

#ifndef __linux__ 

        wchar_t *wszName = 0;
        size_t cchName = 0;

        //
        // Find a device name
        //

        _wdupenv_s(&wszName, 0, U("COMPUTERNAME"));
        if (0 == wszName)
        {
            _wdupenv_s(&wszName, 0, U("HOSTNAME"));
        }
        if (0 == wszName)
        {
            return utility::string_t(U("Unknown"));
        }

        ret = utility::conversions::to_string_t(wszName);

        free(wszName);

#else
            
        char hostname[128];

        if (gethostname(hostname, sizeof hostname) != 0)
        {
            return utility::string_t(U("Unknown"));
        }

        ret = utility::conversions::to_string_t(hostname);

#endif

        return ret;
    }

    utility::string_t getSystemVersion()
    {
#ifndef __linux__
        return utility::string_t(U("Windows"));
#else
        return utility::string_t(U("Linux"));
#endif
    }
}
