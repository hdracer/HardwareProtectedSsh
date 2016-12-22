/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "p11helpers.h"

#ifdef __linux__
using namespace boost::filesystem;
#endif

#define szUSER_KEYS_SUBDIRECTORY                        ".AttestedKeys"
#define szUSER_KEYS_EXTENSION                           ".ak"

//
// http://stackoverflow.com/questions/4891006/how-to-create-a-folder-in-the-home-directory
//
bool _GetUserHomeDirectory(std::string &userHomeDir)
{

#ifndef __linux__ 

    char *szHome = 0;
    size_t cchHome = 0;

    //
    // Find a possible home directory
    //

    _dupenv_s(&szHome, 0, "HOME");
    if (0 == szHome)
    {
        _dupenv_s(&szHome, 0, "USERPROFILE");
    }
    if (0 == szHome)
    {
        return false;
    }

    //
    // Return the directory to be used
    //

    userHomeDir.assign(szHome);
    free(szHome);
    return true;

#else
    const char *homedir;

    if ((homedir = getenv("HOME")) == NULL) 
    {
        homedir = getpwuid(getuid())->pw_dir;
    }

    userHomeDir.assign(homedir);
    return true;

#endif

}

bool _GetUserKeysDirectory(std::string &userKeysDir)
{

#ifndef __linux__ 

    std::tr2::sys::path keysDirPath;

    //
    // Start with the home directory
    //

    if (false == _GetUserHomeDirectory(userKeysDir))
        return false;

    //
    // Append the keys directory
    //

    keysDirPath.append(userKeysDir);
    keysDirPath.append(szUSER_KEYS_SUBDIRECTORY);

    //
    // Ensure the directory tree exists
    //

    std::tr2::sys::create_directories(keysDirPath);

    //
    // Return the path
    //

    userKeysDir.assign(keysDirPath.string());

#else
    
    //
    // Start with the home directory
    //

    if (false == _GetUserHomeDirectory(userKeysDir))
        return false;

    stringstream ss;
    ss << userKeysDir << L"//.strongnet";

    // @todo - create the directory
    userKeysDir = ss.str();

#endif 

    return true;
}

bool PhlpGetUserKeyPath(
    const std::string &keyName, 
    std::string &userKeyPath)
{

#ifndef __linux__

    std::tr2::sys::path keyPath;

    //
    // Start with the keys directory
    //

    if (false == _GetUserKeysDirectory(userKeyPath))
        return false;

    //
    // Append the key name 
    //

    keyPath.append(userKeyPath);
    keyPath.append(keyName);

    //
    // Append the extension
    //

    keyPath.concat(szUSER_KEYS_EXTENSION);
    userKeyPath.assign(keyPath.string());

#else

    //
    // Start with the home directory
    //

    if (false == _GetUserHomeDirectory(userKeyPath))
        return false;

    stringstream ss;
    ss << userKeyPath << L"//.strongnet" << keyName << szUSER_KEYS_EXTENSION;

    // @todo - create the directory
    userKeyPath = ss.str();

#endif
    return true;
}

bool PhlpWriteFile(
    const std::string fileName,
    const std::vector<unsigned char> fileData)
{
    std::ofstream fs;

    //
    // Open the file
    //

    fs.open(fileName, std::ofstream::trunc | std::ofstream::binary);

    //
    // Write the contents
    //

    fs.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    fs.close();
    return true;
}

bool PhlpEnumerateUserKeyFiles(
    std::vector<string> &userKeyFiles)
{
    std::string userKeysDir;

    if (false == _GetUserKeysDirectory(userKeysDir))
        return false;

#ifndef __linux__

    for (auto& p : ::tr2::sys::directory_iterator(userKeysDir))
    {
        userKeyFiles.push_back(p.path().string());
    }

#else

    for (auto& entry : boost::make_iterator_range(directory_iterator(userKeysDir), {}))
    {
        userKeyFiles.push_back(entry.path().string());
    }

#endif

    return true;
}

bool PhlpReadFile(
    const std::string fileName,
    std::vector<unsigned char> &fileData)
{
    std::ifstream fs;
    unsigned int cbFile = 0;

    //
    // Open the file
    //

    fs.open(fileName, std::ofstream::binary);

    //
    // Read the contents
    //
#ifndef __linux__
    cbFile = (unsigned int) std::tr2::sys::file_size(fileName);
#else
    cbFile = (unsigned int) file_size(fileName);
#endif

    fileData.resize(cbFile);
    fs.read(reinterpret_cast<char*>(fileData.data()), fileData.size());
    fs.close();
    return true;
}
