#pragma once

bool PhlpGetUserKeyPath(
    const std::string &keyName,
    std::string &userKeyPath);

bool PhlpEnumerateUserKeyFiles(
    std::vector<string> &userKeyFiles);

bool PhlpWriteFile(
    const std::string fileName,
    const std::vector<unsigned char> fileData);

bool PhlpReadFile(
    const std::string fileName,
    std::vector<unsigned char> &fileData);