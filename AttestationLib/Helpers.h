
namespace helpers
{
    std::wstring s2ws(const std::string& t_str);
    std::string ws2s(const std::wstring& wstr);
    std::string bytesToHex(ByteVec data);
    utility::string_t getDeviceName();
    utility::string_t getSystemVersion();
}
