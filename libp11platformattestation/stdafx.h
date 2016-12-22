#pragma once

#include "targetver.h"
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <iomanip>
#include <fstream>

#ifndef __linux__
// Windows-only
#define WIN32_LEAN_AND_MEAN       
#include <crtdbg.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <wincrypt.h>
#include <filesystem>
#else
// Linux-only
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <typeinfo>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <boost/filesystem.hpp>
#define OutputDebugStringA(x) printf("%s", x)
#define MultiByteToWideChar(a,b,c,d,e,f) assert(d<=f);mbtowc(e,c,d);
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define _snprintf_s(a,b,c,...) snprintf(a,b,__VA_ARGS__)
#endif

#include "cpprest/json.h"

#ifndef __linux__
#pragma warning(once:4251)
#pragma warning(once:4091)
#endif
#include "Tpm2.h"
