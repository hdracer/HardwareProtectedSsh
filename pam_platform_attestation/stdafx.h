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
#define WIN32_LEAN_AND_MEAN       
#include <crtdbg.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <wincrypt.h>
#else
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#define OutputDebugString wprintf
#define MultiByteToWideChar(a,b,c,d,e,f) assert(d<=f);mbtowc(e,c,d);
#endif

//
// STL
//
#include <exception>
#include <numeric>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <initializer_list>
#include <cstdarg>
#include <typeinfo>
#include <chrono>
#include <system_error>

#include "cpprest/json.h"

#ifndef __linux__
#pragma warning(once:4251)
#pragma warning(once:4091)
#endif
#include "Tpm2.h"
