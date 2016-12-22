#pragma once

// By default we use tracking allocators in the debug build
#ifdef _DEBUG   
#define _CRTDBG_MAP_ALLOC
#ifndef DBG_NEW      
#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )      
#define new DBG_NEW   
#endif
#endif  // _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include "targetver.h"

#ifndef __linux__
// Windows stuff
#define WIN32_LEAN_AND_MEAN       
#include <crtdbg.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <wincrypt.h>
#else
// Non-Windows stuff
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#define OutputDebugString wprintf
#define MultiByteToWideChar(a,b,c,d,e,f) assert(d<=f);mbtowc(e,c,d);
#endif

// STL stuff
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
#include <codecvt>
#include <system_error>

// cpprest
//#include "cpprest\http_listener.h"
#include "cpprest/json.h"
#include "cpprest/filestream.h"
#include "cpprest/containerstream.h"
#include "cpprest/producerconsumerstream.h"
#include "cpprest/http_listener.h"
#include "cpprest/http_client.h"

#ifndef __linux__
#pragma warning(once:4251)
#pragma warning(once:4091)
#endif
#include "Tpm2.h"
