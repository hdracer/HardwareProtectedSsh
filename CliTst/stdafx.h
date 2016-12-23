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

// 
// PKCS#11 platform definitions
//

#define CK_PTR *

#ifndef NULL_PTR
#define NULL_PTR 0
#endif//NULL_PTR

#ifndef __linux__
#define CK_IMPORT_SPEC __declspec(dllimport) 

#ifdef CRYPTOKI_EXPORTS 
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else 
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif 

#define CK_CALL_SPEC __cdecl 

#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (CK_CALL_SPEC CK_PTR name)

#else
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif

#include "pkcs11.h"

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
#define OutputDebugStringA(x) printf("%s", x)
#define MultiByteToWideChar(a,b,c,d,e,f) assert(d<=f);mbtowc(e,c,d);
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define _snprintf_s(a,b,c,...) snprintf(a,b,__VA_ARGS__)
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
#include <system_error>
