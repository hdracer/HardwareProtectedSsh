/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3 
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html. 
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"

//
// Flow macros
//

void _OutputDbgStr(
    const char *szFile,
    unsigned int dwLine,
    const char *szMsg,
    wchar_t*wszDetail,
    unsigned int dwStatus)
{
    char rgsz[1024];
    const char *szTag = "INFO";

    if (0 != dwStatus)
        szTag = "ERROR";

    if (wszDetail == NULL)
    {
        _snprintf_s(
            rgsz,
            sizeof(rgsz),
            "%s: %s - 0x%x, file %s, line %d\n",
            szTag,
            szMsg,
            dwStatus,
            szFile,
            dwLine);
    }
    else
    {
        _snprintf_s(
            rgsz,
            sizeof(rgsz),
            "%s: %s (%S) - 0x%x, file %s, line %d\n",
            szTag,
            szMsg,
            wszDetail,
            dwStatus,
            szFile,
            dwLine);
    }

    OutputDebugStringA(rgsz);
}

#define LOG_CALL(_X, _Y) {                                                  \
    _OutputDbgStr(__FILE__, __LINE__, _X, NULL, (CK_ULONG)_Y);              \
}

#define CHECK_ALLOC(_X) {                                                   \
    if (0 == (_X)) {                                                        \
        result = CKR_HOST_MEMORY;                                           \
        goto out;                                                           \
    }                                                                       \
}

#define CHECK_CKR(_X) {                                                     \
    if (CKR_OK != (result = (_X))) {                                        \
        _OutputDbgStr(__FILE__, __LINE__, #_X, NULL, (CK_ULONG) result);    \
        goto out;                                                           \
    }                                                                       \
}        

void TestPaPkcs11()
{
    CK_C_GetFunctionList pfnCkGetFunctionList = 0;
    HMODULE hMod = 0;
    CK_RV result = CKR_OK;
    CK_FUNCTION_LIST_PTR pCkFunctionList = 0;
    CK_SLOT_ID SlotId;
    CK_ULONG cItems = 0;
    CK_SESSION_HANDLE hSession = 0;
    CK_MECHANISM Mechanism = { 0 };
    CK_OBJECT_HANDLE hPublicKey = 0;
    CK_OBJECT_HANDLE hPrivateKey = 0;
    CK_BYTE rgbHash[20];
    CK_BYTE *pbSignature = 0;
    CK_ULONG cbSignature = 0;

    //
    // Load the library
    //

#ifndef __linux__
    if (0 == (hMod = LoadLibraryA("libp11platformattestation.dll")))
#else
    if (0 == (hMod = dload("libp11platformattestation-x64.so", RTLD_NOW)))
#endif
    {
        std::cout << "Failed to load the PKCS#11 library" << std::endl;
        return;
    }
    
    //
    // Find the initial entry point
    //

#ifndef __linux__    
    if (0 == (pfnCkGetFunctionList = (CK_C_GetFunctionList) GetProcAddress(
        hMod, "C_GetFunctionList")))
#else
    if (0 == (pfnCkGetFunctionList = dlsym(hMod, "C_GetFunctionList")))
#endif
    {
        std::cout << "Failed to find PKCS#11 export symbol C_GetFunctionList" << std::endl;
        return;
    }

    //
    // Get the cryptoKi functions
    //

    CHECK_CKR(pfnCkGetFunctionList(&pCkFunctionList));

    //
    // Initialize
    //

    CHECK_CKR(pCkFunctionList->C_Initialize(0));

    //
    // List slots
    //

    cItems = 1;
    CHECK_CKR(pCkFunctionList->C_GetSlotList(true, &SlotId, &cItems));

    //
    // Start a session
    //

    CHECK_CKR(pCkFunctionList->C_OpenSession(
        SlotId,
        CKF_SERIAL_SESSION,
        0,
        0,
        &hSession));

    //
    // Create a key pair
    //

    Mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    CHECK_CKR(pCkFunctionList->C_GenerateKeyPair(
        hSession,
        &Mechanism,
        0,
        0,
        0,
        0,
        &hPublicKey,
        &hPrivateKey));

    //
    // Sign a hash
    //

    Mechanism.mechanism = CKM_RSA_PKCS;
    CHECK_CKR(pCkFunctionList->C_SignInit(
        hSession,
        &Mechanism,
        hPrivateKey));

    CHECK_CKR(pCkFunctionList->C_Sign(
        hSession,
        rgbHash,
        sizeof(rgbHash),
        0,
        &cbSignature));

    CHECK_ALLOC(pbSignature = (CK_BYTE_PTR) malloc(cbSignature));

    CHECK_CKR(pCkFunctionList->C_Sign(
        hSession,
        rgbHash,
        sizeof(rgbHash),
        pbSignature,
        &cbSignature));

    //
    // Verify the signature
    //
    
    // TODO
out:
    if (0 != pbSignature)
        free(pbSignature);
#ifndef __linux__    
    if (0 != hMod)
        FreeLibrary(hMod);
#endif
}

//
// Console entry point
//
int main(int argc, char *argv[])
{
#ifdef __linux__
DllInit();
try {
#endif

    //TestPlatformAttestation();
    TestPaPkcs11();

#ifdef __linux__
}
catch (const runtime_error& exc) {
    cerr << "CliTst: " << exc.what() << "\nExiting...\n";
}
#endif

    return 0;
}

