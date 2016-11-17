/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3 
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html. 
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
//#include "attestationlib.h"
//#include "pam_platform_attestation.h"

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

/*
//
// PCR attestation and AIK activation
//
void TestPlatformAttestation()
{
    CAttestationLib attestationLib;

    //
    // Initialize attestation helper class
    //

    cout << "Initializing test of remote platform attestation using local host TPM 2.0 device..." << endl;
    attestationLib.Initialize(std::string("https://strongnetsvc.jwsecure.com"));

    //
    // List certain TPM capabilities for lab testing
    //

    //attestationLib.ShowTpmCapabilities();

    //
    // Establish an AIK
    //

    if (false == attestationLib.CreateAttestationIdentityKey())
    {
        cout << "Failed to create an Attestation Identity Key" << endl;
        cout << "Confirm that this Endorsement Key hash is trusted by the Attestation Server: " << endl;
        cout << " " << attestationLib.GetEkPubHashBytes() << endl;
        return;
    }
    cout << "Successfully established an Attestation Identity Key with the Attestation Server" << endl;

    //
    // Create a sealed user key
    //

    if (false == attestationLib.CreateSealedUserKey())
    {
        cout << "Failed to create a sealed TPM user key" << endl;
        return;
    }
    cout << "Successfully created a sealed user key" << endl;

    //
    // Check the user key with the AS
    //

    if (false == attestationLib.CheckUserKeyWhitelist())
    {
        cout << "Failed to verify TPM user key with the Attestation Server whitelist" << endl;
        return;
    }
    cout << "Successfully checked TPM user key with Attestation Server whitelist" << endl;

    //
    // Sign and verify
    //

    if (false == attestationLib.SignAndVerifyMessage(std::string("This is a test message")))
    {
        cout << "Failed to sign and verify a message with the TPM user key" << endl;
        return;
    }
    cout << "Successfully signed and verified and message with the TPM user key " << endl;
}
*/

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

out:
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

