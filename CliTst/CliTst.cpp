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

//
// Write hex bytes to console output
//
#define CROW                                                16
static void PrintBytes(char *szTitle, CK_BYTE *pbData, CK_ULONG cbData)
{
    CK_ULONG iByte = 0, iRowItem = 0;

    printf("%s -- %lu bytes\n", szTitle, cbData);

    while (iByte < cbData)
    {
        for (   iRowItem = 0;
                iRowItem < CROW && iByte < cbData;
                iRowItem++, iByte++)
            printf("%02X ", pbData[iByte]);
        printf("\n");
    }
}

//
// Helper loop for enumerating public keys
//
CK_RV _EnumerateFilteredObjects(
    CK_FUNCTION_LIST_PTR pCkFunctionList,
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pAttribFilter,
    CK_ULONG cFilter,
    CK_ATTRIBUTE_PTR pFilteredAttribs,
    CK_ULONG cFilteredAttribs)
{
    CK_RV result = CKR_OK;
    CK_BBOOL fFindInit = false;
    CK_ULONG cItems = 0;
    CK_OBJECT_HANDLE hFoundObject = 0;
    const char *szLabel = 0;

    //
    // Initialize object enumeration
    //

    CHECK_CKR(pCkFunctionList->C_FindObjectsInit(
        hSession,
        pAttribFilter,
        cFilter));
    fFindInit = true;

    //
    // Try for one object
    //

    CHECK_CKR(pCkFunctionList->C_FindObjects(
        hSession,
        &hFoundObject,
        1,
        &cItems));
    if (0 == cItems)
    {
        std::cout << "No PKCS#11 object found of class:  " << *((CK_ULONG *) pAttribFilter[0].pValue) << std::endl;
        goto out;
    }

    std::cout << "Found PKCS#11 object of class:  " << *((CK_ULONG *) pAttribFilter[0].pValue) << std::endl;

    //
    // Query attributes sizes
    //

    CHECK_CKR(pCkFunctionList->C_GetAttributeValue(
        hSession,
        hFoundObject,
        pFilteredAttribs,
        cFilteredAttribs));

    //
    // Allocate attribute buffers
    //

    for (   CK_ULONG iAttrib = 0; 
            iAttrib < cFilteredAttribs; 
            iAttrib++)
    {
        CHECK_ALLOC(pFilteredAttribs[iAttrib].pValue = 
            malloc(pFilteredAttribs[iAttrib].ulValueLen));
    }

    //
    // Query the attribute values
    //

    CHECK_CKR(pCkFunctionList->C_GetAttributeValue(
        hSession,
        hFoundObject,
        pFilteredAttribs,
        cFilteredAttribs));

    //
    // Display attributes
    //

    for (   CK_ULONG iAttrib = 0;
            iAttrib < cFilteredAttribs;
            iAttrib++)
    {
        switch (pFilteredAttribs[iAttrib].type)
        {
        case CKA_ID:
            szLabel = "ID";
            break;
        case CKA_MODULUS:
            szLabel = "Modulus";
            break;
        case CKA_PUBLIC_EXPONENT:
            szLabel = "Public Exponent";
            break;
        case CKA_SUBJECT:
            szLabel = "Subject";
            break;
        case CKA_VALUE:
            szLabel = "Value";
            break;
        default:
            szLabel = "Unknown attribute";
            break;
        }

        PrintBytes(
            (char*)szLabel,
            (CK_BYTE *) pFilteredAttribs[iAttrib].pValue,
            pFilteredAttribs[iAttrib].ulValueLen);
    }

out:
    if (true == fFindInit)
    {
        //
        // Clean-up object enumeration state
        //

        CHECK_CKR(pCkFunctionList->C_FindObjectsFinal(hSession));
    }

    for (   CK_ULONG iAttrib = 0;
            iAttrib < cFilteredAttribs;
            iAttrib++)
    {
        if (0 != pFilteredAttribs[iAttrib].pValue)
        {
            free(pFilteredAttribs[iAttrib].pValue);
            pFilteredAttribs[iAttrib].pValue = 0;
        }
    }

    return result;
}

//
// Helper loop for enumerating public keys and certificates from a token 
// session
//
CK_RV _EnumeratePublicKeysAndCertificates(
    CK_FUNCTION_LIST_PTR pCkFunctionList,
    CK_SESSION_HANDLE hSession)
{
    CK_RV result = CKR_OK;
    CK_OBJECT_CLASS	cert_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE		cert_filter[] = {
        { CKA_CLASS, NULL, sizeof(cert_class) }
    };
    CK_ATTRIBUTE		cert_attribs[] = {
        { CKA_ID, NULL, 0 },
        { CKA_SUBJECT, NULL, 0 },
        { CKA_VALUE, NULL, 0 }
    };
    cert_filter[0].pValue = &cert_class;
    CK_OBJECT_CLASS	pubkey_class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE		pubkey_filter[] = {
        { CKA_CLASS, NULL, sizeof(pubkey_class) }
    };
    CK_ATTRIBUTE		pubkey_attribs[] = {
        { CKA_ID, NULL, 0 },
        { CKA_MODULUS, NULL, 0 },
        { CKA_PUBLIC_EXPONENT, NULL, 0 }
    };
    pubkey_filter[0].pValue = &pubkey_class;

    //
    // Public keys filter
    //

    CHECK_CKR(_EnumerateFilteredObjects(
        pCkFunctionList, 
        hSession, 
        pubkey_filter, 
        sizeof(pubkey_filter) / sizeof(pubkey_filter[0]),
        pubkey_attribs,
        sizeof(pubkey_attribs) / sizeof(pubkey_attribs[0])));

    //
    // Certificates filter
    //

    CHECK_CKR(_EnumerateFilteredObjects(
        pCkFunctionList, 
        hSession, 
        cert_filter, 
        sizeof(cert_filter) / sizeof(cert_filter[0]),
        cert_attribs,
        sizeof(cert_attribs) / sizeof(cert_attribs[0])));

out:
    return result;
}

//
// Routine for exercising PKCS#11 interface
//
CK_RV TestPaPkcs11()
{
    CK_C_GetFunctionList pfnCkGetFunctionList = 0;
    HMODULE hMod = 0;
    CK_RV result = CKR_OK;
    CK_FUNCTION_LIST_PTR pCkFunctionList = 0;
    CK_INFO CkInfo = { 0 };
    CK_SLOT_ID SlotId;
    CK_ULONG cItems = 0;
    CK_TOKEN_INFO CkTokenInfo = { 0 };
    CK_SESSION_HANDLE hSession = 0;
    CK_OBJECT_CLASS	privk_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE privk_filter[] = {
        { CKA_CLASS, NULL, sizeof(privk_class) }
    };
    CK_MECHANISM Mechanism = { 0 };
    CK_OBJECT_HANDLE hPublicKey = 0;
    CK_OBJECT_HANDLE hPrivateKey = 0;
    CK_BYTE rgbHash[20];
    CK_BYTE *pbSignature = 0;
    CK_ULONG cbSignature = 0;

    privk_filter[0].pValue = &privk_class;

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
        return CKR_GENERAL_ERROR;
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
        return CKR_GENERAL_ERROR;
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
    // Query provider information
    //

    CHECK_CKR(pCkFunctionList->C_GetInfo(&CkInfo));
    std::cout << "Using CryptoKi provider " << CkInfo.libraryDescription << std::endl;

    //
    // List slots
    //

    cItems = 1;
    CHECK_CKR(pCkFunctionList->C_GetSlotList(true, &SlotId, &cItems));

    //
    // Confirm that the available token is initialized
    //

    CHECK_CKR(pCkFunctionList->C_GetTokenInfo(SlotId, &CkTokenInfo));
    if (CKF_TOKEN_INITIALIZED & CkTokenInfo.flags)
    {
        std::cout << "Crypto token is initialized" << std::endl;
    }
    else
    {
        std::cout << "Failed to find an initialized crypto token" << std::endl;
        return CKR_GENERAL_ERROR;
    }

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
    // Check for an existing key
    //

    CHECK_CKR(pCkFunctionList->C_FindObjectsInit(
        hSession,
        privk_filter,
        sizeof(privk_filter) / sizeof(privk_filter[0])));

    cItems = 0;
    CHECK_CKR(pCkFunctionList->C_FindObjects(
        hSession,
        &hPrivateKey,
        1,
        &cItems));

    CHECK_CKR(pCkFunctionList->C_FindObjectsFinal(hSession));

    if (0 == hPrivateKey)
    {
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
    }

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

    //
    // Enumerate keys and certificates
    //

    CHECK_CKR(_EnumeratePublicKeysAndCertificates(pCkFunctionList, hSession));

out:
    if (0 != pbSignature)
        free(pbSignature);
#ifndef __linux__    
    if (0 != hMod)
        FreeLibrary(hMod);
#endif

    return result;
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

