/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "libp11platformattestation.h"

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
    _OutputDbgStr(__FILE__, __LINE__, #_X, NULL, (CK_ULONG)_Y);             \
}

//
// Static string defines
//

#define P11PA_INFO_MANUFACTURER_ID "JW Secure, Inc."
#define P11PA_INFO_LIBRARY_DESCRIPTION "PKCS#11 Platform Attestation"

#define P11PA_SLOT_ID 1
#define P11PA_SLOT_INFO_SLOT_DESCRIPTION "P11PA Slot"
#define P11PA_SLOT_INFO_MANUFACTURER_ID P11PA_INFO_MANUFACTURER_ID

#define P11PA_TOKEN_INFO_LABEL "P11PA"
#define P11PA_TOKEN_INFO_MANUFACTURER_ID P11PA_INFO_MANUFACTURER_ID
#define P11PA_TOKEN_INFO_MODEL "P11PA Token"
#define P11PA_TOKEN_INFO_SERIAL_NUMBER "0123456789A"
#define P11PA_TOKEN_INFO_MAX_PIN_LEN 256
#define P11PA_TOKEN_INFO_MIN_PIN_LEN 4

#define P11PA_SESSION_ID 1

#define P11PA_OBJECT_CKA_LABEL "P11PA"
#define P11PA_OBJECT_CKA_VALUE "Unused"
#define P11PA_OBJECT_SIZE 256
#define P11PA_OBJECT_HANDLE_DATA 1
#define P11PA_OBJECT_HANDLE_SECRET_KEY 2
#define P11PA_OBJECT_HANDLE_PUBLIC_KEY 3
#define P11PA_OBJECT_HANDLE_PRIVATE_KEY 4

typedef enum
{
    P11PA_OPERATION_NONE,
    P11PA_OPERATION_FIND,
    P11PA_OPERATION_FIND_COMPLETE,
    P11PA_OPERATION_ENCRYPT,
    P11PA_OPERATION_DECRYPT,
    P11PA_OPERATION_DIGEST,
    P11PA_OPERATION_SIGN,
    P11PA_OPERATION_SIGN_RECOVER,
    P11PA_OPERATION_VERIFY,
    P11PA_OPERATION_VERIFY_RECOVER,
    P11PA_OPERATION_DIGEST_ENCRYPT,
    P11PA_OPERATION_DECRYPT_DIGEST,
    P11PA_OPERATION_SIGN_ENCRYPT,
    P11PA_OPERATION_DECRYPT_VERIFY
} P11PA_OPERATION;

CK_BBOOL p11pa_initialized = CK_FALSE;
CK_BBOOL p11pa_session_opened = CK_FALSE;
CK_ULONG p11pa_session_state = CKS_RO_PUBLIC_SESSION;
P11PA_OPERATION p11pa_active_operation = P11PA_OPERATION_NONE;
CK_OBJECT_HANDLE p11pa_find_result = CKR_OBJECT_HANDLE_INVALID;
CK_FUNCTION_LIST p11pa_functions;

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    if (CK_TRUE == p11pa_initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    UNREFERENCED_PARAMETER(pInitArgs);

    p11pa_initialized = CK_TRUE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    UNREFERENCED_PARAMETER(pReserved);

    p11pa_initialized = CK_FALSE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (NULL == pInfo)
        return CKR_ARGUMENTS_BAD;

    pInfo->cryptokiVersion.major = 0x02;
    pInfo->cryptokiVersion.minor = 0x14;
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, P11PA_INFO_MANUFACTURER_ID, strlen(P11PA_INFO_MANUFACTURER_ID));
    pInfo->flags = 0;
    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    memcpy(pInfo->libraryDescription, P11PA_INFO_LIBRARY_DESCRIPTION, strlen(P11PA_INFO_LIBRARY_DESCRIPTION));
    pInfo->libraryVersion.major = 0x01;
    pInfo->libraryVersion.minor = 0x00;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (NULL == ppFunctionList)
        return CKR_ARGUMENTS_BAD;

    //
    // Set the function pointers at runtime
    //

    p11pa_functions.version.major = 2;
    p11pa_functions.version.minor = 20;
    p11pa_functions.C_Initialize = C_Initialize;
    p11pa_functions.C_Finalize = C_Finalize;
    p11pa_functions.C_GetInfo = C_GetInfo;
    p11pa_functions.C_GetFunctionList = C_GetFunctionList;
    p11pa_functions.C_GetSlotList = C_GetSlotList;
    p11pa_functions.C_GetSlotInfo = C_GetSlotInfo;
    p11pa_functions.C_GetTokenInfo = C_GetTokenInfo;
    p11pa_functions.C_GetMechanismList = C_GetMechanismList;
    p11pa_functions.C_GetMechanismInfo = C_GetMechanismInfo;
    p11pa_functions.C_InitToken = C_InitToken;
    p11pa_functions.C_InitPIN = C_InitPIN;
    p11pa_functions.C_SetPIN = C_SetPIN;
    p11pa_functions.C_OpenSession = C_OpenSession;
    p11pa_functions.C_CloseSession = C_CloseSession;
    p11pa_functions.C_CloseAllSessions = C_CloseAllSessions;
    p11pa_functions.C_GetSessionInfo = C_GetSessionInfo;
    p11pa_functions.C_GetOperationState = C_GetOperationState;
    p11pa_functions.C_SetOperationState = C_SetOperationState;
    p11pa_functions.C_Login = C_Login;
    p11pa_functions.C_Logout = C_Logout;
    p11pa_functions.C_CreateObject = C_CreateObject;
    p11pa_functions.C_CopyObject = C_CopyObject;
    p11pa_functions.C_DestroyObject = C_DestroyObject;
    p11pa_functions.C_GetObjectSize = C_GetObjectSize;
    p11pa_functions.C_GetAttributeValue = C_GetAttributeValue;
    p11pa_functions.C_SetAttributeValue = C_SetAttributeValue;
    p11pa_functions.C_FindObjectsInit = C_FindObjectsInit;
    p11pa_functions.C_FindObjects = C_FindObjects;
    p11pa_functions.C_FindObjectsFinal = C_FindObjectsFinal;
    p11pa_functions.C_EncryptInit = C_EncryptInit;
    p11pa_functions.C_Encrypt = C_Encrypt;
    p11pa_functions.C_EncryptUpdate = C_EncryptUpdate;
    p11pa_functions.C_EncryptFinal = C_EncryptFinal;
    p11pa_functions.C_DecryptInit = C_DecryptInit;
    p11pa_functions.C_Decrypt = C_Decrypt;
    p11pa_functions.C_DecryptUpdate = C_DecryptUpdate;
    p11pa_functions.C_DecryptFinal = C_DecryptFinal;
    p11pa_functions.C_DigestInit = C_DigestInit;
    p11pa_functions.C_Digest = C_Digest;
    p11pa_functions.C_DigestUpdate = C_DigestUpdate;
    p11pa_functions.C_DigestKey = C_DigestKey;
    p11pa_functions.C_DigestFinal = C_DigestFinal;
    p11pa_functions.C_SignInit = C_SignInit;
    p11pa_functions.C_Sign = C_Sign;
    p11pa_functions.C_SignUpdate = C_SignUpdate;
    p11pa_functions.C_SignFinal = C_SignFinal;
    p11pa_functions.C_SignRecoverInit = C_SignRecoverInit;
    p11pa_functions.C_SignRecover = C_SignRecover;
    p11pa_functions.C_VerifyInit = C_VerifyInit;
    p11pa_functions.C_Verify = C_Verify;
    p11pa_functions.C_VerifyUpdate = C_VerifyUpdate;
    p11pa_functions.C_VerifyFinal = C_VerifyFinal;
    p11pa_functions.C_VerifyRecoverInit = C_VerifyRecoverInit;
    p11pa_functions.C_VerifyRecover = C_VerifyRecover;
    p11pa_functions.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
    p11pa_functions.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
    p11pa_functions.C_SignEncryptUpdate = C_SignEncryptUpdate;
    p11pa_functions.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
    p11pa_functions.C_GenerateKey = C_GenerateKey;
    p11pa_functions.C_GenerateKeyPair = C_GenerateKeyPair;
    p11pa_functions.C_WrapKey = C_WrapKey;
    p11pa_functions.C_UnwrapKey = C_UnwrapKey;
    p11pa_functions.C_DeriveKey = C_DeriveKey;
    p11pa_functions.C_SeedRandom = C_SeedRandom;
    p11pa_functions.C_GenerateRandom = C_GenerateRandom;
    p11pa_functions.C_GetFunctionStatus = C_GetFunctionStatus;
    p11pa_functions.C_CancelFunction = C_CancelFunction;
    p11pa_functions.C_WaitForSlotEvent = C_WaitForSlotEvent;

    //
    // Return the populated structure
    //

    *ppFunctionList = &p11pa_functions;
    
    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    UNREFERENCED_PARAMETER(tokenPresent);

    if (NULL == pulCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pSlotList)
    {
        *pulCount = 1;
    }
    else
    {
        if (0 == *pulCount)
            return CKR_BUFFER_TOO_SMALL;

        pSlotList[0] = P11PA_SLOT_ID;
        *pulCount = 1;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (NULL == pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    memcpy(pInfo->slotDescription, P11PA_SLOT_INFO_SLOT_DESCRIPTION, strlen(P11PA_SLOT_INFO_SLOT_DESCRIPTION));
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, P11PA_SLOT_INFO_MANUFACTURER_ID, strlen(P11PA_SLOT_INFO_MANUFACTURER_ID));
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0x01;
    pInfo->hardwareVersion.minor = 0x00;
    pInfo->firmwareVersion.major = 0x01;
    pInfo->firmwareVersion.minor = 0x00;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (NULL == pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo->label, ' ', sizeof(pInfo->label));
    memcpy(pInfo->label, P11PA_TOKEN_INFO_LABEL, strlen(P11PA_TOKEN_INFO_LABEL));
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, P11PA_TOKEN_INFO_MANUFACTURER_ID, strlen(P11PA_TOKEN_INFO_MANUFACTURER_ID));
    memset(pInfo->model, ' ', sizeof(pInfo->model));
    memcpy(pInfo->model, P11PA_TOKEN_INFO_MODEL, strlen(P11PA_TOKEN_INFO_MODEL));
    memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
    memcpy(pInfo->serialNumber, P11PA_TOKEN_INFO_SERIAL_NUMBER, strlen(P11PA_TOKEN_INFO_SERIAL_NUMBER));
    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = (CK_TRUE == p11pa_session_opened) ? 1 : 0;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = ((CK_TRUE == p11pa_session_opened) && ((CKS_RO_PUBLIC_SESSION != p11pa_session_state) || (CKS_RO_USER_FUNCTIONS != p11pa_session_state))) ? 1 : 0;
    pInfo->ulMaxPinLen = P11PA_TOKEN_INFO_MAX_PIN_LEN;
    pInfo->ulMinPinLen = P11PA_TOKEN_INFO_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 0x01;
    pInfo->hardwareVersion.minor = 0x00;
    pInfo->firmwareVersion.major = 0x01;
    pInfo->firmwareVersion.minor = 0x00;
    memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (NULL == pulCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pMechanismList)
    {
        *pulCount = 9;
    }
    else
    {
        if (9 > *pulCount)
            return CKR_BUFFER_TOO_SMALL;

        pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
        pMechanismList[1] = CKM_RSA_PKCS;
        pMechanismList[2] = CKM_SHA1_RSA_PKCS;
        pMechanismList[3] = CKM_RSA_PKCS_OAEP;
        pMechanismList[4] = CKM_DES3_CBC;
        pMechanismList[5] = CKM_DES3_KEY_GEN;
        pMechanismList[6] = CKM_SHA_1;
        pMechanismList[7] = CKM_XOR_BASE_AND_DATA;
        pMechanismList[8] = CKM_AES_CBC;

        *pulCount = 9;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (NULL == pInfo)
        return CKR_ARGUMENTS_BAD;

    switch (type)
    {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 1024;
        pInfo->flags = CKF_GENERATE_KEY_PAIR;
        break;

    case CKM_RSA_PKCS:
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 1024;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP;
        break;

    case CKM_SHA1_RSA_PKCS:
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 1024;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;

    case CKM_RSA_PKCS_OAEP:
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 1024;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;

    case CKM_DES3_CBC:
        pInfo->ulMinKeySize = 192;
        pInfo->ulMaxKeySize = 192;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;

    case CKM_DES3_KEY_GEN:
        pInfo->ulMinKeySize = 192;
        pInfo->ulMaxKeySize = 192;
        pInfo->flags = CKF_GENERATE;
        break;

    case CKM_SHA_1:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;

    case CKM_XOR_BASE_AND_DATA:
        pInfo->ulMinKeySize = 128;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_DERIVE;
        break;

    case CKM_AES_CBC:
        pInfo->ulMinKeySize = 128;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (NULL == pPin)
        return CKR_ARGUMENTS_BAD;

    if ((ulPinLen < P11PA_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > P11PA_TOKEN_INFO_MAX_PIN_LEN))
        return CKR_PIN_LEN_RANGE;

    if (NULL == pLabel)
        return CKR_ARGUMENTS_BAD;

    if (CK_TRUE == p11pa_session_opened)
        return CKR_SESSION_EXISTS;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (CKS_RW_SO_FUNCTIONS != p11pa_session_state)
        return CKR_USER_NOT_LOGGED_IN;

    if (NULL == pPin)
        return CKR_ARGUMENTS_BAD;

    if ((ulPinLen < P11PA_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > P11PA_TOKEN_INFO_MAX_PIN_LEN))
        return CKR_PIN_LEN_RANGE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((CKS_RO_PUBLIC_SESSION == p11pa_session_state) || (CKS_RO_USER_FUNCTIONS == p11pa_session_state))
        return CKR_SESSION_READ_ONLY;

    if (NULL == pOldPin)
        return CKR_ARGUMENTS_BAD;

    if ((ulOldLen < P11PA_TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > P11PA_TOKEN_INFO_MAX_PIN_LEN))
        return CKR_PIN_LEN_RANGE;

    if (NULL == pNewPin)
        return CKR_ARGUMENTS_BAD;

    if ((ulNewLen < P11PA_TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > P11PA_TOKEN_INFO_MAX_PIN_LEN))
        return CKR_PIN_LEN_RANGE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (CK_TRUE == p11pa_session_opened)
        return CKR_SESSION_COUNT;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(pApplication);

    UNREFERENCED_PARAMETER(Notify);

    if (NULL == phSession)
        return CKR_ARGUMENTS_BAD;

    p11pa_session_opened = CK_TRUE;
    p11pa_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    *phSession = P11PA_SESSION_ID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    p11pa_session_opened = CK_FALSE;
    p11pa_session_state = CKS_RO_PUBLIC_SESSION;
    p11pa_active_operation = P11PA_OPERATION_NONE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    p11pa_session_opened = CK_FALSE;
    p11pa_session_state = CKS_RO_PUBLIC_SESSION;
    p11pa_active_operation = P11PA_OPERATION_NONE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pInfo)
        return CKR_ARGUMENTS_BAD;

    pInfo->slotID = P11PA_SLOT_ID;
    pInfo->state = p11pa_session_state;
    pInfo->flags = CKF_SERIAL_SESSION;
    if ((p11pa_session_state != CKS_RO_PUBLIC_SESSION) && (p11pa_session_state != CKS_RO_USER_FUNCTIONS))
        pInfo->flags = pInfo->flags | CKF_RW_SESSION;
    pInfo->ulDeviceError = 0;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pulOperationStateLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pOperationState)
    {
        *pulOperationStateLen = 256;
    }
    else
    {
        if (256 > *pulOperationStateLen)
            return CKR_BUFFER_TOO_SMALL;

        memset(pOperationState, 1, 256);
        *pulOperationStateLen = 256;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pOperationState)
        return CKR_ARGUMENTS_BAD;

    if (256 != ulOperationStateLen)
        return CKR_ARGUMENTS_BAD;

    UNREFERENCED_PARAMETER(hEncryptionKey);

    UNREFERENCED_PARAMETER(hAuthenticationKey);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rv = CKR_OK;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((CKU_SO != userType) && (CKU_USER != userType))
        return CKR_USER_TYPE_INVALID;

    if (NULL == pPin)
        return CKR_ARGUMENTS_BAD;

    if ((ulPinLen < P11PA_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > P11PA_TOKEN_INFO_MAX_PIN_LEN))
        return CKR_PIN_LEN_RANGE;

    switch (p11pa_session_state)
    {
    case CKS_RO_PUBLIC_SESSION:

        if (CKU_SO == userType)
            rv = CKR_SESSION_READ_ONLY_EXISTS;
        else
            p11pa_session_state = CKS_RO_USER_FUNCTIONS;

        break;

    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:

        rv = (CKU_SO == userType) ? CKR_USER_ANOTHER_ALREADY_LOGGED_IN : CKR_USER_ALREADY_LOGGED_IN;

        break;

    case CKS_RW_PUBLIC_SESSION:

        p11pa_session_state = (CKU_SO == userType) ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;

        break;

    case CKS_RW_SO_FUNCTIONS:

        rv = (CKU_SO == userType) ? CKR_USER_ALREADY_LOGGED_IN : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

        break;
    }

    LOG_CALL(__FUNCTION__, 0);
    return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((p11pa_session_state == CKS_RO_PUBLIC_SESSION) || (p11pa_session_state == CKS_RW_PUBLIC_SESSION))
        return CKR_USER_NOT_LOGGED_IN;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == phObject)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++)
    {
        if (NULL == pTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *phObject = P11PA_OBJECT_HANDLE_DATA;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (P11PA_OBJECT_HANDLE_DATA != hObject)
        return CKR_OBJECT_HANDLE_INVALID;

    if (NULL == phNewObject)
        return CKR_ARGUMENTS_BAD;

    if ((NULL != pTemplate) && (0 >= ulCount))
    {
        for (i = 0; i < ulCount; i++)
        {
            if (NULL == pTemplate[i].pValue)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            if (0 >= pTemplate[i].ulValueLen)
                return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    *phNewObject = P11PA_OBJECT_HANDLE_DATA;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((P11PA_OBJECT_HANDLE_DATA != hObject) &&
        (P11PA_OBJECT_HANDLE_SECRET_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hObject))
        return CKR_OBJECT_HANDLE_INVALID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((P11PA_OBJECT_HANDLE_DATA != hObject) &&
        (P11PA_OBJECT_HANDLE_SECRET_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hObject))
        return CKR_OBJECT_HANDLE_INVALID;

    if (NULL == pulSize)
        return CKR_ARGUMENTS_BAD;

    *pulSize = P11PA_OBJECT_SIZE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((P11PA_OBJECT_HANDLE_DATA != hObject) &&
        (P11PA_OBJECT_HANDLE_SECRET_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hObject))
        return CKR_OBJECT_HANDLE_INVALID;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulCount)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++)
    {
        if (CKA_LABEL == pTemplate[i].type)
        {
            if (NULL != pTemplate[i].pValue)
            {
                if (pTemplate[i].ulValueLen < strlen(P11PA_OBJECT_CKA_LABEL))
                    return CKR_BUFFER_TOO_SMALL;
                else
                    memcpy(pTemplate[i].pValue, P11PA_OBJECT_CKA_LABEL, strlen(P11PA_OBJECT_CKA_LABEL));
            }

            pTemplate[i].ulValueLen = (CK_ULONG) strlen(P11PA_OBJECT_CKA_LABEL);
        }
        else if (CKA_VALUE == pTemplate[i].type)
        {
            if (P11PA_OBJECT_HANDLE_PRIVATE_KEY == hObject)
            {
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
            }
            else
            {
                if (NULL != pTemplate[i].pValue)
                {
                    if (pTemplate[i].ulValueLen < strlen(P11PA_OBJECT_CKA_VALUE))
                        return CKR_BUFFER_TOO_SMALL;
                    else
                        memcpy(pTemplate[i].pValue, P11PA_OBJECT_CKA_VALUE, strlen(P11PA_OBJECT_CKA_VALUE));
                }

                pTemplate[i].ulValueLen = (CK_ULONG) strlen(P11PA_OBJECT_CKA_VALUE);
            }
        }
        else
        {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((P11PA_OBJECT_HANDLE_DATA != hObject) &&
        (P11PA_OBJECT_HANDLE_SECRET_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
        (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hObject))
        return CKR_OBJECT_HANDLE_INVALID;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulCount)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++)
    {
        if ((CKA_LABEL == pTemplate[i].type) || (CKA_VALUE == pTemplate[i].type))
        {
            if (NULL == pTemplate[i].pValue)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            if (0 >= pTemplate[i].ulValueLen)
                return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        else
        {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i = 0;
    CK_ULONG_PTR cka_class_value = NULL;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_NONE != p11pa_active_operation)
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    UNREFERENCED_PARAMETER(ulCount);

    p11pa_find_result = CK_INVALID_HANDLE;

    for (i = 0; i < ulCount; i++)
    {
        if (NULL == pTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (CKA_CLASS == pTemplate[i].type)
        {
            if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            cka_class_value = (CK_ULONG_PTR)pTemplate[i].pValue;

            switch (*cka_class_value)
            {
            case CKO_DATA:
                p11pa_find_result = P11PA_OBJECT_HANDLE_DATA;
                break;
            case CKO_SECRET_KEY:
                p11pa_find_result = P11PA_OBJECT_HANDLE_SECRET_KEY;
                break;
            case CKO_PUBLIC_KEY:
                p11pa_find_result = P11PA_OBJECT_HANDLE_PUBLIC_KEY;
                break;
            case CKO_PRIVATE_KEY:
                p11pa_find_result = P11PA_OBJECT_HANDLE_PRIVATE_KEY;
                break;
            }
        }
    }

    p11pa_active_operation = P11PA_OPERATION_FIND;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (    P11PA_OPERATION_FIND != p11pa_active_operation &&
            P11PA_OPERATION_FIND_COMPLETE != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if ((NULL == phObject) && (0 < ulMaxObjectCount))
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulObjectCount)
        return CKR_ARGUMENTS_BAD;

    if (P11PA_OPERATION_FIND_COMPLETE == p11pa_active_operation) 
    {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    switch (p11pa_find_result)
    {
    case P11PA_OBJECT_HANDLE_DATA:
        if (ulMaxObjectCount >= 2)
        {
            phObject[0] = p11pa_find_result;
            phObject[1] = p11pa_find_result;
        }

        *pulObjectCount = 2;
        p11pa_active_operation = P11PA_OPERATION_FIND_COMPLETE;
        break;

    case CK_INVALID_HANDLE:
        *pulObjectCount = 0;
        break;

    default:
        if (ulMaxObjectCount >= 1)
        {
            phObject[0] = p11pa_find_result;
        }

        *pulObjectCount = 1;
        p11pa_active_operation = P11PA_OPERATION_FIND_COMPLETE;
        break;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (    P11PA_OPERATION_FIND != p11pa_active_operation && 
            P11PA_OPERATION_FIND_COMPLETE != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    p11pa_active_operation = P11PA_OPERATION_NONE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_NONE != p11pa_active_operation) &&
        (P11PA_OPERATION_DIGEST != p11pa_active_operation) &&
        (P11PA_OPERATION_SIGN != p11pa_active_operation))
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS:

        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_RSA_PKCS_OAEP:

        if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_DES3_CBC:

        if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_AES_CBC:

        if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    default:

        return CKR_MECHANISM_INVALID;
    }

    switch (p11pa_active_operation)
    {
    case P11PA_OPERATION_NONE:
        p11pa_active_operation = P11PA_OPERATION_ENCRYPT;
        break;
    case P11PA_OPERATION_DIGEST:
        p11pa_active_operation = P11PA_OPERATION_DIGEST_ENCRYPT;
        break;
    case P11PA_OPERATION_SIGN:
        p11pa_active_operation = P11PA_OPERATION_SIGN_ENCRYPT;
        break;
    default:
        return CKR_FUNCTION_FAILED;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_ENCRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulEncryptedDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pEncryptedData)
    {
        if (ulDataLen > *pulEncryptedDataLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulDataLen; i++)
                pEncryptedData[i] = pData[i] ^ 0xAB;

            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulEncryptedDataLen = ulDataLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_ENCRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pEncryptedPart)
    {
        if (ulPartLen > *pulEncryptedPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulPartLen; i++)
                pEncryptedPart[i] = pPart[i] ^ 0xAB;
        }
    }

    *pulEncryptedPartLen = ulPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_ENCRYPT != p11pa_active_operation) &&
        (P11PA_OPERATION_DIGEST_ENCRYPT != p11pa_active_operation) &&
        (P11PA_OPERATION_SIGN_ENCRYPT != p11pa_active_operation))
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pulLastEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pLastEncryptedPart)
    {
        switch (p11pa_active_operation)
        {
        case P11PA_OPERATION_ENCRYPT:
            p11pa_active_operation = P11PA_OPERATION_NONE;
            break;
        case P11PA_OPERATION_DIGEST_ENCRYPT:
            p11pa_active_operation = P11PA_OPERATION_DIGEST;
            break;
        case P11PA_OPERATION_SIGN_ENCRYPT:
            p11pa_active_operation = P11PA_OPERATION_SIGN;
            break;
        default:
            return CKR_FUNCTION_FAILED;
        }
    }

    *pulLastEncryptedPartLen = 0;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_NONE != p11pa_active_operation) &&
        (P11PA_OPERATION_DIGEST != p11pa_active_operation) &&
        (P11PA_OPERATION_VERIFY != p11pa_active_operation))
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS:

        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_RSA_PKCS_OAEP:

        if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_DES3_CBC:

        if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    case CKM_AES_CBC:

        if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;

        break;

    default:

        return CKR_MECHANISM_INVALID;
    }

    switch (p11pa_active_operation)
    {
    case P11PA_OPERATION_NONE:
        p11pa_active_operation = P11PA_OPERATION_DECRYPT;
        break;
    case P11PA_OPERATION_DIGEST:
        p11pa_active_operation = P11PA_OPERATION_DECRYPT_DIGEST;
        break;
    case P11PA_OPERATION_VERIFY:
        p11pa_active_operation = P11PA_OPERATION_DECRYPT_VERIFY;
        break;
    default:
        return CKR_FUNCTION_FAILED;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DECRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pEncryptedData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulEncryptedDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pData)
    {
        if (ulEncryptedDataLen > *pulDataLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulEncryptedDataLen; i++)
                pData[i] = pEncryptedData[i] ^ 0xAB;

            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulDataLen = ulEncryptedDataLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DECRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pEncryptedPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pPart)
    {
        if (ulEncryptedPartLen > *pulPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulEncryptedPartLen; i++)
                pPart[i] = pEncryptedPart[i] ^ 0xAB;
        }
    }

    *pulPartLen = ulEncryptedPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_DECRYPT != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT_DIGEST != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT_VERIFY != p11pa_active_operation))
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pulLastPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pLastPart)
    {
        switch (p11pa_active_operation)
        {
        case P11PA_OPERATION_DECRYPT:
            p11pa_active_operation = P11PA_OPERATION_NONE;
            break;
        case P11PA_OPERATION_DECRYPT_DIGEST:
            p11pa_active_operation = P11PA_OPERATION_DIGEST;
            break;
        case P11PA_OPERATION_DECRYPT_VERIFY:
            p11pa_active_operation = P11PA_OPERATION_VERIFY;
            break;
        default:
            return CKR_FUNCTION_FAILED;
        }
    }

    *pulLastPartLen = 0;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_NONE != p11pa_active_operation) &&
        (P11PA_OPERATION_ENCRYPT != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT != p11pa_active_operation))
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_SHA_1 != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    switch (p11pa_active_operation)
    {
    case P11PA_OPERATION_NONE:
        p11pa_active_operation = P11PA_OPERATION_DIGEST;
        break;
    case P11PA_OPERATION_ENCRYPT:
        p11pa_active_operation = P11PA_OPERATION_DIGEST_ENCRYPT;
        break;
    case P11PA_OPERATION_DECRYPT:
        p11pa_active_operation = P11PA_OPERATION_DECRYPT_DIGEST;
        break;
    default:
        return CKR_FUNCTION_FAILED;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DIGEST != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulDigestLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pDigest)
    {
        if (sizeof(hash) > *pulDigestLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(pDigest, hash, sizeof(hash));
            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulDigestLen = sizeof(hash);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DIGEST != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DIGEST != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
        return CKR_OBJECT_HANDLE_INVALID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_DIGEST != p11pa_active_operation) &&
        (P11PA_OPERATION_DIGEST_ENCRYPT != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT_DIGEST != p11pa_active_operation))
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pulDigestLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pDigest)
    {
        if (sizeof(hash) > *pulDigestLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(pDigest, hash, sizeof(hash));

            switch (p11pa_active_operation)
            {
            case P11PA_OPERATION_DIGEST:
                p11pa_active_operation = P11PA_OPERATION_NONE;
                break;
            case P11PA_OPERATION_DIGEST_ENCRYPT:
                p11pa_active_operation = P11PA_OPERATION_ENCRYPT;
                break;
            case P11PA_OPERATION_DECRYPT_DIGEST:
                p11pa_active_operation = P11PA_OPERATION_DECRYPT;
                break;
            default:
                return CKR_FUNCTION_FAILED;
            }
        }
    }

    *pulDigestLen = sizeof(hash);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_NONE != p11pa_active_operation) &&
        (P11PA_OPERATION_ENCRYPT != p11pa_active_operation))
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
    {
        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else
    {
        return CKR_MECHANISM_INVALID;
    }

    if (P11PA_OPERATION_NONE == p11pa_active_operation)
        p11pa_active_operation = P11PA_OPERATION_SIGN;
    else
        p11pa_active_operation = P11PA_OPERATION_SIGN_ENCRYPT;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_SIGN != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pSignature)
    {
        if (sizeof(signature) > *pulSignatureLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(pSignature, signature, sizeof(signature));
            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulSignatureLen = sizeof(signature);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_SIGN != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_SIGN != p11pa_active_operation) &&
        (P11PA_OPERATION_SIGN_ENCRYPT != p11pa_active_operation))
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pSignature)
    {
        if (sizeof(signature) > *pulSignatureLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(pSignature, signature, sizeof(signature));

            if (P11PA_OPERATION_SIGN == p11pa_active_operation)
                p11pa_active_operation = P11PA_OPERATION_NONE;
            else
                p11pa_active_operation = P11PA_OPERATION_ENCRYPT;
        }
    }

    *pulSignatureLen = sizeof(signature);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_NONE != p11pa_active_operation)
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_RSA_PKCS == pMechanism->mechanism)
    {
        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else
    {
        return CKR_MECHANISM_INVALID;
    }

    p11pa_active_operation = P11PA_OPERATION_SIGN_RECOVER;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_SIGN_RECOVER != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pSignature)
    {
        if (ulDataLen > *pulSignatureLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulDataLen; i++)
                pSignature[i] = pData[i] ^ 0xAB;

            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulSignatureLen = ulDataLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_NONE != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT != p11pa_active_operation))
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
    {
        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else
    {
        return CKR_MECHANISM_INVALID;
    }

    if (P11PA_OPERATION_NONE == p11pa_active_operation)
        p11pa_active_operation = P11PA_OPERATION_VERIFY;
    else
        p11pa_active_operation = P11PA_OPERATION_DECRYPT_VERIFY;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_VERIFY != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pSignature)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (sizeof(signature) != ulSignatureLen)
        return CKR_SIGNATURE_LEN_RANGE;

    if (0 != memcmp(pSignature, signature, sizeof(signature)))
        return CKR_SIGNATURE_INVALID;

    p11pa_active_operation = P11PA_OPERATION_NONE;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_VERIFY != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((P11PA_OPERATION_VERIFY != p11pa_active_operation) &&
        (P11PA_OPERATION_DECRYPT_VERIFY != p11pa_active_operation))
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pSignature)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (sizeof(signature) != ulSignatureLen)
        return CKR_SIGNATURE_LEN_RANGE;

    if (0 != memcmp(pSignature, signature, sizeof(signature)))
        return CKR_SIGNATURE_INVALID;

    if (P11PA_OPERATION_VERIFY == p11pa_active_operation)
        p11pa_active_operation = P11PA_OPERATION_NONE;
    else
        p11pa_active_operation = P11PA_OPERATION_DECRYPT;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_NONE != p11pa_active_operation)
        return CKR_OPERATION_ACTIVE;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_RSA_PKCS == pMechanism->mechanism)
    {
        if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
            return CKR_MECHANISM_PARAM_INVALID;

        if (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hKey)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else
    {
        return CKR_MECHANISM_INVALID;
    }

    p11pa_active_operation = P11PA_OPERATION_VERIFY_RECOVER;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_VERIFY_RECOVER != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pSignature)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulDataLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pData)
    {
        if (ulSignatureLen > *pulDataLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulSignatureLen; i++)
                pData[i] = pSignature[i] ^ 0xAB;

            p11pa_active_operation = P11PA_OPERATION_NONE;
        }
    }

    *pulDataLen = ulSignatureLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DIGEST_ENCRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pEncryptedPart)
    {
        if (ulPartLen > *pulEncryptedPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulPartLen; i++)
                pEncryptedPart[i] = pPart[i] ^ 0xAB;
        }
    }

    *pulEncryptedPartLen = ulPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DECRYPT_DIGEST != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pEncryptedPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pPart)
    {
        if (ulEncryptedPartLen > *pulPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulEncryptedPartLen; i++)
                pPart[i] = pEncryptedPart[i] ^ 0xAB;
        }
    }

    *pulPartLen = ulEncryptedPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_SIGN_ENCRYPT != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pEncryptedPart)
    {
        if (ulPartLen > *pulEncryptedPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulPartLen; i++)
                pEncryptedPart[i] = pPart[i] ^ 0xAB;
        }
    }

    *pulEncryptedPartLen = ulPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_OPERATION_DECRYPT_VERIFY != p11pa_active_operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pEncryptedPart)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulEncryptedPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pulPartLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pPart)
    {
        if (ulEncryptedPartLen > *pulPartLen)
        {
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            for (i = 0; i < ulEncryptedPartLen; i++)
                pPart[i] = pEncryptedPart[i] ^ 0xAB;
        }
    }

    *pulPartLen = ulEncryptedPartLen;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_DES3_KEY_GEN != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == phKey)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++)
    {
        if (NULL == pTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *phKey = P11PA_OBJECT_HANDLE_SECRET_KEY;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_RSA_PKCS_KEY_PAIR_GEN != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    if (NULL == pPublicKeyTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPublicKeyAttributeCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pPrivateKeyTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulPrivateKeyAttributeCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == phPublicKey)
        return CKR_ARGUMENTS_BAD;

    if (NULL == phPrivateKey)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulPublicKeyAttributeCount; i++)
    {
        if (NULL == pPublicKeyTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pPublicKeyTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    for (i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
        if (NULL == pPrivateKeyTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pPrivateKeyTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *phPublicKey = P11PA_OBJECT_HANDLE_PUBLIC_KEY;
    *phPrivateKey = P11PA_OBJECT_HANDLE_PRIVATE_KEY;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    CK_BYTE wrappedKey[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_RSA_PKCS != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    if (P11PA_OBJECT_HANDLE_PUBLIC_KEY != hWrappingKey)
        return CKR_KEY_HANDLE_INVALID;

    if (P11PA_OBJECT_HANDLE_SECRET_KEY != hKey)
        return CKR_KEY_HANDLE_INVALID;

    if (NULL != pWrappedKey)
    {
        if (sizeof(wrappedKey) > *pulWrappedKeyLen)
            return CKR_BUFFER_TOO_SMALL;
        else
            memcpy(pWrappedKey, wrappedKey, sizeof(wrappedKey));
    }

    *pulWrappedKeyLen = sizeof(wrappedKey);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_RSA_PKCS != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    if (P11PA_OBJECT_HANDLE_PRIVATE_KEY != hUnwrappingKey)
        return CKR_KEY_HANDLE_INVALID;

    if (NULL == pWrappedKey)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulWrappedKeyLen)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pTemplate)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulAttributeCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == phKey)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulAttributeCount; i++)
    {
        if (NULL == pTemplate[i].pValue)
            return CKR_ATTRIBUTE_VALUE_INVALID;

        if (0 >= pTemplate[i].ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *phKey = P11PA_OBJECT_HANDLE_SECRET_KEY;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_ULONG i = 0;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (CKM_XOR_BASE_AND_DATA != pMechanism->mechanism)
        return CKR_MECHANISM_INVALID;

    if ((NULL == pMechanism->pParameter) || (sizeof(CK_KEY_DERIVATION_STRING_DATA) != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;

    if (P11PA_OBJECT_HANDLE_SECRET_KEY != hBaseKey)
        return CKR_OBJECT_HANDLE_INVALID;

    if (NULL == phKey)
        return CKR_ARGUMENTS_BAD;

    if ((NULL != pTemplate) && (0 >= ulAttributeCount))
    {
        for (i = 0; i < ulAttributeCount; i++)
        {
            if (NULL == pTemplate[i].pValue)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            if (0 >= pTemplate[i].ulValueLen)
                return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    *phKey = P11PA_OBJECT_HANDLE_SECRET_KEY;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == pSeed)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulSeedLen)
        return CKR_ARGUMENTS_BAD;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    if (NULL == RandomData)
        return CKR_ARGUMENTS_BAD;

    if (0 >= ulRandomLen)
        return CKR_ARGUMENTS_BAD;

    memset(RandomData, 1, ulRandomLen);

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((0 != flags) && (CKF_DONT_BLOCK != flags))
        return CKR_ARGUMENTS_BAD;

    if (NULL == pSlot)
        return CKR_ARGUMENTS_BAD;

    if (NULL != pReserved)
        return CKR_ARGUMENTS_BAD;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_NO_EVENT;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetUnmanagedStructSizeList)(CK_ULONG_PTR pSizeList, CK_ULONG_PTR pulCount)
{
    CK_ULONG sizes[] = {
        sizeof(CK_ATTRIBUTE),
        sizeof(CK_C_INITIALIZE_ARGS),
        sizeof(CK_FUNCTION_LIST),
        sizeof(CK_INFO),
        sizeof(CK_MECHANISM),
        sizeof(CK_MECHANISM_INFO),
        sizeof(CK_SESSION_INFO),
        sizeof(CK_SLOT_INFO),
        sizeof(CK_TOKEN_INFO),
        sizeof(CK_VERSION),
        sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS),
        sizeof(CK_AES_CTR_PARAMS),
        sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS),
        sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS),
        sizeof(CK_CAMELLIA_CTR_PARAMS),
        sizeof(CK_CMS_SIG_PARAMS),
        sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS),
        sizeof(CK_ECDH1_DERIVE_PARAMS),
        sizeof(CK_ECDH2_DERIVE_PARAMS),
        sizeof(CK_ECMQV_DERIVE_PARAMS),
        sizeof(CK_EXTRACT_PARAMS),
        sizeof(CK_KEA_DERIVE_PARAMS),
        sizeof(CK_KEY_DERIVATION_STRING_DATA),
        sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS),
        sizeof(CK_KIP_PARAMS),
        sizeof(CK_MAC_GENERAL_PARAMS),
        sizeof(CK_OTP_PARAM),
        sizeof(CK_OTP_PARAMS),
        sizeof(CK_OTP_SIGNATURE_INFO),
        sizeof(CK_PBE_PARAMS),
        sizeof(CK_PKCS5_PBKD2_PARAMS),
        sizeof(CK_RC2_CBC_PARAMS),
        sizeof(CK_RC2_MAC_GENERAL_PARAMS),
        sizeof(CK_RC2_PARAMS),
        sizeof(CK_RC5_CBC_PARAMS),
        sizeof(CK_RC5_MAC_GENERAL_PARAMS),
        sizeof(CK_RC5_PARAMS),
        sizeof(CK_RSA_PKCS_OAEP_PARAMS),
        sizeof(CK_RSA_PKCS_PSS_PARAMS),
        sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS),
        sizeof(CK_SKIPJACK_RELAYX_PARAMS),
        sizeof(CK_SSL3_KEY_MAT_OUT),
        sizeof(CK_SSL3_KEY_MAT_PARAMS),
        sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS),
        sizeof(CK_SSL3_RANDOM_DATA),
        sizeof(CK_TLS_PRF_PARAMS),
        sizeof(CK_WTLS_KEY_MAT_OUT),
        sizeof(CK_WTLS_KEY_MAT_PARAMS),
        sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS),
        sizeof(CK_WTLS_PRF_PARAMS),
        sizeof(CK_WTLS_RANDOM_DATA),
        sizeof(CK_X9_42_DH1_DERIVE_PARAMS),
        sizeof(CK_X9_42_DH2_DERIVE_PARAMS),
        sizeof(CK_X9_42_MQV_DERIVE_PARAMS),
    };

    CK_ULONG sizes_count = sizeof(sizes) / sizeof(CK_ULONG);

    if (NULL == pulCount)
        return CKR_ARGUMENTS_BAD;

    if (NULL == pSizeList)
    {
        *pulCount = sizes_count;
    }
    else
    {
        if (sizes_count > *pulCount)
            return CKR_BUFFER_TOO_SMALL;

        memcpy(pSizeList, sizes, sizeof(sizes));
        *pulCount = sizes_count;
    }

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EjectToken)(CK_SLOT_ID slotID)
{
    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (P11PA_SLOT_ID != slotID)
        return CKR_SLOT_ID_INVALID;

    LOG_CALL(__FUNCTION__, 0);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InteractiveLogin)(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;

    if (CK_FALSE == p11pa_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((CK_FALSE == p11pa_session_opened) || (P11PA_SESSION_ID != hSession))
        return CKR_SESSION_HANDLE_INVALID;

    switch (p11pa_session_state)
    {
    case CKS_RO_PUBLIC_SESSION:

        p11pa_session_state = CKS_RO_USER_FUNCTIONS;

        break;

    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:

        rv = CKR_USER_ALREADY_LOGGED_IN;

        break;

    case CKS_RW_PUBLIC_SESSION:

        p11pa_session_state = CKS_RW_USER_FUNCTIONS;

        break;

    case CKS_RW_SO_FUNCTIONS:

        rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

        break;
    }

    LOG_CALL(__FUNCTION__, 0);
    return rv;
}
