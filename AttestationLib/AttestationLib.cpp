/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "AttestationLib.h"
#include "Helpers.h"

using namespace TpmCpp;

using namespace utility;
using namespace concurrency;
using namespace concurrency::streams;

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental;
using namespace web::http::experimental::listener;

#define TPM_RESTRICTED_HASH_ALG TPM_ALG_ID::SHA1
#define TPM_USER_HASH_ALG TPM_ALG_ID::SHA256

//
// Structure for flat key storage header
//
typedef struct _ATTESTED_TPM_KEY
{
    unsigned int version;
    unsigned int cbAttestationIdentityKey;
    unsigned int cbAttestedUserKey;
} ATTESTED_TPM_KEY, *PATTESTED_TPM_KEY;

//
// Write hex bytes to console output
//
#define CROW                                                16
static void PrintBytes(char *szTitle, unsigned char *pbData, unsigned long cbData)
{
    unsigned long iByte = 0, iRowItem = 0;

    printf("%s -- %lu bytes\n", szTitle, cbData);

    while (iByte < cbData)
    {
        for (iRowItem = 0;
            iRowItem < CROW && iByte < cbData;
            iRowItem++, iByte++)
            printf("%02X ", pbData[iByte]);
        printf("\n");
    }
}

//
// Class implementation
//

CAttestationLib::CAttestationLib()
{
    return;
}

CAttestationLib::~CAttestationLib(void)
{
    m_tpm.FlushContext(m_hUser);
    m_tpm.FlushContext(m_hAik);
    m_tpm.FlushContext(m_hEk);

    delete m_pDevice;
}

void CAttestationLib::Initialize(
    std::wstring attestationServerHost, 
    std::wstring attestationServerScheme)
{
    //
    // Attestation Web API base address
    //

#ifdef __linux__
    m_attestationServerHost = helpers::ws2s(attestationServerHost);
    m_attestationServerScheme = helpers::ws2s(attestationServerScheme);
#else
    m_attestationServerHost = attestationServerHost;
    m_attestationServerScheme = attestationServerScheme;
#endif 

    // 
    // Tell the TPM2 object where to send commands 
    //

#ifdef __linux__
    //
    // Connect to the Intel TSS resource manager
    //

    TpmTcpDevice *pTcpDevice = new TpmTcpDevice();
    m_pDevice = pTcpDevice;
    if (!pTcpDevice->Connect("127.0.0.1", 2323)) {
        cerr << "Could not connect to the resource manager";
        return;
    }
#else
    //
    // Connect to the TBS
    //

    TpmTbsDevice *pTbsDevice = new TpmTbsDevice();
    m_pDevice = pTbsDevice;
    pTbsDevice->Connect();
#endif
    m_tpm._SetDevice(*m_pDevice);

    //
    // Set platform auth values
    //

    SetPlatformAuthenticationValues();
}

bool CAttestationLib::CreateAttestationIdentityKey()
{
    //
    // Read out the manufacturer Endorsement Key (EK)
    //

    MakeEndorsementKey();
    cout << "EK hash: " << helpers::bytesToHex(
        CryptoServices::Hash(TPM_ALG_ID::SHA256, m_ekPub.ToBuf())) << endl;

    //
    // Create a restricted key in the storage hierarchy
    //

    m_hAik = MakeChildSigningKey(m_hEk, true);
    auto restrictedPubX = m_tpm.ReadPublic(m_hAik);
    m_aikPub = restrictedPubX.outPublic;
    cout << "AIK name: " << helpers::bytesToHex(m_aikPub.GetName()) << endl;

    //
    // For an example of pulling EK manufacturer certificates from the 
    // internet, see:
    // https://github.com/01org/tpm2.0-tools/blob/master/src/tpm2_getmanufec.cpp
    //

    // TODO

    //
    // Request activation to prove linkage between restricted key and EK 
    //

    ByteVec nameOfKeyToActivate = m_hAik.GetName();
    ActivationData encryptedSecret;
    if (false == RestGetActivation(
        m_ekPub,
        m_aikPub,
        encryptedSecret))
    {
        cerr << "RestGetActivation failed" << endl;
        return false;
    }

    //
    // Activation data can only be decrypted on this TPM
    //

    m_decryptedTpmSecret = m_tpm.ActivateCredential(
        m_hAik,
        m_hEk,
        encryptedSecret.CredentialBlob,
        encryptedSecret.Secret);
    return true;
}

bool CAttestationLib::CreateSealedUserKey()
{
    vector<BYTE> NullVec;

    //
    // Read PCR data
    //

    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(
        TPM_USER_HASH_ALG, 7);
    PCR_ReadResponse pcrVals = m_tpm.PCR_Read(pcrsToQuote);

    //
    // Sign the PCR hash with the AIK
    //

    QuoteResponse quote = m_tpm.Quote(
        m_hAik, 
        m_decryptedTpmSecret, 
        TPMS_SCHEME_RSASSA(TPM_USER_HASH_ALG), 
        pcrsToQuote);

    //
    // Create a user signing-only key in the storage hierarchy. 
    //

    TPMT_PUBLIC templ(
        TPM_USER_HASH_ALG,
        TPMA_OBJECT::sign |           // Key attributes
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth,
        NullVec,                      // No policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_SCHEME_RSASSA(TPM_USER_HASH_ALG), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    //
    // Include the same PCR selection as above
    //

    m_userCreate = m_tpm.Create(
        m_hEk,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec),
        templ,
        NullVec,
        pcrsToQuote);

    //
    // Load the new key
    //

    m_hUser = m_tpm.Load(
        m_hEk,
        m_userCreate.outPrivate,
        m_userCreate.outPublic);
    auto userSigningPubX = m_tpm.ReadPublic(m_hUser);
    m_userPub = userSigningPubX.outPublic;

    //
    // Certify the creation of the user key using the AIK
    //

    CertifyCreationResponse createQuote = m_tpm.CertifyCreation(
        m_hAik,
        m_hUser,
        m_decryptedTpmSecret,
        m_userCreate.creationHash,
        TPMS_NULL_SIG_SCHEME(),
        m_userCreate.creationTicket);

    //
    // Send the PCR quote and key certification to the server
    //

    if (false == RestRegisterKey(
        m_aikPub,
        pcrVals, 
        quote,
        m_userCreate.creationData,
        createQuote))
    {
        cerr << "RestRegisterKey failed" << endl;
        return false;
    }

    return true;
}

bool CAttestationLib::SaveSealedUserKey(ByteVec &serializedKey)
{
    ATTESTED_TPM_KEY FlatKey = { 0 };
    unsigned int cbFlatKey = 0;
    ByteVec::iterator it;

    //
    // Serialize the AIK
    //

    ByteVec aikBytes = m_aikCreate.ToBuf();

    //
    // Serialize the user key
    //

    ByteVec userBytes = m_userCreate.ToBuf();

    //
    // Populate the key header
    //
    
    FlatKey.cbAttestationIdentityKey = (unsigned int) aikBytes.size();
    FlatKey.cbAttestedUserKey = (unsigned int) userBytes.size();

    //
    // Build the output
    //

    it = serializedKey.begin();
    serializedKey.insert(
        it + cbFlatKey,
        (unsigned char *) &FlatKey,
        ((unsigned char *) &FlatKey) + sizeof(FlatKey));
    cbFlatKey += (unsigned int) sizeof(FlatKey);

    it = serializedKey.begin();
    serializedKey.insert(
        it + cbFlatKey,
        aikBytes.begin(),
        aikBytes.end());
    cbFlatKey += (unsigned int) aikBytes.size();

    it = serializedKey.begin();
    serializedKey.insert(
        it + cbFlatKey,
        userBytes.begin(),
        userBytes.end());
    cbFlatKey += (unsigned int) userBytes.size();
    return true;
}

bool CAttestationLib::LoadSealedUserKey(ByteVec &serializedKey)
{
    PATTESTED_TPM_KEY pFlatKey = 0;
    unsigned int cbUsed = 0;
    ByteVec::iterator it;
    ByteVec bv;

    //
    // Parameter check
    //

    if (sizeof(ATTESTED_TPM_KEY) >= serializedKey.size())
        return false;

    //
    // Get the header
    //

    pFlatKey = (PATTESTED_TPM_KEY) &serializedKey[0];
    cbUsed += sizeof(ATTESTED_TPM_KEY);

    if (    serializedKey.size() != 
            sizeof(ATTESTED_TPM_KEY) + 
            pFlatKey->cbAttestationIdentityKey + 
            pFlatKey->cbAttestedUserKey)
        return false;

    //
    // Reload the EK
    //

    MakeEndorsementKey();

    //
    // Deserialize the AIK
    //

    it = serializedKey.begin();
    bv.assign(it + cbUsed, it + cbUsed + pFlatKey->cbAttestationIdentityKey);
    m_aikCreate.FromBuf(bv);
    cbUsed += pFlatKey->cbAttestationIdentityKey;

    //
    // Deserialize the user key
    //

    it = serializedKey.begin();
    bv.assign(it + cbUsed, it + cbUsed + pFlatKey->cbAttestedUserKey);
    m_userCreate.FromBuf(bv);
    cbUsed += pFlatKey->cbAttestedUserKey;

    //
    // Reload the user key
    //

    m_hUser = m_tpm.Load(
        m_hEk,
        m_userCreate.outPrivate,
        m_userCreate.outPublic);
    auto userSigningPubX = m_tpm.ReadPublic(m_hUser);
    m_userPub = userSigningPubX.outPublic;
    return true;
}

bool CAttestationLib::CheckUserKeyWhitelist()
{
    return RestLookupRegisteredKey(m_userPub);
}

bool CAttestationLib::VerifySignature(const ByteVec &hashBytes, const ByteVec &signatureBytes)
{
    TPMS_SIGNATURE_RSASSA rsaSsaSig;
    rsaSsaSig.hash = TPM_USER_HASH_ALG;
    rsaSsaSig.sig = signatureBytes;

    return m_userPub.ValidateSignature(
        hashBytes, rsaSsaSig);
}

bool CAttestationLib::SignHash(const ByteVec &hashBytes, ByteVec &signatureBytes)
{
    if (hashBytes.size() < CryptoServices::HashLength(TPM_USER_HASH_ALG))
    {
        return false;
    }

    ByteVec hashToSign;
    hashToSign.assign(
        hashBytes.data() + hashBytes.size() - CryptoServices::HashLength(TPM_USER_HASH_ALG),
        hashBytes.data() + hashBytes.size());

    //
    // Sign a message with the user key
    //

    TpmCpp::SignResponse signature = m_tpm.Sign(
        m_hUser,
        hashToSign,
        TPMS_SCHEME_RSASSA(TPM_USER_HASH_ALG),
        TPMT_TK_HASHCHECK::NullTicket());
    PrintBytes("CAttestationLib::SignHash - Hash", hashToSign.data(), hashToSign.size());
    if (false == m_tpm._LastOperationSucceeded())
    {
        //
        // Handle renewal of the key
        //

        // TODO

        signature.signature = 0;
        cerr << "m_tpm.Sign failed: " << (UINT32) m_tpm._GetLastError() << endl;
        return false;
    }

    //
    // Return the signature bytes
    //

    TPMS_SIGNATURE_RSASSA *pSig = dynamic_cast<TPMS_SIGNATURE_RSASSA *> (signature.signature);
    for (unsigned int iByte = 0; iByte < pSig->sig.size(); iByte++)
    {
        signatureBytes.push_back(pSig->sig[iByte]);
    }
    PrintBytes("CAttestationLib::SignHash - Signature", signatureBytes.data(), signatureBytes.size());
    return true;
}

bool CAttestationLib::SignAndVerifyMessage(const std::string &message)
{
    //
    // Hash the message
    //

    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_USER_HASH_ALG, message).digest;

    //
    // Sign a message with the user key
    //

    auto signature = m_tpm.Sign(
        m_hUser,
        messageHash,
        TPMS_SCHEME_RSASSA(TPM_USER_HASH_ALG),
        TPMT_TK_HASHCHECK::NullTicket());

    //
    // Check the signature.
    //
    // The recipient is assumed to have received the message, its signature, 
    // and the user public key. The latter must either be checked against the 
    // AS whitelist or accompanied by a certificate that must be checked for
    // trust.
    //

    if (false == m_userPub.ValidateSignature(
            messageHash, *signature.signature))
        return false;

    //
    // Process the message, as appropriate for the host app, based on whether 
    // the signature is valid and from a trusted device
    //
    // ...

    return true;
}

ByteVec CAttestationLib::GetEkPubHashBytes()
{
    return CryptoServices::Hash(TPM_ALG_ID::SHA256, m_ekPub.ToBuf());
}

std::string CAttestationLib::GetUserPubHashHex()
{
    ByteVec bvPubHash = CryptoServices::Hash(TPM_ALG_ID::SHA256, m_userPub.ToBuf());

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    std::for_each(
        bvPubHash.cbegin(), 
        bvPubHash.cend(), 
        [&](int c) { ss << std::setw(2) << c; });

    return ss.str();
}

ByteVec CAttestationLib::GetUserPubModulus()
{
    TPM2B_PUBLIC_KEY_RSA *pPub =
        dynamic_cast<TPM2B_PUBLIC_KEY_RSA *> (m_userPub.unique);
    return pPub->buffer;
}

//
// Request an AIK challenge from the Attestation Server 
//
bool CAttestationLib::RestGetActivation(
    TPMT_PUBLIC &clientEkPub,
    TPMT_PUBLIC &clientRestrictedPub,
    ActivationData &activationData)
{
    uri_builder ub;

    //
    // Build the URI
    //

    ub.set_host(m_attestationServerHost);
    ub.set_path(U("/bhtmvc/api/LinuxActivation/"));
    ub.set_scheme(m_attestationServerScheme);
    auto mbk_url = ub.to_string();

    http_client mbk_client(mbk_url);
    http_request request(methods::POST);
    request.headers().set_content_type(U("application/json"));

    //
    // Populate the request
    //

    json::value activation_req_node = json::value::object();
    activation_req_node[U("EkPublic")] = web::json::value::string(
        utility::conversions::to_base64(clientEkPub.ToBuf()));
    activation_req_node[U("AikPublic")] = web::json::value::string(
        utility::conversions::to_base64(clientRestrictedPub.ToBuf()));
    request.set_body(activation_req_node);

    //
    // Send the request and wait
    //

    http_response resp = mbk_client.request(request).get();
    if (status_codes::Created != resp.status_code())
        return false;
    json::value challenge_result = resp.extract_json().get();

    //
    // Decode and return the response
    //

    if (false == challenge_result.is_null() &&
        false == challenge_result[U("Id")].is_null())
    {
        activationData.CredentialBlob = utility::conversions::from_base64(
            challenge_result[U("ChallengeCredential")].as_string());
        activationData.Secret = utility::conversions::from_base64(
            challenge_result[U("ChallengeSecret")].as_string());

        return true;
    }

    return false;
}

//
// Validate platform attestation and key certification with the Attestation Server 
//
bool CAttestationLib::RestRegisterKey(
    TPMT_PUBLIC &clientRestrictedPub,
    PCR_ReadResponse &clientPcrVals,
    QuoteResponse &clientPcrQuote,
    TPMS_CREATION_DATA &clientKeyCreation,
    CertifyCreationResponse &clientKeyQuote)
{
    uri_builder ub;

    //
    // Build the URI
    //

    ub.set_host(m_attestationServerHost);
    ub.set_path(U("/bhtmvc/api/LinuxCertifiedKey/"));
    ub.set_scheme(m_attestationServerScheme);
    auto mbk_url = ub.to_string();

    http_client mbk_client(mbk_url);
    http_request request(methods::POST);
    request.headers().set_content_type(U("application/json"));

    //
    // Populate the request
    //

    json::value reg_req_node = json::value::object();
    reg_req_node[U("AikPublic")] = web::json::value::string(
        utility::conversions::to_base64(clientRestrictedPub.ToBuf()));
    reg_req_node[U("Pcrs")] = web::json::value::string(
        utility::conversions::to_base64(clientPcrVals.ToBuf()));
    reg_req_node[U("PcrQuote")] = web::json::value::string(
        utility::conversions::to_base64(clientPcrQuote.ToBuf()));
    reg_req_node[U("KeyCreationData")] = web::json::value::string(
        utility::conversions::to_base64(clientKeyCreation.ToBuf()));
    reg_req_node[U("KeyQuote")] = web::json::value::string(
        utility::conversions::to_base64(clientKeyQuote.ToBuf()));
    reg_req_node[U("ClientDeviceName")] = web::json::value::string(helpers::getDeviceName());
    reg_req_node[U("SystemVersion")] = web::json::value::string(helpers::getSystemVersion());
    request.set_body(reg_req_node);

    //
    // Send the request and wait
    //

    http_response resp = mbk_client.request(request).get();
    if (status_codes::Created != resp.status_code())
        return false;
    json::value reg_result = resp.extract_json().get();

    //
    // Decode the response
    //

    if (false == reg_result.is_null() &&
        false == reg_result[U("Id")].is_null())
    {
        return true;
    }

    return false;
}

//
// Determine whether the specified public key is trusted/certified
//
bool CAttestationLib::RestLookupRegisteredKey(
    TPMT_PUBLIC &clientPub)
{
    uri_builder ub;

    //
    // Build the URI
    //

    ub.set_host(m_attestationServerHost);
    ub.set_path(U("/bhtmvc/api/LinuxCertifiedKey/"));
    ub.append_query(
        U("publicKeyHash"),
        utility::conversions::to_base64(clientPub.GetName()));
    ub.set_scheme(m_attestationServerScheme);
    auto mbk_url = ub.to_string();

    http_client mbk_client(mbk_url);
    http_request request(methods::GET);
    request.headers().set_content_type(U("application/json"));

    //
    // Send the request and wait
    //

    http_response resp = mbk_client.request(request).get();
    if (status_codes::OK != resp.status_code())
        return false;

    return true;
}

//
// Open the Endorsement Key
//
TPM_HANDLE CAttestationLib::MakeEndorsementKey()
{
    vector<BYTE> NullVec;
    TPMT_PUBLIC storagePrimaryTemplate(
        TPM_RESTRICTED_HASH_ALG,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
        TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        NullVec,           // No policy
        TPMS_RSA_PARMS(    // How child keys should be protected
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    // Create the key
    m_ekCreate = m_tpm.CreatePrimary(
        m_tpm._AdminEndorsement,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec),
        storagePrimaryTemplate,
        NullVec,
        vector<TPMS_PCR_SELECTION>());

    m_hEk = m_ekCreate.objectHandle;
    auto ekPubX = m_tpm.ReadPublic(m_hEk);
    m_ekPub = ekPubX.outPublic;
    return m_hEk;
}

//
// Create an RSA signing key, optionally restricted (i.e., an AIK)
//
TPM_HANDLE CAttestationLib::MakeChildSigningKey(
    TPM_HANDLE parentHandle,
    bool restricted)
{
    vector<BYTE> NullVec;
    TPMA_OBJECT restrictedAttribute;

    if (restricted) {
        restrictedAttribute = TPMA_OBJECT::restricted;
    }

    TPMT_PUBLIC templ(
        TPM_USER_HASH_ALG,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth | restrictedAttribute,
        NullVec,  // No policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_SCHEME_RSASSA(TPM_USER_HASH_ALG), 2048, 65537), // PKCS1.5
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    m_aikCreate = m_tpm.Create(
        parentHandle,
        TPMS_SENSITIVE_CREATE(),
        templ,
        NullVec,
        vector<TPMS_PCR_SELECTION>());

    auto signKey = m_tpm.Load(
        parentHandle, m_aikCreate.outPrivate, m_aikCreate.outPublic);
    return signKey;
}

//
// Assume that TPM ownership has been taken and that auth values are
// non-null.
//
void CAttestationLib::SetPlatformAuthenticationValues()
{
#ifndef __linux__
    WCHAR wszAuthReg[1024] = { 0 };
    UINT32 cbAuthReg = sizeof(wszAuthReg);
    BYTE rgbAuthValue[1024] = { 0 };
    UINT32 cbAuthValue = sizeof(rgbAuthValue);

    //
    // Endorsement
    //

    if (RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement",
        L"EndorsementAuth",
        RRF_RT_REG_SZ,
        NULL,
        wszAuthReg,
        (DWORD*)&cbAuthReg) == ERROR_SUCCESS)
    {
        if (TRUE == CryptStringToBinaryW(
            wszAuthReg,
            0,
            CRYPT_STRING_BASE64,
            rgbAuthValue,
            (DWORD*)&cbAuthValue,
            NULL,
            NULL))
        {
            vector<BYTE> newAuth(rgbAuthValue, rgbAuthValue + cbAuthValue);
            m_tpm._AdminEndorsement.SetAuth(newAuth);
        }
    }

    //
    // Storage
    //

    cbAuthReg = sizeof(wszAuthReg);
    cbAuthValue = sizeof(rgbAuthValue);
    if (RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin",
        L"StorageOwnerAuth",
        RRF_RT_REG_SZ,
        NULL,
        wszAuthReg,
        (DWORD*)&cbAuthReg) == ERROR_SUCCESS)
    {
        if (TRUE == CryptStringToBinaryW(
            wszAuthReg,
            0,
            CRYPT_STRING_BASE64,
            rgbAuthValue,
            (DWORD*)&cbAuthValue,
            NULL,
            NULL))
        {
            vector<BYTE> newAuth(rgbAuthValue, rgbAuthValue + cbAuthValue);
            m_tpm._AdminOwner.SetAuth(newAuth);
        }
    }

#else
    //
    // Linux
    //

    vector<BYTE> newAuth{ '1', '2', '3', '4' };
    m_tpm._AdminOwner.SetAuth(newAuth);
    m_tpm._AdminEndorsement.SetAuth(newAuth);
#endif
}

void CAttestationLib::ShowTpmCapabilities()
{
    UINT32 startVal = 0;

    //
    // Manufacturer information
    // See also https://github.com/ms-iot/security/blob/master/Urchin/T2T/T2T.cpp
    //

    do {
        GetCapabilityResponse caps = m_tpm.GetCapability(TPM_CAP::TPM_PROPERTIES, startVal, 8);
        TPML_TAGGED_TPM_PROPERTY *props = dynamic_cast<TPML_TAGGED_TPM_PROPERTY *> (caps.capabilityData);

        // Print name and value
        for (auto p = props->tpmProperty.begin(); p != props->tpmProperty.end(); p++) {
            char *pCharValue = (char *)&p->value;
            cout << Tpm2::GetEnumString(p->property) << ": ";
            switch (p->property)
            {
            case TPM_PT::FAMILY_INDICATOR:
            case TPM_PT::MANUFACTURER:
            case TPM_PT::VENDOR_STRING_1:
            case TPM_PT::VENDOR_STRING_2:
            case TPM_PT::VENDOR_STRING_3:
            case TPM_PT::VENDOR_STRING_4:
                cout << pCharValue[3] << pCharValue[2] << pCharValue[1] << pCharValue[0];
                break;
            default:
                cout << p->value;
                break;
            }
            cout << endl;
        }

        if (!caps.moreData) {
            break;
        }

        startVal = ((UINT32)props->tpmProperty[props->tpmProperty.size() - 1].property) + 1;
    } while (true);
    cout << endl;

    //
    // Cryptographic capabilities
    //

    cout << "Algorithms:" << endl;
    startVal = 0;
    do {
        GetCapabilityResponse caps = m_tpm.GetCapability(TPM_CAP::ALGS, startVal, 8);
        TPML_ALG_PROPERTY *props = dynamic_cast<TPML_ALG_PROPERTY *> (caps.capabilityData);

        // Print alg name and properties
        for (auto p = props->algProperties.begin(); p != props->algProperties.end(); p++) {
            cout << setw(16) << Tpm2::GetEnumString(p->alg) <<
                ": " << Tpm2::GetEnumString(p->algProperties) << endl;
        }

        if (!caps.moreData) {
            break;
        }

        startVal = ((UINT32)props->algProperties[props->algProperties.size() - 1].alg) + 1;
    } while (true);
    cout << endl;
}
