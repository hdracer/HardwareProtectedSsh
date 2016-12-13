using namespace TpmCpp;

#ifdef ATTESTATIONLIB_EXPORTS
#define ATTESTATIONLIB_API __declspec(dllexport)
#else
#define ATTESTATIONLIB_API __declspec(dllimport)
#endif

// This class is exported from the AttestationLib.dll
class ATTESTATIONLIB_API CAttestationLib {
public:
	CAttestationLib(void);
    ~CAttestationLib(void);
    void Initialize(std::string attestationServerUrl);
    bool CreateAttestationIdentityKey();
    bool CreateSealedUserKey();
    bool SaveSealedUserKey(ByteVec &serializedKey);
    bool LoadSealedUserKey(ByteVec &serializedKey);
    bool CheckUserKeyWhitelist();
    void ShowTpmCapabilities();
    bool SignAndVerifyMessage(const std::string &message);
    bool SignHash(const ByteVec &hashBytes, ByteVec &signatureBytes);
    ByteVec GetEkPubHashBytes();
    std::string GetUserPubHashHex();

private:
    void SetPlatformAuthenticationValues();
    TPM_HANDLE MakeChildSigningKey(TPM_HANDLE parentHandle, bool restricted);
    TPM_HANDLE MakeStoragePrimary();
    TPM_HANDLE MakeEndorsementKey();
    bool RestLookupRegisteredKey(TPMT_PUBLIC &clientPub);
    bool RestRegisterKey(
        TPMT_PUBLIC &clientRestrictedPub,
        PCR_ReadResponse &clientPcrVals,
        QuoteResponse &clientPcrQuote,
        TPMS_CREATION_DATA &clientKeyCreation,
        CertifyCreationResponse &clientKeyQuote);
    bool CAttestationLib::RestGetActivation(
        TPMT_PUBLIC &clientEkPub,
        TPMT_PUBLIC &clientRestrictedPub,
        ActivationData &activationData);

private:
    std::string m_attestationServerUrl;
    TpmDevice *m_pDevice;
    Tpm2 m_tpm;
    CreatePrimaryResponse m_ekCreate;
    TPM_HANDLE m_hEk;
    TPMT_PUBLIC m_ekPub;
    CreatePrimaryResponse m_srkCreate;
    TPM_HANDLE m_hSrk;
    CreateResponse m_aikCreate;
    TPM_HANDLE m_hAik;
    TPMT_PUBLIC m_aikPub;
    CreateResponse m_userCreate;
    TPM_HANDLE m_hUser;
    TPMT_PUBLIC m_userPub;
    ByteVec m_decryptedTpmSecret;
};
