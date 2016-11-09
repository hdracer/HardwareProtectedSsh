// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the PAM_PLATFORM_ATTESTATION_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// PAM_PLATFORM_ATTESTATION_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef PAM_PLATFORM_ATTESTATION_EXPORTS
#define PAM_PLATFORM_ATTESTATION_API __declspec(dllexport)
#else
#define PAM_PLATFORM_ATTESTATION_API __declspec(dllimport)
#endif

// This class is exported from the pam_platform_attestation.dll
class PAM_PLATFORM_ATTESTATION_API Cpam_platform_attestation {
public:
	Cpam_platform_attestation(void);
	// TODO: add your methods here.
};

extern PAM_PLATFORM_ATTESTATION_API int npam_platform_attestation;

PAM_PLATFORM_ATTESTATION_API int fnpam_platform_attestation(void);
