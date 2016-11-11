#ifdef PAM_PLATFORM_ATTESTATION_EXPORTS
#define PAM_PLATFORM_ATTESTATION_API __declspec(dllexport)
#else
#define PAM_PLATFORM_ATTESTATION_API __declspec(dllimport)
#endif

#ifndef __linux__
typedef struct pam_handle pam_handle_t;
#endif

PAM_PLATFORM_ATTESTATION_API int
pam_sm_authenticate(
    pam_handle_t *pamh,
    int flags,
    int argc,
    const char *argv[]);

