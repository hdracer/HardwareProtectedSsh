/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "pam_platform_attestation.h"
#include "attestationlib.h"

#define PAM_SM_AUTH

#ifndef __linux__
#define PAM_EXTERN                  PAM_PLATFORM_ATTESTATION_API
#define PAM_SUCCESS                 0
#define PAM_SERVICE_ERR             3
#define PAM_AUTH_ERR                9
#else
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif
#endif

PAM_EXTERN 
int
pam_sm_authenticate(
    pam_handle_t *pamh,
    int flags,
    int argc,
    const char *argv[])
{
    CAttestationLib attestationLib;
    int result = PAM_SERVICE_ERR;

    //
    // Initialize attestation helper class
    //

    attestationLib.Initialize(std::wstring(L"https://strongnetsvc.jwsecure.com"), std::wstring(L"https"));

    //
    // Establish an AIK
    //

    if (false == attestationLib.CreateAttestationIdentityKey())
        return PAM_AUTH_ERR;

    //
    // Create a sealed user key
    //

    if (false == attestationLib.CreateSealedUserKey())
        return PAM_AUTH_ERR;

    //
    // Check the user key with the AS
    //

    if (false == attestationLib.CheckUserKeyWhitelist())
        return PAM_AUTH_ERR;

    //
    // Host appears to be compliant
    //

    result = PAM_SUCCESS;

    return result;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SERVICE_ERR);
}

/*
struct pam_module pam_platform_attestation_modstruct = {
    "pam_platform_attestation",
    pam_sm_authenticate,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};
*/

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_platform_attestation");
#endif