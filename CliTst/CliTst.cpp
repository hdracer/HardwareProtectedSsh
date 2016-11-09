/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3 
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html. 
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"
#include "attestationlib.h"

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
        cout << " " << attestationLib.GetEkPubHash() << endl;
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

//
// Console entry point
//
int main(int argc, char *argv[])
{
#ifdef __linux__
DllInit();
try {
#endif

    TestPlatformAttestation();

#ifdef __linux__
}
catch (const runtime_error& exc) {
    cerr << "CliTst: " << exc.what() << "\nExiting...\n";
}
#endif

    return 0;
}

