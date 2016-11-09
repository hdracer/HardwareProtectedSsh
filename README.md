# HardwareProtectedSsh

This project allows bidirectional enforcement of hardware-protected keys for SSH. Trusted Platform Module (TPM) attestation ensures that both parties are using hardware root of trust, a secure host, and non-exportable authentication keys.

```
$ ./CliTst 
Initializing test of remote platform attestation using local host TPM 2.0 device...
Successfully established an Attestation Identity Key with the Attestation Server
Successfully created a sealed user key
Successfully checked TPM user key with Attestation Server whitelist
Successfully signed and verified and message with the TPM user key
```
