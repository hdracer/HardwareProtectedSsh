# HardwareProtectedSsh

This project allows bidirectional enforcement of hardware-protected keys for SSH. Trusted Platform Module (TPM) attestation ensures that both parties are using hardware root of trust, a secure host, and non-exportable authentication keys.

```
$ ./CliTst 
Client: open a handle to the TPM Endorsement Key (EK): a536cc4a 38f52fce bdeb0da1 110de204 d0aed7f6 fe6df9f8 efc8a724 2eef8f88
Client: open a handle to the TPM Storage Root Key (SRK)...
Client: create a restricted key: 0004ced3 ffd505eb 5fa2900a 63f254d1 88eb9ff3 db44
Client: decrypted secret: 72d4856e 074371da
Client: create a general purpose signing key on the TPM...
Client: message hash: c93ee7a5 2c78653c c5836f5b 5db1fe53 b9f3219e
Server: signer and message verification succeeded
```
